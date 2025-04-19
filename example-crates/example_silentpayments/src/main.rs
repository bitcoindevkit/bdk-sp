mod indexer;

use std::{
    cmp, env,
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{self, bail, Context};
use clap::{self, Args, Parser, Subcommand};
use miniscript::{
    descriptor::{DescriptorSecretKey, DescriptorType},
    Descriptor, DescriptorPublicKey, ToPublicKey,
};
use rand::{rng, seq::SliceRandom, RngCore};
use serde_json::json;

use bdk_chain::{
    local_chain::{self, LocalChain},
    tx_graph, BlockId, ChainOracle, ConfirmationBlockTime, FullTxOut, Merge, TxGraph, TxPosInBlock,
};

use bdk_file_store::Store;

use bdk_coin_select::Candidate;

use bdk_silentpayments::{
    bitcoin::{
        address::NetworkUnchecked,
        bip32::{self, DerivationPath},
        constants,
        secp256k1::{Secp256k1, SecretKey},
        Address, Amount, Block, Network, OutPoint, Psbt, ScriptBuf, TxOut,
    },
    encoding::SilentPaymentCode,
    receive::{Scanner, SpOut},
    send::XprivSilentPaymentSender,
};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client},
    Emitter,
};

use crate::indexer::{Custom, SpIndexer, SpIndexes, SpIndexesChangeSet};

#[allow(dead_code)]
const SILENT_PAYMENT_SPEND_WIF: &str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";
#[allow(dead_code)]
const SILENT_PAYMENT_SCAN_WIF: &str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
#[allow(dead_code)]
const SILENT_PAYMENT_SPEND_SECRETKEY: &str =
    "6d87b87889341032b6509470233601a722834808def6454450bf42a9af22d263";
#[allow(dead_code)]
const SILENT_PAYMENT_SCAN_SECRETKEY: &str =
    "b700f356a63cbab8da1fb7b3e5cbbfbb4e56d83c8b7271d0bc6f92882f70aa85";
const SILENT_PAYMENT_ENCODED: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

const CHANGE_LABEL: u32 = 0;

const DB_MAGIC: &[u8] = b"bdk_example_silentpayments";
const DB_PATH: &str = ".bdk_example_silentpayments.db";

/// Delay for printing status to stdout.
const STDOUT_PRINT_DELAY: Duration = Duration::from_secs(6);
/// Delay for committing to persistence.
const DB_COMMIT_DELAY: Duration = Duration::from_secs(60);

/// A changeset for [`Wallet`](crate::Wallet).
#[derive(Default, Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ChangeSet {
    /// Descriptors for recipient addresses.
    pub scan_descriptor: Option<Descriptor<DescriptorPublicKey>>,
    pub spend_descriptor: Option<Descriptor<DescriptorPublicKey>>,
    /// Stores the network type of the transaction data.
    pub network: Option<bitcoin::Network>,
    /// Changes to the [`LocalChain`](local_chain::LocalChain).
    pub local_chain: local_chain::ChangeSet,
    /// Changes to [`TxGraph`](tx_graph::TxGraph).
    pub tx_graph: tx_graph::ChangeSet<ConfirmationBlockTime>,
    /// Changes to [`SpIndexes`](SpIndexes).
    pub indexes: SpIndexesChangeSet,
}

impl Merge for ChangeSet {
    fn merge(&mut self, other: Self) {
        if other.scan_descriptor.is_some() {
            self.scan_descriptor = other.scan_descriptor;
        }
        if other.spend_descriptor.is_some() {
            self.spend_descriptor = other.spend_descriptor;
        }
        if other.network.is_some() {
            self.network = other.network;
        }
        Merge::merge(&mut self.local_chain, other.local_chain);
        Merge::merge(&mut self.tx_graph, other.tx_graph);
        Merge::merge(&mut self.indexes, other.indexes);
    }

    fn is_empty(&self) -> bool {
        self.scan_descriptor.is_none()
            && self.spend_descriptor.is_none()
            && self.network.is_none()
            && self.local_chain.is_empty()
            && self.tx_graph.is_empty()
            && self.indexes.is_empty()
    }
}

#[derive(Args, Debug, Clone)]
pub struct RpcArgs {
    /// RPC URL
    #[clap(env = "RPC_URL", long, default_value = "127.0.0.1:8332")]
    url: String,
    /// RPC auth username
    #[clap(env = "RPC_USER", long)]
    rpc_user: Option<String>,
    /// RPC auth password
    #[clap(env = "RPC_PASS", long)]
    rpc_password: Option<String>,
}

impl RpcArgs {
    fn new_client(&self) -> anyhow::Result<Client> {
        Ok(Client::new(
            &self.url,
            match (&self.rpc_user, &self.rpc_password) {
                (None, None) => Auth::None,
                (Some(user), Some(pass)) => Auth::UserPass(user.clone(), pass.clone()),
                (Some(_), None) => panic!("rpc auth: missing rpc_pass"),
                (None, Some(_)) => panic!("rpc auth: missing rpc_user"),
            },
        )?)
    }
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct SpArgs {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Generate {
        /// Network
        #[clap(long, short, default_value = "signet")]
        network: Network,
    },
    Code {
        #[clap(long)]
        label: Option<u32>,
        /// Private descriptor
        #[clap(long = "scan", env = "SCAN_DESCRIPTOR")]
        scan_descriptor: Option<String>,
    },
    Init {
        /// Network
        #[clap(long, short, default_value = "signet", env = "NETWORK")]
        network: Network,
        /// Descriptor
        #[clap(long = "scan", env = "SCAN_DESCRIPTOR")]
        scan_descriptor: String,
        /// Change descriptor
        #[clap(long = "spend", env = "SPEND_DESCRIPTOR")]
        spend_descriptor: String,
    },
    /// Replace PSBT single taproot output with a silent payment derived taproot output
    ToSilentPayment {
        /// Silent payment code from which you want to derive the script pub key
        #[clap(long = "code", default_value = SILENT_PAYMENT_ENCODED)]
        silent_payment_code: String,
        /// The amount denominated in satoshis of the output you are going to replace
        #[clap(long)]
        amount: u64,
        /// The original PSBT you are trying to replace outputs from
        #[clap(long)]
        psbt: String,
        /// Private descriptor you need to get the private keys to create the silent payment script
        /// pubkey
        #[clap(long)]
        descriptor: Option<String>,
        /// Debug print the PSBT
        #[clap(long, short)]
        debug: bool,
    },
    /// Use bitcoind RPC to scan the blockchain looking for silent payment outputs belonging to the
    /// provided silent payment code
    Scan {
        /// The scan key needed to generate the shared secret in combination with tx inputs
        #[clap(long = "scan", env = "SCAN_DESCRIPTOR")]
        scan_descriptor: String,
        /// Silent payment code to get the spend pub key from to derive the full script pubkey
        #[clap(long = "code", default_value = SILENT_PAYMENT_ENCODED)]
        silent_payment_code: String,
        /// The RPC parameters to communicate with bitcoind RPC
        #[clap(flatten)]
        rpc_args: RpcArgs,
    },
    NewPsbt {
        /// Amount to send in satoshis
        value: u64,
        /// Recipient address
        address: Address<NetworkUnchecked>,
        /// Set max absolute timelock (from consensus value)
        #[clap(long, short)]
        after: Option<u32>,
        /// Set max relative timelock (from consensus value)
        #[clap(long, short)]
        older: Option<u32>,
        /// Coin selection algorithm
        #[clap(long, short, default_value = "bnb")]
        coin_select: CoinSelectionAlgo,
        /// Debug print the PSBT
        #[clap(long, short)]
        debug: bool,
    },
    Balance,
}

#[derive(Clone, Debug, Default)]
pub enum CoinSelectionAlgo {
    LargestFirst,
    SmallestFirst,
    OldestFirst,
    NewestFirst,
    #[default]
    BranchAndBound,
}

impl FromStr for CoinSelectionAlgo {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use CoinSelectionAlgo::*;
        Ok(match s {
            "largest-first" => LargestFirst,
            "smallest-first" => SmallestFirst,
            "oldest-first" => OldestFirst,
            "newest-first" => NewestFirst,
            "bnb" => BranchAndBound,
            unknown => bail!("unknown coin selection algorithm '{}'", unknown),
        })
    }
}

impl std::fmt::Display for CoinSelectionAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CoinSelectionAlgo::*;
        write!(
            f,
            "{}",
            match self {
                LargestFirst => "largest-first",
                SmallestFirst => "smallest-first",
                OldestFirst => "oldest-first",
                NewestFirst => "newest-first",
                BranchAndBound => "bnb",
            }
        )
    }
}

#[inline]
fn is_change(spout: &SpOut, _: ScriptBuf) -> bool {
    spout.label.map_or(false, |x| x == CHANGE_LABEL)
}

fn main() -> anyhow::Result<()> {
    let Init {
        args,
        graph,
        chain,
        db,
        sp_code,
        mut indexes,
    } = match init_or_load(DB_MAGIC, DB_PATH)? {
        Some(init) => init,
        None => return Ok(()),
    };

    match args.command {
        Commands::Init { .. } | Commands::Generate { .. } => {
            unreachable!("already handled by init_or_load")
        }
        Commands::Code {
            label,
            scan_descriptor,
        } => {
            let secp = Secp256k1::new();

            match label {
                None => {
                    let mut obj = serde_json::Map::new();
                    obj.insert(
                        "silent_payment_code".to_string(),
                        json!(sp_code.to_string()),
                    );
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                }
                Some(_) if scan_descriptor.is_none() => bail!("unable to generate labelled silent payment code without spend private descriptor"),
                Some(m) => {
                    let scan_sk = get_sk_from_sp_descriptor(scan_descriptor.unwrap())?;

                    let label = SilentPaymentCode::get_label(scan_sk, m);
                    let labelled_sp_code = sp_code.add_label(label)?;
                    let neg_spend_pk = sp_code.spend.negate(&secp);
                    #[allow(non_snake_case)]
                    // label_G = B_m - B_spend
                    let label_G = labelled_sp_code.spend.combine(&neg_spend_pk)?;
                    indexes.label_to_tweak.insert(label_G, (label, m));
                    {
                        let db = &mut *db.lock().unwrap();
                        db.append(&ChangeSet {
                            indexes: indexes.into(),
                            ..Default::default()
                        })?;
                    }
                    let mut obj = serde_json::Map::new();
                    obj.insert(
                        "labelled_silent_payment_code".to_string(),
                        json!(labelled_sp_code.to_string()),
                    );
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                }
            };
        }
        Commands::ToSilentPayment {
            silent_payment_code,
            amount,
            psbt,
            descriptor,
            debug,
        } => {
            let mut psbt = Psbt::from_str(psbt.as_str())?;

            let single_external_txout = psbt
                .unsigned_tx
                .output
                .iter()
                .find(|x| x.value == Amount::from_sat(amount))
                .expect("send to multiple addresses not implemented yet")
                .clone();

            if !single_external_txout.script_pubkey.is_p2tr() {
                bail!("can only replace p2tr outputs");
            }

            let desc_str = match descriptor {
                Some(s) => s,
                None => env::var("DESCRIPTOR").context("unable to sign")?,
            };

            let secp = Secp256k1::signing_only();
            let (_, keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;

            if keymap.is_empty() {
                bail!("unable to sign")
            }

            let master_privkey = match keymap.iter().next().expect("not empty") {
                (_, DescriptorSecretKey::XPrv(privkey)) => privkey.xkey,
                _ => unimplemented!("multi xkey signer"),
            };

            let sp_sender = XprivSilentPaymentSender::new(master_privkey);

            let silent_payment_code = SilentPaymentCode::try_from(silent_payment_code.as_str())?;

            let mut outputs_and_derivation_paths = <Vec<(OutPoint, DerivationPath)>>::new();
            for (psbt_input, txin) in psbt.inputs.iter().zip(psbt.unsigned_tx.input.clone()) {
                for (fingerprint, path) in psbt_input
                    .bip32_derivation
                    .values()
                    .chain(psbt_input.tap_key_origins.values().map(|x| &x.1))
                {
                    if *fingerprint == master_privkey.fingerprint(&secp) {
                        outputs_and_derivation_paths.push((txin.previous_output, path.clone()));
                        break;
                    }
                }
            }

            let sp_script_pubkeys =
                sp_sender.send_to(&outputs_and_derivation_paths, &[silent_payment_code])?;

            let txout = TxOut {
                value: single_external_txout.value,
                script_pubkey: sp_script_pubkeys
                    .first()
                    .expect("only provided one silent payment code")
                    .clone(),
            };

            psbt.unsigned_tx.output = psbt
                .unsigned_tx
                .output
                .into_iter()
                .map(|x| {
                    if x.script_pubkey == single_external_txout.script_pubkey {
                        txout.clone()
                    } else {
                        x
                    }
                })
                .collect();

            if debug {
                dbg!(psbt);
            } else {
                // print base64 encoded psbt
                let fee = psbt.fee()?.to_sat();
                let mut obj = serde_json::Map::new();
                obj.insert("psbt".to_string(), json!(psbt.to_string()));
                obj.insert("fee".to_string(), json!(fee));
                println!("{}", serde_json::to_string_pretty(&obj)?);
            };
        }
        Commands::Scan {
            scan_descriptor,
            silent_payment_code,
            rpc_args,
        } => {
            let start = Instant::now();
            let scan_sk = get_sk_from_sp_descriptor(scan_descriptor)?;
            let silent_payment_code = SilentPaymentCode::try_from(silent_payment_code.as_str())?;

            let rpc_client = rpc_args.new_client()?;
            let chain_tip = chain.lock().unwrap().tip();
            let custom_client = Custom(&rpc_client);
            let scanner = Scanner::new(scan_sk, silent_payment_code.spend, indexes.label_to_tweak);
            let mut sp_indexer =
                SpIndexer::<_, bdk_chain::ConfirmationBlockTime>::new(custom_client, scanner);

            let mut emitter = Emitter::new(&rpc_client, chain_tip, 0);
            let mut db_stage = ChangeSet::default();

            let mut last_db_commit = Instant::now();
            let mut last_print = Instant::now();
            let mut never_printed = true;

            while let Some(emission) = emitter.next_block()? {
                let mut chain = chain.lock().unwrap();
                let mut graph = graph.lock().unwrap();
                let height = emission.block_height();

                db_stage.local_chain.merge(
                    chain
                        .apply_update(emission.checkpoint)
                        .expect("must always apply as we receive blocks in order from emitter"),
                );

                let block = &emission.block;
                let hash = block.block_hash();
                let Block { ref txdata, .. } = block;

                let block_id = BlockId { hash, height };
                for (tx_pos, tx) in txdata.iter().enumerate().skip(1) {
                    if !tx.output.iter().any(|x| x.script_pubkey.is_p2tr()) {
                        continue;
                    }
                    let tx_graph_stage = sp_indexer.index_tx(tx)?;
                    if !tx_graph_stage.is_empty() || sp_indexer.spends_owned_spouts(tx) {
                        let txid = tx.compute_txid();
                        db_stage.tx_graph.merge(tx_graph_stage);
                        let anchor = TxPosInBlock {
                            block,
                            block_id,
                            tx_pos,
                        }
                        .into();
                        db_stage.tx_graph.merge(graph.insert_tx(tx.clone()));
                        db_stage.tx_graph.merge(graph.insert_anchor(txid, anchor));
                    }
                }

                // commit staged db changes in intervals
                if last_db_commit.elapsed() >= DB_COMMIT_DELAY {
                    let db = &mut *db.lock().unwrap();
                    last_db_commit = Instant::now();
                    db_stage.indexes.merge(sp_indexer.indexes.clone().into());
                    if let Some(changeset) = db_stage.take() {
                        db.append(&changeset)?;
                    }
                    println!(
                        "[{:>10}s] committed to db (took {}s)",
                        start.elapsed().as_secs_f32(),
                        last_db_commit.elapsed().as_secs_f32()
                    );
                }

                // print synced-to height and current balance in intervals
                if last_print.elapsed() >= STDOUT_PRINT_DELAY {
                    last_print = Instant::now();
                    let synced_to = chain.tip();
                    let outpoints = sp_indexer
                        .indexes
                        .spouts
                        .clone()
                        .into_iter()
                        .map(|(x, y)| (y, x));
                    let balance =
                        { graph.balance(&*chain, synced_to.block_id(), outpoints, |_, _| false) };
                    println!(
                        "[{:>10}s] synced to {} @ {} | total: {}",
                        start.elapsed().as_secs_f32(),
                        synced_to.hash(),
                        synced_to.height(),
                        balance.total()
                    );
                    never_printed = false;
                }
            }

            let db = &mut *db.lock().unwrap();
            db_stage.indexes.merge(sp_indexer.indexes.clone().into());
            if let Some(changeset) = db_stage.take() {
                db.append(&changeset)?;
            }
            println!(
                "[{:>10}s] committed to db (took {}s)",
                start.elapsed().as_secs_f32(),
                last_db_commit.elapsed().as_secs_f32()
            );

            if never_printed {
                let chain = &*chain.lock().unwrap();
                let graph = &*graph.lock().unwrap();
                let synced_to = chain.tip();
                let outpoints = sp_indexer
                    .indexes
                    .spouts
                    .clone()
                    .into_iter()
                    .map(|(x, y)| (y, x));
                let balance = { graph.balance(chain, synced_to.block_id(), outpoints, is_change) };
                println!(
                    "[{:>10}s] synced to {} @ {} | total: {}",
                    start.elapsed().as_secs_f32(),
                    synced_to.hash(),
                    synced_to.height(),
                    balance.total()
                );
            }

            let spouts = sp_indexer
                .indexes
                .spouts
                .values()
                .map(|x| x.outpoint.txid)
                .collect::<Vec<_>>();
            let mut obj = serde_json::Map::new();
            obj.insert("silent_payments_found".to_string(), json!(&spouts));
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        Commands::Balance => {
            let graph = &*graph.lock().unwrap();
            let chain = &*chain.lock().unwrap();
            fn print_balances<'a>(
                title_str: &'a str,
                items: impl IntoIterator<Item = (&'a str, Amount)>,
            ) {
                println!("{}:", title_str);
                for (name, amount) in items.into_iter() {
                    println!("    {:<10} {:>12} sats", name, amount.to_sat())
                }
            }

            let outpoints = indexes.spouts.into_iter().map(|(x, y)| (y, x));

            let balance = graph.try_balance(chain, chain.get_chain_tip()?, outpoints, is_change)?;

            let confirmed_total = balance.confirmed + balance.immature;
            let unconfirmed_total = balance.untrusted_pending + balance.trusted_pending;

            print_balances(
                "confirmed",
                [
                    ("total", confirmed_total),
                    ("spendable", balance.confirmed),
                    ("immature", balance.immature),
                ],
            );
            print_balances(
                "unconfirmed",
                [
                    ("total", unconfirmed_total),
                    ("trusted", balance.trusted_pending),
                    ("untrusted", balance.untrusted_pending),
                ],
            );
        }
        Commands::NewPsbt {
            value,
            address,
            after: _,
            older: _,
            coin_select,
            debug: _,
        } => {
            let chain = &*chain.lock().unwrap();
            let graph = &*graph.lock().unwrap();

            let chain_tip = chain.get_chain_tip()?;
            let address = address.require_network(sp_code.network)?;
            let outpoints = indexes.spouts.into_iter().map(|(x, y)| (y, x));
            #[allow(clippy::type_complexity)]
            let mut utxos = graph
                .try_filter_chain_unspents(chain, chain_tip, outpoints)?
                .filter_map(
                    |(spout, full_txo)| -> Option<
                        Result<
                            (SpOut, FullTxOut<ConfirmationBlockTime>),
                            <bdk_chain::local_chain::LocalChain as bdk_chain::ChainOracle>::Error,
                        >,
                    > {
                        if full_txo.is_mature(chain_tip.height) {
                            Some(Ok((spout, full_txo)))
                        } else {
                            None
                        }
                    },
                )
                .collect::<Result<Vec<(SpOut, FullTxOut<ConfirmationBlockTime>)>, _>>()?;

            match coin_select {
                CoinSelectionAlgo::LargestFirst => {
                    utxos.sort_by_key(|(_, utxo)| cmp::Reverse(utxo.txout.value))
                }
                CoinSelectionAlgo::SmallestFirst => utxos.sort_by_key(|(_, utxo)| utxo.txout.value),
                CoinSelectionAlgo::OldestFirst => {
                    utxos.sort_by_key(|(_, utxo)| utxo.chain_position)
                }
                CoinSelectionAlgo::NewestFirst => {
                    utxos.sort_by_key(|(_, utxo)| cmp::Reverse(utxo.chain_position))
                }
                CoinSelectionAlgo::BranchAndBound => utxos.shuffle(&mut rng()),
            }

            // build candidate set
            let _candidates: Vec<Candidate> = utxos
                .iter()
                .map(|(_plan, utxo)| {
                    Candidate::new(
                        utxo.txout.value.to_sat(),
                        // key spend path:
                        // scriptSigLen(4) + stackLen(1) + stack[Sig]Len(1) + stack[Sig](65)
                        4 + 1 + 1 + 65,
                        true,
                    )
                })
                .collect();

            // create recipient output(s)
            let mut _outputs = [TxOut {
                value: Amount::from_sat(value),
                script_pubkey: address.script_pubkey(),
            }];

            // TODO:
            // [ ] Create change output with identifiable fingerprint
            // [ ] Create SilentPaymentSender which doesn't depend of DerivationPaths to get a_sum

            //let mut change_output = TxOut {
            //value: Amount::ZERO,
            //script_pubkey: change_script,
            //};
        } // sort utxos if cs-algo requires it
    };

    Ok(())
}

/// The initial state returned by [`init_or_load`].
pub struct Init {
    /// CLI args
    pub args: SpArgs,
    /// Indexed graph
    pub graph: Mutex<TxGraph>,
    /// Local chain
    pub chain: Mutex<LocalChain>,
    pub sp_code: SilentPaymentCode,
    pub indexes: SpIndexes,
    /// Database
    pub db: Mutex<Store<ChangeSet>>,
}

pub fn init_or_load(db_magic: &[u8], db_path: &str) -> anyhow::Result<Option<Init>> {
    let args = SpArgs::parse();

    match args.command {
        Commands::Generate { network } => {
            let secp = Secp256k1::new();
            let mut seed = [0x00; 32];
            rand::rng().fill_bytes(&mut seed);

            let m = bip32::Xpriv::new_master(network, &seed)?;
            let fp = m.fingerprint(&secp);
            let scan_privkey_derivation = "1h/0";
            let spend_privkey_derivation = "0h/0";
            let path = if m.network.is_mainnet() {
                "352h/0h/0h"
            } else {
                "352h/1h/0h"
            };

            let descriptors: Vec<String> = [scan_privkey_derivation, spend_privkey_derivation]
                .iter()
                .map(|final_deriv| format!("tr([{fp}]{m}/{path}/{final_deriv})"))
                .collect();
            let scan_privkey_descriptor = &descriptors[0];
            let spend_privkey_descriptor = &descriptors[1];
            let (scan_descriptor, scan_keymap) =
                <Descriptor<DescriptorPublicKey>>::parse_descriptor(
                    &secp,
                    scan_privkey_descriptor,
                )?;
            let (spend_descriptor, spend_keymap) =
                <Descriptor<DescriptorPublicKey>>::parse_descriptor(
                    &secp,
                    spend_privkey_descriptor,
                )?;
            let mut obj = serde_json::Map::new();
            obj.insert(
                "public_scan_descriptor".to_string(),
                json!(scan_descriptor.to_string()),
            );
            obj.insert(
                "private_scan_descriptor".to_string(),
                json!(scan_descriptor.to_string_with_secret(&scan_keymap)),
            );
            obj.insert(
                "public_spend_descriptor".to_string(),
                json!(spend_descriptor.to_string()),
            );
            obj.insert(
                "private_spend_descriptor".to_string(),
                json!(spend_descriptor.to_string_with_secret(&spend_keymap)),
            );
            println!("{}", serde_json::to_string_pretty(&obj)?);
            Ok(None)
        }
        Commands::Init {
            network,
            scan_descriptor,
            spend_descriptor,
        } => {
            let mut changeset = ChangeSet::default();

            // parse descriptors
            let secp = Secp256k1::new();
            let (scan, _) =
                Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &scan_descriptor)?;
            let (spend, _) =
                Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &spend_descriptor)?;

            changeset.scan_descriptor = Some(scan);
            changeset.spend_descriptor = Some(spend);

            // create new
            let (_, chain_changeset) =
                LocalChain::from_genesis_hash(constants::genesis_block(network).block_hash());
            changeset.network = Some(network);
            changeset.local_chain = chain_changeset;
            let mut db = Store::<ChangeSet>::create(db_magic, db_path)?;
            db.append(&changeset)?;
            println!("New database {DB_PATH}");
            Ok(None)
        }
        _ => {
            let (db, changeset) =
                Store::<ChangeSet>::load(db_magic, db_path).context("could not open file store")?;

            let changeset = changeset.expect("should not be empty");

            let network = changeset.network.expect("changeset network");
            let sp_code = if let (Some(scan_d), Some(spend_d)) =
                (changeset.scan_descriptor, changeset.spend_descriptor)
            {
                if !scan_d.has_wildcard() && !spend_d.has_wildcard() {
                    let scan_def_d = scan_d.at_derivation_index(0)?;
                    let spend_def_d = spend_d.at_derivation_index(0)?;
                    match (scan_def_d, spend_def_d) {
                        (Descriptor::Tr(scan_), Descriptor::Tr(spend_)) => {
                            let scan = scan_.internal_key().to_public_key();
                            let spend = spend_.internal_key().to_public_key();
                            SilentPaymentCode {
                                scan: bitcoin::secp256k1::PublicKey::from_slice(
                                    &scan.to_bytes()[..],
                                )?,
                                spend: bitcoin::secp256k1::PublicKey::from_slice(
                                    &spend.to_bytes()[..],
                                )?,
                                version: 0,
                                network,
                            }
                        }
                        _ => return Ok(None),
                    }
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            };

            let chain = Mutex::new({
                let (mut chain, _) =
                    LocalChain::from_genesis_hash(constants::genesis_block(network).block_hash());
                chain.apply_changeset(&changeset.local_chain)?;
                chain
            });

            let mut tx_graph = TxGraph::default();
            tx_graph.apply_changeset(changeset.tx_graph);

            let indexes = SpIndexes::from(changeset.indexes);
            let graph = Mutex::new(tx_graph);
            let db = Mutex::new(db);

            Ok(Some(Init {
                args,
                sp_code,
                graph,
                chain,
                db,
                indexes,
            }))
        }
    }
}

fn get_sk_from_sp_descriptor(desc_str: String) -> Result<SecretKey, anyhow::Error> {
    let secp = Secp256k1::signing_only();
    let (descriptor, keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;

    if descriptor.desc_type() != DescriptorType::Tr {
        bail!("silent payment descriptors should be Taproot")
    }

    if keymap.is_empty() {
        bail!("unable to derive label")
    }

    // note: we're only looking at the first entry in the keymap
    // the idea is to find something that impls `GetKey`
    match keymap.iter().next().expect("not empty") {
        (_, DescriptorSecretKey::XPrv(privkey)) => {
            let derived_key = privkey.xkey.derive_priv(&secp, &privkey.derivation_path)?;
            Ok(derived_key.private_key)
        }
        _ => unimplemented!("multi xkey signer"),
    }
}
