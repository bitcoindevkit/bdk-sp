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

use bdk_coin_select::{
    metrics::LowestFee, Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, Target,
    TargetFee, TargetOutputs,
};

use bdk_sp::{
    bitcoin::{
        absolute,
        address::NetworkUnchecked,
        bip32::{self, DerivationPath},
        constants,
        key::{Keypair, UntweakedPublicKey},
        secp256k1::{Message, Scalar, Secp256k1, SecretKey},
        sighash::{Prevouts, SighashCache},
        taproot::Signature,
        transaction::Version,
        Address, Amount, Block, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType,
        Transaction, TxIn, TxOut, XOnlyPublicKey,
    },
    encoding::SilentPaymentCode,
    receive::{Scanner, SpOut},
    send::{SpSender, XprivSilentPaymentSender},
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
        address: Option<Address<NetworkUnchecked>>,
        /// Silent payment code from which you want to derive the script pub key
        #[clap(long = "code")]
        silent_payment_code: Option<String>,
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
        /// The descriptor of the spending key needed to generate the shared secret in combination with tx inputs
        #[clap(long = "spend", env = "SPEND_DESCRIPTOR")]
        spend_descriptor: String,
    },
    SignPsbt {
        /// PSBT
        #[clap(long)]
        psbt: String,
        /// The descriptor of the spending key needed to generate the shared secret in combination with tx inputs
        #[clap(long = "spend", env = "SPEND_DESCRIPTOR")]
        spend_descriptor: String,
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

    let fake_address = {
        let secp = Secp256k1::verification_only();
        let scan_key = UntweakedPublicKey::from(sp_code.scan);

        Address::p2tr(&secp, scan_key, None, sp_code.network)
    };

    let change_fake_script = {
        let secp = Secp256k1::verification_only();
        let change_label_key = UntweakedPublicKey::from(
            *indexes
                .num_to_label
                .get(&CHANGE_LABEL)
                .expect("change label should always exist"),
        );

        ScriptBuf::new_p2tr(&secp, change_label_key, None)
    };

    match args.command {
        Commands::Init { .. } | Commands::Generate { .. } => {
            unreachable!("already handled by init_or_load")
        }
        Commands::Code {
            label,
            scan_descriptor,
        } => {
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
                    let labelled_sp_code = indexes.add_label(sp_code, scan_sk, m)?;
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
            let chain = &mut *chain.lock().unwrap();
            let graph = &mut *graph.lock().unwrap();

            let start = Instant::now();
            let scan_sk = get_sk_from_sp_descriptor(scan_descriptor)?;
            let silent_payment_code = SilentPaymentCode::try_from(silent_payment_code.as_str())?;

            let rpc_client = rpc_args.new_client()?;
            let custom_client = Custom(&rpc_client);
            let scanner = Scanner::new(
                scan_sk,
                silent_payment_code.spend,
                indexes.clone().label_to_tweak,
            );
            let mut sp_indexer = SpIndexer::<_, bdk_chain::ConfirmationBlockTime>::new(
                custom_client,
                scanner,
                indexes,
                graph.clone(),
            );

            let mut emitter = Emitter::new(&rpc_client, chain.tip(), 0);
            let mut db_stage = ChangeSet::default();

            let mut last_db_commit = Instant::now();
            let mut last_print = Instant::now();
            let mut never_printed = true;

            while let Some(emission) = emitter.next_block()? {
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
                        graph.balance(&*chain, synced_to.block_id(), outpoints, is_change);
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
                let synced_to = chain.tip();
                let outpoints = sp_indexer
                    .indexes
                    .spouts
                    .clone()
                    .into_iter()
                    .map(|(x, y)| (y, x));
                let balance = graph.balance(chain, synced_to.block_id(), outpoints, is_change);
                println!(
                    "[{:>10}s] synced to {} @ {} | total: {}",
                    start.elapsed().as_secs_f32(),
                    synced_to.hash(),
                    synced_to.height(),
                    balance.total()
                );
            }
        }
        Commands::Balance => {
            let graph = &*graph.lock().unwrap();
            let chain = &*chain.lock().unwrap();
            fn print_balances<'a>(
                title_str: &'a str,
                items: impl IntoIterator<Item = (&'a str, Amount)>,
            ) -> anyhow::Result<()> {
                let mut obj = serde_json::Map::new();
                let mut sub_obj = serde_json::Map::new();
                for (name, amount) in items.into_iter() {
                    sub_obj.insert(name.to_string(), json!(amount.to_sat()));
                }
                obj.insert(title_str.to_string(), json!(sub_obj));
                println!("{}", serde_json::to_string_pretty(&obj)?);
                Ok(())
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
            )?;
            print_balances(
                "unconfirmed",
                [
                    ("total", unconfirmed_total),
                    ("trusted", balance.trusted_pending),
                    ("untrusted", balance.untrusted_pending),
                ],
            )?;
        }
        Commands::NewPsbt {
            value,
            address,
            after: _,
            older: _,
            coin_select,
            debug: _,
            silent_payment_code,
            spend_descriptor,
        } => {
            let chain = &*chain.lock().unwrap();
            let graph = &*graph.lock().unwrap();

            let chain_tip = chain.get_chain_tip()?;
            let mut sp_codes = <Vec<(ScriptBuf, SilentPaymentCode)>>::new();
            let final_address = match (&silent_payment_code, address) {
                (Some(sp_code), None) => {
                    sp_codes.push((
                        fake_address.script_pubkey(),
                        SilentPaymentCode::try_from(sp_code.as_str())?,
                    ));
                    fake_address.clone()
                }
                (None, Some(address)) => address.require_network(sp_code.network)?,
                _ => bail!("mixed silent payments not yet allowed"),
            };
            let outpoints = indexes.spouts.clone().into_iter().map(|(x, y)| (y, x));
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
            let candidates: Vec<Candidate> = utxos
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
            let mut outputs = vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: final_address.script_pubkey(),
            }];

            let mut change_output = TxOut {
                value: Amount::ZERO,
                script_pubkey: change_fake_script.clone(),
            };

            let min_drain_value = change_fake_script.minimal_non_dust().to_sat();

            let target = Target {
                outputs: TargetOutputs::fund_outputs(
                    outputs
                        .iter()
                        .map(|output| (output.weight().to_wu(), output.value.to_sat())),
                ),
                fee: TargetFee::default(),
            };

            let change_policy = ChangePolicy {
                min_value: min_drain_value,
                drain_weights: DrainWeights::TR_KEYSPEND,
            };

            // run coin selection
            let mut selector = CoinSelector::new(&candidates);
            match coin_select {
                CoinSelectionAlgo::BranchAndBound => {
                    let metric = LowestFee {
                        target,
                        long_term_feerate: FeeRate::from_sat_per_vb(10.0),
                        change_policy,
                    };
                    match selector.run_bnb(metric, 10_000) {
                        Ok(_) => {}
                        Err(_) => selector
                            .select_until_target_met(target)
                            .context("selecting coins")?,
                    }
                }
                _ => selector
                    .select_until_target_met(target)
                    .context("selecting coins")?,
            }

            // get the selected plan utxos
            let selected: Vec<(SpOut, FullTxOut<ConfirmationBlockTime>)> =
                selector.apply_selection(&utxos).cloned().collect();

            // if the selection tells us to use change and the change value is sufficient, we add it as an output
            let drain = selector.drain(target, change_policy);
            if drain.value > min_drain_value {
                change_output.value = Amount::from_sat(drain.value);
                outputs.push(change_output.clone());
                let change_label_scalar = indexes
                    .get_label(CHANGE_LABEL)
                    .expect("change label should always exist");
                let change_spcode = sp_code.add_label(change_label_scalar)?;
                sp_codes.push((change_output.script_pubkey, change_spcode));
            }

            let unsigned_tx = Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::from_height(chain.get_chain_tip()?.height)?,
                input: selected
                    .iter()
                    .map(|(_sp_out, utxo)| TxIn {
                        previous_output: utxo.outpoint,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        ..Default::default()
                    })
                    .collect(),
                output: outputs.to_vec(),
            };
            // update psbt with plan
            let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
            for (i, (_sp_out, utxo)) in selected.iter().enumerate() {
                let psbt_input = &mut psbt.inputs[i];
                psbt_input.witness_utxo = Some(utxo.txout.clone());
            }

            if !sp_codes.is_empty() {
                let spend_sk = get_sk_from_sp_descriptor(spend_descriptor)?;
                let spouts = selected.into_iter().map(|x| x.0).collect::<Vec<SpOut>>();
                let just_sp_codes = sp_codes
                    .clone()
                    .iter()
                    .map(|x| x.1.clone())
                    .collect::<Vec<SilentPaymentCode>>();
                let just_sp_script_pubkeys = sp_codes
                    .clone()
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<ScriptBuf>>();
                let sp_spks = SpSender::new(spend_sk).send_to(&spouts, &just_sp_codes)?;
                // WARN: collect iterator to avoid consuming it while checking for outputs
                let spk_to_sp_spk = just_sp_script_pubkeys
                    .iter()
                    .zip(sp_spks)
                    .collect::<Vec<(&ScriptBuf, ScriptBuf)>>();

                let new_outputs = outputs
                    .clone()
                    .into_iter()
                    .map(|x| {
                        // WARN: use iter() here instead of directly using an iterator to keep all
                        // the values in the spk_to_sp_spk collection, instead of consuming the
                        // full iterator and miss all scriptpubkeys after the first iteration.
                        if let Some(sp_spk) = spk_to_sp_spk.iter().find_map(|(spk, sp_spk)| {
                            if x.script_pubkey == **spk {
                                Some(sp_spk)
                            } else {
                                None
                            }
                        }) {
                            TxOut {
                                value: x.value,
                                script_pubkey: sp_spk.clone(),
                            }
                        } else {
                            x
                        }
                    })
                    .collect::<Vec<TxOut>>();
                psbt.unsigned_tx.output = new_outputs;
            }
            // print base64 encoded psbt
            let fee = psbt.fee()?.to_sat();
            let mut obj = serde_json::Map::new();
            obj.insert("psbt".to_string(), json!(psbt.to_string()));
            obj.insert("fee".to_string(), json!(fee));
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        Commands::SignPsbt {
            psbt,
            spend_descriptor,
        } => {
            let secp = Secp256k1::new();
            let spend_sk = get_sk_from_sp_descriptor(spend_descriptor)?;
            let mut psbt = Psbt::from_str(psbt.as_str())?;
            let sighash_type = TapSighashType::Default;
            let prevouts = psbt
                .inputs
                .iter()
                .map(|x| x.witness_utxo.clone().unwrap())
                .collect::<Vec<TxOut>>();
            let prevouts = Prevouts::All(&prevouts);

            let sighash = SighashCache::new(&mut psbt.unsigned_tx)
                .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
                .expect("failed to construct sighash");

            // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
            let msg = Message::from(sighash);

            for i in 0..psbt.inputs.len() {
                let psbt_input = &mut psbt.inputs[i];
                if let Some(txout) = &psbt_input.witness_utxo {
                    if let Some(spout) = indexes.script_to_spout.get(&txout.script_pubkey) {
                        let sk = spend_sk.add_tweak(&Scalar::from(spout.tweak))?;
                        let keypair = Keypair::from_secret_key(&secp, &sk);
                        let (x_only_internal, _parity) = XOnlyPublicKey::from_keypair(&keypair);

                        let signature = secp.sign_schnorr(&msg, &keypair);

                        let signature = Signature {
                            signature,
                            sighash_type,
                        };
                        psbt_input.tap_key_sig = Some(signature);
                        psbt_input.tap_internal_key = Some(x_only_internal);
                    }
                }
            }

            let mut obj = serde_json::Map::new();
            obj.insert("psbt".to_string(), json!(psbt.to_string()));
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
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
            let mut indexes = SpIndexes::default();

            // parse descriptors
            let secp = Secp256k1::new();
            let (scan, _) =
                Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &scan_descriptor)?;
            let (spend, _) =
                Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &spend_descriptor)?;

            let sp_code = get_sp_code_from_descriptors(&scan, &spend, network)?;

            let scan_sk = get_sk_from_sp_descriptor(scan_descriptor)?;
            indexes.add_label(sp_code, scan_sk, CHANGE_LABEL)?;

            changeset.indexes = indexes.into();
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
                get_sp_code_from_descriptors(&scan_d, &spend_d, network)?
            } else {
                bail!("Loaded db is missing scan or spend descriptors")
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

fn get_sp_code_from_descriptors(
    scan: &Descriptor<DescriptorPublicKey>,
    spend: &Descriptor<DescriptorPublicKey>,
    network: Network,
) -> Result<SilentPaymentCode, anyhow::Error> {
    if !scan.has_wildcard() && !spend.has_wildcard() {
        let scan_def_d = scan.at_derivation_index(0)?;
        let spend_def_d = spend.at_derivation_index(0)?;
        match (scan_def_d, spend_def_d) {
            (Descriptor::Tr(scan_), Descriptor::Tr(spend_)) => {
                let scan = scan_.internal_key().to_public_key();
                let spend = spend_.internal_key().to_public_key();
                Ok(SilentPaymentCode {
                    scan: bitcoin::secp256k1::PublicKey::from_slice(&scan.to_bytes()[..])?,
                    spend: bitcoin::secp256k1::PublicKey::from_slice(&spend.to_bytes()[..])?,
                    version: 0,
                    network,
                })
            }
            _ => bail!("Silent payment descriptors can only be Taproot."),
        }
    } else {
        bail!("Silent payment descriptors should be definitive (non derivable).")
    }
}
