use std::collections::{BTreeMap, BTreeSet};
use std::iter::Extend;

use bdk_chain::{tx_graph, Merge, TxGraph};

use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::{
    bitcoin::{
        secp256k1::{PublicKey, Scalar, SecretKey},
        OutPoint, Transaction, TxOut, Txid,
    },
    receive::{Scanner, SpOut, SpReceiveError},
};

use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};
use bitcoin::key::{Secp256k1, TweakedPublicKey};
use bitcoin::ScriptBuf;

#[derive(Clone, Default, Debug)]
pub struct SpIndexes {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub script_to_spout: BTreeMap<ScriptBuf, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_spout: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: BTreeMap<PublicKey, (Scalar, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
}

impl SpIndexes {
    pub fn add_label(
        &mut self,
        sp_code: SilentPaymentCode,
        scan_sk: SecretKey,
        m: u32,
    ) -> Result<SilentPaymentCode, SpReceiveError> {
        let secp = Secp256k1::verification_only();
        let label = SilentPaymentCode::get_label(scan_sk, m);
        let labelled_sp_code = sp_code.add_label(label)?;
        let neg_spend_pk = sp_code.spend.negate(&secp);
        #[allow(non_snake_case)]
        // label_G = B_m - B_spend
        let label_G = labelled_sp_code.spend.combine(&neg_spend_pk)?;
        self.label_to_tweak.insert(label_G, (label, m));
        self.num_to_label.insert(m, label_G);
        Ok(labelled_sp_code)
    }

    pub fn get_label(&self, m: u32) -> Option<Scalar> {
        if let Some(label_pk) = self.num_to_label.get(&m) {
            self.label_to_tweak.get(&label_pk).and_then(|x| Some(x.0))
        } else {
            None
        }
    }

    pub fn txouts_in_tx(&self, txid: Txid) -> impl DoubleEndedIterator<Item = &SpOut> {
        self.spouts
            .range(OutPoint::new(txid, u32::MIN)..=OutPoint::new(txid, u32::MAX))
            .map(|(_op, spout)| spout)
    }

    pub fn txout(&self, outpoint: OutPoint) -> Option<TxOut> {
        self.spouts.get(&outpoint).map(Into::into)
    }
}

impl From<SpIndexesChangeSet> for SpIndexes {
    fn from(value: SpIndexesChangeSet) -> Self {
        let label_to_tweak = value
            .label_to_tweak
            .into_iter()
            .map(|(key, (value, m))| (key, (Scalar::from(value), m)))
            .collect();
        Self {
            spouts: value.spouts,
            script_to_spout: value.script_to_spout,
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_spout: value.label_to_spout,
            label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

impl From<SpIndexes> for SpIndexesChangeSet {
    fn from(value: SpIndexes) -> Self {
        let label_to_tweak = value
            .label_to_tweak
            .into_iter()
            .map(|(key, (value, m))| {
                (
                    key,
                    (
                        SecretKey::from_slice(&value.to_be_bytes()).expect("infallible"),
                        m,
                    ),
                )
            })
            .collect();
        Self {
            spouts: value.spouts,
            script_to_spout: value.script_to_spout,
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_spout: value.label_to_spout,
            label_to_tweak,
            num_to_label: value.num_to_label,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[must_use]
pub struct SpIndexesChangeSet {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub script_to_spout: BTreeMap<ScriptBuf, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_spout: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: BTreeMap<PublicKey, (SecretKey, u32)>,
    pub num_to_label: BTreeMap<u32, PublicKey>,
}

impl Merge for SpIndexesChangeSet {
    fn merge(&mut self, other: Self) {
        // We use `extend` instead of `BTreeMap::append` due to performance issues with `append`.
        // Refer to https://github.com/rust-lang/rust/issues/34666#issuecomment-675658420
        self.spouts.extend(other.spouts);
        self.script_to_spout.extend(other.script_to_spout);
        self.txid_to_shared_secret
            .extend(other.txid_to_shared_secret);
        self.label_to_spout.extend(other.label_to_spout);
        self.label_to_tweak.extend(other.label_to_tweak);
        self.num_to_label.extend(other.num_to_label);
    }

    fn is_empty(&self) -> bool {
        self.spouts.is_empty()
            && self.script_to_spout.is_empty()
            && self.txid_to_shared_secret.is_empty()
            && self.label_to_spout.is_empty()
            && self.label_to_tweak.is_empty()
            && self.num_to_label.is_empty()
    }
}

pub struct SpIndexer<T, A> {
    prevout_source: T,
    pub scanner: Scanner,
    // NOTE: Redundancy of the OutPoint here is to have a fast way to query particular SpOuts
    // associated with a particular Outpoint.
    // NOTE: Do not create SpIndex::spouts method which include OutPoint inside iterator because there is
    // no reason to have the outpoint twice here (one in the tuple and another inside the SpOut)
    // and a DoubleEndedIterator can also be obtained using the BTreeMap::values method
    pub indexes: SpIndexes,
    pub tx_graph: TxGraph<A>,
}

pub trait PrevoutSource {
    fn get_tx_prevouts(&self, tx: &Transaction) -> Vec<TxOut>;
}

impl<A: bdk_chain::Anchor, T: PrevoutSource> SpIndexer<T, A> {
    pub fn new(
        prevout_source: T,
        scanner: Scanner,
        indexes: SpIndexes,
        tx_graph: TxGraph<A>,
    ) -> Self {
        Self {
            prevout_source,
            scanner,
            indexes,
            tx_graph,
        }
    }

    pub fn spends_owned_spouts(&self, tx: &Transaction) -> bool {
        let input_matches = tx
            .input
            .iter()
            .any(|input| self.indexes.spouts.contains_key(&input.previous_output));
        input_matches
    }

    pub fn index_tx(&mut self, tx: &Transaction) -> Result<tx_graph::ChangeSet<A>, SpReceiveError> {
        let prevouts = self.prevout_source.get_tx_prevouts(tx);
        let txid = tx.compute_txid();
        let ecdh_shared_secret = self
            .scanner
            .compute_shared_secret(tx, &prevouts)
            .expect("infallible");

        let spouts = self
            .scanner
            .scan_txouts(tx, ecdh_shared_secret)
            .flatten()
            .collect::<Vec<SpOut>>();

        let mut tx_graph_changeset = tx_graph::ChangeSet::<A>::default();
        // Add tx and prevouts to tx_graph
        if !spouts.is_empty() && !self.indexes.txid_to_shared_secret.contains_key(&txid) {
            self.indexes
                .txid_to_shared_secret
                .insert(txid, ecdh_shared_secret);
            tx_graph_changeset.merge(self.tx_graph.insert_tx(tx.clone()));
            for (prevout, outpoint) in prevouts
                .iter()
                .zip(tx.input.iter().map(|x| x.previous_output))
            {
                tx_graph_changeset.merge(self.tx_graph.insert_txout(outpoint, prevout.clone()));
            }
        }

        // Index spouts
        for spout in spouts {
            let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(spout.xonly_pubkey);
            let script_pubkey = ScriptBuf::new_p2tr_tweaked(x_only_tweaked);

            self.indexes.spouts.insert(spout.outpoint, spout.clone());

            self.indexes
                .label_to_spout
                .insert((spout.label, spout.clone()));
            self.indexes
                .script_to_spout
                .insert(script_pubkey, spout.clone());
        }

        Ok(tx_graph_changeset)
    }
}

pub(crate) struct Custom<'a>(pub(crate) &'a Client);

impl PrevoutSource for Custom<'_> {
    fn get_tx_prevouts(&self, tx: &Transaction) -> Vec<TxOut> {
        let mut prevouts = <Vec<TxOut>>::new();
        let outpoint_refs = tx.input.iter().map(|x| x.previous_output);
        for OutPoint { txid, vout } in outpoint_refs {
            let prev_tx = self
                .0
                .get_raw_transaction_info(&txid, None)
                .expect("reckless")
                .transaction()
                .expect("reckless");
            let prevout = prev_tx.tx_out(vout as usize).expect("reckless").clone();
            prevouts.push(prevout);
        }
        prevouts
    }
}
