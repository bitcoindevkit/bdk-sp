use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::iter::Extend;

use bdk_chain::{tx_graph, Merge, TxGraph};

use bdk_sp::{
    bitcoin::{
        secp256k1::{PublicKey, Scalar, SecretKey},
        OutPoint, Transaction, TxOut, Txid,
    },
    receive::{Scanner, SpOut, SpReceiveError},
};

use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi};

#[derive(Clone, Default)]
pub struct SpIndexes {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_output: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: HashMap<PublicKey, (Scalar, u32)>,
}

impl SpIndexes {
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
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_output: value.label_to_output,
            label_to_tweak,
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
            txid_to_shared_secret: value.txid_to_shared_secret,
            label_to_output: value.label_to_output,
            label_to_tweak,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[must_use]
pub struct SpIndexesChangeSet {
    pub spouts: BTreeMap<OutPoint, SpOut>,
    pub txid_to_shared_secret: BTreeMap<Txid, PublicKey>,
    pub label_to_output: BTreeSet<(Option<u32>, SpOut)>,
    pub label_to_tweak: HashMap<PublicKey, (SecretKey, u32)>,
}

impl Merge for SpIndexesChangeSet {
    fn merge(&mut self, other: Self) {
        // We use `extend` instead of `BTreeMap::append` due to performance issues with `append`.
        // Refer to https://github.com/rust-lang/rust/issues/34666#issuecomment-675658420
        self.spouts.extend(other.spouts);
        self.txid_to_shared_secret
            .extend(other.txid_to_shared_secret);
        self.label_to_output.extend(other.label_to_output);
        self.label_to_tweak.extend(other.label_to_tweak);
    }

    fn is_empty(&self) -> bool {
        self.spouts.is_empty()
            && self.txid_to_shared_secret.is_empty()
            && self.label_to_output.is_empty()
            && self.label_to_tweak.is_empty()
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
    pub fn new(prevout_source: T, scanner: Scanner) -> Self {
        Self {
            prevout_source,
            scanner,
            indexes: SpIndexes::default(),
            tx_graph: TxGraph::default(),
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
        let ecdh_shared_secret = self
            .scanner
            .compute_shared_secret(tx, &prevouts)
            .expect("infallible");

        // Index labels
        let label_to_spouts = self
            .scanner
            .scan_txouts(tx, ecdh_shared_secret)
            .flatten()
            .map(|spout| (spout.label, spout.clone()))
            .collect::<BTreeSet<(Option<u32>, SpOut)>>();

        self.indexes.label_to_output.extend(label_to_spouts.clone());

        let spouts = label_to_spouts
            .iter()
            .map(|(_, spout)| (spout.outpoint, spout.clone()))
            .collect::<BTreeMap<OutPoint, SpOut>>();

        let mut tx_graph_changeset = tx_graph::ChangeSet::<A>::default();

        // Add tx and prevouts to tx_graph
        if !spouts.is_empty()
            && !self
                .indexes
                .txid_to_shared_secret
                .contains_key(&tx.compute_txid())
        {
            self.indexes
                .txid_to_shared_secret
                .insert(tx.compute_txid(), ecdh_shared_secret);
            tx_graph_changeset.merge(self.tx_graph.insert_tx(tx.clone()));
            for (prevout, outpoint) in prevouts
                .iter()
                .zip(tx.input.iter().map(|x| x.previous_output))
            {
                tx_graph_changeset.merge(self.tx_graph.insert_txout(outpoint, prevout.clone()));
            }
        }
        // Index spouts
        self.indexes.spouts.extend(spouts);

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
