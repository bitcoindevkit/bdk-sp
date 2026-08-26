use crate::filters::kyoto::{DatabaseBuffer, FilterEvent, WriteRange, TABLE_DEF};
use bip157::{tokio::sync::mpsc::UnboundedSender, BlockFilter, BlockHash, UnboundedReceiver};
use bitcoin::{
    absolute::Height, hashes::serde::Deserialize, secp256k1::PublicKey, Amount, Network,
};
use futures::StreamExt;
use indexer::{
    bdk_chain::{BlockId, ConfirmationBlockTime},
    v2::SpIndexerV2 as SpIndexer,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use redb::Database;
use reqwest::{Client, Url};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug)]
pub enum BlindbitError {
    Reqwest(reqwest::Error),
    ParseUrl(url::ParseError),
    Serde(serde_json::Error),
}

impl From<serde_json::Error> for BlindbitError {
    fn from(value: serde_json::Error) -> Self {
        BlindbitError::Serde(value)
    }
}

impl From<url::ParseError> for BlindbitError {
    fn from(value: url::ParseError) -> Self {
        Self::ParseUrl(value)
    }
}

impl From<reqwest::Error> for BlindbitError {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

#[derive(Debug, Deserialize)]
pub struct InfoResponse {
    pub network: Network,
    pub height: Height,
    pub tweaks_only: bool,
    pub tweaks_full_basic: bool,
    pub tweaks_full_with_dust_filter: bool,
    pub tweaks_cut_through_with_dust_filter: bool,
}

#[derive(Debug, Deserialize)]
pub struct BlockHeightResponse {
    pub height: Height,
}

#[derive(Debug, Clone)]
pub struct BlindbitClient {
    host_url: Url,
    client: Client,
}

impl BlindbitClient {
    pub fn new(host_url: String) -> Result<Self, BlindbitError> {
        let mut host_url = Url::parse(&host_url)?;
        let client = Client::new();

        // we need a trailing slash, if not present we append it
        if !host_url.path().ends_with('/') {
            host_url.set_path(&format!("{}/", host_url.path()));
        }

        tracing::info!("Subscribing to tweak server {}", host_url);

        Ok(BlindbitClient { host_url, client })
    }

    pub async fn block_height(&self) -> Result<Height, BlindbitError> {
        let url = self.host_url.join("block-height")?;

        let res = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        let blkheight: BlockHeightResponse = serde_json::from_str(&res.text().await?)?;
        Ok(blkheight.height)
    }

    pub async fn tweaks(
        &self,
        block_height: u32,
        dust_limit: Amount,
    ) -> Result<Vec<PublicKey>, BlindbitError> {
        let url = self.host_url.join(&format!("tweaks/{}", block_height))?;

        let res = self
            .client
            .get(url)
            .query(&[("dustLimit", format!("{}", dust_limit.to_sat()))])
            .send()
            .await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn info(&self) -> Result<InfoResponse, BlindbitError> {
        let url = self.host_url.join("info")?;

        let res = self.client.get(url).send().await?;
        Ok(serde_json::from_str(&res.text().await?)?)
    }
}

pub enum TweakEvent {
    Matches((BlockHash, HashMap<[u8; 34], PublicKey>)),
    Synced(BlockId),
}

pub struct BlindbitSubscriber {
    db: Arc<Mutex<Database>>,
    unspent_script_pubkeys: Vec<[u8; 34]>,
    indexer: SpIndexer<ConfirmationBlockTime>,
    client: BlindbitClient,
    requests: UnboundedReceiver<FilterEvent>,
    sender: UnboundedSender<TweakEvent>,
}

impl BlindbitSubscriber {
    pub fn new(
        unspent_script_pubkeys: Vec<[u8; 34]>,
        indexer: SpIndexer<ConfirmationBlockTime>,
        host_url: String,
        requests: UnboundedReceiver<FilterEvent>,
        sender: UnboundedSender<TweakEvent>,
    ) -> Result<(Self, DatabaseBuffer), BlindbitError> {
        // Set up the database
        tracing::info!("Setting up filter database...");
        let db = Arc::new(Mutex::new(Database::create("filter_data.redb").unwrap()));
        let db_buffer = DatabaseBuffer::new(Arc::clone(&db));
        Ok((
            Self {
                db,
                unspent_script_pubkeys,
                indexer,
                client: BlindbitClient::new(host_url)?,
                requests,
                sender,
            },
            db_buffer,
        ))
    }

    pub async fn run(&mut self) {
        while let Some(filter_event) = self.requests.recv().await {
            match filter_event {
                FilterEvent::Changes(changes) => {
                    self.process_changes(changes).await;
                }
                FilterEvent::Tip(tip) => {
                    self.sender.send(TweakEvent::Synced(tip)).unwrap();
                }
            }
        }
    }

    async fn process_changes(&mut self, changes: WriteRange) {
        let base = changes
            .writes
            .last_key_value()
            .map(|(height, _)| *height)
            .unwrap_or_default();
        let mut progress = changes
            .writes
            .first_key_value()
            .map(|(height, _)| *height)
            .unwrap_or_default();

        let client = self.client.clone();
        let mut stream = futures::stream::iter(changes.writes)
            .map(move |(height, hash)| {
                let client = client.clone();
                async move {
                    if let Ok(tweaks) = client.tweaks(height, Amount::from_sat(1000)).await {
                        (height, hash, tweaks)
                    } else {
                        (height, hash, vec![])
                    }
                }
            })
            .buffer_unordered(200);

        let read = self.db.lock().unwrap().begin_read().unwrap();
        let table = read.open_table(TABLE_DEF).unwrap();
        while let Some((height, hash, tweaks)) = stream.next().await {
            tracing::info!("Tweaks {progress}/{base}");
            progress += 1;

            let filter_bytes = table.get(&height).unwrap().unwrap();
            let filter = BlockFilter::new(&filter_bytes.value());

            let all_spks: HashMap<[u8; 34], PublicKey> = tweaks
                .par_iter()
                .flat_map(|tweak| {
                    self.indexer
                        .derive_spks_for_tweak(tweak)
                        .into_iter()
                        .map(|spk| (spk, *tweak))
                        .collect::<Vec<_>>()
                })
                .collect::<HashMap<[u8; 34], PublicKey>>();

            let mut only_spks: Vec<[u8; 34]> = all_spks.clone().into_keys().collect();
            // unspent script pubkeys can only be present in blocks with tweaks, because they are
            // by themselves inputs available for shared secret derivation
            only_spks.extend_from_slice(&self.unspent_script_pubkeys);

            if !all_spks.is_empty() && filter.match_any(&hash, only_spks.into_iter()).unwrap() {
                tracing::info!("Match found for block {hash} at height {height}");
                self.sender
                    .send(TweakEvent::Matches((hash, all_spks)))
                    .unwrap();
            }
        }
    }
}
