use bip157::tokio;
use bip157::tokio::net::TcpStream;
use bip157::tokio::time::{timeout, Duration};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Txid;
use electrum_streaming_client::response::{FullTx, HeaderResp};
use electrum_streaming_client::{request, AsyncClient, Event};
use futures::channel::mpsc::UnboundedReceiver;
pub use futures::StreamExt;
use serde::{Deserialize, Serialize};

pub const DUMMY_COINBASE: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f20000000000000000000";

#[derive(Debug)]
pub enum FrigateError {
    JsonRpc(jsonrpc::Error),
    ParseUrl(url::ParseError),
    Serde(serde_json::Error),
    Generic(String),
}

impl From<serde_json::Error> for FrigateError {
    fn from(value: serde_json::Error) -> Self {
        FrigateError::Serde(value)
    }
}

impl From<url::ParseError> for FrigateError {
    fn from(value: url::ParseError) -> Self {
        Self::ParseUrl(value)
    }
}

impl From<jsonrpc::Error> for FrigateError {
    fn from(value: jsonrpc::Error) -> Self {
        Self::JsonRpc(value)
    }
}

impl From<std::io::Error> for FrigateError {
    fn from(value: std::io::Error) -> Self {
        Self::Generic(format!("Generic error {:?}", value))
    }
}

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrigateError::Generic(str) => write!(f, "{str}"),
            _ => write!(f, "Something wrong happened"),
        }
    }
}
impl std::error::Error for FrigateError {}

pub struct FrigateClient {
    pub host_url: String,
    pub client: AsyncClient,
    pub events: UnboundedReceiver<Event>,
    pub worker: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    pub request_timeout: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    pub height: u32,
    pub tx_hash: Txid,
    pub tweak_key: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct NotifPayload {
    scan_private_key: SecretKey,
    spend_public_key: PublicKey,
    address: String,
    labels: Option<Vec<u32>>,
    start_height: u32,
    progress: f32,
    history: Vec<History>,
}

#[derive(Serialize, Deserialize)]
pub struct SubscribeRequest {
    pub scan_priv_key: SecretKey,
    pub spend_pub_key: PublicKey,
    pub start_height: Option<u32>,
    pub labels: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    pub scan_priv_key: SecretKey,
    pub spend_pub_key: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct GetRequest {
    pub tx_hash: Txid,
}

impl FrigateClient {
    pub async fn connect(host_url: &str) -> Result<Self, FrigateError> {
        let stream = TcpStream::connect(host_url)
            .await
            .map_err(|_| FrigateError::Generic("Can't connect to socket".to_string()))?;

        let (reader, writer) = stream.into_split();
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        let worker = tokio::spawn(async move {
            tracing::debug!("Worker task started");
            match worker.await {
                Ok(()) => {
                    tracing::debug!("Worker task completed successfully");
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("Worker task failed: {}", e);
                    Err(e)
                }
            }
        });

        Ok(Self {
            host_url: host_url.to_string(),
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Sets a custom request timeout for this client.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn get_block_header(&mut self, height: u32) -> Result<HeaderResp, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::Header { height }),
        )
        .await
        .map_err(|_| FrigateError::Generic("Header request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res)
    }

    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Generic("GetTx request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res)
    }

    pub async fn version(&mut self) -> Result<Vec<String>, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::Version {
                client_name: "bdk-sp".into(),
                version: "1.4".into(),
            }),
        )
        .await
        .map_err(|_| FrigateError::Generic("Version request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res)
    }

    pub async fn subscribe(&mut self, req: &SubscribeRequest) -> Result<String, FrigateError> {
        let subscribe_req = request::Subscribe {
            scan_priv_key: req.scan_priv_key,
            scan_pub_key: req.spend_pub_key,
            labels: req.labels.clone(),
            start_height: req.start_height,
        };

        tracing::debug!("Sending subscribe event request...");
        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Generic("Subscribe request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;

        tracing::info!("Subscribed to silent payment address: {}", res);
        Ok(res)
    }

    pub async fn unsubscribe(&mut self, req: &UnsubscribeRequest) -> Result<(), FrigateError> {
        let unsubscribe_req = request::UnSubscribe {
            scan_priv_key: req.scan_priv_key,
            scan_pub_key: req.spend_pub_key,
        };

        let res = timeout(
            self.request_timeout,
            self.client.send_request(unsubscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Generic("Unsubscribe request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;

        tracing::info!("Unsubscribed to silent payment address: {:?}", res);
        Ok(())
    }
}
