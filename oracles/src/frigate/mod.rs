use bip157::tokio;
use bip157::tokio::net::TcpStream;
use bip157::tokio::time::{timeout, Duration};
use bitcoin::Txid;
use electrum_streaming_client::response::{FullTx, HeaderResp};
use electrum_streaming_client::{request, AsyncClient, Event};
use futures::channel::mpsc::UnboundedReceiver;
pub use futures::StreamExt;

pub const DUMMY_COINBASE: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f20000000000000000000";

#[derive(Debug)]
pub enum FrigateError {
    Connection(String),
    Timeout(String),
    Request(String),
    Io(String),
}

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrigateError::Connection(msg) => write!(f, "connection error: {msg}"),
            FrigateError::Timeout(msg) => write!(f, "request timeout: {msg}"),
            FrigateError::Request(msg) => write!(f, "request error: {msg}"),
            FrigateError::Io(msg) => write!(f, "I/O error: {msg}"),
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

impl FrigateClient {
    pub async fn connect(host_url: &str) -> Result<Self, FrigateError> {
        let stream = TcpStream::connect(host_url).await.map_err(|err| {
            FrigateError::Connection(format!("can't connect to socket '{host_url}': {err}"))
        })?;

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
        .map_err(|_| FrigateError::Timeout("Header request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Header request failed: {e}")))?;
        Ok(res)
    }

    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("GetTx request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("GetTx request failed: {e}")))?;
        Ok(res)
    }

    pub async fn version(&mut self) -> Result<String, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::ServerVersion {
                client_name: "bdk-sp".into(),
                protocol_version: request::SupportedVersion::Range([
                    "1.3.2".into(),
                    "1.4.1".into(),
                ]),
            }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Version request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
        Ok(res.protocol_version)
    }

    pub async fn subscribe(
        &mut self,
        subscribe_req: request::SpSubscribe,
    ) -> Result<String, FrigateError> {
        tracing::debug!("Sending subscribe event request...");
        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Subscribe request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Subscribe request failed: {e}")))?;

        tracing::info!("Subscribed to silent payment address: {}", res);
        Ok(res)
    }

    pub async fn unsubscribe(
        &mut self,
        unsub_req: request::SpUnsubscribe,
    ) -> Result<(), FrigateError> {
        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_string()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        tracing::info!("Unsubscribed to silent payment address: {:?}", res);
        Ok(())
    }
}
