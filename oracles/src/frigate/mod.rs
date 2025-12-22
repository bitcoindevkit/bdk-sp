use bip157::tokio::io::{AsyncReadExt, AsyncWriteExt};
use bip157::tokio::net::TcpStream;
use bip157::tokio::time::{timeout, Duration};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    client: Box<TcpStream>,
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
    pub scan_privkey: SecretKey,
    pub spend_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct GetRequest {
    pub tx_hash: Txid,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestPayload {
    pub method: String,
    pub params: Value,
    pub id: serde_json::Value,
    pub jsonrpc: String,
}

const SUBSCRIBE_RPC_METHOD: &str = "blockchain.silentpayments.subscribe";
const UNSUBSCRIBE_RPC_METHOD: &str = "blockchain.silentpayments.unsubscribe";
const GET_RPC_METHOD: &str = "blockchain.transaction.get";
const VERSION_RPC_METHOD: &str = "server.version";
const BLOCK_HEADER_RPC_METHOD: &str = "blockchain.block.header";
const STREAM_READ_BYTES: usize = 4096;
pub const DUMMY_COINBASE: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f20000000000000000000";

impl FrigateClient {
    pub async fn connect(host_url: &str) -> Result<Self, FrigateError> {
        let stream = TcpStream::connect(host_url)
            .await
            .map_err(|_| FrigateError::Generic("Can't connect to socket".to_string()))?;

        Ok(Self {
            host_url: host_url.to_string(),
            client: Box::new(stream),
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Sets a custom request timeout for this client.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn read_from_stream(&mut self, size: usize) -> Result<Value, FrigateError> {
        let mut buffer = vec![0; size];
        let n = self.client.read(&mut buffer).await?;

        tracing::debug!("Read bytes from stream {n}");
        match n {
            0 => Err(FrigateError::Generic("Nothing read".to_string())),
            _ => {
                let response_str = String::from_utf8_lossy(&buffer[..n]);
                let result: Value =
                    serde_json::from_str(&response_str).map_err(FrigateError::Serde)?;

                Ok(result)
            }
        }
    }

    async fn send_request(&mut self, req_bytes: &[u8]) -> Result<Value, FrigateError> {
        match timeout(self.request_timeout, async {
            self.client.write_all(req_bytes).await?;
            self.client.write_all(b"\n").await?;
            self.client.flush().await?;
            self.read_from_stream(STREAM_READ_BYTES).await
        })
        .await
        {
            Ok(res) => res,
            Err(_) => Err(FrigateError::Generic(format!(
                "request timed out after {:?}",
                self.request_timeout
            ))),
        }
    }

    pub async fn get_block_header(&mut self, height: u32) -> Result<String, FrigateError> {
        let params = vec![height];
        let req = RequestPayload {
            method: BLOCK_HEADER_RPC_METHOD.to_string(),
            params: serde_json::json!(params),
            id: serde_json::Value::from(5),
            jsonrpc: "2.0".to_string(),
        };
        let req_bytes = serde_json::to_vec(&req)?;
        let res = self.send_request(&req_bytes).await?;

        tracing::debug!("[Block Header Request] Result {:?}", res);
        Ok(String::from(res["result"].as_str().unwrap()))
    }

    pub async fn get_transaction(
        &mut self,
        txid: String,
    ) -> Result<(String, String), FrigateError> {
        let params = vec![txid, "true".to_string()];
        let req = RequestPayload {
            method: GET_RPC_METHOD.to_string(),
            id: serde_json::Value::from(4),
            params: serde_json::json!(params),
            jsonrpc: "2.0".to_string(),
        };
        let req_bytes = serde_json::to_vec(&req)?;
        let res = self.send_request(&req_bytes).await?;

        tracing::debug!("[Get tx Request] Result {:#?}", res);
        let blockhash = String::from(res["result"]["blockhash"].as_str().unwrap());
        let hex = String::from(res["result"]["hex"].as_str().unwrap());
        Ok((blockhash, hex))
    }

    pub async fn version(&mut self) -> Result<(), FrigateError> {
        let params = vec!["frigate-cli", "1.4"];

        let req = RequestPayload {
            method: VERSION_RPC_METHOD.to_string(),
            params: serde_json::json!(params),
            id: serde_json::Value::from(3),
            jsonrpc: "2.0".to_string(),
        };

        let req_bytes = serde_json::to_vec(&req)?;
        self.send_request(&req_bytes).await?;

        Ok(())
    }

    pub async fn subscribe(
        &mut self,
        req: &SubscribeRequest,
    ) -> Result<Option<(Vec<History>, f32)>, FrigateError> {
        self.version().await?;
        let mut params: Vec<Value> = vec![
            serde_json::json!(req.scan_priv_key),
            serde_json::json!(req.spend_pub_key),
        ];

        if let Some(start_height) = req.start_height {
            params.push(serde_json::json!(start_height));
        }

        if let Some(labels) = &req.labels {
            params.push(serde_json::json!(labels));
        }

        let req = RequestPayload {
            method: SUBSCRIBE_RPC_METHOD.to_string(),
            params: serde_json::json!(params),
            id: serde_json::Value::from(2),
            jsonrpc: "2.0".to_string(),
        };

        let req_bytes = serde_json::to_vec(&req)?;
        let result = self.send_request(&req_bytes).await?;

        if result["result"].is_string() {
            tracing::info!(
                "Subscribed to silent payment address: {:?}",
                result["result"]
            );
            return Ok(None);
        } else if result["params"].is_object() {
            let histories: Vec<History> =
                serde_json::from_value(result["params"]["history"].clone())
                    .map_err(FrigateError::Serde)?;
            let progress = result["params"]["progress"].as_f64().unwrap_or(0.0) as f32;
            return Ok(Some((histories, progress)));
        }

        Ok(None)
    }

    pub async fn unsubscribe(&mut self, req: &UnsubscribeRequest) -> Result<String, FrigateError> {
        let params: Vec<Value> = vec![
            serde_json::json!(req.scan_privkey),
            serde_json::json!(req.spend_pubkey),
        ];

        self.version().await?;
        let req = RequestPayload {
            method: UNSUBSCRIBE_RPC_METHOD.to_string(),
            id: serde_json::Value::from(1),
            params: serde_json::json!(params),
            jsonrpc: "2.0".to_string(),
        };

        let req_bytes = serde_json::to_vec(&req)?;
        let result = self.send_request(&req_bytes).await?;

        Ok(result["result"].to_string())
    }

    pub async fn subscribe_with_timeout(
        &mut self,
        req: &SubscribeRequest,
    ) -> Result<Option<(Vec<History>, f32)>, FrigateError> {
        match self.subscribe(req).await {
            Ok(res) => Ok(res),
            Err(e) => {
                if e.to_string().contains("timed out") {
                    tracing::warn!("subscribe request timed out, attempting unsubscribe");
                    let unsub = UnsubscribeRequest {
                        scan_privkey: req.scan_priv_key,
                        spend_pubkey: req.spend_pub_key,
                    };
                    let _ = self.unsubscribe(&unsub).await;
                }
                Err(e)
            }
        }
    }
}
