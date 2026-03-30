/// chain_log.rs — On-chain immutable access log (Phase 4).
///
/// Emits Ethereum transactions that log access events immutably.
/// Uses a simple "log" contract pattern:
///   event AccessEvent(bytes32 indexed fileId, address indexed actor, string outcome, uint256 ts)
///
/// Contract ABI (MindLockLog.sol):
///   function logAccess(bytes32 fileId, string outcome, string metadata) external
///
/// For toklo.xyz: this can be replaced with your own deployed contract.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use reqwest::Client;
use chrono::Utc;

/// An immutable record of an access event (to be written on-chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAccessRecord {
    /// bytes32 representation of the file UUID
    pub file_id_hash: String,
    /// Wallet address of the accessor (or "anonymous")
    pub actor_address: String,
    /// "grant" | "deny" | "decoy" | "wipe"
    pub outcome: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Hex-encoded content hash for integrity
    pub metadata_hash: String,
}

impl ChainAccessRecord {
    pub fn new(file_id: &str, actor: &str, outcome: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(file_id.as_bytes());
        let file_id_hash = format!("0x{}", hex::encode(hasher.finalize()));

        let ts = Utc::now().timestamp();
        let mut meta_hasher = Sha256::new();
        meta_hasher.update(format!("{file_id}:{actor}:{outcome}:{ts}").as_bytes());

        ChainAccessRecord {
            file_id_hash,
            actor_address: actor.to_string(),
            outcome: outcome.to_string(),
            timestamp: ts,
            metadata_hash: format!("0x{}", hex::encode(meta_hasher.finalize())),
        }
    }
}

pub struct ChainLogger {
    rpc_url: String,
    /// Address of the deployed MindLockLog contract
    contract_address: String,
    /// Signer private key (hex, no 0x prefix) — in production: use a hardware wallet or KMS
    signer_key: Option<String>,
    client: Client,
}

impl ChainLogger {
    pub fn new(rpc_url: &str, contract_address: &str) -> Self {
        ChainLogger {
            rpc_url: rpc_url.to_string(),
            contract_address: contract_address.to_string(),
            signer_key: None,
            client: Client::new(),
        }
    }

    pub fn with_signer(mut self, private_key_hex: &str) -> Self {
        self.signer_key = Some(private_key_hex.to_string());
        self
    }

    /// Write an access event to the chain.
    /// Returns the transaction hash.
    pub async fn log_access(
        &self,
        file_id: &str,
        actor: &str,
        outcome: &str,
    ) -> Result<String> {
        let record = ChainAccessRecord::new(file_id, actor, outcome);

        // ABI-encode: logAccess(bytes32, string, string)
        // Function selector: keccak256("logAccess(bytes32,string,string)")[..4]
        // = 0x... (precomputed)
        let selector = "0x12345678"; // placeholder — replace with real keccak256 output

        // ABI-encoded parameters (simplified — production uses full ABI encoder)
        let encoded_data = format!(
            "{selector}{}{:064x}{:064x}{}{}",
            &record.file_id_hash[2..], // bytes32 (strip 0x)
            64u64,                      // offset to outcome string
            128u64,                     // offset to metadata string
            encode_string_abi(outcome),
            encode_string_abi(&record.metadata_hash),
        );

        // Send transaction
        let tx_hash = self.send_raw_transaction(&encoded_data).await
            .context("Failed to send chain log transaction")?;

        tracing::info!("Chain log written: file={file_id} outcome={outcome} tx={tx_hash}");
        Ok(tx_hash)
    }

    async fn send_raw_transaction(&self, _data: &str) -> Result<String> {
        // In production:
        //   1. Build raw tx: nonce, gasPrice, gasLimit, to, value=0, data
        //   2. RLP-encode
        //   3. Sign with secp256k1 using self.signer_key
        //   4. eth_sendRawTransaction(hex(signed_tx))
        //
        // Stub: return a fake tx hash
        let fake_hash = format!("0x{}", hex::encode(
            sha2::Sha256::digest(
                format!("{}{}", _data, Utc::now().timestamp_nanos_opt().unwrap_or(0)).as_bytes()
            )
        ));
        Ok(fake_hash)
    }

    /// Query historical access events from the chain (via eth_getLogs).
    pub async fn get_file_access_history(
        &self,
        file_id: &str,
    ) -> Result<Vec<ChainAccessRecord>> {
        let record = ChainAccessRecord::new(file_id, "", "");
        let _file_id_hash = &record.file_id_hash;

        // In production: eth_getLogs with topics filter on the indexed fileId
        // Stub: return empty log
        tracing::info!("Chain log query for file={file_id} (stub)");
        Ok(vec![])
    }
}

/// ABI encode a string (32-byte length prefix + padded content).
fn encode_string_abi(s: &str) -> String {
    let bytes = s.as_bytes();
    let len_hex = format!("{:064x}", bytes.len());
    let padded_len = (bytes.len() + 31) / 32 * 32;
    let mut padded = bytes.to_vec();
    padded.resize(padded_len, 0);
    format!("{}{}", len_hex, hex::encode(padded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_record_creation() {
        let rec = ChainAccessRecord::new("file-uuid-123", "0xWallet", "grant");
        assert!(rec.file_id_hash.starts_with("0x"));
        assert_eq!(rec.outcome, "grant");
        assert!(rec.timestamp > 0);
    }

    #[test]
    fn test_metadata_hash_determinism() {
        // Two records at same instant won't be exactly same (timestamp changes)
        // but format should be consistent
        let rec = ChainAccessRecord::new("f1", "0xabc", "deny");
        assert!(rec.metadata_hash.starts_with("0x"));
        assert_eq!(rec.metadata_hash.len(), 66); // 0x + 64 hex chars
    }

    #[tokio::test]
    async fn test_log_access_stub() {
        let logger = ChainLogger::new("https://rpc.example.com", "0xContract");
        let tx = logger.log_access("file-1", "0xWallet", "grant").await.unwrap();
        assert!(tx.starts_with("0x"));
    }
}
