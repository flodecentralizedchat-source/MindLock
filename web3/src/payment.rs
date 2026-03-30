/// payment.rs — Pay-to-open gate (Phase 4).
///
/// Flow:
///   1. Client requests a payment invoice (amount + recipient address + nonce)
///   2. Client sends an on-chain ETH transfer with the nonce in calldata
///   3. Client submits tx hash to the server
///   4. Server verifies tx via eth_getTransactionReceipt:
///        • correct `to` address
///        • correct `value` (>= required_wei)
///        • nonce present in input data
///        • tx confirmed (>= 1 block)
///   5. Server marks nonce as used (prevents replay)
///   6. File unlocks

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInvoice {
    pub invoice_id: String,
    pub file_id: String,
    pub recipient_address: String,
    pub required_wei: u128,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}

impl PaymentInvoice {
    pub fn new(file_id: &str, recipient: &str, required_wei: u128) -> Self {
        let nonce = format!("ml-{}", Uuid::new_v4().simple());
        PaymentInvoice {
            invoice_id: Uuid::new_v4().to_string(),
            file_id: file_id.to_string(),
            recipient_address: recipient.to_string(),
            required_wei,
            nonce,
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    pub fn is_expired(&self) -> bool { Utc::now() > self.expires_at }

    /// ETH amount formatted for display.
    pub fn eth_amount(&self) -> f64 { self.required_wei as f64 / 1e18 }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentStatus {
    Pending,
    Confirmed { tx_hash: String, block: u64 },
    Failed { reason: String },
    Expired,
}

pub struct PaymentGate {
    rpc_url: String,
    client: Client,
}

impl PaymentGate {
    pub fn new(rpc_url: &str) -> Self {
        PaymentGate { rpc_url: rpc_url.to_string(), client: Client::new() }
    }

    /// Verify an on-chain payment transaction.
    pub async fn verify_payment(
        &self,
        invoice: &PaymentInvoice,
        tx_hash: &str,
    ) -> Result<PaymentStatus> {
        if invoice.is_expired() {
            return Ok(PaymentStatus::Expired);
        }

        let receipt = self.get_transaction_receipt(tx_hash).await?;

        let Some(rec) = receipt else {
            return Ok(PaymentStatus::Pending);
        };

        // Check recipient
        let to = rec.get("to").and_then(|v| v.as_str()).unwrap_or("");
        if !to.eq_ignore_ascii_case(&invoice.recipient_address) {
            return Ok(PaymentStatus::Failed { reason: "Wrong recipient address".into() });
        }

        // Check value
        let value_hex = rec.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
        let value = u128::from_str_radix(
            value_hex.trim_start_matches("0x"), 16
        ).unwrap_or(0);

        if value < invoice.required_wei {
            return Ok(PaymentStatus::Failed {
                reason: format!("Insufficient payment: got {value} wei, need {}", invoice.required_wei)
            });
        }

        // Check nonce in input data
        let input = rec.get("input").and_then(|v| v.as_str()).unwrap_or("");
        let nonce_hex = hex::encode(invoice.nonce.as_bytes());
        if !input.contains(&nonce_hex) {
            return Ok(PaymentStatus::Failed { reason: "Nonce not found in transaction data".into() });
        }

        // Check confirmations
        let block_hex = rec.get("blockNumber").and_then(|v| v.as_str()).unwrap_or("0x0");
        let block = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        Ok(PaymentStatus::Confirmed { tx_hash: tx_hash.to_string(), block })
    }

    async fn get_transaction_receipt(&self, tx_hash: &str) -> Result<Option<serde_json::Value>> {
        #[derive(serde::Serialize)]
        struct Req { jsonrpc: &'static str, method: &'static str, params: [&'static str; 1], id: u64 }
        #[derive(serde::Deserialize)]
        struct Resp { result: Option<serde_json::Value> }

        // Can't borrow tx_hash into a 'static array easily — clone into owned String
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1
        });

        let resp: Resp = self.client
            .post(&self.rpc_url)
            .json(&body)
            .send().await.context("RPC send failed")?
            .json().await.context("RPC parse failed")?;

        Ok(resp.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoice_not_expired() {
        let inv = PaymentInvoice::new("file-1", "0xRecipient", 1_000_000_000_000_000);
        assert!(!inv.is_expired());
    }

    #[test]
    fn test_eth_amount_formatting() {
        let inv = PaymentInvoice::new("file-1", "0xRecipient", 1_000_000_000_000_000_000u128);
        assert!((inv.eth_amount() - 1.0).abs() < 1e-9);
    }
}
