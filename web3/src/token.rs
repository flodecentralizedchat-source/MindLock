/// token.rs — ERC-20 and ERC-721 token balance verification via Ethereum JSON-RPC.
///
/// Calls `eth_call` with the ABI-encoded `balanceOf(address)` selector.
/// No external Ethereum library required — raw JSON-RPC over reqwest.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use reqwest::Client;

pub struct TokenGateChecker {
    rpc_url: String,
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Raw balance in token base units (wei for ERC-20)
    pub raw: u128,
    /// Formatted with 18 decimals
    pub formatted: f64,
    pub wallet: String,
    pub contract: String,
}

impl TokenGateChecker {
    pub fn new(rpc_url: &str) -> Self {
        TokenGateChecker {
            rpc_url: rpc_url.to_string(),
            client: Client::new(),
        }
    }

    // ── ERC-20 balanceOf ──────────────────────────────────────────────────────

    /// Check ERC-20 token balance for a wallet address.
    /// ABI encodes: balanceOf(address) → bytes4(keccak256("balanceOf(address)")) = 0x70a08231
    pub async fn get_erc20_balance(&self, wallet: &str, contract: &str) -> Result<TokenBalance> {
        let wallet_padded = pad_address_to_32bytes(wallet)?;
        let call_data = format!("0x70a08231{wallet_padded}"); // balanceOf(address)

        let result_hex = self.eth_call(contract, &call_data).await?;
        let raw = hex_to_u128(&result_hex)?;

        Ok(TokenBalance {
            raw,
            formatted: raw as f64 / 1e18,
            wallet: wallet.to_lowercase(),
            contract: contract.to_lowercase(),
        })
    }

    // ── ERC-721 ownerOf ───────────────────────────────────────────────────────

    /// Check ERC-721 token ownership.
    /// ABI: ownerOf(uint256) → 0x6352211e
    pub async fn get_nft_owner(&self, contract: &str, token_id: u128) -> Result<String> {
        let token_id_hex = format!("{token_id:064x}");
        let call_data = format!("0x6352211e{token_id_hex}");

        let result_hex = self.eth_call(contract, &call_data).await?;
        // Result is a 32-byte padded address — last 20 bytes are the address
        let addr_hex = result_hex.trim_start_matches("0x");
        if addr_hex.len() >= 40 {
            Ok(format!("0x{}", &addr_hex[addr_hex.len()-40..]))
        } else {
            anyhow::bail!("Invalid address returned from RPC")
        }
    }

    // ── ERC-721 balanceOf ─────────────────────────────────────────────────────

    pub async fn get_nft_balance(&self, wallet: &str, contract: &str) -> Result<u128> {
        let wallet_padded = pad_address_to_32bytes(wallet)?;
        let call_data = format!("0x70a08231{wallet_padded}");
        let result_hex = self.eth_call(contract, &call_data).await?;
        hex_to_u128(&result_hex)
    }

    // ── Raw JSON-RPC call ─────────────────────────────────────────────────────

    async fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        #[derive(Serialize)]
        struct EthCallParams {
            to: String,
            data: String,
        }
        #[derive(Serialize)]
        struct JsonRpcRequest {
            jsonrpc: &'static str,
            method: &'static str,
            params: (EthCallParams, &'static str),
            id: u64,
        }
        #[derive(Deserialize)]
        struct JsonRpcResponse {
            result: Option<String>,
            error: Option<serde_json::Value>,
        }

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_call",
            params: (EthCallParams { to: to.to_string(), data: data.to_string() }, "latest"),
            id: 1,
        };

        let resp: JsonRpcResponse = self.client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .context("RPC request failed")?
            .json()
            .await
            .context("RPC response parse failed")?;

        if let Some(err) = resp.error {
            anyhow::bail!("RPC error: {err}");
        }

        resp.result.ok_or_else(|| anyhow::anyhow!("Empty RPC result"))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Pad an Ethereum address to 32 bytes (ABI encoding).
fn pad_address_to_32bytes(addr: &str) -> Result<String> {
    let clean = addr.strip_prefix("0x").unwrap_or(addr);
    if clean.len() != 40 {
        anyhow::bail!("Invalid address length");
    }
    Ok(format!("{:0>64}", clean)) // left-pad to 64 hex chars (32 bytes)
}

/// Parse a 0x-prefixed hex string to u128.
fn hex_to_u128(hex: &str) -> Result<u128> {
    let clean = hex.trim_start_matches("0x");
    if clean.is_empty() || clean == "0" { return Ok(0); }
    // Take last 32 chars (16 bytes = u128 max)
    let trimmed = if clean.len() > 32 { &clean[clean.len()-32..] } else { clean };
    u128::from_str_radix(trimmed, 16)
        .context(format!("Failed to parse hex as u128: {hex}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_address() {
        let padded = pad_address_to_32bytes("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        assert_eq!(padded.len(), 64);
        assert!(padded.starts_with("000000000000000000000000"));
    }

    #[test]
    fn test_hex_to_u128_zero() {
        assert_eq!(hex_to_u128("0x").unwrap_or(0), 0);
        assert_eq!(hex_to_u128("0x0").unwrap(), 0);
    }

    #[test]
    fn test_hex_to_u128_value() {
        // 1 ether = 1e18 wei = 0xDE0B6B3A7640000
        let val = hex_to_u128("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000").unwrap();
        assert_eq!(val, 1_000_000_000_000_000_000u128);
    }
}
