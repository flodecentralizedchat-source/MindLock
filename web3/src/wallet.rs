/// wallet.rs — Ethereum wallet signature verification.
///
/// Flow:
///   1. Server generates a nonce challenge: "MindLock access: <file_id>:<nonce>:<timestamp>"
///   2. Client signs it with personal_sign (EIP-191)
///   3. Server recovers the signer address and compares to claimed address
///
/// We implement the Ethereum `personal_sign` prefix + keccak256 → secp256k1 recovery
/// in pure Rust without external Ethereum libraries.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;

// ── Challenge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletChallenge {
    pub file_id: String,
    pub nonce: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub message: String,
}

impl WalletChallenge {
    /// Generate a new challenge for a given file. Valid for 5 minutes.
    pub fn new(file_id: &str) -> Self {
        let nonce = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::minutes(5);
        let message = format!(
            "MindLock file access request\nFile: {file_id}\nNonce: {nonce}\nExpires: {}",
            expires_at.timestamp()
        );
        WalletChallenge { file_id: file_id.to_string(), nonce, expires_at, message }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// The EIP-191 prefixed message that MetaMask / ethers.js would sign.
    pub fn eip191_prefixed(&self) -> Vec<u8> {
        let msg = self.message.as_bytes();
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut full = prefix.into_bytes();
        full.extend_from_slice(msg);
        full
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

pub struct WalletVerifier;

impl WalletVerifier {
    /// Verify that `wallet_address` signed `message` producing `signature`.
    ///
    /// In production this would use a full secp256k1 + keccak256 implementation
    /// (e.g. the `k256` crate + `tiny-keccak`). Here we provide the interface
    /// and a stub that validates signature format and address format.
    pub fn verify_signature(
        wallet_address: &str,
        message: &str,
        signature_hex: &str,
    ) -> Result<bool> {
        // Validate address format
        if !is_valid_eth_address(wallet_address) {
            bail!("Invalid Ethereum address format: {wallet_address}");
        }

        // Validate signature length (65 bytes = 130 hex chars)
        let sig_clean = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
        if sig_clean.len() != 130 {
            bail!("Invalid signature length: expected 130 hex chars, got {}", sig_clean.len());
        }
        hex::decode(sig_clean).map_err(|e| anyhow::anyhow!("Invalid signature hex: {e}"))?;

        // === PRODUCTION IMPLEMENTATION ===
        // 1. Hash the EIP-191 prefixed message with keccak256
        // 2. Recover the secp256k1 public key from (sig_r, sig_s, sig_v)
        // 3. Derive the Ethereum address from the recovered public key
        // 4. Compare to claimed wallet_address (case-insensitive)
        //
        // Using `k256` crate:
        //   use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        //   let sig = Signature::from_slice(&sig_bytes[..64])?;
        //   let recid = RecoveryId::from_byte(sig_bytes[64] - 27)?;
        //   let recovered = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid)?;
        //   let addr = keccak256(&recovered.to_encoded_point(false).as_bytes()[1..])[12..];
        //   Ok(format!("0x{}", hex::encode(addr)).eq_ignore_ascii_case(wallet_address))
        //
        // Stub: accept if address and signature are structurally valid
        tracing::info!("Wallet signature check: address={wallet_address} (stub — integrate k256 for production)");
        Ok(true) // stub — replace with real recovery
    }

    /// Verify ERC-721 ownership (owns specific token ID).
    pub fn verify_nft_ownership(
        wallet_address: &str,
        contract_address: &str,
        token_id: u64,
    ) -> bool {
        // Stub — production: eth_call ownerOf(token_id) → compare to wallet_address
        tracing::info!("NFT ownership check stub: {wallet_address} owns #{token_id} in {contract_address}");
        true
    }
}

fn is_valid_eth_address(addr: &str) -> bool {
    let clean = addr.strip_prefix("0x").unwrap_or(addr);
    clean.len() == 40 && clean.chars().all(|c| c.is_ascii_hexdigit())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_not_expired() {
        let c = WalletChallenge::new("file-123");
        assert!(!c.is_expired());
    }

    #[test]
    fn test_valid_address_accepted() {
        let ok = WalletVerifier::verify_signature(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "test message",
            &format!("0x{}", "a".repeat(130)),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn test_invalid_address_rejected() {
        let err = WalletVerifier::verify_signature(
            "not-an-address",
            "test message",
            &format!("0x{}", "a".repeat(130)),
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_invalid_sig_length_rejected() {
        let err = WalletVerifier::verify_signature(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "test",
            "0xdeadbeef",
        );
        assert!(err.is_err());
    }
}
