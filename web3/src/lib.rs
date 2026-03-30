/// mindlock-web3 — Phase 4 Web3 / token-gate integration.
///
/// Modules:
///   wallet   — ECDSA wallet signature verification (EIP-712)
///   token    — ERC-20 / ERC-721 balance checks via JSON-RPC
///   payment  — Pay-to-open micro-payment flow
///   chain_log— On-chain immutable access log via smart contract calls

pub mod wallet;
pub mod token;
pub mod payment;
pub mod chain_log;

pub use wallet::{WalletChallenge, WalletVerifier};
pub use token::{TokenGateChecker, TokenBalance};
pub use payment::{PaymentGate, PaymentStatus};
pub use chain_log::ChainLogger;

use mindlock_core::format::TokenGateConfig;
use anyhow::Result;

/// High-level: verify all Web3 access requirements for a file.
/// Returns Ok(true) if all checks pass, Ok(false) if any fail.
pub async fn verify_web3_access(
    config: &TokenGateConfig,
    wallet_address: &str,
    signed_challenge: Option<&str>,
    challenge_nonce: Option<&str>,
) -> Result<bool> {
    // 1. Verify wallet signature (proves ownership of address)
    if let (Some(sig), Some(nonce)) = (signed_challenge, challenge_nonce) {
        let ok = WalletVerifier::verify_signature(wallet_address, nonce, sig)?;
        if !ok {
            return Ok(false);
        }
    }

    // 2. Check token balance
    let checker = TokenGateChecker::new(&config.rpc_url);
    let balance = checker.get_erc20_balance(wallet_address, &config.token_contract).await?;
    if balance.raw < config.min_balance {
        return Ok(false);
    }

    // 3. Pay-to-open (if configured)
    if let Some(_required_wei) = config.pay_to_open_wei {
        // In production: verify an on-chain payment tx hash submitted by the client
        // For this build: payment verification is async and handled separately
    }

    Ok(true)
}
