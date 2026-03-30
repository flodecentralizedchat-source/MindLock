use thiserror::Error;

#[derive(Debug, Error)]
pub enum MindLockError {
    // Crypto
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed — wrong password or corrupted file")]
    DecryptionFailed,
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    // Format
    #[error("Invalid .mindlock file: {0}")]
    InvalidFormat(String),
    #[error("File version {0} not supported by this build")]
    UnsupportedVersion(u8),
    #[error("File magic bytes mismatch — not a .mindlock file")]
    MagicMismatch,

    // Rules / Access
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("File has expired")]
    FileExpired,
    #[error("Open limit reached ({0} opens used)")]
    OpenLimitReached(u32),
    #[error("Device not trusted")]
    UntrustedDevice,
    #[error("Access outside allowed time window")]
    TimeWindowViolation,

    // Behavior
    #[error("Behavioral anomaly detected — access denied")]
    BehaviorAnomaly,

    // Decoy
    #[error("Decoy mode active")]
    DecoyActive,

    // Wipe
    #[error("File has been wiped — payload is permanently destroyed")]
    FileWiped,

    // Web3
    #[error("Wallet verification failed: {0}")]
    WalletVerification(String),
    #[error("Insufficient token balance for access")]
    InsufficientTokens,
    #[error("Payment required to unlock this file")]
    PaymentRequired,

    // I/O
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Catch-all
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, MindLockError>;
