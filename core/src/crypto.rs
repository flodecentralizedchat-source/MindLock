/// crypto.rs — MVP + Phase 2 cryptographic primitives.
///
/// Stack:
///   • Key derivation : Argon2id (memory-hard, side-channel resistant)
///   • Symmetric enc  : AES-256-GCM (authenticated encryption)
///   • Asymmetric     : RSA-4096 + OAEP/SHA-256 (optional key wrapping)
///   • Integrity      : HMAC-SHA-256 over header + ciphertext
///   • Zeroization    : all key material zeroed on drop via `zeroize`

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use crate::{MindLockError, Result};

#[path = "crypto/shamir.rs"]
pub mod shamir;

// ── Constants ────────────────────────────────────────────────────────────────

pub const KEY_LEN: usize    = 32;  // 256-bit
pub const NONCE_LEN: usize  = 12;  // 96-bit GCM nonce
pub const SALT_LEN: usize   = 32;  // Argon2 salt
pub const HMAC_LEN: usize   = 32;  // SHA-256 output

// Argon2id params (OWASP 2023 recommendation for high-security)
const ARGON2_M_COST: u32    = 65536; // 64 MB memory
const ARGON2_T_COST: u32    = 3;     // 3 iterations
const ARGON2_P_COST: u32    = 4;     // 4 parallel lanes

// ── Key material ─────────────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub key_bytes: [u8; KEY_LEN],
    pub salt: [u8; SALT_LEN],
}

impl DerivedKey {
    /// Derive a new key from a password (generates fresh random salt).
    pub fn new_from_password(password: &[u8]) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self::from_password_and_salt(password, &salt)
    }

    /// Re-derive key from password + existing salt (for unlock).
    pub fn from_password_and_salt(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
            .map_err(|e| MindLockError::KeyDerivation(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let salt_str = SaltString::encode_b64(salt)
            .map_err(|e| MindLockError::KeyDerivation(e.to_string()))?;

        let hash = argon2
            .hash_password(password, &salt_str)
            .map_err(|e| MindLockError::KeyDerivation(e.to_string()))?;

        let hash_bytes = hash.hash.ok_or_else(|| {
            MindLockError::KeyDerivation("Empty hash output".into())
        })?;

        let mut key_bytes = [0u8; KEY_LEN];
        key_bytes.copy_from_slice(hash_bytes.as_bytes());

        Ok(DerivedKey { key_bytes, salt: *salt })
    }
}

// ── Symmetric encryption ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedBlob {
    pub nonce: Vec<u8>,     // 12 bytes
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,      // Argon2 salt — stored in file header
    pub hmac: Vec<u8>,      // HMAC-SHA256(salt || nonce || ciphertext)
}

/// Encrypt plaintext with a password. Returns an `EncryptedBlob`.
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<EncryptedBlob> {
    // 1. Derive key
    let dk = DerivedKey::new_from_password(password)?;

    // 2. Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 3. AES-256-GCM encrypt (authenticated)
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dk.key_bytes));
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MindLockError::EncryptionFailed(e.to_string()))?;

    // 4. HMAC over (salt || nonce || ciphertext) — integrity check independent of GCM tag
    let hmac_bytes = compute_hmac(&dk.key_bytes, &dk.salt, &nonce_bytes, &ciphertext);

    Ok(EncryptedBlob {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        salt: dk.salt.to_vec(),
        hmac: hmac_bytes,
    })
}

/// Decrypt a blob with a password. Verifies HMAC before attempting GCM decrypt.
pub fn decrypt(blob: &EncryptedBlob, password: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    if blob.salt.len() != SALT_LEN {
        return Err(MindLockError::InvalidFormat("Bad salt length".into()));
    }
    salt.copy_from_slice(&blob.salt);

    let dk = DerivedKey::from_password_and_salt(password, &salt)?;
    decrypt_with_key(blob, &dk)
}

/// Decrypt a blob with a pre-derived or reconstructed Shard-based key.
pub fn decrypt_with_key(blob: &EncryptedBlob, dk: &DerivedKey) -> Result<Vec<u8>> {
    // 1. Verify HMAC first — integrity must be checked before expensive GCM decrypt
    let expected_hmac = compute_hmac(&dk.key_bytes, &dk.salt, &blob.nonce, &blob.ciphertext);
    if expected_hmac != blob.hmac {
        return Err(MindLockError::DecryptionFailed);
    }

    // 2. AES-256-GCM decrypt
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dk.key_bytes));
    let nonce  = Nonce::from_slice(&blob.nonce);

    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| MindLockError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Re-encrypt with a new password (key rotation).
pub fn reencrypt(blob: &EncryptedBlob, old_password: &[u8], new_password: &[u8]) -> Result<EncryptedBlob> {
    let plaintext = decrypt(blob, old_password)?;
    encrypt(&plaintext, new_password)
}

// ── HMAC helper ───────────────────────────────────────────────────────────────

fn compute_hmac(key: &[u8], salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key length valid");
    mac.update(salt);
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().to_vec()
}

// ── Device fingerprinting (Phase 2) ──────────────────────────────────────────

/// A stable device fingerprint derived from system properties.
/// On real hardware this would hash CPU ID + MAC + hostname + OS build ID.
/// Here we provide the interface + a test stub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeviceFingerprint(pub String);

impl DeviceFingerprint {
    /// Compute fingerprint from raw system identity bytes.
    pub fn from_system_bytes(raw: &[u8]) -> Self {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"mindlock-device-v1:");
        hasher.update(raw);
        DeviceFingerprint(hex::encode(hasher.finalize()))
    }

    /// Derive from hostname + username (cross-platform stub).
    pub fn current() -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown-host".into());
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown-user".into());
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let raw = format!("{hostname}|{user}|{os}|{arch}");
        Self::from_system_bytes(raw.as_bytes())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"MindLock top-secret payload";
        let password  = b"super-secure-password-123";

        let blob   = encrypt(plaintext, password).expect("encrypt");
        let output = decrypt(&blob, password).expect("decrypt");

        assert_eq!(plaintext.as_slice(), output.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let blob = encrypt(b"secret", b"correct-password").expect("encrypt");
        let result = decrypt(&blob, b"wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let mut blob = encrypt(b"secret data", b"password").expect("encrypt");
        // Flip a byte in ciphertext
        blob.ciphertext[0] ^= 0xFF;
        let result = decrypt(&blob, b"password");
        assert!(result.is_err());
    }

    #[test]
    fn test_device_fingerprint_stable() {
        let fp1 = DeviceFingerprint::current();
        let fp2 = DeviceFingerprint::current();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_reencrypt() {
        let blob = encrypt(b"data", b"old-pass").unwrap();
        let new_blob = reencrypt(&blob, b"old-pass", b"new-pass").unwrap();
        let output = decrypt(&new_blob, b"new-pass").unwrap();
        assert_eq!(output, b"data");
    }
}
