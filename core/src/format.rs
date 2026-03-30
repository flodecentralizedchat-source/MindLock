/// format.rs — The .mindlock binary file format.
///
/// Binary layout (big-endian):
///   [0..4]   Magic bytes : 0x4D 0x4C 0x4B 0x21  ("MLK!")
///   [4]      Version     : u8 (current = 1)
///   [5..9]   Header len  : u32 — length of the JSON-encoded MindLockHeader
///   [9..N]   Header JSON : MindLockHeader (rules, metadata, fingerprints …)
///   [N..]    Payload     : bincode-encoded EncryptedBlob
///
/// The header is JSON for human-debuggability and forward compatibility.
/// The payload is bincode for compact binary efficiency.

use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::{
    crypto::{EncryptedBlob, DeviceFingerprint},
    rules::AccessPolicy,
    MindLockError, Result,
};

// ── Magic + Version ───────────────────────────────────────────────────────────

pub const MAGIC: [u8; 4] = [0x4D, 0x4C, 0x4B, 0x21];  // "MLK!"
pub const FORMAT_VERSION: u8 = 1;

// ── Header ────────────────────────────────────────────────────────────────────

/// Everything the runtime needs to evaluate access — stored in plaintext
/// so rules can be checked before any decryption attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MindLockHeader {
    /// Unique file identity (used for remote revocation lookup)
    pub file_id: Uuid,

    /// Human-readable label (not secret)
    pub label: String,

    /// Original filename + extension (stored for restoration)
    pub original_filename: String,

    /// MIME type of the original file
    pub mime_type: String,

    /// File size (bytes) before encryption
    pub plaintext_size: u64,

    /// When this file was locked
    pub created_at: DateTime<Utc>,

    /// Identity of the locker
    pub created_by: String,

    /// Access policy (rules engine) — Phase 2+
    pub policy: AccessPolicy,

    /// Trusted device fingerprints (empty = any device allowed)
    pub trusted_devices: Vec<DeviceFingerprint>,

    /// Phase 3: remote control server URL (None = offline-only)
    pub control_server: Option<String>,

    /// Phase 4: Web3 token-gate config (None = no token gate)
    pub token_gate: Option<TokenGateConfig>,

    /// Phase 5: MPC / Shard policy (None = single password)
    pub shard_policy: Option<ShardPolicy>,

    /// Has the file been wiped?  If true, payload is zeroed junk.
    pub wiped: bool,

    /// Decoy blob present? (Phase 2)
    pub has_decoy: bool,

    /// Behavior profile hash (Phase 3 — SHA-256 of enrolled baseline)
    pub behavior_profile_hash: Option<String>,
}

impl MindLockHeader {
    pub fn new(
        label: impl Into<String>,
        original_filename: impl Into<String>,
        mime_type: impl Into<String>,
        plaintext_size: u64,
        created_by: impl Into<String>,
        policy: AccessPolicy,
    ) -> Self {
        MindLockHeader {
            file_id: Uuid::new_v4(),
            label: label.into(),
            original_filename: original_filename.into(),
            mime_type: mime_type.into(),
            plaintext_size,
            created_at: Utc::now(),
            created_by: created_by.into(),
            policy,
            trusted_devices: Vec::new(),
            control_server: None,
            token_gate: None,
            shard_policy: None,
            wiped: false,
            has_decoy: false,
            behavior_profile_hash: None,
        }
    }
}

// ── Token gate config (Phase 4) ───────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenGateConfig {
    /// Chain ID (e.g., 1 = Ethereum mainnet, 137 = Polygon)
    pub chain_id: u64,
    /// ERC-20 / ERC-721 contract address of the required token
    pub token_contract: String,
    /// Minimum balance required (in token base units)
    pub min_balance: u128,
    /// Optional: pay-to-open amount in wei
    pub pay_to_open_wei: Option<u128>,
    /// RPC endpoint for on-chain verification
    pub rpc_url: String,
}

// ── MPC / Shard policy (Phase 5) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardPolicy {
    /// Total number of shards created (N)
    pub total_shards: u8,
    /// Minimum shards required to reconstruct (K)
    pub threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShard {
    /// Index of this shard (X coordinate)
    pub index: u8,
    /// The shard data (Y coordinate / piece of secrets)
    pub data: Vec<u8>,
}

// ── Full file container ───────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MindLockFile {
    pub header: MindLockHeader,
    /// Real encrypted payload
    pub payload: EncryptedBlob,
    /// Optional decoy encrypted payload (Phase 2)
    pub decoy_payload: Option<EncryptedBlob>,
}

impl MindLockFile {
    pub fn new(header: MindLockHeader, payload: EncryptedBlob) -> Self {
        MindLockFile { header, payload, decoy_payload: None }
    }

    pub fn with_decoy(mut self, decoy: EncryptedBlob) -> Self {
        self.header.has_decoy = true;
        self.decoy_payload = Some(decoy);
        self
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /// Write the complete .mindlock binary to a `Write` sink.
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        // Magic
        w.write_all(&MAGIC)?;
        // Version
        w.write_all(&[FORMAT_VERSION])?;

        // Header JSON
        let header_json = serde_json::to_vec(&self.header)
            .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;
        let header_len = header_json.len() as u32;
        w.write_all(&header_len.to_be_bytes())?;
        w.write_all(&header_json)?;

        // Payload (bincode)
        let payload_bytes = bincode::serialize(&self.payload)
            .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;
        let payload_len = payload_bytes.len() as u64;
        w.write_all(&payload_len.to_be_bytes())?;
        w.write_all(&payload_bytes)?;

        // Decoy payload (if present)
        if let Some(decoy) = &self.decoy_payload {
            let decoy_bytes = bincode::serialize(decoy)
                .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;
            let decoy_len = decoy_bytes.len() as u64;
            w.write_all(&decoy_len.to_be_bytes())?;
            w.write_all(&decoy_bytes)?;
        } else {
            w.write_all(&0u64.to_be_bytes())?; // zero-length decoy sentinel
        }

        Ok(())
    }

    /// Read a .mindlock binary from a `Read` source.
    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        // Magic
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(MindLockError::MagicMismatch);
        }

        // Version
        let mut ver = [0u8; 1];
        r.read_exact(&mut ver)?;
        if ver[0] != FORMAT_VERSION {
            return Err(MindLockError::UnsupportedVersion(ver[0]));
        }

        // Header
        let mut hlen_bytes = [0u8; 4];
        r.read_exact(&mut hlen_bytes)?;
        let hlen = u32::from_be_bytes(hlen_bytes) as usize;

        let mut header_json = vec![0u8; hlen];
        r.read_exact(&mut header_json)?;
        let header: MindLockHeader = serde_json::from_slice(&header_json)
            .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;

        // Payload
        let mut plen_bytes = [0u8; 8];
        r.read_exact(&mut plen_bytes)?;
        let plen = u64::from_be_bytes(plen_bytes) as usize;

        let mut payload_bytes = vec![0u8; plen];
        r.read_exact(&mut payload_bytes)?;
        let payload: EncryptedBlob = bincode::deserialize(&payload_bytes)
            .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;

        // Decoy (may be zero-length)
        let mut dlen_bytes = [0u8; 8];
        r.read_exact(&mut dlen_bytes)?;
        let dlen = u64::from_be_bytes(dlen_bytes) as usize;

        let decoy_payload = if dlen > 0 {
            let mut decoy_bytes = vec![0u8; dlen];
            r.read_exact(&mut decoy_bytes)?;
            let decoy: EncryptedBlob = bincode::deserialize(&decoy_bytes)
                .map_err(|e| MindLockError::InvalidFormat(e.to_string()))?;
            Some(decoy)
        } else {
            None
        };

        Ok(MindLockFile { header, payload, decoy_payload })
    }

    /// Convenience: write to a file path.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let f = std::fs::File::create(path)?;
        let mut w = std::io::BufWriter::new(f);
        self.write_to(&mut w)?;
        Ok(())
    }

    /// Convenience: read from a file path.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let f = std::fs::File::open(path)?;
        let r = std::io::BufReader::new(f);
        Self::read_from(r)
    }

    /// Return header-only info (no payload read needed if using streaming).
    pub fn file_id(&self) -> Uuid { self.header.file_id }
    pub fn label(&self)   -> &str { &self.header.label }
    pub fn is_wiped(&self) -> bool { self.header.wiped }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt;
    use crate::rules::AccessPolicy;
    use std::io::Cursor;

    fn sample_file() -> MindLockFile {
        let blob = encrypt(b"hello world", b"password").unwrap();
        let header = MindLockHeader::new(
            "Test file",
            "hello.txt",
            "text/plain",
            11,
            "tester",
            AccessPolicy::default(),
        );
        MindLockFile::new(header, blob)
    }

    #[test]
    fn test_roundtrip_in_memory() {
        let file = sample_file();
        let mut buf = Vec::new();
        file.write_to(&mut buf).unwrap();
        let loaded = MindLockFile::read_from(Cursor::new(&buf)).unwrap();
        assert_eq!(file.header.label, loaded.header.label);
        assert_eq!(file.header.file_id, loaded.header.file_id);
    }

    #[test]
    fn test_bad_magic_rejected() {
        let mut buf = vec![0u8; 100];
        buf[0] = 0xFF; // corrupt magic
        let result = MindLockFile::read_from(Cursor::new(&buf));
        assert!(matches!(result, Err(MindLockError::MagicMismatch)));
    }

    #[test]
    fn test_with_decoy() {
        let blob  = encrypt(b"real data",  b"real-pass").unwrap();
        let decoy = encrypt(b"fake data",  b"fake-pass").unwrap();
        let header = MindLockHeader::new("doc", "doc.pdf", "application/pdf", 9, "me", AccessPolicy::default());
        let file = MindLockFile::new(header, blob).with_decoy(decoy);

        let mut buf = Vec::new();
        file.write_to(&mut buf).unwrap();
        let loaded = MindLockFile::read_from(Cursor::new(&buf)).unwrap();
        assert!(loaded.header.has_decoy);
        assert!(loaded.decoy_payload.is_some());
    }
}
