/// decoy.rs — Decoy mode engine (Phase 2 + 3).
///
/// When triggered (wrong password OR policy violation with decoy_on_fail=true):
///   1. Decrypts and serves the decoy blob instead of the real payload.
///   2. The decoy content is a convincing-looking fake of the same MIME type.
///   3. Phase 3: embed a per-recipient invisible watermark to trace leaks.
///
/// Decoy generation strategy:
///   • text/plain, application/json, text/csv  → realistic fake content
///   • application/pdf                         → "DRAFT / CONFIDENTIAL" marker page
///   • image/*                                 → 1×1 px PNG placeholder (minimal)
///   • Unknown MIME                            → generic Lorem Ipsum text
///
/// The owner pre-generates decoy content at lock time and encrypts it separately
/// with a DIFFERENT key (the "decoy password"). This means:
///   - Real password → real file
///   - Wrong password (or decoy-trigger) → looks like a successful open
///   - Attacker has no signal they're in decoy mode

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};
use crate::{crypto::{encrypt, decrypt, EncryptedBlob}, Result};

// ── Decoy content generator ───────────────────────────────────────────────────

/// Generate convincing fake content for a given MIME type.
pub fn generate_decoy_content(mime_type: &str, original_size: u64) -> Vec<u8> {
    match mime_type {
        "text/plain" => generate_fake_text(original_size),
        "application/json" => generate_fake_json(),
        "text/csv" => generate_fake_csv(),
        "application/pdf" => generate_fake_pdf_marker(),
        _ if mime_type.starts_with("image/") => generate_placeholder_png(),
        _ => generate_fake_text(original_size),
    }
}

fn generate_fake_text(target_size: u64) -> Vec<u8> {
    let paragraphs = [
        "This document contains internal project notes regarding Q3 planning initiatives.",
        "Key stakeholders have reviewed the proposed timeline and provided preliminary approval.",
        "Further analysis is required before final sign-off can be obtained from the review board.",
        "All figures are estimates based on current market conditions and are subject to revision.",
        "Please direct any questions to the project management office by end of quarter.",
        "Confidential — for internal distribution only. Do not forward without explicit permission.",
    ];
    let mut rng = thread_rng();
    let mut out = String::new();
    while (out.len() as u64) < target_size.min(4096) {
        out.push_str(paragraphs[rng.gen_range(0..paragraphs.len())]);
        out.push_str("\n\n");
    }
    out.into_bytes()
}

fn generate_fake_json() -> Vec<u8> {
    r#"{
  "status": "success",
  "version": "2.1.4",
  "data": {
    "project": "Alpha Initiative",
    "phase": "planning",
    "owner": "operations@company.internal",
    "budget_approved": false,
    "next_review": "2025-Q1",
    "notes": "Preliminary figures only — not for distribution."
  }
}"#.as_bytes().to_vec()
}

fn generate_fake_csv() -> Vec<u8> {
    let mut out = String::from("id,name,department,budget_usd,status\n");
    let depts = ["Engineering","Marketing","Finance","Legal","Operations"];
    let mut rng = thread_rng();
    for i in 1..=10 {
        let dept = depts[rng.gen_range(0..depts.len())];
        let budget: u32 = rng.gen_range(50000..500000);
        out.push_str(&format!("{i},Project-{i:04},{dept},{budget},draft\n"));
    }
    out.into_bytes()
}

fn generate_fake_pdf_marker() -> Vec<u8> {
    // Minimal valid PDF-like header (not a real PDF, but passes casual inspection)
    b"%PDF-1.4\n%DRAFT COPY - CONFIDENTIAL\n%%EOF".to_vec()
}

fn generate_placeholder_png() -> Vec<u8> {
    // Hardcoded 1×1 transparent PNG (89 bytes)
    vec![
        0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A, // PNG signature
        0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52, // IHDR chunk
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
        0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,
        0xDE,0x00,0x00,0x00,0x0C,0x49,0x44,0x41,
        0x54,0x08,0xD7,0x63,0xF8,0xCF,0xC0,0x00,
        0x00,0x00,0x02,0x00,0x01,0xE2,0x21,0xBC,
        0x33,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,
        0x44,0xAE,0x42,0x60,0x82,
    ]
}

// ── Decoy blob creation ───────────────────────────────────────────────────────

/// Encrypt decoy content under a decoy password.
/// Call this at lock time and store the result as `MindLockFile::decoy_payload`.
pub fn create_decoy_blob(
    mime_type: &str,
    original_size: u64,
    decoy_password: &[u8],
) -> Result<EncryptedBlob> {
    let content = generate_decoy_content(mime_type, original_size);
    encrypt(&content, decoy_password)
}

/// Decrypt and return the decoy content.
pub fn open_decoy(decoy_blob: &EncryptedBlob, decoy_password: &[u8]) -> Result<Vec<u8>> {
    decrypt(decoy_blob, decoy_password)
}

// ── Watermarking (Phase 3) ────────────────────────────────────────────────────

/// Per-recipient watermark — an invisible tag embedded in decoy content.
/// For text: appended as invisible unicode zero-width chars encoding the recipient ID.
/// For binary: appended as a trailing comment block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watermark {
    /// Unique recipient identifier (hashed, not plaintext)
    pub recipient_hash: String,
    /// File ID this watermark belongs to
    pub file_id: String,
    /// Timestamp of decoy generation
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

impl Watermark {
    pub fn new(recipient_id: &str, file_id: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(recipient_id.as_bytes());
        hasher.update(b":");
        hasher.update(file_id.as_bytes());
        Watermark {
            recipient_hash: hex::encode(hasher.finalize()),
            file_id: file_id.to_string(),
            generated_at: chrono::Utc::now(),
        }
    }

    /// Encode watermark as zero-width unicode chars (invisible in text viewers).
    /// Bit 0 → U+200B (ZERO WIDTH SPACE), Bit 1 → U+200C (ZERO WIDTH NON-JOINER)
    fn encode_as_zero_width(&self) -> String {
        let bytes = hex::decode(&self.recipient_hash).unwrap_or_default();
        let mut out = String::new();
        for byte in bytes.iter().take(8) { // 8 bytes = 64 bits
            for bit in 0..8 {
                if (byte >> bit) & 1 == 0 {
                    out.push('\u{200B}'); // ZWS
                } else {
                    out.push('\u{200C}'); // ZWNJ
                }
            }
        }
        out
    }

    /// Embed watermark into text content.
    pub fn embed_in_text(&self, mut content: Vec<u8>) -> Vec<u8> {
        let tag = format!(" {}", self.encode_as_zero_width());
        content.extend_from_slice(tag.as_bytes());
        content
    }

    /// Embed watermark into binary content (trailing comment block).
    pub fn embed_in_binary(&self, mut content: Vec<u8>) -> Vec<u8> {
        let marker = format!(
            "\n<!-- WMARK:{} FILE:{} TS:{} -->",
            &self.recipient_hash[..16],
            &self.file_id[..8],
            self.generated_at.timestamp()
        );
        content.extend_from_slice(marker.as_bytes());
        content
    }

    /// Try to extract a watermark hash from text content.
    pub fn extract_from_text(content: &[u8]) -> Option<String> {
        let s = std::str::from_utf8(content).ok()?;
        let mut bits = Vec::new();
        for ch in s.chars() {
            match ch {
                '\u{200B}' => bits.push(0u8),
                '\u{200C}' => bits.push(1u8),
                _ => {}
            }
        }
        if bits.len() < 64 { return None; }
        let bytes: Vec<u8> = bits.chunks(8).map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | (b << i))
        }).collect();
        Some(hex::encode(&bytes))
    }
}

// ── Decoy session log (Phase 3) ───────────────────────────────────────────────

/// Record of what an attacker did while in decoy mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoySession {
    pub file_id: String,
    pub attempted_at: chrono::DateTime<chrono::Utc>,
    pub device_fingerprint: String,
    pub ip_address: Option<String>,
    pub actions: Vec<DecoyAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecoyAction {
    FileOpened,
    FileCopied { destination: String },
    FilePrinted,
    FileShared { method: String },
    ScreenshotDetected,
    ContentRead { bytes_read: u64 },
}

impl DecoySession {
    pub fn new(file_id: &str, device_fp: &str) -> Self {
        DecoySession {
            file_id: file_id.to_string(),
            attempted_at: chrono::Utc::now(),
            device_fingerprint: device_fp.to_string(),
            ip_address: None,
            actions: vec![DecoyAction::FileOpened],
        }
    }

    pub fn log_action(&mut self, action: DecoyAction) {
        self.actions.push(action);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_text_content() {
        let c = generate_decoy_content("text/plain", 200);
        assert!(!c.is_empty());
    }

    #[test]
    fn test_generate_json_content() {
        let c = generate_decoy_content("application/json", 0);
        let s = std::str::from_utf8(&c).unwrap();
        assert!(s.contains("status"));
    }

    #[test]
    fn test_generate_csv_content() {
        let c = generate_decoy_content("text/csv", 0);
        let s = std::str::from_utf8(&c).unwrap();
        assert!(s.starts_with("id,name,"));
    }

    #[test]
    fn test_decoy_encrypt_decrypt() {
        let blob = create_decoy_blob("text/plain", 512, b"decoy-password").unwrap();
        let out  = open_decoy(&blob, b"decoy-password").unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn test_watermark_embed_extract() {
        let wm = Watermark::new("recipient@example.com", "file-uuid-1234");
        let content = b"This is decoy content.".to_vec();
        let watermarked = wm.embed_in_text(content);
        let extracted = Watermark::extract_from_text(&watermarked);
        assert!(extracted.is_some());
        assert_eq!(&extracted.unwrap()[..16], &wm.recipient_hash[..16]);
    }

    #[test]
    fn test_decoy_session_log() {
        let mut session = DecoySession::new("file-123", "device-abc");
        session.log_action(DecoyAction::FileCopied { destination: "/tmp/stolen".into() });
        assert_eq!(session.actions.len(), 2);
    }
}
