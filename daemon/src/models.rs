use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Persisted file registration record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: Uuid,
    pub label: String,
    pub original_filename: String,
    pub mime_type: String,
    pub plaintext_size: i64,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// Full policy JSON (mirrors MindLockHeader.policy)
    pub policy_json: serde_json::Value,
    /// Comma-separated trusted device fingerprints
    pub trusted_devices: Vec<String>,
    pub wiped: bool,
    pub revoked: bool,
    pub control_server: Option<String>,
    /// Serialised TokenGateConfig JSON
    pub token_gate_json: Option<serde_json::Value>,
    /// SHA-256 hash of enrolled behavior baseline
    pub behavior_profile_hash: Option<String>,
    /// Open count (mirrors policy.open_count — kept in sync)
    pub open_count: i32,
    /// Failed attempt count
    pub failed_attempts: i32,
}

/// One entry in the access log.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AccessLogEntry {
    pub id: Uuid,
    pub file_id: Uuid,
    pub attempted_at: DateTime<Utc>,
    pub device_fingerprint: String,
    pub ip_address: Option<String>,
    /// "grant" | "deny" | "decoy" | "wipe"
    pub outcome: String,
    pub deny_reason: Option<String>,
    pub user_agent: Option<String>,
}

/// Request body for access check.
#[derive(Debug, Deserialize)]
pub struct AccessCheckRequest {
    pub device_fingerprint: String,
    pub ip_address: Option<String>,
    /// Unix timestamp ms
    pub timestamp_ms: Option<i64>,
    /// Behavior check result (Phase 3)
    pub behavior_ok: Option<bool>,
    /// Token gate result (Phase 4)
    pub token_gate_ok: Option<bool>,
    /// Ethereum wallet address for verify_web3_access (Phase 4)
    pub wallet_address: Option<String>,
}

/// Response for access check.
#[derive(Debug, Serialize)]
pub struct AccessCheckResponse {
    /// "grant" | "deny" | "decoy" | "wipe"
    pub decision: String,
    pub reason: Option<String>,
    pub opens_remaining: Option<u32>,
}

/// Request body for policy update.
#[derive(Debug, Deserialize)]
pub struct PolicyUpdateRequest {
    pub max_opens: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub enforce_device_trust: Option<bool>,
    pub max_failed_attempts: Option<u32>,
    pub decoy_on_fail: Option<bool>,
    pub require_behavior_auth: Option<bool>,
    pub require_token_gate: Option<bool>,
    pub revoked: Option<bool>,
}

/// Request body for file registration.
#[derive(Debug, Deserialize)]
pub struct RegisterFileRequest {
    pub file_id: Uuid,
    pub label: String,
    pub original_filename: String,
    pub mime_type: String,
    pub plaintext_size: i64,
    pub created_by: String,
    pub policy_json: serde_json::Value,
    pub trusted_devices: Vec<String>,
    pub control_server: Option<String>,
    pub token_gate_json: Option<serde_json::Value>,
    pub behavior_profile_hash: Option<String>,
}
