use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use chrono::Utc;
use crate::models::*;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(url)
            .await?;
        Ok(Database { pool })
    }

    /// Run all schema migrations.
    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS files (
                id                    UUID PRIMARY KEY,
                label                 TEXT NOT NULL,
                original_filename     TEXT NOT NULL,
                mime_type             TEXT NOT NULL DEFAULT '',
                plaintext_size        BIGINT NOT NULL DEFAULT 0,
                created_by            TEXT NOT NULL DEFAULT '',
                created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                policy_json           JSONB NOT NULL DEFAULT '{}',
                trusted_devices       TEXT[] NOT NULL DEFAULT '{}',
                wiped                 BOOLEAN NOT NULL DEFAULT FALSE,
                revoked               BOOLEAN NOT NULL DEFAULT FALSE,
                control_server        TEXT,
                token_gate_json       JSONB,
                behavior_profile_hash TEXT,
                open_count            INTEGER NOT NULL DEFAULT 0,
                failed_attempts       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS access_log (
                id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                file_id             UUID NOT NULL REFERENCES files(id),
                attempted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                device_fingerprint  TEXT NOT NULL,
                ip_address          TEXT,
                outcome             TEXT NOT NULL,
                deny_reason         TEXT,
                user_agent          TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_access_log_file_id ON access_log(file_id);
            CREATE INDEX IF NOT EXISTS idx_access_log_attempted_at ON access_log(attempted_at DESC);
        "#).execute(&self.pool).await?;
        Ok(())
    }

    // ── Files ──────────────────────────────────────────────────────────────────

    pub async fn register_file(&self, req: &RegisterFileRequest) -> anyhow::Result<FileRecord> {
        let rec = sqlx::query_as::<_, FileRecord>(r#"
            INSERT INTO files
              (id, label, original_filename, mime_type, plaintext_size, created_by,
               created_at, policy_json, trusted_devices, control_server,
               token_gate_json, behavior_profile_hash)
            VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,$8,$9,$10,$11)
            ON CONFLICT (id) DO UPDATE SET
              label = EXCLUDED.label,
              policy_json = EXCLUDED.policy_json,
              trusted_devices = EXCLUDED.trusted_devices
            RETURNING *
        "#)
        .bind(req.file_id)
        .bind(&req.label)
        .bind(&req.original_filename)
        .bind(&req.mime_type)
        .bind(req.plaintext_size)
        .bind(&req.created_by)
        .bind(&req.policy_json)
        .bind(&req.trusted_devices)
        .bind(&req.control_server)
        .bind(&req.token_gate_json)
        .bind(&req.behavior_profile_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn get_file(&self, id: Uuid) -> anyhow::Result<Option<FileRecord>> {
        let rec = sqlx::query_as::<_, FileRecord>("SELECT * FROM files WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(rec)
    }

    pub async fn revoke_file(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE files SET revoked = TRUE WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn wipe_file(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE files SET wiped = TRUE, revoked = TRUE WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn increment_opens(&self, id: Uuid) -> anyhow::Result<i32> {
        let row: (i32,) = sqlx::query_as(
            "UPDATE files SET open_count = open_count + 1 WHERE id = $1 RETURNING open_count"
        ).bind(id).fetch_one(&self.pool).await?;
        Ok(row.0)
    }

    pub async fn increment_failures(&self, id: Uuid) -> anyhow::Result<i32> {
        let row: (i32,) = sqlx::query_as(
            "UPDATE files SET failed_attempts = failed_attempts + 1 WHERE id = $1 RETURNING failed_attempts"
        ).bind(id).fetch_one(&self.pool).await?;
        Ok(row.0)
    }

    pub async fn reset_failures(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE files SET failed_attempts = 0 WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_policy(&self, id: Uuid, req: &PolicyUpdateRequest) -> anyhow::Result<()> {
        // Merge patches into existing policy_json using PostgreSQL jsonb
        if let Some(rev) = req.revoked {
            sqlx::query("UPDATE files SET revoked = $1 WHERE id = $2")
                .bind(rev).bind(id).execute(&self.pool).await?;
        }
        let patch = serde_json::json!({
            "max_opens": req.max_opens,
            "expires_at": req.expires_at,
            "enforce_device_trust": req.enforce_device_trust,
            "max_failed_attempts": req.max_failed_attempts,
            "decoy_on_fail": req.decoy_on_fail,
            "require_behavior_auth": req.require_behavior_auth,
            "require_token_gate": req.require_token_gate,
        });
        // Remove null fields before merging
        let patch_clean: serde_json::Value = patch.as_object()
            .unwrap()
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into();

        sqlx::query("UPDATE files SET policy_json = policy_json || $1 WHERE id = $2")
            .bind(patch_clean).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ── Access log ─────────────────────────────────────────────────────────────

    pub async fn log_access(
        &self,
        file_id: Uuid,
        device_fp: &str,
        ip: Option<&str>,
        outcome: &str,
        deny_reason: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(r#"
            INSERT INTO access_log
              (file_id, attempted_at, device_fingerprint, ip_address, outcome, deny_reason, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#)
        .bind(file_id)
        .bind(Utc::now())
        .bind(device_fp)
        .bind(ip)
        .bind(outcome)
        .bind(deny_reason)
        .bind(user_agent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_access_log(&self, file_id: Uuid, limit: i64) -> anyhow::Result<Vec<AccessLogEntry>> {
        let entries = sqlx::query_as::<_, AccessLogEntry>(
            "SELECT * FROM access_log WHERE file_id = $1 ORDER BY attempted_at DESC LIMIT $2"
        )
        .bind(file_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(entries)
    }
}
