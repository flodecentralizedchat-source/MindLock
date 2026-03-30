use axum::{
    extract::{Path, State, Json, ConnectInfo},
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use uuid::Uuid;
use mindlock_core::rules::{AccessContext, AccessDecision, RulesEngine, AccessPolicy};
use mindlock_core::crypto::DeviceFingerprint;
use mindlock_core::format::TokenGateConfig;
use crate::{AppState, models::*};

// ── Error type ────────────────────────────────────────────────────────────────

struct ApiError(anyhow::Error);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": self.0.to_string()}).to_string())
            .into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self { ApiError(e.into()) }
}
type ApiResult<T> = Result<T, ApiError>;

// ── Router ────────────────────────────────────────────────────────────────────

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/health",                     get(health))
        .route("/files",                      post(register_file))
        .route("/files/:id",                  get(get_file))
        .route("/files/:id/check-access",     post(check_access))
        .route("/files/:id/revoke",           post(revoke_file))
        .route("/files/:id/update-policy",    post(update_policy))
        .route("/files/:id/access-log",       get(get_access_log))
        .route("/files/:id/wipe",             post(wipe_file))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    serde_json::json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}).to_string()
}

/// POST /api/files — register a new file with the control server.
async fn register_file(
    State(state): State<AppState>,
    Json(req): Json<RegisterFileRequest>,
) -> ApiResult<impl IntoResponse> {
    let rec = state.db.register_file(&req).await?;
    Ok((StatusCode::CREATED, serde_json::to_string(&rec).unwrap()))
}

/// GET /api/files/:id — fetch file metadata.
async fn get_file(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    match state.db.get_file(id).await? {
        Some(rec) => Ok((StatusCode::OK, serde_json::to_string(&rec).unwrap())),
        None => Ok((StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.to_string())),
    }
}

/// POST /api/files/:id/check-access — central access decision point.
/// The client (CLI or desktop app) calls this before decrypting locally.
async fn check_access(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<AccessCheckRequest>,
) -> ApiResult<impl IntoResponse> {
    let Some(rec) = state.db.get_file(id).await? else {
        return Ok((StatusCode::NOT_FOUND,
            serde_json::json!({"decision":"deny","reason":"file not found"}).to_string()));
    };

    // Revoked / wiped — server-side override
    if rec.revoked {
        state.db.log_access(id, &req.device_fingerprint, Some(&addr.ip().to_string()),
            "deny", Some("revoked"), None).await?;
        let resp = AccessCheckResponse {
            decision: "deny".into(),
            reason: Some("Access has been revoked by the owner".into()),
            opens_remaining: None,
        };
        return Ok((StatusCode::OK, serde_json::to_string(&resp).unwrap()));
    }
    if rec.wiped {
        let resp = AccessCheckResponse {
            decision: "wipe".into(),
            reason: Some("File has been wiped".into()),
            opens_remaining: None,
        };
        return Ok((StatusCode::OK, serde_json::to_string(&resp).unwrap()));
    }

    // Reconstruct policy from DB record
    let mut policy: AccessPolicy = serde_json::from_value(rec.policy_json.clone())
        .unwrap_or_default();
    policy.open_count   = rec.open_count as u32;
    policy.failed_attempts = rec.failed_attempts as u32;

    // Build access context
    let trusted: Vec<DeviceFingerprint> = rec.trusted_devices.iter()
        .map(|s| DeviceFingerprint(s.clone())).collect();

    let mut ctx = AccessContext::new(trusted);
    ctx.device = DeviceFingerprint(req.device_fingerprint.clone());
    ctx.behavior_ok   = req.behavior_ok;
    
    // Phase 4: Server-side Token Gate Verification
    if let Some(gate_json) = &rec.token_gate_json {
        let gate_config: TokenGateConfig = serde_json::from_value(gate_json.clone())
            .unwrap_or_default();
        
        if let Some(wallet) = &req.wallet_address {
            tracing::info!("Performing server-side Web3 check for wallet: {}", wallet);
            let ok = mindlock_web3::verify_web3_access(&gate_config, wallet, None, None).await
                .unwrap_or(false);
            ctx.token_gate_ok = Some(ok);
        } else {
            ctx.token_gate_ok = Some(false);
        }
    } else {
        ctx.token_gate_ok = req.token_gate_ok;
    }

    // Evaluate
    let decision = RulesEngine::evaluate(&policy, &ctx);

    let (outcome, reason, http_decision) = match &decision {
        AccessDecision::Grant => {
            state.db.increment_opens(id).await?;
            state.db.reset_failures(id).await?;
            let remaining = policy.max_opens.map(|m| m.saturating_sub(policy.open_count + 1));
            ("grant", None, AccessCheckResponse {
                decision: "grant".into(),
                reason: None,
                opens_remaining: remaining,
            })
        }
        AccessDecision::Decoy => {
            state.db.increment_failures(id).await?;
            ("decoy", None, AccessCheckResponse {
                decision: "decoy".into(),
                reason: None,
                opens_remaining: None,
            })
        }
        AccessDecision::SelfDestruct => {
            state.db.wipe_file(id).await?;
            ("wipe", Some("self-destruct triggered"), AccessCheckResponse {
                decision: "wipe".into(),
                reason: Some("Self-destruct triggered".into()),
                opens_remaining: Some(0),
            })
        }
        AccessDecision::Deny(r) => {
            let failures = state.db.increment_failures(id).await?;
            // Check if we should remotely trigger wipe
            if let Some(max) = policy.max_failed_attempts {
                if failures as u32 >= max {
                    state.db.wipe_file(id).await?;
                }
            }
            ("deny", Some(r.as_str()), AccessCheckResponse {
                decision: "deny".into(),
                reason: Some(r.clone()),
                opens_remaining: None,
            })
        }
    };

    state.db.log_access(id, &req.device_fingerprint,
        Some(&addr.ip().to_string()), outcome, reason, None).await?;

    Ok((StatusCode::OK, serde_json::to_string(&http_decision).unwrap()))
}

/// POST /api/files/:id/revoke — immediately revoke all access.
async fn revoke_file(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.db.revoke_file(id).await?;
    Ok((StatusCode::OK, r#"{"status":"revoked"}"#))
}

/// POST /api/files/:id/update-policy — remotely update access rules.
async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<PolicyUpdateRequest>,
) -> ApiResult<impl IntoResponse> {
    state.db.update_policy(id, &req).await?;
    Ok((StatusCode::OK, r#"{"status":"updated"}"#))
}

/// GET /api/files/:id/access-log — paginated access history.
async fn get_access_log(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let entries = state.db.get_access_log(id, 100).await?;
    Ok((StatusCode::OK, serde_json::to_string(&entries).unwrap()))
}

/// POST /api/files/:id/wipe — remote wipe command.
async fn wipe_file(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.db.wipe_file(id).await?;
    Ok((StatusCode::OK, r#"{"status":"wiped"}"#))
}
