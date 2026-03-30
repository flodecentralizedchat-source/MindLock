/// mindlockd — MindLock remote control daemon (Phase 3).
///
/// REST API:
///   POST /api/files/register          Register a new .mindlock file
///   GET  /api/files/:id               Get file metadata + policy
///   POST /api/files/:id/check-access  Validate access context → Grant/Deny/Decoy
///   POST /api/files/:id/revoke        Immediately revoke all access
///   POST /api/files/:id/update-policy Update policy rules remotely
///   GET  /api/files/:id/access-log    Get full access history
///   POST /api/files/:id/wipe          Remote wipe signal
///   GET  /api/health                  Health check

mod db;
mod routes;
mod models;
mod config;
mod middleware;

use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;

pub use config::AppConfig;
pub use db::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "mindlockd=debug,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Config
    let config = AppConfig::from_env()?;
    let addr = format!("{}:{}", config.host, config.port);

    // Database
    let db = Database::connect(&config.database_url).await?;
    db.run_migrations().await?;

    let state = AppState {
        db: Arc::new(db),
        config: Arc::new(config),
    };

    // Router
    let app = Router::new()
        .nest("/api", routes::api_router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!("mindlockd listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
