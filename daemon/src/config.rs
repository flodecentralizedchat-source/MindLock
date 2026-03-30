use anyhow::Context;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    /// HMAC secret for signing API tokens
    pub api_secret: String,
    /// Max requests per minute per IP (rate limiting)
    pub rate_limit_rpm: u32,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(AppConfig {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8743".into())
                .parse::<u16>()
                .context("Invalid PORT")?,
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://mindlock:mindlock@localhost/mindlock".into()),
            api_secret: std::env::var("API_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".into()),
            rate_limit_rpm: std::env::var("RATE_LIMIT_RPM")
                .unwrap_or_else(|_| "60".into())
                .parse()
                .unwrap_or(60),
        })
    }
}
