//! JWT configuration loaded from the environment.

use crate::{env_int, env_or};

pub const DEFAULT_JWT_SECRET: &str = "change-me-in-production-please-32bytes-min";

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        Self {
            secret: env_or("JWT_SECRET", DEFAULT_JWT_SECRET),
            issuer: env_or("JWT_ISSUER", "iam-auth"),
            access_ttl_secs: env_int("ACCESS_TOKEN_TTL", 900),
            refresh_ttl_secs: env_int("REFRESH_TOKEN_TTL", 604800),
        }
    }
}

/// Whether APP_ENV indicates production.
pub fn is_production() -> bool {
    matches!(env_or("APP_ENV", "development").as_str(), "production" | "prod")
}

/// Shared gateway→service token (empty disables enforcement; local dev).
pub fn internal_token() -> String {
    env_or("INTERNAL_SERVICE_TOKEN", "")
}

/// NATS JetStream URL for async inter-service events. Empty disables the
/// publisher/consumer (lazy profile healing remains), keeping the broker optional.
pub fn nats_url() -> String {
    env_or("NATS_URL", "")
}

// ── v0.2 Security+ feature toggles (defaults keep current behavior) ──

/// Block login for unverified users when true.
pub fn require_email_verification() -> bool {
    env_or("REQUIRE_EMAIL_VERIFICATION", "false") == "true"
}

/// Failed-login threshold before lockout (0 disables).
pub fn login_max_failures() -> i64 {
    crate::env_int("LOGIN_MAX_FAILURES", 5)
}

/// Lockout duration in seconds.
pub fn login_lockout_secs() -> i64 {
    crate::env_int("LOGIN_LOCKOUT_SECONDS", 900)
}

/// Whether sensitive actions are written to the audit log.
pub fn audit_enabled() -> bool {
    env_or("AUDIT_ENABLED", "true") != "false"
}

/// Fail fast on insecure configuration in production.
pub fn validate_security() -> Result<(), String> {
    if !is_production() {
        return Ok(());
    }
    let secret = env_or("JWT_SECRET", DEFAULT_JWT_SECRET);
    if secret == DEFAULT_JWT_SECRET || secret.len() < 32 {
        return Err("JWT_SECRET must be a strong value (>=32 bytes) in production".into());
    }
    if env_or("BOOTSTRAP_ADMIN_PASSWORD", "") == "admin12345" {
        return Err("BOOTSTRAP_ADMIN_PASSWORD must not be the default in production".into());
    }
    if internal_token().is_empty() {
        return Err("INTERNAL_SERVICE_TOKEN must be set in production".into());
    }
    Ok(())
}
