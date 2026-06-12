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

/// Shared gateway→service token. Empty does NOT disable enforcement on its own —
/// internal auth is fail-closed (see `internal_auth_optional`).
pub fn internal_token() -> String {
    env_or("INTERNAL_SERVICE_TOKEN", "")
}

/// Explicit opt-out to run internal services without the shared token (local dev
/// / tests). Must be set deliberately; a missing token is otherwise fail-closed
/// so a misconfigured deployment rejects every internal call instead of allowing
/// all of them.
pub fn internal_auth_optional() -> bool {
    env_or("INTERNAL_AUTH_OPTIONAL", "") == "true"
}

/// NATS JetStream URL for async inter-service events. Empty disables the
/// publisher/consumer (lazy profile healing remains), keeping the broker optional.
pub fn nats_url() -> String {
    env_or("NATS_URL", "")
}

/// OTLP endpoint URL for trace export (e.g. http://jaeger:4317). Empty disables
/// tracing, keeping observability optional.
pub fn otlp_endpoint() -> String {
    env_or("OTEL_EXPORTER_OTLP_ENDPOINT", "")
}

/// Listen address for the Prometheus /metrics endpoint.
pub fn metrics_addr() -> String {
    format!("0.0.0.0:{}", env_or("METRICS_PORT", "9100"))
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

/// Substrings that betray a placeholder/demo/dev secret. The committed demo
/// values (k8s-demo-…-rotate-me, app_secret, dev-…-change-me, ChangeMeAdmin-…)
/// all contain one, so exact-matching the old defaults was not enough.
const WEAK_SECRET_MARKERS: &[&str] = &[
    "change-me", "changeme", "rotate-me", "k8s-demo", "demo-secret",
    "dev-internal", "admin12345", "app_secret", "console-demo",
];

fn looks_weak(s: &str) -> bool {
    let l = s.to_lowercase();
    WEAK_SECRET_MARKERS.iter().any(|m| l.contains(m))
}

/// Fail fast on insecure configuration in production. Rejects not just the
/// original defaults but any value carrying a placeholder marker, so a
/// repo-committed demo secret cannot boot a production deployment.
pub fn validate_security() -> Result<(), String> {
    if !is_production() {
        return Ok(());
    }
    let secret = env_or("JWT_SECRET", DEFAULT_JWT_SECRET);
    if secret.len() < 32 || looks_weak(&secret) {
        return Err("JWT_SECRET must be a strong, non-placeholder value (>=32 bytes) in production".into());
    }
    let admin = env_or("BOOTSTRAP_ADMIN_PASSWORD", "");
    if admin.is_empty() || looks_weak(&admin) {
        return Err("BOOTSTRAP_ADMIN_PASSWORD must be set to a strong, non-placeholder value in production".into());
    }
    let token = internal_token();
    if token.is_empty() || looks_weak(&token) {
        return Err("INTERNAL_SERVICE_TOKEN must be set to a strong, non-placeholder value in production".into());
    }
    // The DB password is embedded in the connection URL — reject placeholder creds.
    for k in ["AUTH_DATABASE_URL", "USER_DATABASE_URL", "DATABASE_URL"] {
        let v = env_or(k, "");
        if !v.is_empty() && looks_weak(&v) {
            return Err(format!("{k} must not use a placeholder database password in production"));
        }
    }
    Ok(())
}
