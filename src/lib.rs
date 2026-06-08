//! Shared utilities for the Rust services: config, JWT, password hashing, telemetry.

pub mod config;
pub mod email;
pub mod events;
pub mod jwt;
pub mod password;
pub mod telemetry;

use std::env;

/// Read an env var or fall back to a default.
pub fn env_or(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_string())
}

/// Read a required env var or panic.
pub fn must_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("required env var {key} is not set"))
}

/// Read an integer env var or fall back.
pub fn env_int(key: &str, fallback: i64) -> i64 {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(fallback)
}
