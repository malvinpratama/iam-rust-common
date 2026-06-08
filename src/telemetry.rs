//! Tracing/log initialization.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize JSON structured logging honoring RUST_LOG / LOG_LEVEL.
pub fn init(service: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(crate::env_or("LOG_LEVEL", "info")))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(false))
        .init();

    tracing::info!(service, "telemetry initialized");
}
