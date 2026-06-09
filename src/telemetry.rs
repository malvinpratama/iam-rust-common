//! Tracing/log initialization with optional OTLP export to a collector (Jaeger).

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn json_only() {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(crate::env_or("LOG_LEVEL", "info")))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(false))
        .init();
}

/// Initialize logging. When OTEL_EXPORTER_OTLP_ENDPOINT is set, spans are
/// exported via OTLP (and the W3C propagator is installed for cross-service
/// trace linking); otherwise JSON structured logs only.
pub fn init(service: &str) {
    if crate::config::otlp_endpoint().is_empty() {
        json_only();
    } else {
        match init_tracing_opentelemetry::tracing_subscriber_ext::init_subscribers() {
            Ok(guard) => {
                // Keep the exporter/providers alive for the process lifetime.
                std::mem::forget(guard);
            }
            Err(e) => {
                json_only();
                tracing::warn!(error = %e, "OTLP tracer init failed; logging only");
            }
        }
    }
    tracing::info!(service, "telemetry initialized");
}
