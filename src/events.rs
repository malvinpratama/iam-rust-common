//! Asynchronous inter-service event contract + NATS JetStream helpers.
//!
//! Auth publishes user-lifecycle events (via a transactional outbox + relay);
//! the user service consumes them idempotently. Auth and user never call each
//! other directly.

use std::time::Duration;

use async_nats::jetstream::{self, stream};
use serde::{Deserialize, Serialize};

pub const STREAM: &str = "IAM_EVENTS";
pub const SUBJECT_PREFIX: &str = "iam.";
pub const SUBJECT_USER_REGISTERED: &str = "iam.user.registered";
pub const SUBJECT_USER_DELETED: &str = "iam.user.deleted";
pub const SUBJECT_USER_RESTORED: &str = "iam.user.restored";

/// Event type tags as stored in the auth outbox (subject = prefix + type).
pub const TYPE_USER_REGISTERED: &str = "user.registered";
pub const TYPE_USER_DELETED: &str = "user.deleted";
pub const TYPE_USER_RESTORED: &str = "user.restored";

/// Published after an identity is created; drives profile creation.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRegistered {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
}

/// Published after an identity is deleted; drives profile deletion. Soft by
/// default; `hard` requests permanent removal.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserDeleted {
    pub user_id: String,
    #[serde(default)]
    pub hard: bool,
}

/// Published after a soft-deleted identity is restored; un-deletes the profile.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRestored {
    pub user_id: String,
}

/// Connect to NATS and return a JetStream context (infinite reconnect).
pub async fn connect(url: &str) -> anyhow::Result<jetstream::Context> {
    let client = async_nats::connect(url)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(jetstream::new(client))
}

/// Idempotently create the IAM_EVENTS stream (safe to call from any service).
pub async fn ensure_stream(js: &jetstream::Context) -> anyhow::Result<()> {
    js.get_or_create_stream(stream::Config {
        name: STREAM.to_string(),
        subjects: vec![format!("{SUBJECT_PREFIX}user.>")],
        max_age: Duration::from_secs(72 * 3600),
        ..Default::default()
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(())
}
