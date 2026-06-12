//! Email sending abstraction. The default sender logs the message instead of
//! using SMTP, so verification/reset flows work in dev without an email server.

/// Delivers a message to a recipient.
pub trait Sender: Send + Sync {
    fn send(&self, to: &str, subject: &str, body: &str);
}

/// Writes emails to the structured log (development default).
pub struct LogSender;

impl Sender for LogSender {
    fn send(&self, to: &str, subject: &str, body: &str) {
        // The body carries a credential (verification / password-reset token).
        // Never write it to logs in production — warn instead so the
        // misconfiguration is visible, and wire a real SMTP sender for prod.
        if crate::config::is_production() {
            tracing::warn!(to, subject, "email suppressed: LogSender must not be used in production (no SMTP configured)");
            return;
        }
        tracing::info!(to, subject, body, "email (dev log sender)");
    }
}
