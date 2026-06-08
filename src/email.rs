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
        tracing::info!(to, subject, body, "email (dev log sender)");
    }
}
