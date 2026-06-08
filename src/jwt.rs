//! HS256 access-token issuance and verification.

use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::config::JwtConfig;

/// Generate a random 128-bit token id (hex).
fn gen_jti() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub iss: String,
    pub jti: String, // token id — used for access-token revocation
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token encode failed")]
    Encode,
    #[error("invalid or expired token")]
    Invalid,
}

#[derive(Clone)]
pub struct JwtManager {
    secret: String,
    issuer: String,
    access_ttl_secs: i64,
}

impl JwtManager {
    pub fn new(cfg: &JwtConfig) -> Self {
        Self {
            secret: cfg.secret.clone(),
            issuer: cfg.issuer.clone(),
            access_ttl_secs: cfg.access_ttl_secs,
        }
    }

    pub fn access_ttl_secs(&self) -> i64 {
        self.access_ttl_secs
    }

    pub fn issue(&self, user_id: &str, email: &str) -> Result<String, JwtError> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            iss: self.issuer.clone(),
            jti: gen_jti(),
            iat: now,
            exp: now + self.access_ttl_secs,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|_| JwtError::Encode)
    }

    pub fn parse(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[self.issuer.clone()]);
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|_| JwtError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr(ttl: i64) -> JwtManager {
        JwtManager::new(&JwtConfig {
            secret: "test-secret-which-is-long-enough-32b".into(),
            issuer: "iam-auth".into(),
            access_ttl_secs: ttl,
            refresh_ttl_secs: 0,
        })
    }

    #[test]
    fn issue_and_parse() {
        let m = mgr(60);
        let tok = m.issue("user-123", "a@b.com").unwrap();
        let claims = m.parse(&tok).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "a@b.com");
    }

    #[test]
    fn rejects_tampered() {
        let m = mgr(60);
        let tok = m.issue("user-123", "a@b.com").unwrap();
        assert!(m.parse(&format!("{tok}x")).is_err());
    }

    #[test]
    fn rejects_expired() {
        // -3600s puts exp well beyond jsonwebtoken's default 60s leeway.
        let m = mgr(-3600);
        let tok = m.issue("user-123", "a@b.com").unwrap();
        assert!(m.parse(&tok).is_err());
    }
}
