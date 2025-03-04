use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: Option<String>,
    aud: String,
    iat: u64,
    nonce: Option<String>, // TODO: maybe the more secure Nonce type from openidconnect?
}

pub struct JwtProof {
    issuer_id: Option<String>,
    encoding_key: EncodingKey,
}

impl JwtProof {
    pub fn new(key_material: &str, issuer_id: &str) -> Self {
        let encoding_key = EncodingKey::from_secret(key_material.as_bytes());
        Self {
            issuer_id: Some(issuer_id.to_string()),
            encoding_key,
        }
    }

    pub fn create_jwt(&self, audience: &str, issued_at: u64, nonce: &str) -> String {
        let claims = Claims {
            iss: self.issuer_id.clone(),
            aud: audience.to_string(),
            iat: issued_at,
            nonce: Some(nonce.to_string()),
        };

        // Algorithm::RS256 is better, but requires a private key file. For demo and test purposes,
        // we use HS256, which is very simple requires no key files and is easy to use.
        let alg = Algorithm::HS256;

        let header = Header {
            alg,
            typ: Some("openid4vci-proof+jwt".to_string()),
            ..Default::default()
        };

        encode(&header, &claims, &self.encoding_key).expect("JWT creation failed")
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation() {
        let key_material = "This is a very poor secret key";
        let issuer_id ="issuer123";
        let audience = "audience123";
        let issued_at = current_timestamp();
        let nonce = "nonce123";

        let jwt_proof = JwtProof::new(key_material, issuer_id);
        let jwt = jwt_proof.create_jwt(audience, issued_at, nonce);

        assert!(!jwt.is_empty());
    }
}
