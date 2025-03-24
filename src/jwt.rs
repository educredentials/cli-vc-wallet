extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

use jwk::{JsonWebKey, Key};
use jwt::{encode, EncodingKey, Header, jwk::Jwk};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: Option<String>,
    aud: String,
    iat: u64,
    exp: u64,
    nonce: Option<String>, // TODO: maybe the more secure Nonce type from openidconnect?
}

pub struct JwtProof {
    issuer_id: Option<String>,
    encoding_key: EncodingKey,
    x509_cert_chain: Vec<String>,
}

impl JwtProof {
    pub fn new(key_material: &str, x509_cert: &str, issuer_id: &str) -> Self {
        let encoding_key =
            EncodingKey::from_ec_pem(key_material.as_bytes()).expect("Key creation failed");

        // Remove PEM headers and footers and join the lines
        let x509_cert = x509_cert
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<&str>>()
            .join("");

        Self {
            issuer_id: Some(issuer_id.to_string()),
            encoding_key,
            x509_cert_chain: vec![x509_cert.to_string()],
        }
    }

    pub fn create_jwt(&self, audience: &str, issued_at: u64, nonce: &str) -> String {
        let claims = Claims {
            iss: self.issuer_id.clone(),
            aud: audience.to_string(),
            iat: issued_at,
            exp: issued_at + 3600,
            nonce: Some(nonce.to_string()),
        };

        // We are using ECDSA with SHA-256, because this seems the only one that is supported by
        // the sphereon agent API.
        let jwk_alg = jwk::Algorithm::ES256;
        let jwt_alg = jwt::Algorithm::ES256; // Somehow the From trait is not implemented for this
                                             // eventhough we have the jwt-convert feature enabled

        let mut json_web_key = JsonWebKey::new(Key::generate_p256());
        json_web_key.set_algorithm(jwk_alg).expect("Algorithm setting failed");
        let as_json = serde_json::to_string(&json_web_key).expect("JSON conversion failed");
        let as_key: Jwk = serde_json::from_str(&as_json).expect("JSON conversion failed");

        let header = Header {
            alg: jwt_alg,
            typ: Some("openid4vci-proof+jwt".to_string()),
            x5c: Some(self.x509_cert_chain.clone()),
            jwk: Some(as_key),
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
    use jsonwebtoken::{decode, DecodingKey, Validation};

    use super::*;

    const RAW_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYNSe/XuijHxl6oUt\nivHHsZc/I5RSUKFuD/VsWwp8syKhRANCAAS5Xk/90hQgfsqpHcQNCwkaLLW9LvRP\nDJGRWCzGfZJp88R12tD5t/PRqXeTwgp3FH4HCY3+i9GcPQm0/MLEVJPR\n-----END PRIVATE KEY-----";
    const RAW_X509: &str = "MIIB3jCCAYWgAwIBAgIUQcFG9LXWEbsv5Gh4ZMShzoTHTv0wCgYIKoZIzj0EAwIwRTELMAkGA1UE\nBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5\nIEx0ZDAeFw0yNTAzMTgxNjA3MDdaFw0yNjAzMTgxNjA3MDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYD\nVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAS5Xk/90hQgfsqpHcQNCwkaLLW9LvRPDJGRWCzGfZJp88R12tD5\nt/PRqXeTwgp3FH4HCY3+i9GcPQm0/MLEVJPRo1MwUTAdBgNVHQ4EFgQU2A0iSQzXy21s91l+SfAE\nLyIcspMwHwYDVR0jBBgwFoAU2A0iSQzXy21s91l+SfAELyIcspMwDwYDVR0TAQH/BAUwAwEB/zAK\nBggqhkjOPQQDAgNHADBEAiAgxsIWGtgmYy264YpST2J93GMB/loNGrV6xo+u7D3nSwIgWt2BJ+9D\ngKp4a9xtoCbn2tmkRGFyjpfgrSYALdGRk88=";
    const RAW_PUB: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuV5P/dIUIH7KqR3EDQsJGiy1vS70\nTwyRkVgsxn2SafPEddrQ+bfz0al3k8IKdxR+BwmN/ovRnD0JtPzCxFST0Q==\n-----END PUBLIC KEY-----";

    #[test]
    fn test_jwt_setup() {
        let issuer_id = "issuer123";

        let jwt_proof = JwtProof::new(RAW_PEM, RAW_X509, issuer_id);
        assert_eq!(jwt_proof.issuer_id, Some(issuer_id.to_string()));
    }

    #[test]
    fn test_jwt_creation() {
        let issuer_id = "issuer123";
        let audience = "audience123";
        let issued_at = current_timestamp();
        let nonce = "nonce123";

        let jwt_proof = JwtProof::new(RAW_PEM, RAW_X509, issuer_id);
        let jwt = jwt_proof.create_jwt(audience, issued_at, nonce);

        assert!(!jwt.is_empty());
    }

    #[test]
    fn test_decode_jwt() {
        let issuer_id = "issuer123";
        let audience = "audience123";
        let issued_at = current_timestamp();
        let nonce = "nonce123";
        let jwt_proof = JwtProof::new(RAW_PEM, RAW_X509, issuer_id);
        let jwt = jwt_proof.create_jwt(audience, issued_at, nonce);

        let key = DecodingKey::from_ec_pem(RAW_PUB.as_bytes()).expect("Key creation failed");
        let mut validation = Validation::new(jwt::Algorithm::ES256);
        validation.set_audience(&[audience]);
        let token_message = decode::<Claims>(&jwt, &key, &validation).expect("Decoding failed");

        assert_eq!(token_message.header.alg, jwt::Algorithm::ES256);
        // Sphereon expects this .alg to be set.
        assert_eq!(
            token_message.header.jwk.unwrap().common.key_algorithm,
            Some(jwt::jwk::KeyAlgorithm::ES256)
        );

        assert_eq!(token_message.claims.aud, audience);
        assert_eq!(token_message.claims.iss, Some(issuer_id.to_string()));
        assert_eq!(token_message.claims.iat, issued_at);
        assert_eq!(token_message.claims.nonce, Some(nonce.to_string()));
    }
}
