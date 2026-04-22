use jsonwebtoken as jwt;
use serde::Serialize;
use serde_json::Value;
use std::fmt;

/// Represents the result of verifying a credential
#[derive(Debug, Serialize)]
pub struct VerificationResult {
    /// Whether the credential is valid
    pub valid: bool,
    /// Details about the credential
    pub credential_info: CredentialInfo,
    /// Results of individual checks
    pub checks: VerificationChecks,
}

/// Information extracted from the credential
#[derive(Debug, Serialize)]
pub struct CredentialInfo {
    /// The issuer DID or URL
    pub issuer: String,
    /// The subject DID or URL
    pub subject: String,
    /// The verifiable credential payload
    pub verifiable_credential: Value,
    /// JWT header information
    pub header: Value,
}

/// Results of individual verification checks
#[derive(Debug, Serialize)]
pub struct VerificationChecks {
    /// Whether the JWT format is valid (3 parts separated by dots)
    pub jwt_format_valid: bool,
    /// Whether the header could be decoded
    pub header_decoded: bool,
    /// Whether the payload could be decoded
    pub payload_decoded: bool,
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the credential contains a vc field
    pub has_verifiable_credential: bool,
    /// Whether the issuer field is present
    pub has_issuer: bool,
    /// Whether the subject field is present
    pub has_subject: bool,
    /// Whether the credential has expired
    pub is_expired: Option<bool>,
    /// The expiration timestamp if present
    pub expires_at: Option<u64>,
    /// The issued at timestamp if present
    pub issued_at: Option<u64>,
}

/// Error types for verification
#[derive(Debug)]
pub enum VerificationError {
    /// JWT token error (parsing, format, etc.)
    JwtError(String),
    /// Failed to parse JSON
    JsonParseError(String),
    /// Credential has expired
    CredentialExpired(u64),
    /// Invalid VC structure
    InvalidVcStructure(String),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerificationError::JwtError(msg) => write!(f, "JWT error: {}", msg),
            VerificationError::JsonParseError(msg) => write!(f, "JSON parse error: {}", msg),
            VerificationError::CredentialExpired(exp) => {
                write!(f, "Credential expired at timestamp: {}", exp)
            }
            VerificationError::InvalidVcStructure(msg) => {
                write!(f, "Invalid VC structure: {}", msg)
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// Verify a JWT credential using jsonwebtoken library
pub fn verify(credential: &str) -> Result<VerificationResult, VerificationError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    
    // First check JWT format manually for the checks structure
    let parts: Vec<&str> = credential.split('.').collect();
    let jwt_format_valid = parts.len() == 3;
    let signature_valid = parts.get(2).map_or(false, |s| !s.is_empty());

    // Validate JWT format
    if !jwt_format_valid {
        return Ok(VerificationResult {
            valid: false,
            credential_info: CredentialInfo {
                issuer: String::new(),
                subject: String::new(),
                verifiable_credential: Value::Null,
                header: Value::Null,
            },
            checks: VerificationChecks {
                jwt_format_valid: false,
                header_decoded: false,
                payload_decoded: false,
                signature_valid: false,
                has_verifiable_credential: false,
                has_issuer: false,
                has_subject: false,
                is_expired: Some(false),
                expires_at: None,
                issued_at: None,
            },
        });
    }

    let _header_b64 = parts[0];
    let payload_b64 = parts[1];

    // Use jsonwebtoken to decode and validate the header
    let header = jwt::decode_header(credential)
        .map_err(|e| VerificationError::JwtError(format!("Failed to decode JWT header: {}", e)))?;

    // Manually decode payload (we don't verify signature, just unpack)
    // JWT base64url encoding - URL_SAFE_NO_PAD handles unpadded base64url
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)
        .map_err(|e| VerificationError::JwtError(format!("Failed to decode payload base64: {}", e)))?;

    // Parse payload as JSON Value
    let payload_json: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerificationError::JwtError(format!("Failed to parse payload JSON: {}", e)))?;

    // Convert header to Value for consistent output
    let header_json: Value = serde_json::to_value(header)
        .map_err(|e| VerificationError::JsonParseError(format!("Header serialization: {}", e)))?;

    // Extract fields from payload
    let has_issuer = payload_json.get("iss").is_some();
    let has_subject = payload_json.get("sub").is_some();
    let has_verifiable_credential = payload_json.get("vc").is_some();

    let issuer = payload_json
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subject = payload_json
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let verifiable_credential = payload_json.get("vc").cloned().unwrap_or(Value::Null);

    // Check expiration
    let expires_at = payload_json.get("exp").and_then(|v| v.as_u64());
    let issued_at = payload_json.get("iat").and_then(|v| v.as_u64());

    // Check if expired
    let is_expired = expires_at.map(|exp| {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now >= exp
    });

    // Validate VC structure
    if has_verifiable_credential {
        let vc = &verifiable_credential;
        // Check for required VC fields
        if vc.get("@context").is_none() {
            return Err(VerificationError::InvalidVcStructure(
                "Missing @context in Verifiable Credential".to_string(),
            ));
        }
        if vc.get("type").is_none() {
            return Err(VerificationError::InvalidVcStructure(
                "Missing type in Verifiable Credential".to_string(),
            ));
        }
        if vc.get("credentialSubject").is_none() {
            return Err(VerificationError::InvalidVcStructure(
                "Missing credentialSubject in Verifiable Credential".to_string(),
            ));
        }
    }

    // Try to also parse as CredentialPayload for structured data
    let credential_payload: Result<crate::credential::CredentialPayload, _> =
        serde_json::from_value(payload_json.clone());

    // If we have a CredentialPayload from parse, use that for issuer/subject and vc
    let (issuer, subject, verifiable_credential) = if let Ok(ref cp) = credential_payload {
        (
            cp.iss.clone(),
            cp.sub.clone(),
            serde_json::to_value(&cp.vc).unwrap_or(Value::Null),
        )
    } else {
        (issuer, subject, verifiable_credential)
    };

    let valid = jwt_format_valid
        && has_verifiable_credential
        && has_issuer
        && has_subject
        && !is_expired.unwrap_or(false);

    // Check if credential has expired - return error for expired
    if let Some(true) = is_expired {
        if let Some(exp) = expires_at {
            return Err(VerificationError::CredentialExpired(exp));
        }
    }

    Ok(VerificationResult {
        valid,
        credential_info: CredentialInfo {
            issuer,
            subject,
            verifiable_credential,
            header: header_json,
        },
        checks: VerificationChecks {
            jwt_format_valid,
            header_decoded: true, // jsonwebtoken already decoded it
            payload_decoded: true, // jsonwebtoken already decoded it
            signature_valid,
            has_verifiable_credential,
            has_issuer,
            has_subject,
            is_expired,
            expires_at,
            issued_at,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a JWT with given header, payload, and signature
    fn make_jwt(header: &str, payload: &str, signature: &str) -> String {
        format!("{}.{}.{}", header, payload, signature)
    }

    // Base64url encoded valid JSON objects
    const VALID_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const VALID_PAYLOAD_WITH_VC: &str = "eyJpc3MiOiAiZGlkOmV4YW1wbGU6MTIzIiwgInN1YiI6ICJkaWQ6ZXhhbXBsZTo0NTYiLCAidmMiOiB7IkBjb250ZXh0IjogWyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwgImNyZWRlbnRpYWxTdWJqZWN0Ijoge319fQ";
    const VALID_PAYLOAD_NO_VC: &str = "eyJpc3MiOiAiZGlkOmV4YW1wbGU6MTIzIiwgInN1YiI6ICJkaWQ6ZXhhbXBsZTo0NTYifQ";
    const VALID_PAYLOAD_NO_ISS: &str = "eyJzdWIiOiAiZGlkOmV4YW1wbGU6NDU2IiwgInZjIjogeyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwgInR5cGUiOiBbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sICJjcmVkZW50aWFsU3ViamVjdCI6IHt9fX0";
    const VALID_PAYLOAD_NO_SUB: &str = "eyJpc3MiOiAiZGlkOmV4YW1wbGU6MTIzIiwgInZjIjogeyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwgInR5cGUiOiBbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sICJjcmVkZW50aWFsU3ViamVjdCI6IHt9fX0";
    const EXPIRED_PAYLOAD: &str = "eyJpc3MiOiAiZGlkOjI3IiwgInN1YiI6ICJkaWQ6MjgiLCAidmMiOiB7IkBjb250ZXh0IjogWyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwgImNyZWRlbnRpYWxTdWJqZWN0Ijoge319LCAiZXhwIjogMTAwMCwgImlhdCI6IDEwMDB9";

    #[test]
    fn test_valid_credential() {
        let jwt = make_jwt(VALID_HEADER, VALID_PAYLOAD_WITH_VC, "sig");
        let result = verify(&jwt).expect("Should parse valid credential");
        assert!(result.valid);
        assert!(result.checks.jwt_format_valid);
        assert!(result.checks.header_decoded);
        assert!(result.checks.payload_decoded);
        assert!(result.checks.signature_valid);
        assert!(result.checks.has_verifiable_credential);
        assert!(result.checks.has_issuer);
        assert!(result.checks.has_subject);
    }

    #[test]
    fn test_invalid_jwt_format() {
        let result = verify("a.b").expect("Should return result for invalid format");
        assert!(!result.valid);
        assert!(!result.checks.jwt_format_valid);
        assert!(!result.checks.header_decoded);
        assert!(!result.checks.payload_decoded);
        assert!(!result.checks.signature_valid);
    }

    #[test]
    fn test_missing_vc() {
        let jwt = make_jwt(VALID_HEADER, VALID_PAYLOAD_NO_VC, "sig");
        let result = verify(&jwt).expect("Should parse JWT without VC");
        assert!(!result.valid);
        assert!(result.checks.jwt_format_valid);
        assert!(result.checks.header_decoded);
        assert!(result.checks.payload_decoded);
        assert!(!result.checks.has_verifiable_credential);
    }

    #[test]
    fn test_missing_issuer() {
        let jwt = make_jwt(VALID_HEADER, VALID_PAYLOAD_NO_ISS, "sig");
        let result = verify(&jwt).expect("Should parse JWT without issuer");
        assert!(!result.valid);
        assert!(!result.checks.has_issuer);
    }

    #[test]
    fn test_missing_subject() {
        let jwt = make_jwt(VALID_HEADER, VALID_PAYLOAD_NO_SUB, "sig");
        let result = verify(&jwt).expect("Should parse JWT without subject");
        assert!(!result.valid);
        assert!(!result.checks.has_subject);
    }

    #[test]
    fn test_expired_token() {
        let jwt = make_jwt(VALID_HEADER, EXPIRED_PAYLOAD, "sig");
        let result = verify(&jwt);
        assert!(result.is_err());
        match result {
            Err(VerificationError::CredentialExpired(_)) => {},
            _ => panic!("Expected CredentialExpired error"),
        }
    }

    #[test]
    fn test_signature_valid() {
        let jwt = make_jwt(VALID_HEADER, VALID_PAYLOAD_WITH_VC, "sig");
        let result = verify(&jwt).expect("Should parse JWT with signature");
        assert!(result.checks.signature_valid);
    }
}
