use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
    /// Whether the signature is present
    pub signature_present: bool,
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
    /// Failed to decode base64
    Base64DecodeError(String),
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
            VerificationError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
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

/// Verify a JWT credential
pub fn verify(credential: &str) -> Result<VerificationResult, VerificationError> {
    let parts: Vec<&str> = credential.split('.').collect();

    // Check JWT format
    let jwt_format_valid = parts.len() == 3;
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
                signature_present: false,
                has_verifiable_credential: false,
                has_issuer: false,
                has_subject: false,
                is_expired: Some(false),
                expires_at: None,
                issued_at: None,
            },
        });
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature = parts[2].to_string();

    // Decode header
    let header_decoded = URL_SAFE_NO_PAD.decode(header_b64).is_ok();
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| VerificationError::Base64DecodeError(format!("Header: {}", e)))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| VerificationError::JsonParseError(format!("Header: {}", e)))?;

    // Decode payload
    let payload_decoded = URL_SAFE_NO_PAD.decode(payload_b64).is_ok();
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| VerificationError::Base64DecodeError(format!("Payload: {}", e)))?;

    // Try to parse as CredentialPayload first to get structured data
    let credential_payload: Result<crate::credential::CredentialPayload, _> =
        serde_json::from_slice(&payload_bytes);

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerificationError::JsonParseError(format!("Payload: {}", e)))?;

    // Extract fields from payload
    let has_issuer = payload.get("iss").is_some();
    let has_subject = payload.get("sub").is_some();
    let has_verifiable_credential = payload.get("vc").is_some();

    let issuer = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subject = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let verifiable_credential = payload.get("vc").cloned().unwrap_or(Value::Null);

    // Check expiration
    let expires_at = payload.get("exp").and_then(|v| v.as_u64());
    let issued_at = payload.get("iat").and_then(|v| v.as_u64());

    // Check if expired (current timestamp vs exp)
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

    // If we have a CredentialPayload from parse, use that for issuer/subject
    let (issuer, subject, verifiable_credential) = if let Ok(cp) = credential_payload {
        (cp.iss, cp.sub, cp.vc)
    } else {
        (issuer, subject, verifiable_credential)
    };

    let valid = jwt_format_valid
        && header_decoded
        && payload_decoded
        && has_verifiable_credential
        && has_issuer
        && has_subject
        && !is_expired.unwrap_or(false);

    // Check if credential has expired
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
            header,
        },
        checks: VerificationChecks {
            jwt_format_valid,
            header_decoded,
            payload_decoded,
            signature_present: !signature.is_empty(),
            has_verifiable_credential,
            has_issuer,
            has_subject,
            is_expired,
            expires_at,
            issued_at,
        },
    })
}
