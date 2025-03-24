use core::fmt;
use serde::Serialize;

#[derive(Debug)]
pub struct Credential {}

// TODO: implement "proofs" and "credential_response_encryption"
// TODO: decide on credential_identifier if we can get this from the token endpoint
#[derive(Serialize, Debug)]
pub struct CredentialRequest {
    format: String,
    credential_configuration_id: String,
    proof: Option<Proof>,
}

impl CredentialRequest {
    pub fn new(credential_configuration_id: String, jwt_proof: String) -> Self {
        let proof = Some(Proof {
            proof_type: "jwt".to_string(),
            jwt: Some(jwt_proof),
        });
        Self {
            format: "jwt_vc_json".to_string(),
            credential_configuration_id,
            proof,
        }
    }
}

// TODO: implement other proof types than jwt.
#[derive(Serialize, Debug)]
pub struct Proof {
    proof_type: String,
    jwt: Option<String>,
}

#[derive(Debug)]
pub struct CredentialError {
    message: String,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
