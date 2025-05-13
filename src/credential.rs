use core::fmt;
use openidconnect::AccessToken;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::http_client::http_client;

#[derive(Deserialize, Debug)]
pub struct CredentialResponse {
    pub credentials: Option<Vec<String>>,
}

// Should adhere to the following spec:
// Verifiable Credentials Data Model v2.0 https://w3c.github.io/vc-data-model/#data-schemas
// TODO: We get this as JWT, so we need to decode that first then parse the JSON of the payload
// into this struct.
// #[derive(Deserialize, Debug)]
// pub struct VerifiableCredential {
//     // #[serde(rename = "@context")]
//     // context: Vec<String>, // Do we need this?
//     pub id: Option<String>,
//     #[serde(rename = "type")]
//     pub credential_type: Value, // use serde_json::Value;
//     pub name: Option<String>,
//     pub description: Option<String>,
//     pub issuer: Value,
//
//     #[serde(rename = "credentialSubject")]
//     pub credential_subject: Value,
// }
// Could be used with e.g.
// println!("Credential");
// println!("\ttype:        {}", &credential.credential_type);
// println!("\tid:          {}", &credential.id.as_ref().unwrap_or(&"No ID".to_string()));
// println!("\tname:        {}", &credential.name.as_ref().unwrap_or(&"No Name".to_string()));
// println!("\tdescription: {}", &credential.description.as_ref().unwrap_or(&"No Description".to_string()));
// println!("\tissuer:      {}", &credential.issuer);
// println!("\tsubject:     {}", &credential.credential_subject);

// TODO: implement all of credential error responses as defined in:
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
//
// TODO: implement "proofs" and "credential_response_encryption"
// TODO: decide on credential_identifier if we can get this from the token endpoint
// TODO: implement "credential_request_encryption"
#[derive(Serialize, Debug)]
pub struct CredentialRequest {
    credential_endpoint: Url,
    format: String,
    credential_configuration_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_state: Option<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<AccessToken>,

    #[serde(skip)]
    client: reqwest::Client,
}

impl CredentialRequest {
    pub fn new(
        credential_endpoint: Url,
        credential_configuration_id: String,
        jwt_proof: String,
        issuer_state: Option<String>,
        access_token: Option<AccessToken>,
    ) -> Self {
        let proof = Some(Proof {
            proof_type: "jwt".to_string(),
            jwt: Some(jwt_proof),
        });

        let client = http_client().expect("Could not create HTTP client");

        Self {
            credential_endpoint,
            format: "jwt_vc_json".to_string(),
            credential_configuration_id: credential_configuration_id.clone(),
            proof,
            issuer_state,
            credential_type: vec![
                "VerifiableCredential".to_string(),
                credential_configuration_id,
            ],
            access_token,
            client,
        }
    }

    pub async fn execute(&self) -> Result<CredentialResponse, CredentialError> {
        let body = serde_json::to_string(&self).expect("Could not serialize CredentialRequest");

        let mut req = self
            .client
            .post(self.credential_endpoint.clone())
            .header("Content-Type", "application/json")
            .body(body);

        if let Some(access_token) = &self.access_token {
            req = req.bearer_auth(access_token.secret());
        }

        let response = req.send().await.expect("Could not send request");
        if !response.status().is_success() {
            return Err(CredentialError {
                message: format!("Request failed with status: {}", response.status()),
            });
        }
        // TODO: Warn if the response status is not 202:
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
        // > The HTTP status code MUST be 202 (see Section 15.3.3 of [RFC9110])

        // TODO: Check if the response is application/json and return error if not:
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3-5
        // > If the Credential Response is not encrypted, the media type of the response MUST be set to application/json.

        self.handle_response(response).await
    }

    pub async fn handle_response(
        &self,
        response: reqwest::Response,
    ) -> Result<CredentialResponse, CredentialError> {
        let body = response.text().await.expect("Could not read response body");
        let credential = serde_json::from_str(&body)?;

        Ok(credential)
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

impl From<serde_json::Error> for CredentialError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            message: format!("Could not deserialize response: {}", error),
        }
    }
}
