use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use core::fmt;
use openidconnect::AccessToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    #[serde(skip)]
    credential_endpoint: Url,

    format: String,
    credential_configuration_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_state: Option<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,

    #[serde(skip)]
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

pub struct JwtCredential {
    pub header: Value,
    pub payload: CredentialPayload,
    pub signature: String,
}

impl fmt::Display for JwtCredential {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "JwtCredential {{ header: {}, payload: {}, signature: {} }}",
            self.header, self.payload, self.signature
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialPayload {
    pub vc: serde_json::Value, // VerifiableCredential,
    pub iss: String,
    pub sub: String,
}

impl fmt::Display for CredentialPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CredentialPayload {{ vc: {}, iss: {}, sub: {} }}",
            self.vc, self.iss, self.sub
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    // pub issuer: String,
    pub issuer: Option<String>, // TODO: should no be optional. Why is it not in our example?
    pub credential_subject: Value,
    pub name: Option<String>,
    pub description: Option<String>,
}

impl fmt::Display for VerifiableCredential {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "VerifiableCredential {{ id: {:?}, credential_type: {:?}, issuer: {:?}, credential_subject: {:?}, name: {:?}, description: {:?} }}",
            self.id, self.credential_type, self.issuer, self.credential_subject, self.name, self.description
        )
    }
}

impl JwtCredential {
    pub fn new(header: Value, payload: CredentialPayload, signature: String) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }

    pub fn from_jwt(jwt: &str) -> Result<Self, CredentialError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(CredentialError {
                message: "Invalid JWT format".to_string(),
            });
        }

        let header = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| CredentialError {
                message: format!("Failed to decode header: {}", e),
            })?;
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| CredentialError {
                message: format!("Failed to decode payload: {}", e),
            })?;
        let signature = parts[2].to_string();

        let header_json: Value =
            serde_json::from_slice(&header).map_err(|e| CredentialError {
                message: format!("Failed to parse header JSON: {}", e),
            })?;

        let payload_json: CredentialPayload =
            serde_json::from_slice(&payload).map_err(|e| CredentialError {
                message: format!("Failed to parse payload JSON: {}", e),
            })?;

        Ok(Self::new(header_json, payload_json, signature))
    }
}

#[cfg(test)]
mod tests {
    // use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    // use jsonwebkey::Key;
    // use jsonwebtoken::Validation;

    use super::*;

    const CREDENTIAL: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvb2IvdjNwMC9jb250ZXh0LTMuMC4yLmpzb24iXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIk9wZW5CYWRnZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIk9wZW5CYWRnZUNyZWRlbnRpYWwiXSwiYWNoaWV2ZW1lbnQiOnsiaWQiOiJodHRwczovL2RlbW8uZWR1YmFkZ2VzLm5sL3B1YmxpYy9hc3NlcnRpb25zL1ZkZnZRdE9vUVJteHUxLXVDelBIc1EiLCJ0eXBlIjpbIkFjaGlldmVtZW50Il0sImNyaXRlcmlhIjp7Im5hcnJhdGl2ZSI6IlRlc3QgZGFuaWVsIG1pY3JvIn0sImRlc2NyaXB0aW9uIjoiVGVzdCBkYW5pZWwgbWljcm8iLCJuYW1lIjoiVGVzdCBkYW5pZWwgbWljcm8iLCJpbWFnZSI6eyJ0eXBlIjoiSW1hZ2UiLCJpZCI6Imh0dHBzOi8vYXBpLWRlbW8uZWR1YmFkZ2VzLm5sL21lZGlhL3VwbG9hZHMvYmFkZ2VzL2lzc3Vlcl9iYWRnZWNsYXNzXzI3OGRjYWM5LWJkMmQtNDgwZS1hMmYxLTdiZTk2NWE3ZDcxNC5wbmcifSwiaW5MYW5ndWFnZSI6ImVuX0VOIiwiRUNUUyI6NSwiZWR1Y2F0aW9uUHJvZ3JhbUlkZW50aWZpZXIiOiJbMTIzNDU2NzhdIiwicGFydGljaXBhdGlvblR5cGUiOiJwZXJzb25hbGl6ZWQifSwiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnE0NDNaNjkzV1ZrN3dkVWRhYUg5RmhDeXNidmZWYnJuNTRmWXQyanJBVmhqcnlyNDhBVGFOS3ZyejhobTRYQkIzdkdRVDZQRkNxb1ZuNG5aMzRwejdibXlVV05LNjNlbTZZVjVnMWozbkNoeldyNU5QcTZvc2NuS204dEdRSEdtNnQifX0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9vYi92M3AwL2NvbnRleHQtMy4wLjIuanNvbiJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6d2ViOmVkdWJhZGdlcy5wb2M0LmVkdXdhbGxldC5ubCIsIm5hbWUiOiJIYWlyZHJlc3NlcnMifSwibmFtZSI6IlRlc3QgZGFuaWVsIG1pY3JvIiwiZGVzY3JpcHRpb24iOiJUZXN0IGRhbmllbCBtaWNybyIsInZhbGlkRnJvbSI6IjIwMjQtMDQtMzBUMTM6MTk6MDEuMjExOTQ2WiIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDQtMzBUMTM6MTk6MDEuMjExOTQ2WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJPcGVuQmFkZ2VDcmVkZW50aWFsIl0sImFjaGlldmVtZW50Ijp7ImlkIjoiaHR0cHM6Ly9kZW1vLmVkdWJhZGdlcy5ubC9wdWJsaWMvYXNzZXJ0aW9ucy9WZGZ2UXRPb1FSbXh1MS11Q3pQSHNRIiwidHlwZSI6WyJBY2hpZXZlbWVudCJdLCJjcml0ZXJpYSI6eyJuYXJyYXRpdmUiOiJUZXN0IGRhbmllbCBtaWNybyJ9LCJkZXNjcmlwdGlvbiI6IlRlc3QgZGFuaWVsIG1pY3JvIiwibmFtZSI6IlRlc3QgZGFuaWVsIG1pY3JvIiwiaW1hZ2UiOnsidHlwZSI6IkltYWdlIiwiaWQiOiJodHRwczovL2FwaS1kZW1vLmVkdWJhZGdlcy5ubC9tZWRpYS91cGxvYWRzL2JhZGdlcy9pc3N1ZXJfYmFkZ2VjbGFzc18yNzhkY2FjOS1iZDJkLTQ4MGUtYTJmMS03YmU5NjVhN2Q3MTQucG5nIn0sImluTGFuZ3VhZ2UiOiJlbl9FTiIsIkVDVFMiOjUsImVkdWNhdGlvblByb2dyYW1JZGVudGlmaWVyIjoiWzEyMzQ1Njc4XSIsInBhcnRpY2lwYXRpb25UeXBlIjoicGVyc29uYWxpemVkIn0sImlkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxNDQzWjY5M1dWazd3ZFVkYWFIOUZoQ3lzYnZmVmJybjU0Zll0MmpyQVZoanJ5cjQ4QVRhTkt2cno4aG00WEJCM3ZHUVQ2UEZDcW9WbjRuWjM0cHo3Ym15VVdOSzYzZW02WVY1ZzFqM25DaHpXcjVOUHE2b3NjbkttOHRHUUhHbTZ0In0sInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticTQ0M1o2OTNXVms3d2RVZGFhSDlGaEN5c2J2ZlZicm41NGZZdDJqckFWaGpyeXI0OEFUYU5LdnJ6OGhtNFhCQjN2R1FUNlBGQ3FvVm40blozNHB6N2JteVVXTks2M2VtNllWNWcxajNuQ2h6V3I1TlBxNm9zY25LbTh0R1FIR202dCIsIm5iZiI6MTcxNDQ4MzE0MSwiaXNzIjoiZGlkOndlYjplZHViYWRnZXMucG9jNC5lZHV3YWxsZXQubmwifQ.SMX6vY7vipilUmVfryhwxc9flH3S8Z3Y0bg4VlYyZGTQepLAztNuXm3C0hnVsi4PcnbYySPmSDReGeGD8oN2Dw";

    // const JWK_KEYPAIR: &str = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"1m7_9vg6sb8kaAn5hYfwZPq82gWk1QqymOBc3vEqvKo\",\"y\":\"D2VCtPP4CaaNCwyUCFoS-QYfgkmoKEo_OS81RsftfW4\",\"d\":\"BSXpiHt48ZnlC_PYyJwBzYhEM2BUigW5smuO5sNK4sM\"}";

    #[test]
    fn header_test() {
        let result = JwtCredential::from_jwt(CREDENTIAL);
        assert!(result.is_ok(), "JWT parsing failed: {:?}", result.err());

        let header = result.unwrap().header;
        // assert_eq!(header.typ, Some("JWT".to_string()));
        // assert_eq!(header.alg, Algorithm::EdDSA); //Some("EdDSA".to_string()));
        // assert_eq!(header.jku, None);
        // assert_eq!(header.jwk, None);
        // assert_eq!(header.kid, None);
        dbg!(&header);
        assert_eq!(header["alg"], "EdDSA");
    }

    #[test]
    fn payload_test() {
        let result = JwtCredential::from_jwt(CREDENTIAL);
        assert!(result.is_ok(), "JWT parsing failed: {:?}", result.err());

        let payload = result.unwrap().payload;
        assert_eq!(payload.iss, "did:web:edubadges.poc4.eduwallet.nl");
        assert_eq!(payload.sub, "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbq443Z693WVk7wdUdaaH9FhCysbvfVbrn54fYt2jrAVhjryr48ATaNKvrz8hm4XBB3vGQT6PFCqoVn4nZ34pz7bmyUWNK63em6YV5g1j3nChzWr5NPq6oscnKm8tGQHGm6t");

        // assert_eq!(payload.vc.credential_type[0], "VerifiableCredential");
        // assert_eq!(payload.vc.credential_type[1], "OpenBadgeCredential");
        // assert_eq!(payload.vc.id, Some("https://demo.edubadges.nl/public/assets/credentials/2c4d1b8e-0a3f-4b5c-9f7d-6a2e0f3a5b7c.json".to_string()));
        dbg!(&payload.vc);
        assert_eq!(payload.vc["@context"][0], "https://www.w3.org/2018/credentials/v1 FAAL");
    }
}
