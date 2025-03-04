use core::fmt;

use reqwest::blocking::Client;
use serde::Deserialize;
use url::Url;

pub fn get_from(base_url: String) -> Result<CredentialIssuerMetadata, FetchError> {
    let client = Client::new();
    let well_known_url = format!("{}/.well-known/openid-credential-issuer", base_url);
    let response = client.get(well_known_url).send()?;
    Ok(serde_json::from_str(&response.text()?)?)
}

#[derive(Debug)]
pub struct FetchError {
    message: String,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<reqwest::Error> for FetchError {
    fn from(error: reqwest::Error) -> Self {
        FetchError {
            message: format!("Failed to fetch the well-known configuration: {}", error),
        }
    }
}

impl From<serde_json::Error> for FetchError {
    fn from(error: serde_json::Error) -> Self {
        FetchError {
            message: format!("Failed to parse the well-known configuration: {}", error),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub authorization_servers: Option<Vec<String>>,
}

impl CredentialIssuerMetadata {
    pub(crate) fn first_authorization_server(&self) -> Option<Url> {
        let first = self.authorization_servers.as_ref()?.first()?;

        Url::parse(first).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialIssuerMetadata;
    use url::Url;

    #[test]
    fn test_deserialize_well_known() {
        let well_known_content = r##"{
  "credential_issuer": "https://impala-bright-grub.ngrok-free.app/oid4vci",
  "credential_endpoint": "https://impala-bright-grub.ngrok-free.app/oid4vci/credentials",
  "authorization_servers": [
    "https://dev-osum556uqkceigfq.us.auth0.com"
  ],
  "client_name": "Example",
  "client_uri": "https://findynet.fi",
  "logo_uri": "https://findynet.fi/wp-content/uploads/2024/02/findynet-logo.png",
  "tos_uri": "https://sphereon.com/sphereon-wallet-terms-and-conditions",
  "policy_uri": "https://sphereon.com/sphereon-wallet-privacy-policy",
  "contacts": [
    "dev@sphereon.com",
    "support@sphereon.com"
  ],
  "display": [],
  "credential_configurations_supported": {},
  "credential_supplier_config": {}
}"##;

        let parsed: CredentialIssuerMetadata = serde_json::from_str(well_known_content).unwrap();
        assert!(parsed.authorization_servers.is_some());
        assert_eq!(
            parsed.first_authorization_server(),
            Url::parse("https://dev-osum556uqkceigfq.us.auth0.com").ok()
        );
    }
}
