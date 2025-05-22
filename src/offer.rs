use std::fmt::Display;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Deserialize, Debug)]
pub struct OpenIdCredentialOffer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_offer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_offer_uri: Option<String>,
}

impl OpenIdCredentialOffer {
    pub fn validate(&self) -> Result<(), String> {
        if self.credential_offer.is_none() && self.credential_offer_uri.is_none() {
            return Err("Neither credential_offer nor credential_offer_uri is present".to_string());
        }
        if self.credential_offer.is_some() && self.credential_offer_uri.is_some() {
            return Err("Both credential_offer and credential_offer_uri are present".to_string());
        }
        Ok(())
    }

    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let url = Url::parse(uri).map_err(|e| format!("Could not parse URL: {}", e))?;
        let query = url
            .query()
            .ok_or_else(|| "No query parameters in offer URI".to_string())?;
        serde_qs::from_str(query).map_err(|e| format!("Invalid OpenID Credential Offer: {}", e))
    }

    pub fn credential_flow(&self) -> Result<CredentialOfferFlow, String> {
        let grants = self
            .credential_offer()
            .expect("TODO: can only work on by_value for now")
            .grants
            .expect("No grants present. TODO: fetch from issuer metadata instead");

        // TODO: If grants is not present or is empty, the Wallet MUST determine the Grant Types the
        // Credential Issuer's Authorization Server supports using the respective metadata. When multiple
        // grants are present, it is at the Wallet's discretion which one to use.
        if grants.pre_authorized_code.is_none() && grants.authorization_code.is_none() {
            return Err(
                "Neither pre_authorized_code nor authorization_code is present".to_string(),
            );
        }
        if grants.pre_authorized_code.is_some() && grants.authorization_code.is_some() {
            return Err("Both pre_authorized_code and authorization_code are present".to_string());
        }

        if let Some(_) = grants.pre_authorized_code {
            return Ok(CredentialOfferFlow::PreAuthorizedCodeFlow);
        } else if let Some(_) = grants.authorization_code {
            return Ok(CredentialOfferFlow::AuthorizationCodeFlow);
        } else {
            return Err("No valid grant type found".to_string());
        }
    }

    pub fn is_by_value(&self) -> bool {
        self.credential_offer.is_some()
    }

    pub fn credential_offer(&self) -> Result<CredentialOffer, serde_json::Error> {
        let offer = self.credential_offer.as_ref().expect("No credential offer");
        Ok(serde_json::from_str(&offer)?)
    }
}

#[derive(Debug, PartialEq)]
pub enum CredentialOfferFlow {
    PreAuthorizedCodeFlow,
    AuthorizationCodeFlow,
}

impl Display for CredentialOfferFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOfferFlow::PreAuthorizedCodeFlow => "Pre-authorized code flow".fmt(f),
            CredentialOfferFlow::AuthorizationCodeFlow => "Authorization code flow".fmt(f),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<Grants>,
}

impl CredentialOffer {
    pub fn get_issuer_state(&self) -> Option<String> {
        if let Some(grants) = &self.grants {
            if let Some(authorization_code) = &grants.authorization_code {
                return authorization_code.issuer_state.clone();
            }
        }
        None
    }
}

impl Display for CredentialOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialOffer {{ credential_issuer: {}, credential_configuration_ids: {:?} }}",
            self.credential_issuer, self.credential_configuration_ids
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Grants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,

    #[serde(rename = "authorization_code")]
    pub authorization_code: Option<AuthorizationCode>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    // TODO: string that the Wallet can use to identify the Authorization Server to use with this
    // grant type when authorization_servers parameter in the Credential Issuer metadata has
    // multiple entries. It MUST NOT be used otherwise. The value of this parameter MUST match with
    // one of the values in the authorization_servers array obtained from the Credential Issuer
    // metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
    // TODO: string that the Wallet can use to identify the Authorization Server to use with this
    // grant type when authorization_servers parameter in the Credential Issuer metadata has
    // multiple entries. It MUST NOT be used otherwise. The value of this parameter MUST match with
    // one of the values in the authorization_servers array obtained from the Credential Issuer
    // metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Url;

    #[test]
    fn deserialize_co_by_value() {
        let offer = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credential_configuration_ids%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D";
        let url = Url::parse(offer).expect("Could not parse URL");
        let query = url.query().expect("No query parameters in offer URI");

        let openid_credential_offer: OpenIdCredentialOffer =
            serde_qs::from_str(query).expect("Could not deserialize query parameters");

        assert!(openid_credential_offer.validate().is_ok());

        let credential_offer: CredentialOffer = serde_json::from_str(
            &openid_credential_offer
                .credential_offer
                .expect("No credential offer"),
        )
        .expect("Could not deserialize credential offer");

        assert_eq!(
            credential_offer.credential_issuer,
            "https://credential-issuer.example.com"
        );
    }

    #[test]
    fn deserialize_co_uri_test() {
        let offer = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver%2Eexample%2Ecom%2Fcredential-offer%2FGkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";
        let url = Url::parse(offer).expect("Could not parse URL");
        let query = url.query().expect("No query parameters in offer URI");

        let openid_credential_offer: OpenIdCredentialOffer =
            serde_qs::from_str(query).expect("Could not deserialize query parameters");

        assert!(openid_credential_offer.validate().is_ok());
        assert_eq!(openid_credential_offer.credential_offer_uri.expect("No credential offer"), "https://server.example.com/credential-offer/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM");
    }

    #[test]
    fn deserialize_co_ref_and_value() {
        let offer = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver%2Eexample%2Ecom%2Fcredential-offer%2FGkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM&credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credential_configuration_ids%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D";
        let url = Url::parse(offer).expect("Could not parse URL");
        let query = url.query().expect("No query parameters in offer URI");

        let openid_credential_offer: OpenIdCredentialOffer =
            serde_qs::from_str(query).expect("Could not deserialize query parameters");

        assert_eq!(
            openid_credential_offer.validate(),
            Err("Both credential_offer and credential_offer_uri are present".to_string())
        );
    }

    #[test]
    fn deserialize_co_authn_type() {
        let offer = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credential_configuration_ids%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D";
        let url = Url::parse(offer).expect("Could not parse URL");
        let query = url.query().expect("No query parameters in offer URI");
        let openid_credential_offer: OpenIdCredentialOffer =
            serde_qs::from_str(query).expect("Could not deserialize query parameters");

        assert_eq!(
            openid_credential_offer.credential_flow().unwrap(),
            CredentialOfferFlow::PreAuthorizedCodeFlow
        );
    }
}
