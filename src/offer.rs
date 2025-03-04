use serde::Deserialize;

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

    pub fn is_by_value(&self) -> bool {
        self.credential_offer.is_some()
    }

    pub fn credential_offer(&self) -> Result<CredentialOffer, serde_json::Error> {
        let offer = self.credential_offer.as_ref().expect("No credential offer");
        Ok(serde_json::from_str(&offer)?)
    }
}

#[derive(Deserialize, Debug)]
pub struct CredentialOffer {
    pub credential_issuer: String,
}

#[cfg(test)]
mod tests {
    use crate::Url;
    use super::*;

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
}
