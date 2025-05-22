use crate::{
    offer::{CredentialOffer, CredentialOfferFlow, OpenIdCredentialOffer},
    output::{debug, info, sub_info, LogExpect},
};

pub fn handle_offer_command(offer: &str) -> CredentialOffer {
    debug("Processing offer", Some(&offer));
    let openid_url =
        OpenIdCredentialOffer::from_uri(&offer).log_expect("Invalid OpenID Credential Offer");

    openid_url
        .validate()
        .log_expect("Invalid OpenID Credential Offer");

    let offer: CredentialOffer;
    if openid_url.is_by_value() {
        info("Credential Offer Type", Some(&"By Value"));
        offer = openid_url
            .credential_offer()
            .log_expect("Invalid Credential Offer");
    } else {
        info("Credential Offer is by Reference", None::<&String>);
        todo!("Implement Normalizing the Credential Offer by fetching it");
    }

    let flow = openid_url
        .credential_flow()
        .log_expect("Invalid Credential Flow");

    info("Credential Offer Flow", Some(&flow));
    let grants = offer.clone().grants.log_expect("No grants found");
    match flow {
        CredentialOfferFlow::AuthorizationCodeFlow => {
            let state = &grants.authorization_code.unwrap().issuer_state.unwrap();
            sub_info("Authorization Code State", Some(&state), 2);
        }
        CredentialOfferFlow::PreAuthorizedCodeFlow => {
            let pre_authorized_code = &grants.pre_authorized_code.unwrap().pre_authorized_code;
            sub_info("Pre-authorized Code", Some(&pre_authorized_code), 2);
        }
    }

    debug("Credential Offer", Some(&offer));

    offer
}
