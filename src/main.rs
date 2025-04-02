use jwt::JwtProof;
use url::Url;

use tokio;

mod credential;
mod jwt;
mod offer;
mod oidc;
mod redirect_server;
mod well_known;

use credential::CredentialRequest;
use offer::{CredentialOffer, OpenIdCredentialOffer};
use oidc::do_the_dance;
use well_known::get_from;

#[tokio::main]
async fn main() {
    env_logger::init();
    // client_id and client_secret from ENV
    // TODO: Normally wallets don't have client_id and client_secret, but we need it for the OIDC
    // dance in its current form, since our oidc server in current config requires both. We must
    // implement dynamic client registration to get rid of this.
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID ENV var not set");
    // Set optional client_secret from ENV
    let client_secret = std::env::var("OIDC_CLIENT_SECRET").map_or(None, |s| Some(s.to_string()));

    let pop_keypair = std::env::var("KEYPAIR").expect("KEYPAIR ENV var not set");
    let pop_did = std::env::var("DID").expect("DID ENV var not set");

    // Read the offer from STDIN
    let mut offer_input = String::new();
    std::io::stdin()
        .read_line(&mut offer_input)
        .expect("Could not read line");
    let offer_input = offer_input.trim().to_string();
    if offer_input.is_empty() {
        eprintln!("Expected input from STDIN, but got an empty string.");
        return;
    }
    log("Input", Some(&offer_input));

    let uri = Url::parse(&offer_input).expect("Could not parse URL");
    let query = uri.query().expect("No query parameters in offer URI");
    let openid_url: OpenIdCredentialOffer =
        serde_qs::from_str(&query).expect("Invalid OpenID Credential Offer");

    openid_url
        .validate()
        .expect("Invalid OpenID Credential Offer");

    let offer: CredentialOffer;
    if openid_url.is_by_value() {
        log("Credential Offer by Value", None::<&String>);
        offer = openid_url
            .credential_offer()
            .expect("Invalid Credential Offer");
    } else {
        log("Credential Offer by Reference", None::<&String>);
        todo!("Implement Fetching the Credential Offer");
    }
    log("Credential Offer", Some(&offer));

    log(
        "Getting Server Metadata for issuer",
        Some(&offer.credential_issuer),
    );
    let well_known = get_from(offer.credential_issuer).await.unwrap();
    let first_authorization_server = well_known
        .first_authorization_server()
        .expect("No Authorization Servers found");

    log(
        "First Authorization Server",
        Some(&first_authorization_server.to_string()),
    );

    let redirect_url = Url::parse("http://localhost:8000").unwrap();
    let (access_token, _nonce) = do_the_dance(
        first_authorization_server,
        redirect_url,
        client_id,
        client_secret,
    )
    .await
    .expect("Could not authenticate and authorize user");

    log("Access Token", Some(&access_token.secret()));

    let configuration_id;
    // TODO: Implement user selection of one of the credential_configuration_ids
    // As per design principles of this tool, we should not be making any decisions on behalf of
    // the user.
    if offer.credential_configuration_ids.len() == 1 {
        configuration_id = offer.credential_configuration_ids[0].clone();
    } else {
        todo!("Implement user selection of one of the credential_configuration_ids");
    }

    // build our proof
    let jwt_key = JwtProof::new(&pop_keypair, &pop_did);
    let proof = jwt_key.create_jwt(
        &well_known.credential_issuer,
        jwt::current_timestamp(),
        None,
    );
    log("Proof", Some(&proof));
    let credential_endpoint = Url::parse(&well_known.credential_endpoint).unwrap();
    let credential_request = CredentialRequest::new(
        credential_endpoint,
        configuration_id,
        proof,
        Some("auth-1337".to_string()),
        Some(access_token),
    );

    let credential_response = credential_request.execute().await.unwrap();
    log("Credential Response", Some(&credential_response));
    if let Some(credentials) = credential_response.credentials {
        credentials.iter().for_each(|credential| {
            log("Credential", Some(credential));
        });
    }
}

// Helper function to log a message and an optional value
// value must implement Debug
fn log<T: std::fmt::Debug>(message: &str, value: Option<&T>) {
    match value {
        Some(value) => println!("{}\n\t {:?}", message, value),
        None => println!("{}", message),
    }
}
