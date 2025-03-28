use jwt::JwtProof;
use openidconnect::AccessToken;
use url::Url;

use tokio;

mod cli;
mod credential;
mod jwt;
mod offer;
mod oidc;
mod redirect_server;
mod well_known;

use credential::{Credential, CredentialError, CredentialRequest};
use offer::{CredentialOffer, OpenIdCredentialOffer};
use oidc::do_the_dance;
use well_known::{get_from, CredentialIssuerMetadata};

#[tokio::main]
async fn main() {
    env_logger::init();
    // client_id and client_secret from ENV
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID ENV var not set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET ENV var not set");
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY ENV var not set");
    let x509_cert = std::env::var("X509_DER_CERT_BASE46").expect("X509_DER_CERT_BASE46 ENV var not set");

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

    // TODO: We should probably start a server on the redirect URL and capture the token there
    let redirect_url = Url::parse("http://localhost:8000").unwrap();
    let (access_token, nonce) = do_the_dance(
        first_authorization_server,
        redirect_url,
        client_id,
        Some(client_secret),
    )
    .await
    .expect("Could not authenticate and authorize user");

    log("Access Token", Some(&access_token.secret()));

    let configuration_id;
    if offer.credential_configuration_ids.len() == 1 {
        configuration_id = offer.credential_configuration_ids[0].clone();
    } else {
        todo!("Implement user selection of one of the credential_configuration_ids");
    }

    // build our proof
    let jwt_key = JwtProof::new(&private_key, &x509_cert, "cli-vc-wallet");
    let proof = jwt_key.create_jwt(
        &well_known.credential_issuer,
        jwt::current_timestamp(),
        nonce.secret(),
    );
    log("Proof", Some(&proof));
    let credential: Credential =
        fetch_credential(&access_token, &well_known, configuration_id, proof).await.unwrap();
    log("Credential", Some(&credential));
}

async fn fetch_credential(
    access_token: &AccessToken,
    well_known: &CredentialIssuerMetadata, // TODO: do we need the entire well_known here or just the credential_endpoint?
    configuration_id: String,
    proof: String,
) -> Result<Credential, CredentialError> {
    let credentialrequest = CredentialRequest::new(configuration_id, proof);

    let body =
        serde_json::to_string(&credentialrequest).expect("Could not serialize CredentialRequest");

    let client = reqwest::ClientBuilder::new()
        .connection_verbose(true)
        .build()
        .expect("Could not create client");

    let response = client
        .post(&well_known.credential_endpoint)
        .header("Authorization", format!("Bearer {}", access_token.secret()))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("Could not send request");

    log("Response", Some(&response));
    // TODO: Check the response status and return an error if it's not 200
    // TODO: Deserialize the response into a Credential
    Ok(Credential {})
}

// Helper function to log a message and an optional value
// value must implement Debug
fn log<T: std::fmt::Debug>(message: &str, value: Option<&T>) {
    match value {
        Some(value) => println!("{}\n\t {:?}", message, value),
        None => println!("{}", message),
    }
}
