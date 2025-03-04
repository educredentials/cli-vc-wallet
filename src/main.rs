use jwt::JwtProof;
use url::Url;

mod credential;
mod jwt;
mod offer;
mod oidc;
mod well_known;

use credential::{Credential, CredentialError, CredentialRequest};
use offer::{CredentialOffer, OpenIdCredentialOffer};
use oidc::{do_the_dance, AccessToken};
use well_known::{get_from, CredentialIssuerMetadata};

fn main() {
    // client_id and client_secret from ENV
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID ENV var not set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET ENV var not set");
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY ENV var not set");

    // read offer from offer.txt
    let offer_input = std::fs::read_to_string("offer.txt")
        .expect("Could not read offer.txt")
        .trim()
        .to_string();
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
        "Getting well-known Configuration from ",
        Some(&offer.credential_issuer),
    );

    let well_known = get_from(offer.credential_issuer).unwrap();
    // TODO: Check that proof_types_supported contains "jwt" and that cryptographic_suites_supported
    // is one we support

    let first_authorization_server = well_known
        .first_authorization_server()
        .expect("No Authorization Servers found");

    log(
        "First Authorization Server",
        Some(&first_authorization_server.to_string()),
    );

    // TODO: We should probably start a server on the redirect URL and capture the token there
    let (access_token, nonce) = do_the_dance(
        first_authorization_server,
        Url::parse("http://localhost:8000").unwrap(),
        client_id,
        Some(client_secret),
        prompt_code_url,
    )
    .expect("Could not authenticate and authorize user");

    log("Access Token", Some(&access_token.secret()));

    let configuration_id;
    if offer.credential_configuration_ids.len() == 1 {
        configuration_id = offer.credential_configuration_ids[0].clone();
    } else {
        todo!("Implement user selection of one of the credential_configuration_ids");
    }

    // build our proof
    let jwt_key = JwtProof::new(&private_key, "cli-vc-wallet");
    let proof = jwt_key.create_jwt(
        &well_known.credential_issuer,
        jwt::current_timestamp(),
        nonce.secret(),
    );
    log("Proof", Some(&proof));
    let credential: Credential =
        fetch_credential(&access_token, &well_known, configuration_id, proof).unwrap();
    log("Credential", Some(&credential));
}

fn fetch_credential(
    access_token: &AccessToken,
    well_known: &CredentialIssuerMetadata, // TODO: do we need the entire well_known here or just the credential_endpoint?
    configuration_id: String,
    proof: String,
) -> Result<Credential, CredentialError> {
    let credentialrequest = CredentialRequest::new(configuration_id, proof);

    println!("POST {}", &well_known.credential_endpoint);
    println!("Authorization: Bearer {}", access_token.secret());
    println!("Credential Request: {:?}", credentialrequest);

    let body = serde_json::to_string(&credentialrequest).expect("Could not serialize CredentialRequest");

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(&well_known.credential_endpoint)
        .header("Authorization", format!("Bearer {}", access_token.secret()))
        .header("Content-Type", "application/json")
        .body(body).send().expect("Could not send request");

    dbg!(&response);
    // INK: stuck here, with the response being a 400 Bad Request
    // and the agent logging "sphereon-standalone-agent-full  | sendErrorResponse (400): {"error":"invalid_token"}
    dbg!(&response.text());
    Ok(Credential {})
}

fn prompt_code_url(message: String) -> String {
    println!("Open the following url in your browser: {}", message);

    let mut input = String::new();
    println!("Paste the full redirect URL here:");
    std::io::stdin()
        .read_line(&mut input)
        .expect("Could not read line");

    let redirect_url = Url::parse(&input).expect("Could not parse URL");
    let token = redirect_url.query_pairs().next().unwrap().1;

    println!("Received authorization code: {}", token);

    token.to_string()
}

// Helper function to log a message and an optional value
// value must implement Debug
fn log<T: std::fmt::Debug>(message: &str, value: Option<&T>) {
    match value {
        Some(value) => println!("{}\n\t {:?}", message, value),
        None => println!("{}", message),
    }
}
