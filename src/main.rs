use oidc::do_the_dance;

mod offer;
mod oidc;
mod well_known;

use offer::{CredentialOffer, OpenIdCredentialOffer};
use url::Url;
use well_known::get_from;

fn main() {
    // client_id and client_secret from ENV
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID ENV var not set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET ENV var not set");

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

    let first_authorization_server = well_known
        .first_authorization_server()
        .expect("No Authorization Servers found");

    log(
        "First Authorization Server",
        Some(&first_authorization_server.to_string()),
    );

    // TODO: We should probably start a server on the redirect URL and capture the token there
    let access_token = do_the_dance(
        first_authorization_server,
        Url::parse("http://localhost:8000").unwrap(),
        client_id,
        Some(client_secret),
        prompt_code_url,
    ).expect("Could not authenticate and authorize user");

    log("Access Token", Some(&access_token.secret()));
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
