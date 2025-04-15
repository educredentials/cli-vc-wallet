use clap::Parser;
use cli::{Cli, Commands};
use jwt::JwtProof;
use openidconnect::AccessToken;
use output::{debug, info, stdout, LogExpect};
use url::Url;

use tokio;

mod cli;
mod credential;
mod http_client;
mod jwt;
mod offer;
mod oidc;
mod output;
mod redirect_server;
mod well_known;

use credential::CredentialRequest;
use offer::{CredentialOffer, OpenIdCredentialOffer};
use oidc::do_the_dance;
use well_known::get_from;

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let t = Some("test");
    t.log_expect("test");

    match &cli.command {
        Commands::Offer { offer } => {
            debug("Processing offer", Some(&offer));
            let uri = Url::parse(&offer).log_expect("Could not parse URL");
            let query = uri.query().log_expect("No query parameters in offer URI");
            let openid_url: OpenIdCredentialOffer =
                serde_qs::from_str(&query).log_expect("Invalid OpenID Credential Offer");

            openid_url
                .validate()
                .log_expect("Invalid OpenID Credential Offer");

            let offer: CredentialOffer;
            if openid_url.is_by_value() {
                info("Credential Offer is by Value", None::<&String>);
                offer = openid_url
                    .credential_offer()
                    .log_expect("Invalid Credential Offer");
            } else {
                info("Credential Offer is by Reference", None::<&String>);
                todo!("Implement Normalizing the Credential Offer by fetching it");
            }

            debug("Credential Offer", Some(&offer));
            stdout(&offer);
        }
        Commands::Authorize {
            url,
            client_id,
            client_secret,
            redirect_url,
        } => {
            info("Starting Authorization Flow", Some(&url));
            // TODO: Normally wallets don't have client_id and client_secret, but we need it for the OIDC
            // dance in its current form, since our oidc server in current config requires both. We must
            // implement dynamic client registration to get rid of this.
            let url = Url::parse(url).log_expect("Invalid URL");
            debug("Authorization URL", Some(&url));

            let redirect_url = redirect_url
                .as_ref()
                .map_or("http://localhost:8080/", |r| r.as_str());

            let redirect_url = Url::parse(&redirect_url).unwrap();
            debug("Redirect URL", Some(&redirect_url));

            let (access_token, _nonce) =
                do_the_dance(url, redirect_url, client_id, client_secret.as_ref())
                    .await
                    .log_expect("Could not authenticate and authorize user");

            debug("Access Token", Some(&access_token.secret()));
        }
        Commands::Issuer { url } => {
            info("Getting Server Metadata for issuer", Some(&url));
            let well_known = get_from(url).await.unwrap();
            debug("Credential Issuer Metadata", Some(&well_known));
            let first_authorization_server = well_known
                .first_authorization_server()
                .log_expect("No Authorization Servers found");

            info(
                "First Authorization Server",
                Some(&first_authorization_server.to_string()),
            );
            stdout(&well_known);
        }
        Commands::Request {
            configuration_id,
            credential_issuer,
            credential_endpoint,
            access_token,
            proof_type: _,
            algorithm: _,
        } => {
            let pop_keypair = std::env::var("KEYPAIR").log_expect("KEYPAIR ENV var not set");
            let pop_did = std::env::var("DID").log_expect("DID ENV var not set");

            // build our proof
            let jwt_key = JwtProof::new(&pop_keypair, &pop_did);
            let proof = jwt_key.create_jwt(&credential_issuer, jwt::current_timestamp(), None);
            info("Offering proof", Some(&proof));
            let credential_endpoint = Url::parse(&credential_endpoint).unwrap();
            let access_token = AccessToken::new(access_token.to_string());

            let credential_request = CredentialRequest::new(
                credential_endpoint,
                configuration_id.to_string(),
                proof,
                Some("auth-1337".to_string()),
                Some(access_token),
            );

            let credential_response = credential_request.execute().await.unwrap();
            debug("Credential Response", Some(&credential_response));
            if let Some(credentials) = credential_response.credentials {
                credentials.iter().for_each(|credential| {
                    info("Credential", Some(credential));
                });
            }
            // TODO: Implement credential request
        }
        Commands::Verify { credential } => {
            println!("Verifying credential: {}", credential);
            // TODO: Implement verification
        }
    }
}
