use clap::Parser;
use cli::{Cli, Commands};
use dialoguer::{Confirm, Input, Select};
use jwt::JwtProof;
use openidconnect::AccessToken;
use output::{debug, info, stdout, LogExpect};
use url::Url;

use tokio;

mod cli;
mod cli_flow;
mod credential;
mod http_client;
mod jwt;
mod offer;
mod oidc;
mod output;
mod redirect_server;
mod verify;
mod well_known;

use credential::{CredentialRequest, JwtCredential};
use oidc::do_the_dance;
use verify::verify;
use well_known::get_from;

use cli_flow::handle_offer_command;

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Offer { offer } => {
            let normalized = handle_offer_command(offer).await;
            stdout(&normalized);
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
                .map_or("http://localhost:8000/", |r| r.as_str());

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
            let first_authorization_server = well_known
                .first_authorization_server()
                .map(|s| s.to_string())
                .unwrap_or("No Authorization Server".to_string());

            info(
                "First Authorization Server",
                Some(&first_authorization_server),
            );
            stdout(&well_known);
        }
        Commands::Proof {
            credential_issuer,
            nonce,
            keypair,
            did,
        } => {
            info("Generating Proof of Possession", Some(&credential_issuer));
            
            let keypair_str = keypair.to_string();
            let did_str = did.to_string();
            
            // build our proof of Possession
            let jwt_key = JwtProof::new(&keypair_str, &did_str);
            let proof = jwt_key.create_jwt(
                &credential_issuer,
                jwt::current_timestamp(),
                nonce.as_ref().map(|s| s.to_string())
            );
            
            info("Generated Proof of Possession JWT", Some(&proof));
            stdout(&proof);
        }
        Commands::Request {
            configuration_id,
            credential_issuer: _,
            credential_endpoint,
            issuer_state,
            access_token,
            proof,
        } => {
            info("Requesting credential with provided proof", Some(&proof.to_string()));
            let credential_endpoint = Url::parse(&credential_endpoint).unwrap();

            // Optional Access Token
            let access_token = access_token
                .as_ref()
                .map(|s| AccessToken::new(s.to_string()));

            let credential_request = CredentialRequest::new(
                credential_endpoint,
                configuration_id.to_string(),
                proof.to_string(),
                issuer_state.as_ref().map(|s| s.to_string()),
                access_token,
            );
            debug("Credential Request", Some(&credential_request));

            let credential_response = credential_request.execute().await.unwrap();
            debug("Credential Response", Some(&credential_response));
            if let Some(credentials) = credential_response.credentials {
                credentials.iter().for_each(|credential| {
                    let unpacked_credential =
                        JwtCredential::from_jwt(credential).expect("Could not unpack credential");
                    info("Credential", Some(&unpacked_credential.to_string()));
                });
            }
        }
        Commands::Display { credential } => {
            info("Displaying Credential", Some(&credential));
            let unpacked_credential =
                JwtCredential::from_jwt(credential).expect("Could not unpack credential");
            stdout(&unpacked_credential);
        }
        Commands::Verify { credential } => {
            println!("Verifying credential: {}", credential);
            let result = verify(credential);
            match result {
                Ok(_) => println!("Credential is valid"),
                Err(e) => println!("Credential verification failed: {:?}", e),
            }
        }
        Commands::Interactive { offer } => {
            info("Starting Interactive Flow", Some(&offer));
            let normalized = handle_offer_command(offer).await;
            info("Credential Offer", Some(&normalized));

            // Get authorization server url
            let well_known = get_from(&normalized.credential_issuer).await.unwrap();
            debug("Issuer Metadata", Some(&well_known));

            info("Credential offer flow", Some(&normalized.flow));
            let select_default: usize = match normalized.flow {
                offer::CredentialOfferFlow::AuthorizationCodeFlow => 0,
                offer::CredentialOfferFlow::PreAuthorizedCodeFlow => 1,
            };
            let selection = Select::new()
                .with_prompt("What flow do you want to use?")
                .default(select_default)
                .items(&["Authorization Code Flow", "Pre-authorized Code Flow"])
                .interact()
                .unwrap();

            let access_token: Option<AccessToken>;

            match selection {
                0 => {
                    let first_authorization_server = well_known
                        .first_authorization_server()
                        .map(|s| s.to_string());

                    info("Authorization Server", first_authorization_server.as_ref());

                    let auth_server = Url::parse(
                        &first_authorization_server
                            .expect("TODO: implement pre-authorized code flow"),
                    )
                    .expect("Invalid URL");

                    // Authorize the client
                    let redirect_url = Url::parse("http://localhost:8000/").unwrap();
                    let client_id: String = Input::new()
                        .with_prompt("Enter client_id")
                        .default(std::env::var("OIDC_CLIENT_ID").unwrap_or_default())
                        .interact_text()
                        .unwrap();

                    let (ref_access_token, _) =
                        do_the_dance(auth_server, redirect_url, &client_id, None)
                            .await
                            .log_expect("Could not authenticate and authorize user");
                    access_token = Some(ref_access_token.clone());

                    debug("Access Token", Some(&ref_access_token.secret()));
                }
                1 => {
                    // Pre-authorized code flow
                    info::<String>("Pre-authorized Code Flow", None);
                    let pre_authorized_code: String = Input::new()
                        .with_prompt("Enter pre-authorized code")
                        .default(normalized.get_pre_authorized_code().unwrap_or_default())
                        .interact_text()
                        .unwrap();

                    access_token = Some(AccessToken::new(pre_authorized_code));
                }
                _ => unreachable!(),
            };

            let confirmation = Confirm::new()
                .with_prompt("Do you want to proceed with the credential request?")
                .interact()
                .unwrap();
            if !confirmation {
                info::<&str>("Aborting credential request", None);
                return;
            }

            let configuration_id = Select::new()
                .with_prompt("Select credential configuration ID")
                .default(0)
                .items(&normalized.credential_configuration_ids)
                .interact()
                .unwrap();

            let configuration_id = normalized
                .credential_configuration_ids
                .get(configuration_id)
                .expect("Invalid configuration ID");

            let pop_keypair: String = Input::new()
                .with_prompt("Enter your keypair")
                .default(std::env::var("KEYPAIR").unwrap_or_default())
                .interact_text()
                .unwrap();
            let pop_did: String = Input::new()
                .with_prompt("Enter your DID")
                .default(std::env::var("DID").unwrap_or_default())
                .interact_text()
                .unwrap();

            let jwt_key = JwtProof::new(&pop_keypair, &pop_did);
            let proof = jwt_key.create_jwt(
                &well_known.credential_issuer,
                jwt::current_timestamp(),
                None,
            );

            let credential_endpoint = Url::parse(&well_known.credential_endpoint).unwrap();
            let credential_request = CredentialRequest::new(
                credential_endpoint,
                configuration_id.to_string(),
                proof.to_string(),
                normalized.get_issuer_state(),
                access_token,
            );
            // debug("Credential Request", Some(&credential_request));
            let credential_response = credential_request.execute().await.unwrap();
            debug("Credential Response", Some(&credential_response));
            if let Some(credentials) = credential_response.credentials {
                credentials.iter().for_each(|credential| {
                    let unpacked_credential =
                        JwtCredential::from_jwt(credential).expect("Could not unpack credential");
                    info("Credential", Some(&unpacked_credential.to_string()));
                });
            }
        }
    }
}
