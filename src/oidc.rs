use anyhow::anyhow;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    reqwest, AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use url::Url;

// Re-exports
pub use openidconnect::AccessToken;

use crate::log;
use crate::redirect_server::start_redirect_server;

pub async fn do_the_dance(
    base_url: Url,
    redirect_url: Url,
    client_id: String,
    client_secret: Option<String>,
) -> Result<(AccessToken, Nonce), anyhow::Error> {
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .connection_verbose(true)
        .build()
        .expect("Client should build");

    // Use OpenID Connect Discovery to fetch the provider metadata.
    // normalize the URL by ensuring there is no trailing slash
    let normalized_url = base_url.to_string().trim_end_matches('/').to_string();
    let issuer_url = IssuerUrl::new(normalized_url)?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id),
        client_secret.map(|client_secret| ClientSecret::new(client_secret)),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, _csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge) // Set the PKCE code challenge.
        .url();

    println!("Open the following url in your browser: {}", auth_url);

    let token = start_redirect_server().await;

    log("Received authorization code:", Some(&token));

    // Now you can exchange it for an access token and ID token.
    let exchange_client = client
        .exchange_code(AuthorizationCode::new(token.to_string()))?
        .set_pkce_verifier(pkce_verifier);
    println!("Exchanging code for token at {:?}", client.token_uri());

    let token_response = exchange_client.request_async(&http_client).await?;
    println!(
        "Recieved access token of type: {:?}, and the value is {:?}",
        token_response.token_type(),
        token_response.access_token().secret()
    );

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
    let id_token_verifier = client.id_token_verifier();
    let claims = id_token.claims(&id_token_verifier, &nonce)?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    println!(
        "User {} with e-mail address {} has authenticated successfully for {:?}",
        claims.subject().as_str(),
        claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>"),
        claims.audiences(),
    );

    Ok((token_response.access_token().clone(), nonce.clone()))
}
