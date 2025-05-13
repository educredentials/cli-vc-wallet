use axum::{extract::Query, response::Html, routing::get, Router};
use std::{
    collections::HashMap,
    net::ToSocketAddrs,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

/// Starts a simple HTTP server on localhost:8000 that waits for an OAuth redirect,
/// extracts the 'code' parameter, and then shuts down.
pub async fn start_redirect_server(redirect_url: &Url) -> String {
    // Channel to communicate the code between the handler and this function
    let (tx, rx) = oneshot::channel::<String>();
    let tx = Arc::new(Mutex::new(Some(tx)));

    // Set up a simple router with a single GET endpoint
    let app = Router::new().route(
        "/",
        get(move |query_params| {
            let tx_clone = Arc::clone(&tx);
            handle_redirect_callback(query_params, tx_clone)
        }),
    );

    // Start the server
    let addr = format!(
        "{}:{}",
        redirect_url.host_str().unwrap(),
        redirect_url.port().unwrap()
    )
    .to_socket_addrs()
    .expect("Invalid redirect URL")
    .next()
    .expect("No address found");
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    // Create a cancellation channel
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Spawn the server in the background
    let server_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
                println!("OAuth code received, shutting down server");
            })
            .await
            .expect("Server failed");
    });

    // Wait for the authorization code
    let code = rx.await.expect("Failed to receive authorization code");

    // Trigger the shutdown
    let _ = shutdown_tx.send(());

    // Wait for the server to shutdown (optional)
    let _ = server_task.await;
    code
}

/// Handles the redirect callback, extracting the 'code' parameter and sending it
/// through the provided channel. Returns an HTML response to the browser.
async fn handle_redirect_callback(
    Query(params): Query<HashMap<String, String>>,
    tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
) -> Html<String> {
    if let Some(code) = params.get("code") {
        // Send the code through the channel
        if let Some(sender) = tx.lock().unwrap().take() {
            let _ = sender.send(code.clone());
        }

        Html("<h1>Authorization Successful</h1><p>You can close this window now.</p>".to_string())
    } else {
        Html("<h1>Error</h1><p>No authorization code provided.</p>".to_string())
    }
}

