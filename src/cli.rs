use clap::{Parser, Subcommand};
use clap_stdin::MaybeStdin;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Process and normalize a credential offer
    /// 
    /// Given a credential offer, this command will:
    /// - Determine if the offer is by value or by reference
    /// - Check if credential request requires Authorization Code Flow or is pre-authorized
    /// - Extract any pre-shared secrets or requirements
    /// - Identify the credential type(s) in the offer
    #[command(verbatim_doc_comment)]
    Offer {
        /// The credential offer to process. This must be the full URI.
        /// Use - to read from stdin
        #[arg(short, long, value_name = "OFFER", required = true)]
        offer: MaybeStdin<String>,
    },

    /// Handle authorization flow for credential issuance
    /// 
    /// This command will:
    /// - Print the authorization URL to stdout
    /// - Start a local webserver for callback handling
    /// - Exchange authorization code for access token
    /// - Print access token to stdout on success
    /// - Print errors to stderr on failure
    #[command(verbatim_doc_comment)]
    Authorize {
        #[arg(short, long, value_name = "AUTHORZATION_URL")]
        url: MaybeStdin<String>,
        #[arg(short, long, value_name = "OIDC_CLIENT_ID")]
        client_id: String,
        #[arg(long, value_name = "OIDC_CLIENT_SECRET")]
        client_secret: Option<String>,
        /// The redirect URL to use for authorization. If not provided, defaults to
        /// "http://localhost:8080/"
        #[arg(short, long, value_name = "REDIRECT_URL")]
        redirect_url: Option<String>,
    },

    /// Retrieve and display issuer metadata
    /// 
    /// This command will show:
    /// - Supported proof types and algorithms
    /// - Authorization server details (if configured)
    /// - Issuer endpoints
    /// - Issuer DID
    /// - Issuer public key(s)
    /// - Supported credential types
    #[command(verbatim_doc_comment)]
    Issuer {
        #[arg(short, long, value_name = "ISSUER_URL")]
        url: MaybeStdin<String>,
    },

    /// Request credential from issuer
    /// 
    /// This command requires either:
    /// - An access token from authorization
    /// - OR a pre-shared secret
    /// 
    /// It will:
    /// - Allow proof type and algorithm selection
    /// - Display proof before sending
    /// - Request credential from issuer
    /// - Output credential to stdout
    #[command(verbatim_doc_comment)]
    Request {
        #[arg(short, long, value_name = "CONFIGURATION_ID")]
        configuration_id: String,
        #[arg(short = 'i', long, value_name = "CREDENTIAL_ISSUER")]
        credential_issuer: String,
        #[arg(short = 'e', long, value_name = "CREDENTIAL_ENDPOINT")]
        credential_endpoint: String,
        #[arg(short = 's', long, value_name = "ISSUER_STATE")]
        issuer_state: Option<String>,
        #[arg(short = 't', long, value_name = "ACCESS_TOKEN")]
        access_token: Option<String>,
        #[arg(short, long, value_name = "PROOF_TYPE")]
        proof_type: Option<String>,
        #[arg(short, long, value_name = "ALGORITHM")]
        algorithm: Option<String>,
    },

    /// Verify a credential and its proof
    /// 
    /// This command will:
    /// - Display the proof from the issuer
    /// - Verify the proof
    /// - Verify the credential
    /// - Output verification results
    #[command(verbatim_doc_comment)]
    Verify {
        #[arg(value_name = "CREDENTIAL")]
        credential: String,
    },

    /// - [ ] `vc-wallet interactive` - given only a credential offer, walk the user through the entire flow.
    ///  - [ ] On each step, show the user what has been resolved, which calls were made, 
    ///  - [ ] what the next step will be with a prompt to continue or abort.
    ///  - [ ] For each step, ask the user what values and choices they must provide.
    ///  - [ ] Show the user the contents of the final credential and the proof.
    #[command(verbatim_doc_comment)]
    Interactive {
        #[arg(short, long, value_name = "OFFER")]
        offer: MaybeStdin<String>,
    },
}
