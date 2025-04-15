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
        #[arg(value_name = "NORMALIZED_OFFER")]
        credential_issuer: String,
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
        #[arg(value_name = "ISSUER_URL")]
        url: String,
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
        #[arg(value_name = "CONFIGURATION_ID")]
        configuration_id: String,
        #[arg(value_name = "CREDENTIAL_ISSUER")]
        credential_issuer: String,
        #[arg(value_name = "CREDENTIAL_ENDPOINT")]
        credential_endpoint: String,
        #[arg(value_name = "ACCESS_TOKEN")]
        access_token: String,
        #[arg(long, value_name = "PROOF_TYPE")]
        proof_type: Option<String>,
        #[arg(long, value_name = "ALGORITHM")]
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
}
