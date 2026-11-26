//! `fabric agent-stream identities`: the did:webvh identities of an Agent
//! Stream, run through the identity commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

use crate::{
    client::GatewayClient,
    commands::{self, Output, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// List the did:webvh identities you may manage.
    ///
    /// Agent Stream lists the identities you own and those with no owner.
    List,
    /// Get an identity by ID.
    ///
    /// Agent Stream answers with the public key only, never the private one.
    /// `integrations` is a reserved sibling route and returns the identity
    /// integrations configuration rather than an identity.
    Get {
        /// Identity's UUID, as `list` prints it, not its DID.
        id: String,
    },
    /// Create an identity, optionally from a JSON document.
    ///
    /// Without --file Agent Stream generates an Ed25519 key pair and uses a
    /// DID path of `agents/<uuid>`. To bring your own keys, put them under
    /// `key_pair` as JWKs, not PEM.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create {
        /// JSON document `{did_path?, metadata?, key_pair?}`. Every field is
        /// optional; Agent Stream fills in whatever the document omits. A key
        /// pair belongs under `key_pair`: an unwrapped one is rejected,
        /// because Agent Stream would ignore it and install one of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Update an identity's DID document from a JSON document.
    ///
    /// A deactivated identity, or a connection point's identity, cannot be
    /// updated.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        id: String,
        /// JSON document `{did_document, update_keys?, ttl?}`. A bare DID
        /// document is rejected: it belongs under `did_document`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Rotate an identity's signing keys.
    ///
    /// The new key takes over at once, with no confirmation prompt, and the
    /// answer carries its public key as `new_public_key`. Without --file
    /// Agent Stream generates the new key pair. A deactivated identity, or a
    /// connection point's identity, cannot be rotated.
    #[command(name = "rotate-keys", after_long_help = ROTATE_KEYS_EXAMPLES)]
    RotateKeys {
        id: String,
        /// JSON document `{"new_key_pair": {public_key, private_key,
        /// key_type?}}`, both keys JWKs, not PEM. A document without
        /// `new_key_pair` is rejected, because Agent Stream would ignore it
        /// and install a key pair of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Transfer an identity to a new controller.
    ///
    /// The transfer takes effect at once, with no confirmation prompt.
    /// `new_controller` must be a DID. `current_owner_authorization` proves
    /// control of the identity's current signing key: a compact JWS (alg
    /// EdDSA, with a `kid` naming a verification method of this DID) whose
    /// payload carries a fresh `iat` and the challenge
    /// `transfer-ownership:<did>:<version-id>:<new-controller>`, where
    /// <version-id> is the identity's latest `version_id` (see `history`). A
    /// deactivated identity, or a connection point's identity, cannot be
    /// transferred.
    #[command(after_long_help = TRANSFER_EXAMPLES)]
    Transfer {
        id: String,
        /// JSON document `{new_controller, current_owner_authorization,
        /// new_owner_authorization?, new_ownership_proof?, transfer_reason?}`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show an identity's version history.
    History { id: String },
    /// Read or write an identity's trust-score policy.
    ///
    /// Agent Stream stores this policy and returns it, but does not enforce
    /// it on requests. Unrelated to `fabric agent-stream policies`, which
    /// manages the Rego policy definitions Agent Stream does enforce.
    #[command(name = "trust-policy")]
    TrustPolicy {
        #[command(subcommand)]
        command: TrustPolicyCommand,
    },
    /// Deactivate an identity.
    ///
    /// This is the identity's delete route, and it runs at once with no
    /// confirmation prompt. Agent Stream appends a deactivation entry to the
    /// DID log and clears the identity's active flag. The record is kept and
    /// stays readable, but a deactivated identity cannot be updated, rotated,
    /// transferred or deactivated again. A connection point's identity cannot
    /// be deactivated.
    Deactivate { id: String },
}

#[derive(Debug, Subcommand)]
pub enum TrustPolicyCommand {
    /// Get an identity's trust-score policy.
    ///
    /// Agent Stream returns its built-in defaults for an identity that has
    /// never had a policy set, so a result does not prove one was configured.
    Get { id: String },
    /// Set an identity's trust-score policy from a JSON document.
    ///
    /// Send the document `trust-policy get <id> --output json` returns, edited:
    /// the policy under `config`, holding `minTrustScore` (0.0 to 1.0) and,
    /// for each of five components, a threshold, a weight and whether it is
    /// required. The stored policy is replaced as a whole. A connection
    /// point's identity cannot have its policy set.
    #[command(after_long_help = TRUST_POLICY_SET_EXAMPLES)]
    Set {
        id: String,
        /// JSON document `{"config": {...}}`. A bare policy, without the
        /// `config` wrapper, is refused and never sent.
        #[arg(short, long)]
        file: PathBuf,
    },
}

/// Examples shown at the bottom of `identities create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Let Agent Stream generate the keys:
    fabric agent-stream identities create

  Choose the DID path and bring your own Ed25519 key pair:
    fabric agent-stream identities create --file identity.json
  where identity.json is:
    {
      "did_path": "agents/billing",
      "key_pair": {
        "public_key":  {"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"},
        "private_key": {"kty": "OKP", "crv": "Ed25519",
                        "x": "<base64url>", "d": "<base64url>"},
        "key_type": "Ed25519"
      }
    }"#;

/// Examples shown at the bottom of `identities update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Replace the DID document:
    fabric agent-stream identities update <id> --file identity-update.json
  where identity-update.json wraps the complete new DID document:
    {"did_document": {"id": "did:webvh:...", "verificationMethod": [...]}}"#;

/// Examples shown at the bottom of `identities rotate-keys --help`.
const ROTATE_KEYS_EXAMPLES: &str = r#"Examples:
  Let Agent Stream generate the new key pair:
    fabric agent-stream identities rotate-keys <id>

  Supply your own Ed25519 key pair:
    fabric agent-stream identities rotate-keys <id> --file rotate-keys.json
  where rotate-keys.json is:
    {
      "new_key_pair": {
        "public_key":  {"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"},
        "private_key": {"kty": "OKP", "crv": "Ed25519",
                        "x": "<base64url>", "d": "<base64url>"}
      }
    }"#;

/// Examples shown at the bottom of `identities transfer --help`.
const TRANSFER_EXAMPLES: &str = r#"Examples:
  Find the latest version_id to sign into the challenge:
    fabric agent-stream identities history <id> --output json

  Transfer the identity:
    fabric agent-stream identities transfer <id> --file transfer.json
  where transfer.json is:
    {
      "new_controller": "did:web:partner.example.com",
      "current_owner_authorization": "<compact JWS>",
      "transfer_reason": "Handed over to partner"
    }"#;

/// Examples shown at the bottom of `identities trust-policy set --help`.
const TRUST_POLICY_SET_EXAMPLES: &str = r#"Examples:
  Save the current policy, edit it, and send it back:
    fabric agent-stream identities trust-policy get <id> --output json > \
      trust-policy.json
    fabric agent-stream identities trust-policy set <id> \
      --file trust-policy.json"#;

/// Runs one `identities` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: IdentityCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::Identities(command.into()), output).await
}

impl From<IdentityCommand> for commands::IdentityCommand {
    fn from(command: IdentityCommand) -> Self {
        match command {
            IdentityCommand::List => Self::List,
            // Agent Stream never sends the private key, so there is nothing
            // for --reveal to show.
            IdentityCommand::Get { id } => Self::Get { id, reveal: false },
            IdentityCommand::Create { file } => Self::Create { file },
            IdentityCommand::Update { id, file } => Self::Update { id, file },
            IdentityCommand::RotateKeys { id, file } => Self::RotateKeys { id, file },
            IdentityCommand::Transfer { id, file } => Self::Transfer { id, file },
            IdentityCommand::History { id } => Self::History { id },
            IdentityCommand::TrustPolicy { command } => Self::TrustPolicy {
                command: match command {
                    TrustPolicyCommand::Get { id } => commands::TrustPolicyCommand::Get { id },
                    TrustPolicyCommand::Set { id, file } => commands::TrustPolicyCommand::Set { id, file },
                },
            },
            IdentityCommand::Deactivate { id } => Self::Deactivate { id },
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{
        agent_stream::test_support::{scripted_agent_stream, start_lines},
        commands::Cli,
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn json_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), contents).expect("write the document");
        file
    }

    #[tokio::test]
    async fn each_command_reaches_its_identity_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/identities/i-1/history", "HTTP/1.1 200 OK", "[]"),
            ("GET /api/v1/identities/i-1/policy", "HTTP/1.1 200 OK", "{}"),
            ("PUT /api/v1/identities/i-1/policy", "HTTP/1.1 200 OK", "{}"),
            ("POST /api/v1/identities/i-1/update", "HTTP/1.1 200 OK", "{}"),
            ("POST /api/v1/identities/i-1/rotate-keys", "HTTP/1.1 200 OK", "{}"),
            ("POST /api/v1/identities/i-1/transfer", "HTTP/1.1 200 OK", "{}"),
            ("GET /api/v1/identities/i-1", "HTTP/1.1 200 OK", r#"{"id":"i-1"}"#),
            ("DELETE /api/v1/identities/i-1", "HTTP/1.1 200 OK", "{}"),
            ("POST /api/v1/identities", "HTTP/1.1 201 Created", r#"{"id":"i-1"}"#),
            ("GET /api/v1/identities", "HTTP/1.1 200 OK", r#"{"identities":[],"count":0}"#),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"did_document":{}}"#);
        let policy = json_file(r#"{"config":{"minTrustScore":0.9}}"#);
        let id = || "i-1".to_owned();
        let path = |file: &tempfile::NamedTempFile| file.path().to_path_buf();

        for command in [
            IdentityCommand::List,
            IdentityCommand::Get { id: id() },
            IdentityCommand::Create { file: None },
            IdentityCommand::Update {
                id: id(),
                file: path(&document),
            },
            IdentityCommand::RotateKeys { id: id(), file: None },
            IdentityCommand::Transfer {
                id: id(),
                file: path(&document),
            },
            IdentityCommand::History { id: id() },
            IdentityCommand::TrustPolicy {
                command: TrustPolicyCommand::Get { id: id() },
            },
            IdentityCommand::TrustPolicy {
                command: TrustPolicyCommand::Set { id: id(), file: path(&policy) },
            },
            IdentityCommand::Deactivate { id: id() },
        ] {
            run(&client, command, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/identities HTTP/1.1",
                "GET /api/v1/identities/i-1 HTTP/1.1",
                "POST /api/v1/identities HTTP/1.1",
                "POST /api/v1/identities/i-1/update HTTP/1.1",
                "POST /api/v1/identities/i-1/rotate-keys HTTP/1.1",
                "POST /api/v1/identities/i-1/transfer HTTP/1.1",
                "GET /api/v1/identities/i-1/history HTTP/1.1",
                "GET /api/v1/identities/i-1/policy HTTP/1.1",
                "PUT /api/v1/identities/i-1/policy HTTP/1.1",
                "DELETE /api/v1/identities/i-1 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn the_refusals_of_a_document_agent_stream_would_misread_name_agent_stream_and_send_nothing() {
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let client = client(host);
        let bare_key_pair = json_file(r#"{"public_key":{"x":"p"}}"#);
        let bare_policy = json_file(r#"{"minTrustScore":0.9}"#);

        let create = run(
            &client,
            IdentityCommand::Create {
                file: Some(
                    bare_key_pair
                        .path()
                        .to_path_buf(),
                ),
            },
            Output::Table,
        )
        .await
        .expect_err("an unwrapped key pair");
        let rotate = run(
            &client,
            IdentityCommand::RotateKeys {
                id: "i-1".to_owned(),
                file: Some(
                    bare_key_pair
                        .path()
                        .to_path_buf(),
                ),
            },
            Output::Table,
        )
        .await
        .expect_err("an unwrapped key pair");
        let trust_policy = run(
            &client,
            IdentityCommand::TrustPolicy {
                command: TrustPolicyCommand::Set {
                    id: "i-1".to_owned(),
                    file: bare_policy
                        .path()
                        .to_path_buf(),
                },
            },
            Output::Table,
        )
        .await
        .expect_err("a bare policy");

        assert!(
            create.to_string().ends_with(
                "x and d. Agent Stream ignores an unwrapped document and installs a key pair of its own instead."
            ),
            "{create}"
        );
        assert!(
            rotate.to_string().ends_with(
                "x and d. Agent Stream ignores an unwrapped document and installs a key pair of its own instead."
            ),
            "{rotate}"
        );
        assert_eq!(
            trust_policy.to_string(),
            r#"--file document must wrap the policy: {"config": {...}}. Take the document to edit from `fabric agent-stream identities trust-policy get <id> --output json`, which carries the policy under the same key."#
        );
        assert!(start_lines(&requests).is_empty());
    }

    #[test]
    fn get_has_no_reveal_flag_since_agent_stream_never_sends_the_private_key() {
        Cli::try_parse_from(["fabric", "agent-stream", "identities", "get", "i-1"]).expect("get parses");
        let error = Cli::try_parse_from(["fabric", "agent-stream", "identities", "get", "i-1", "--reveal"])
            .expect_err("--reveal would show nothing more");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument, "{error}");
    }
}
