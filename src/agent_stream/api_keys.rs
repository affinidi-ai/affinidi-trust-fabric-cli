//! `fabric agent-stream api-keys`: the API keys of an Agent Stream's
//! Surfaces, run through the API key commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{
    client::GatewayClient,
    commands::{self, ApiKeyCreateArgs, ApiKeySurfaceArgs, Output, SharedCommand, parse_label, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum ApiKeyCommand {
    /// List API keys across every Surface, or for one of them.
    List {
        /// ID of the Surface to list keys for; a Surface name is not accepted.
        /// Omit to list every key.
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Get an API key's metadata. The secret is never returned.
    Get {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: SurfaceArgs,
    },
    /// Create an API key for a Surface.
    ///
    /// The key's secret is printed once and never again: Agent Stream keeps
    /// only its hash. In table mode the secret goes alone to standard output,
    /// so `$(...)` captures just the secret, and the confirmation goes to
    /// standard error. `--output json` prints the whole answer, secret
    /// included.
    ///
    /// A key made with flags never expires. To give it a lifetime, set
    /// `expires_in_seconds` in a --file document; the answer then carries
    /// `expires_at`. A key cannot be edited afterwards: to change its
    /// client_id, labels or lifetime, create a new key and revoke or delete
    /// the old one.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Revoke an API key without removing its record.
    ///
    /// Agent Stream stops accepting the key, and `list` keeps showing it with
    /// a revoked status. A revoked key cannot be rotated; create a new key
    /// instead. The command asks for confirmation first unless you pass --yes.
    #[command(after_long_help = REVOKE_EXAMPLES)]
    Revoke {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: SurfaceArgs,
        /// Name Agent Stream logs as having revoked the key.
        #[arg(long, default_value = "api")]
        actor: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Replace an API key with a new one that has a new id and secret.
    ///
    /// Agent Stream revokes the key at once and issues a new key with the same
    /// client_id, labels and lifetime; the old key's id stays in `list` as
    /// revoked, and the new key's `rotated_from` names it. The new secret is
    /// printed once, the same way `create` prints it: alone on standard output
    /// in table mode, with the confirmation naming the new key's id on
    /// standard error. A revoked key cannot be rotated. The command asks for
    /// confirmation first unless you pass --yes.
    #[command(after_long_help = ROTATE_EXAMPLES)]
    Rotate {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: SurfaceArgs,
        /// Name Agent Stream logs for the rotation and stores as the new key's
        /// `issuer.actor`.
        #[arg(long, default_value = "api")]
        actor: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Delete an API key.
    ///
    /// The key and its record are removed, so unlike `revoke` it no longer
    /// shows in `list`. The command asks for confirmation first unless you pass
    /// --yes. Pass --agent-id to skip looking up the key's Surface, for
    /// example when your token can delete keys but not list them.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: SurfaceArgs,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// The Surface a single-key command acts on. Agent Stream addresses a key by
/// its Surface and then its own id, so a command given the key alone looks the
/// Surface up first.
#[derive(Debug, Args)]
pub struct SurfaceArgs {
    /// ID of the Surface the key belongs to; a Surface name is not accepted.
    /// Omit to look it up by key id.
    #[arg(long)]
    agent_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// ID of the Surface the key belongs to; a Surface name is not accepted.
    agent_id: String,
    /// External client identifier the key is issued to.
    #[arg(long, required_unless_present = "file")]
    client_id: Option<String>,
    /// Label as name=value. Repeat for multiple labels.
    #[arg(long = "label", value_parser = parse_label)]
    labels: Vec<(String, String)>,
    /// JSON document `{client_id, labels?, expires_in_seconds?}`. The other
    /// creation flags are ignored when it is set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

/// Examples shown at the bottom of `api-keys create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a key and keep its secret in a shell variable:
    KEY=$(fabric agent-stream api-keys create <surface-id> \
      --client-id billing --label team=ops)

  Create a key that expires after 30 days, from a document:
    fabric agent-stream api-keys create <surface-id> --file api-key.json
  where api-key.json is:
    {"client_id": "billing", "labels": {"team": "ops"},
     "expires_in_seconds": 2592000}"#;

/// Examples shown at the bottom of `api-keys revoke --help`.
const REVOKE_EXAMPLES: &str = r#"Examples:
  Revoke a key, confirming at the prompt:
    fabric agent-stream api-keys revoke <key-id>

  Revoke from a script, naming who did it:
    fabric agent-stream api-keys revoke <key-id> --actor ops-team --yes"#;

/// Examples shown at the bottom of `api-keys rotate --help`.
const ROTATE_EXAMPLES: &str = r#"Examples:
  Rotate from a script and keep the new secret in a shell variable:
    SECRET=$(fabric agent-stream api-keys rotate <key-id> --yes)

  Rotate, naming who did it:
    fabric agent-stream api-keys rotate <key-id> --actor ops-team"#;

/// Examples shown at the bottom of `api-keys delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Delete a key from a script:
    fabric agent-stream api-keys delete <key-id> --yes

  Name the key's Surface to skip the lookup:
    fabric agent-stream api-keys delete <key-id> --agent-id <surface-id> --yes"#;

/// Runs one `api-keys` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: ApiKeyCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::ApiKeys(command.into()), output).await
}

impl From<SurfaceArgs> for ApiKeySurfaceArgs {
    fn from(SurfaceArgs { agent_id }: SurfaceArgs) -> Self {
        Self { agent_id }
    }
}

impl From<ApiKeyCommand> for commands::ApiKeyCommand {
    fn from(command: ApiKeyCommand) -> Self {
        match command {
            ApiKeyCommand::List { agent_id } => Self::List { agent_id },
            ApiKeyCommand::Get { key_id, surface } => Self::Get {
                key_id,
                surface: surface.into(),
            },
            ApiKeyCommand::Create(args) => Self::Create(ApiKeyCreateArgs {
                agent_id: args.agent_id,
                client_id: args.client_id,
                labels: args.labels,
                file: args.file,
            }),
            ApiKeyCommand::Revoke { key_id, surface, actor, yes } => Self::Revoke {
                key_id,
                surface: surface.into(),
                actor,
                yes,
            },
            ApiKeyCommand::Rotate { key_id, surface, actor, yes } => Self::Rotate {
                key_id,
                surface: surface.into(),
                actor,
                yes,
            },
            ApiKeyCommand::Delete { key_id, surface, yes } => Self::Delete {
                key_id,
                surface: surface.into(),
                yes,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_stream::test_support::{Route, scripted_agent_stream, start_lines};

    const TOKEN: &str = "aspat_test";
    const KEY_COLLECTION: Route = (
        "GET /api/v1/api-keys",
        "HTTP/1.1 200 OK",
        r#"[{"key_id":"ak_1","agent_id":"pipe-1","status":"active"},{"key_id":"ak_2","agent_id":"pipe-1"},{"key_id":"ak_2","agent_id":"pipe-2"}]"#,
    );

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn by_key_id(key_id: &str) -> ApiKeyCommand {
        ApiKeyCommand::Get {
            key_id: key_id.to_owned(),
            surface: SurfaceArgs { agent_id: None },
        }
    }

    #[tokio::test]
    async fn each_command_reaches_the_route_of_the_surface_the_key_belongs_to() {
        let created = r#"{"key_id":"ak_9","secret":"ask_secret","agent_id":"pipe-1","client_id":"billing"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/api-keys/pipe-1/ak_1", "HTTP/1.1 200 OK", r#"{"key_id":"ak_1"}"#),
            ("POST /api/v1/api-keys/pipe-1/ak_1/revoke", "HTTP/1.1 200 OK", ""),
            ("POST /api/v1/api-keys/pipe-1/ak_1/rotate", "HTTP/1.1 200 OK", created),
            ("DELETE /api/v1/api-keys/pipe-1/ak_1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/api-keys/pipe-1", "HTTP/1.1 201 Created", created),
            ("GET /api/v1/api-keys/pipe-1", "HTTP/1.1 200 OK", "[]"),
            KEY_COLLECTION,
        ])
        .await;
        let client = client(host);
        let surface = || SurfaceArgs { agent_id: None };

        for command in [
            ApiKeyCommand::List {
                agent_id: Some("pipe-1".to_owned()),
            },
            by_key_id("ak_1"),
            ApiKeyCommand::Create(CreateArgs {
                agent_id: "pipe-1".to_owned(),
                client_id: Some("billing".to_owned()),
                labels: vec![("team".to_owned(), "ops".to_owned())],
                file: None,
            }),
            ApiKeyCommand::Revoke {
                key_id: "ak_1".to_owned(),
                surface: surface(),
                actor: "ops".to_owned(),
                yes: true,
            },
            ApiKeyCommand::Rotate {
                key_id: "ak_1".to_owned(),
                surface: surface(),
                actor: "ops".to_owned(),
                yes: true,
            },
            ApiKeyCommand::Delete {
                key_id: "ak_1".to_owned(),
                surface: SurfaceArgs {
                    agent_id: Some("pipe-1".to_owned()),
                },
                yes: true,
            },
        ] {
            run(&client, command, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/api-keys/pipe-1 HTTP/1.1",
                "GET /api/v1/api-keys HTTP/1.1",
                "GET /api/v1/api-keys/pipe-1/ak_1 HTTP/1.1",
                "POST /api/v1/api-keys/pipe-1 HTTP/1.1",
                "GET /api/v1/api-keys HTTP/1.1",
                "POST /api/v1/api-keys/pipe-1/ak_1/revoke HTTP/1.1",
                "GET /api/v1/api-keys HTTP/1.1",
                "POST /api/v1/api-keys/pipe-1/ak_1/rotate HTTP/1.1",
                "DELETE /api/v1/api-keys/pipe-1/ak_1 HTTP/1.1",
            ]
        );
        let requests = requests.lock().unwrap();
        assert!(requests[3].ends_with(r#"{"client_id":"billing","labels":{"team":"ops"}}"#), "{}", requests[3]);
    }

    #[tokio::test]
    async fn a_file_document_carries_its_lifetime_to_agent_stream_unchanged() {
        let document = r#"{"client_id":"billing","expires_in_seconds":2592000}"#;
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), document).expect("write the document");
        let (host, requests) = scripted_agent_stream(vec![(
            "POST /api/v1/api-keys/pipe-1",
            "HTTP/1.1 201 Created",
            r#"{"key_id":"ak_9","secret":"ask_secret","expires_at":"2027-01-01T00:00:00Z"}"#,
        )])
        .await;

        run(
            &client(host),
            ApiKeyCommand::Create(CreateArgs {
                agent_id: "pipe-1".to_owned(),
                client_id: None,
                labels: Vec::new(),
                file: Some(file.path().to_path_buf()),
            }),
            Output::Json,
        )
        .await
        .expect("create");

        let requests = requests.lock().unwrap();
        assert!(requests[0].ends_with(document), "{}", requests[0]);
    }

    #[tokio::test]
    async fn the_key_lookup_messages_name_a_surface() {
        let (host, _) = scripted_agent_stream(vec![KEY_COLLECTION]).await;
        let client = client(host);

        let missing = run(&client, by_key_id("ak_7"), Output::Json)
            .await
            .expect_err("no Surface carries the key");
        let collision = run(&client, by_key_id("ak_2"), Output::Json)
            .await
            .expect_err("two Surfaces carry the key");

        assert_eq!(missing.to_string(), "API key 'ak_7' not found on any Surface this token can see");
        assert_eq!(
            collision.to_string(),
            "API key 'ak_2' is on more than one Surface (pipe-1, pipe-2); pass --agent-id <surface-id> to choose one"
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_and_a_collection_that_is_not_a_list_name_agent_stream_and_a_surface() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/api-keys", "HTTP/1.1 200 OK", "{}")]).await;

        let not_a_list = run(&client(host), by_key_id("ak_1"), Output::Json)
            .await
            .expect_err("the collection is not a list");

        assert_eq!(
            format!("{not_a_list:#}"),
            "Agent Stream answered the API key collection with something other than a list"
        );
    }
}
