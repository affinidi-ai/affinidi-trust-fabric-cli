//! `fabric agent-stream connections`: the Trust Fabric connection records of
//! an Agent Stream, run through the connection commands Agent Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum ConnectionCommand {
    /// List Trust Fabric connections.
    ///
    /// Each record's type is `self` for this Agent Stream or `remote` for a
    /// peer. Its status is `active`, `pending`, `awaiting-approval`,
    /// `disabled`, or `failed`. --output json prints every field Agent Stream
    /// sends, including `runtime_status`, the connection health only the list
    /// answer may carry; `get` prints the stored record. Any signed-in user
    /// can read connections; an access token with its own scope list needs
    /// gateways.view.
    List,
    /// Get a Trust Fabric connection by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream connections list`. It
    /// is sent as given: a name is not looked up. Any signed-in user can read
    /// connections; an access token with its own scope list needs
    /// gateways.view.
    Get {
        /// Trust Fabric connection ID, as `list` prints it.
        id: String,
    },
    /// Create a Trust Fabric connection from a JSON document.
    ///
    /// The document carries `name`, `description`, and `did`, the peer's
    /// DID. The record is created with the type `remote`. Table output prints
    /// the new record's ID; --output json prints the whole record. Needs the
    /// gateways.edit permission.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a Trust Fabric connection from a JSON document.
    ///
    /// Agent Stream changes only `name`, `description`, and `status`, and
    /// ignores other fields, so the DID cannot change. `status` is one of
    /// `active`, `pending`, `awaiting-approval`, `disabled`, or `failed`.
    /// Needs the gateways.edit permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Trust Fabric connection ID, as `list` prints it.
        id: String,
        /// JSON document carrying any of `name`, `description`, `status`. Use
        /// '-' to read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a Trust Fabric connection by ID.
    ///
    /// The command asks for confirmation first unless you pass --yes. Agent
    /// Stream refuses to delete the `self` record. Deleting a `remote` record
    /// stops the listeners of its connection points and deletes the
    /// connection points Agent Stream created for it; the ones a user created
    /// are kept. Needs the gateways.delete permission.
    Delete {
        /// Trust Fabric connection ID, as `list` prints it.
        id: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `connections create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Record a peer by its DID:
    fabric agent-stream connections create --file peer.json
  where peer.json is:
    {"name": "Partner", "description": "EU partner", "did": "did:web:partner.example"}"#;

/// Examples shown at the bottom of `connections update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Disable a Trust Fabric connection:
    echo '{"status": "disabled"}' | fabric agent-stream connections update \
      <id> --file -"#;

impl ConnectionCommand {
    /// Whether this is a delete that asks for confirmation first, because
    /// --yes was not given.
    pub(crate) fn asks_before_deleting(&self) -> bool {
        matches!(self, Self::Delete { yes: false, .. })
    }
}

impl commands::SharedCommand {
    /// The shared form of an Agent Stream connection command, which remembers
    /// whether a delete asks for confirmation first.
    pub(crate) fn connections(command: ConnectionCommand) -> Self {
        Self::Connections {
            ask_first: command.asks_before_deleting(),
            command: command.into(),
        }
    }
}

impl From<ConnectionCommand> for commands::CrudCommand {
    fn from(command: ConnectionCommand) -> Self {
        match command {
            ConnectionCommand::List => Self::List,
            ConnectionCommand::Get { id } => Self::Get { id },
            ConnectionCommand::Create(args) => Self::Create(args),
            ConnectionCommand::Update { id, file } => Self::Update { id, file },
            ConnectionCommand::Delete { id, .. } => Self::Delete { id },
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{
        agent_stream::test_support::{json_file, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Cli, Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[test]
    fn only_a_delete_without_yes_asks_first_and_agent_gateway_has_no_yes() {
        let delete = |yes| ConnectionCommand::Delete { id: "g-1".to_owned(), yes };

        assert!(delete(false).asks_before_deleting());
        assert!(!delete(true).asks_before_deleting());
        assert!(!ConnectionCommand::Get { id: "g-1".to_owned() }.asks_before_deleting());
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "connections", "delete", "g-1", "--yes"]).is_ok());
        assert!(
            Cli::try_parse_from(["fabric", "agent-gateway", "connections", "delete", "g-1", "--yes"]).is_err(),
            "Agent Gateway's connections delete keeps its flags"
        );
    }

    #[tokio::test]
    async fn each_command_reaches_its_gateways_route() {
        let record = r#"{"id":"g-1","name":"Partner","did":"did:web:partner.example","gateway_type":"remote"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/gateways/g-1", "HTTP/1.1 200 OK", record),
            ("PUT /api/v1/gateways/g-1", "HTTP/1.1 200 OK", record),
            ("DELETE /api/v1/gateways/g-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/gateways", "HTTP/1.1 200 OK", record),
            ("GET /api/v1/gateways", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"name":"Partner"}"#);
        let file = || document.path().to_path_buf();

        for command in [
            ConnectionCommand::List,
            ConnectionCommand::Get { id: "g-1".to_owned() },
            ConnectionCommand::Create(JsonFileArgs { file: file() }),
            ConnectionCommand::Update {
                id: "g-1".to_owned(),
                file: file(),
            },
            ConnectionCommand::Delete {
                id: "g-1".to_owned(),
                yes: true,
            },
        ] {
            run_shared(&client, SharedCommand::connections(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/gateways HTTP/1.1",
                "GET /api/v1/gateways/g-1 HTTP/1.1",
                "POST /api/v1/gateways HTTP/1.1",
                "PUT /api/v1/gateways/g-1 HTTP/1.1",
                "DELETE /api/v1/gateways/g-1 HTTP/1.1",
            ]
        );
    }
}
