//! `fabric agent-stream connections`: the Trust Fabric connection records of
//! an Agent Stream, run through the connection commands Agent Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum ConnectionCommand {
    /// List connections.
    ///
    /// Each record's type is `self` for this Agent Stream or `remote` for a
    /// peer. Its status is `active`, `pending`, `awaiting-approval`,
    /// `disabled`, or `failed`. --output json prints every field Agent Stream
    /// sends, including `runtime_status`, the connection health only the list
    /// answer may carry; `get` prints the stored record. Any signed-in user
    /// can read connections; an access token with its own scope list needs
    /// gateways.view.
    List,
    /// Get a connection by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream connections list`. It
    /// is sent as given: a name is not looked up. Any signed-in user can read
    /// connections; an access token with its own scope list needs
    /// gateways.view.
    Get {
        /// Connection ID, as `list` prints it.
        id: String,
    },
    /// Create a connection record from a JSON document.
    ///
    /// The document carries `name`, `description`, and `did`, the peer's
    /// DID. The record is created with the type `remote`. Table output prints
    /// the new record's ID; --output json prints the whole record. Needs the
    /// gateways.edit permission.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a connection from a JSON document.
    ///
    /// Agent Stream changes only `name`, `description`, and `status`, and
    /// ignores other fields, so the DID cannot change. `status` is one of
    /// `active`, `pending`, `awaiting-approval`, `disabled`, or `failed`.
    /// Needs the gateways.edit permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Connection ID, as `list` prints it.
        id: String,
        /// JSON document carrying any of `name`, `description`, `status`. Use
        /// '-' to read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a connection by ID.
    ///
    /// It runs at once, with no confirmation prompt. Agent Stream refuses to
    /// delete the `self` record. Deleting a `remote` record stops the
    /// listeners of its connection points and deletes the connection points
    /// Agent Stream created for it; the ones a user created are kept. Needs
    /// the gateways.delete permission.
    Delete {
        /// Connection ID, as `list` prints it.
        id: String,
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
  Disable a connection:
    echo '{"status": "disabled"}' | fabric agent-stream connections update \
      <id> --file -"#;

impl From<ConnectionCommand> for commands::CrudCommand {
    fn from(command: ConnectionCommand) -> Self {
        match command {
            ConnectionCommand::List => Self::List,
            ConnectionCommand::Get { id } => Self::Get { id },
            ConnectionCommand::Create(args) => Self::Create(args),
            ConnectionCommand::Update { id, file } => Self::Update { id, file },
            ConnectionCommand::Delete { id } => Self::Delete { id },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
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
        let document = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(document.path(), r#"{"name":"Partner"}"#).expect("write the document");
        let file = || document.path().to_path_buf();

        for command in [
            ConnectionCommand::List,
            ConnectionCommand::Get { id: "g-1".to_owned() },
            ConnectionCommand::Create(JsonFileArgs { file: file() }),
            ConnectionCommand::Update {
                id: "g-1".to_owned(),
                file: file(),
            },
            ConnectionCommand::Delete { id: "g-1".to_owned() },
        ] {
            run_shared(&client, SharedCommand::Connections(command.into()), Output::Json)
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
