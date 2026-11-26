//! `fabric agent-stream connection-points`: the DIDComm invitations other
//! appliances use to connect to an Agent Stream, run through the
//! connection point commands Agent Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum ConnectionPointCommand {
    /// List connection points.
    ///
    /// Lists the connection points users created; the ones Agent Stream
    /// creates for a connection are left out. Needs the
    /// `connection_points.view` permission. No answer but create's carries
    /// the invitation secret.
    List,
    /// Get a connection point by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream connection-points
    /// list`. It is sent as given: a name is not looked up. Needs the
    /// `connection_points.view` permission.
    Get {
        /// Connection point ID, as `list` prints it.
        id: String,
    },
    /// Create a connection point from a JSON document.
    ///
    /// The document needs `gateway_id`, the ID of this Agent Stream's own
    /// connection record (type `self` in `fabric agent-stream connections
    /// list`), `mediator_id` (see `fabric agent-stream mediators list`),
    /// `name`, `description`, and `secret`, which a peer must know to accept
    /// the invitation and which must be 32 to 256 bytes long. It may also carry
    /// `expiry_seconds`, `did_method` (`web`, the default, `peer`, or
    /// `webvh`), and `integrations`, a list of objects with `integration_id`
    /// and `variables`. `integration_id` and `integration_variables` are an
    /// older form of one integration. Needs the `connection_points.edit`
    /// permission.
    ///
    /// Table output prints only the new connection point's ID. With --output
    /// json the answer is printed as Agent Stream sent it, which includes the
    /// `secret` you sent; no other answer carries it.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a connection point from a JSON document.
    ///
    /// Agent Stream changes only `name`, `description`, `enabled`, and the
    /// integration list, and ignores other fields. It reads the integration
    /// list as `integration_integrations`, not as the `integrations` field
    /// `get` prints, so send only the fields you change rather than editing
    /// `get` output. Needs the `connection_points.edit` permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Connection point ID, as `list` prints it.
        id: String,
        /// JSON document carrying any of `name`, `description`, `enabled`,
        /// `integration_integrations`. Use '-' to read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a connection point by ID.
    ///
    /// It runs at once, with no confirmation prompt. Agent Stream stops the
    /// connection point's listener, then deletes it. Needs the
    /// `connection_points.delete` permission.
    Delete {
        /// Connection point ID, as `list` prints it.
        id: String,
    },
}

/// Examples shown at the bottom of `connection-points create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create an invitation that expires in a day:
    fabric agent-stream connection-points create --file invitation.json
  where invitation.json is:
    {"gateway_id": "<self-id>", "mediator_id": "<mediator-id>",
     "name": "EU partners", "description": "Invitation for EU partners",
     "secret": "<32 to 256 bytes>", "expiry_seconds": 86400}"#;

/// Examples shown at the bottom of `connection-points update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Change the description and turn the connection point on:
    echo '{"description": "EU partners", "enabled": true}' | \
      fabric agent-stream connection-points update <id> --file -"#;

impl From<ConnectionPointCommand> for commands::CrudCommand {
    fn from(command: ConnectionPointCommand) -> Self {
        match command {
            ConnectionPointCommand::List => Self::List,
            ConnectionPointCommand::Get { id } => Self::Get { id },
            ConnectionPointCommand::Create(args) => Self::Create(args),
            ConnectionPointCommand::Update { id, file } => Self::Update { id, file },
            ConnectionPointCommand::Delete { id } => Self::Delete { id },
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
    async fn each_command_reaches_its_connection_point_route() {
        let point = r#"{"id":"cp-1","gateway_id":"g-self","name":"Door","enabled":true}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/connection-points/cp-1", "HTTP/1.1 200 OK", point),
            ("PUT /api/v1/connection-points/cp-1", "HTTP/1.1 200 OK", point),
            ("DELETE /api/v1/connection-points/cp-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/connection-points", "HTTP/1.1 200 OK", r#"{"connection_point":{"id":"cp-1"}}"#),
            ("GET /api/v1/connection-points", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(document.path(), r#"{"name":"Door"}"#).expect("write the document");
        let file = || document.path().to_path_buf();

        for command in [
            ConnectionPointCommand::List,
            ConnectionPointCommand::Get { id: "cp-1".to_owned() },
            ConnectionPointCommand::Create(JsonFileArgs { file: file() }),
            ConnectionPointCommand::Update {
                id: "cp-1".to_owned(),
                file: file(),
            },
            ConnectionPointCommand::Delete { id: "cp-1".to_owned() },
        ] {
            run_shared(&client, SharedCommand::ConnectionPoints(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/connection-points HTTP/1.1",
                "GET /api/v1/connection-points/cp-1 HTTP/1.1",
                "POST /api/v1/connection-points HTTP/1.1",
                "PUT /api/v1/connection-points/cp-1 HTTP/1.1",
                "DELETE /api/v1/connection-points/cp-1 HTTP/1.1",
            ]
        );
    }
}
