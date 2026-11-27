//! `fabric agent-stream mediators`: the DIDComm mediator records of an Agent
//! Stream, run through the mediator commands Agent Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum MediatorCommand {
    /// List mediators.
    ///
    /// `get` and --output json print every field Agent Stream sends. Any
    /// signed-in user can read mediators; an access token with its own scope
    /// list needs mediators.view.
    List,
    /// Get a mediator by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream mediators list`. It is
    /// sent as given: a name is not looked up. Any signed-in user can read
    /// mediators; an access token with its own scope list needs
    /// mediators.view.
    Get {
        /// Mediator ID, as `list` prints it.
        id: String,
    },
    /// Create a mediator record from a JSON document.
    ///
    /// The document carries `name`, `description`, `did`, the mediator's DID,
    /// and optionally `did_document`. Without `did_document`, Agent Stream
    /// resolves the DID itself. It checks the mediator's DID document before
    /// saving and refuses one it cannot use. It also makes a new did:peer to
    /// talk to the mediator with, shown as `our_did`; its keys are never in
    /// an answer. Needs the mediators.edit permission.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a mediator from a JSON document.
    ///
    /// Agent Stream changes only `name`, `description`, `did`, and `status`
    /// (`active` or `disabled`), and ignores other fields. It checks the
    /// mediator's DID document again before saving and refuses the change
    /// when it cannot use it. Needs the mediators.edit permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Mediator ID, as `list` prints it.
        id: String,
        /// JSON document carrying any of `name`, `description`, `did`,
        /// `status`. Use '-' to read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a mediator by ID.
    ///
    /// It runs at once, with no confirmation prompt. Agent Stream stops the
    /// listeners of the connection points that use the mediator, but keeps
    /// those connection points. Needs the mediators.delete permission.
    Delete {
        /// Mediator ID, as `list` prints it.
        id: String,
    },
}

/// Examples shown at the bottom of `mediators create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Add a mediator by its DID:
    echo '{"name": "EU mediator", "description": "", "did": "did:web:mediator.example"}' \
      | fabric agent-stream mediators create --file -"#;

/// Examples shown at the bottom of `mediators update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Disable a mediator:
    echo '{"status": "disabled"}' | fabric agent-stream mediators update \
      <id> --file -"#;

impl From<MediatorCommand> for commands::CrudCommand {
    fn from(command: MediatorCommand) -> Self {
        match command {
            MediatorCommand::List => Self::List,
            MediatorCommand::Get { id } => Self::Get { id },
            MediatorCommand::Create(args) => Self::Create(args),
            MediatorCommand::Update { id, file } => Self::Update { id, file },
            MediatorCommand::Delete { id } => Self::Delete { id },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{json_file, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_mediator_route() {
        let mediator = r#"{"id":"m-1","name":"EU mediator","did":"did:web:mediator.example","status":"active"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/mediators/m-1", "HTTP/1.1 200 OK", mediator),
            ("PUT /api/v1/mediators/m-1", "HTTP/1.1 200 OK", mediator),
            ("DELETE /api/v1/mediators/m-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/mediators", "HTTP/1.1 200 OK", mediator),
            ("GET /api/v1/mediators", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"name":"EU mediator"}"#);
        let file = || document.path().to_path_buf();

        for command in [
            MediatorCommand::List,
            MediatorCommand::Get { id: "m-1".to_owned() },
            MediatorCommand::Create(JsonFileArgs { file: file() }),
            MediatorCommand::Update {
                id: "m-1".to_owned(),
                file: file(),
            },
            MediatorCommand::Delete { id: "m-1".to_owned() },
        ] {
            run_shared(&client, SharedCommand::Mediators(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/mediators HTTP/1.1",
                "GET /api/v1/mediators/m-1 HTTP/1.1",
                "POST /api/v1/mediators HTTP/1.1",
                "PUT /api/v1/mediators/m-1 HTTP/1.1",
                "DELETE /api/v1/mediators/m-1 HTTP/1.1",
            ]
        );
    }
}
