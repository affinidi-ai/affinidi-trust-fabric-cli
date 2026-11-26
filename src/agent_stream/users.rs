//! `fabric agent-stream users`: the users of an Agent Stream, run through the
//! user commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

use crate::{
    client::GatewayClient,
    commands::{self, Output, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List users.
    List,
    /// Get a user by ID.
    ///
    /// `integrations` is a reserved sibling route and returns the
    /// integration assignments rather than a user.
    Get {
        /// User's ID, as `list` prints it, not the username.
        user_id: String,
    },
    /// Update a user's role, status, or profile from a JSON document.
    ///
    /// Fields the document omits keep their current values. `role` is
    /// `administrator`, `poweruser` or `user`, and `status` is `new`,
    /// `approved` or `disabled`. Only an administrator can change a role or a
    /// status. Changing a user's role, or moving them out of `approved`, ends
    /// their active sessions. The ID `integrations` is refused: it is a
    /// reserved route, not a user.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// User's ID, as `list` prints it.
        user_id: String,
        /// JSON document carrying any of `role`, `status`, `first_name`,
        /// `last_name`, `email`, `department`, `job_title`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a user by ID.
    ///
    /// It runs at once, with no confirmation prompt. The user's access tokens
    /// are revoked and their active sessions end. A user who signs in through
    /// an OpenID or SAML provider is not removed: Agent Stream keeps the
    /// record, disabled, and refuses their sign-ins through that provider.
    /// Table output then says `Disabled user` instead of `Deleted user`. With
    /// --output json the answer's `outcome` is `removed` or `disabled`. Agent
    /// Stream refuses to delete an administrator or your own account.
    Delete {
        /// User's ID, as `list` prints it, not the username.
        user_id: String,
    },
}

/// Examples shown at the bottom of `users update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Approve a new user:
    echo '{"status": "approved"}' | fabric agent-stream users update \
      <user-id> --file -

  Make a user a power user and set their job title:
    fabric agent-stream users update <user-id> --file user.json
  where user.json is:
    {"role": "poweruser", "job_title": "Platform engineer"}

  Disable a user, which also ends their sessions:
    echo '{"status": "disabled"}' | fabric agent-stream users update \
      <user-id> --file -"#;

/// Runs one `users` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: UserCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::Users(command.into()), output).await
}

impl From<UserCommand> for commands::UserCommand {
    fn from(command: UserCommand) -> Self {
        match command {
            UserCommand::List => Self::List,
            UserCommand::Get { user_id } => Self::Get { user_id },
            UserCommand::Update { user_id, file } => Self::Update { user_id, file },
            UserCommand::Delete { user_id } => Self::Delete { user_id },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_stream::test_support::{scripted_agent_stream, start_lines};

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_user_route() {
        let user = r#"{"user_id":"u-1","username":"ada","role":"user","status":"approved"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/users/u-1", "HTTP/1.1 200 OK", user),
            ("PUT /api/v1/users/u-1", "HTTP/1.1 200 OK", user),
            ("DELETE /api/v1/users/u-1", "HTTP/1.1 200 OK", r#"{"outcome":"disabled"}"#),
            ("GET /api/v1/users", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let update = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(update.path(), r#"{"status":"approved"}"#).expect("write the document");

        for command in [
            UserCommand::List,
            UserCommand::Get { user_id: "u-1".to_owned() },
            UserCommand::Update {
                user_id: "u-1".to_owned(),
                file: update.path().to_path_buf(),
            },
            UserCommand::Delete { user_id: "u-1".to_owned() },
        ] {
            run(&client, command, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/users HTTP/1.1",
                "GET /api/v1/users/u-1 HTTP/1.1",
                "PUT /api/v1/users/u-1 HTTP/1.1",
                "DELETE /api/v1/users/u-1 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn update_refuses_the_reserved_integrations_route_and_names_the_agent_stream_api_command() {
        let (host, requests) = scripted_agent_stream(vec![]).await;

        let error = run(
            &client(host),
            UserCommand::Update {
                user_id: "integrations".to_owned(),
                file: PathBuf::from("/nonexistent/user.json"),
            },
            Output::Table,
        )
        .await
        .expect_err("a PUT there replaces every user-integration assignment");

        assert_eq!(
            error.to_string(),
            "'integrations' is a reserved route, not a user id; use `fabric agent-stream api put \
             /v1/users/integrations --file <file>` to rewrite the assignments"
        );
        assert!(start_lines(&requests).is_empty());
    }
}
