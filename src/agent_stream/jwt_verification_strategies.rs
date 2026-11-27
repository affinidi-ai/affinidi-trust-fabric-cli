//! `fabric agent-stream jwt-verification-strategies`: the JWT verification
//! strategies of an Agent Stream, run through the strategy commands Agent
//! Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{self, CrudCommand, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum JwtStrategyCommand {
    /// List JWT verification strategies.
    ///
    /// Needs the jwt_verification_strategies.view permission.
    List,
    /// Get a JWT verification strategy by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream
    /// jwt-verification-strategies list`. It is sent as given: a name is not
    /// looked up. Needs the jwt_verification_strategies.view permission.
    Get {
        /// Strategy ID, as `list` prints it.
        id: String,
    },
    /// Create a JWT verification strategy from a JSON document.
    ///
    /// The document carries `name`, `expected_issuer`, `jwks_source`, and
    /// optionally `tenant_id`, where `jwks_source` is `{"type": "remote",
    /// "jwks_uri": ...}` or `{"type": "static", "jwks": [...]}`. From a
    /// session login, `tenant_id` names the tenant that owns the new strategy.
    /// An access token limited to a tenant always uses its own tenant and
    /// refuses another, and an appliance-wide access token refuses
    /// `tenant_id`. Needs the jwt_verification_strategies.edit permission.
    Create(JsonFileArgs),
    /// Update a JWT verification strategy from a JSON document.
    ///
    /// The document replaces the strategy's `name`, `expected_issuer` and
    /// `jwks_source`, so send all three. `tenant_id` is ignored and the
    /// strategy keeps its tenant; `fabric agent-stream tenant-ownership set
    /// jwt-verification-strategies <ID> --tenant <TENANT>` changes it. Needs
    /// the jwt_verification_strategies.edit permission.
    Update {
        /// Strategy ID, as `list` prints it.
        id: String,
        /// JSON document with `name`, `expected_issuer` and `jwks_source`.
        /// Use '-' to read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a JWT verification strategy by ID.
    ///
    /// The command asks for confirmation first unless you pass --yes, and
    /// Agent Stream does not check whether anything still uses the strategy.
    /// Needs the jwt_verification_strategies.delete permission.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Strategy ID, as `list` prints it.
        id: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Check that a JWKS URI is reachable and serves a parseable key set.
    ///
    /// Agent Stream fetches the URI and reports `valid` and `key_count`.
    /// Nothing is saved. A URI that cannot be fetched or parsed exits non-zero
    /// with Agent Stream's reason. Run this before pointing a strategy's
    /// `jwks_source` at the URI. Needs the jwt_verification_strategies.edit
    /// permission.
    #[command(name = "validate-jwks-uri")]
    ValidateJwksUri {
        /// URI of the JSON Web Key Set, for example
        /// https://idp.example.com/.well-known/jwks.json.
        uri: String,
    },
}

/// Examples shown at the bottom of `jwt-verification-strategies --help`.
pub const EXAMPLES: &str = r#"Examples:
  Check a remote key set, then create a strategy that uses it:
    JWKS=https://idp.example.com/.well-known/jwks.json
    fabric agent-stream jwt-verification-strategies validate-jwks-uri "$JWKS"
    fabric agent-stream jwt-verification-strategies create --file strategy.json
  where strategy.json is:
    {
      "name": "Partner IdP",
      "expected_issuer": "https://idp.example.com/",
      "jwks_source": {
        "type": "remote",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json"
      }
    }

  Pin the keys in the document instead of fetching them:
    "jwks_source": {
      "type": "static",
      "jwks": [{"kty": "RSA", "kid": "2026-09", "n": "...", "e": "AQAB"}]
    }

  Change a strategy: save it, edit it, send it back:
    fabric agent-stream jwt-verification-strategies get <id> --output json > \
      strategy.json
    fabric agent-stream jwt-verification-strategies update <id> \
      --file strategy.json"#;

/// Examples shown at the bottom of `jwt-verification-strategies delete
/// --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Find the strategy's ID, then delete it after the prompt:
    fabric agent-stream jwt-verification-strategies list
    fabric agent-stream jwt-verification-strategies delete <id>

  Delete it from a script, with no prompt:
    fabric agent-stream jwt-verification-strategies delete <id> --yes"#;

impl JwtStrategyCommand {
    /// Whether this is a delete that asks for confirmation first, because
    /// --yes was not given.
    fn asks_before_deleting(&self) -> bool {
        matches!(self, Self::Delete { yes: false, .. })
    }
}

impl commands::SharedCommand {
    /// The shared form of an Agent Stream strategy command, which remembers
    /// whether a delete asks for confirmation first.
    pub(crate) fn jwt_verification_strategies(command: JwtStrategyCommand) -> Self {
        Self::JwtVerificationStrategies {
            ask_first: command.asks_before_deleting(),
            command: command.into(),
        }
    }
}

impl From<JwtStrategyCommand> for commands::JwtStrategyCommand {
    fn from(command: JwtStrategyCommand) -> Self {
        match command {
            JwtStrategyCommand::List => Self::Crud(CrudCommand::List),
            JwtStrategyCommand::Get { id } => Self::Crud(CrudCommand::Get { id }),
            JwtStrategyCommand::Create(args) => Self::Crud(CrudCommand::Create(args)),
            JwtStrategyCommand::Update { id, file } => Self::Crud(CrudCommand::Update { id, file }),
            JwtStrategyCommand::Delete { id, .. } => Self::Crud(CrudCommand::Delete { id }),
            JwtStrategyCommand::ValidateJwksUri { uri } => Self::ValidateJwksUri { uri },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{ScriptedPrompter, json_file, request_body, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared, run_shared_with},
    };

    const TOKEN: &str = "aspat_test";

    const STRATEGY: &str = r#"{"id":"j-1","name":"Partner IdP","expected_issuer":"https://idp.example.com/","jwks_source":{"type":"remote","jwks_uri":"https://idp.example.com/jwks.json"}}"#;

    const JWKS_URI: &str = "https://idp.example.com/jwks.json";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_strategy_route() {
        let (host, requests) = scripted_agent_stream(vec![
            (
                "POST /api/v1/jwt-verification-strategies/validate-jwks-uri",
                "HTTP/1.1 200 OK",
                r#"{"valid":true,"key_count":1}"#,
            ),
            ("GET /api/v1/jwt-verification-strategies/j-1", "HTTP/1.1 200 OK", STRATEGY),
            ("PUT /api/v1/jwt-verification-strategies/j-1", "HTTP/1.1 200 OK", STRATEGY),
            ("DELETE /api/v1/jwt-verification-strategies/j-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/jwt-verification-strategies", "HTTP/1.1 201 Created", STRATEGY),
            ("GET /api/v1/jwt-verification-strategies", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = json_file(STRATEGY);
        let file = || document.path().to_path_buf();

        for command in [
            JwtStrategyCommand::List,
            JwtStrategyCommand::Get { id: "j-1".to_owned() },
            JwtStrategyCommand::Create(JsonFileArgs { file: file() }),
            JwtStrategyCommand::Update {
                id: "j-1".to_owned(),
                file: file(),
            },
            JwtStrategyCommand::Delete {
                id: "j-1".to_owned(),
                yes: true,
            },
            JwtStrategyCommand::ValidateJwksUri { uri: JWKS_URI.to_owned() },
        ] {
            run_shared(&client, SharedCommand::jwt_verification_strategies(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/jwt-verification-strategies HTTP/1.1",
                "GET /api/v1/jwt-verification-strategies/j-1 HTTP/1.1",
                "POST /api/v1/jwt-verification-strategies HTTP/1.1",
                "PUT /api/v1/jwt-verification-strategies/j-1 HTTP/1.1",
                "DELETE /api/v1/jwt-verification-strategies/j-1 HTTP/1.1",
                "POST /api/v1/jwt-verification-strategies/validate-jwks-uri HTTP/1.1",
            ]
        );
        let sent: serde_json::Value = serde_json::from_str(request_body(&requests.lock().unwrap()[5])).expect("JSON");
        assert_eq!(sent, serde_json::json!({"uri": JWKS_URI}));
    }

    fn delete(yes: bool) -> SharedCommand {
        SharedCommand::jwt_verification_strategies(JwtStrategyCommand::Delete { id: "j-1".to_owned(), yes })
    }

    #[tokio::test]
    async fn a_declined_delete_names_the_strategy_and_host_and_sends_no_delete() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/jwt-verification-strategies/j-1", "HTTP/1.1 200 OK", STRATEGY)])
                .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), delete(false), Output::Table, &mut prompter)
            .await
            .expect("a declined delete is not an error");

        assert_eq!(prompter.questions, [format!("Delete JWT verification strategy 'Partner IdP' (j-1) on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. JWT verification strategy 'j-1' was not deleted."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/jwt-verification-strategies/j-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_delete_with_yes_sends_the_delete_without_asking() {
        let (host, requests) = scripted_agent_stream(vec![(
            "DELETE /api/v1/jwt-verification-strategies/j-1",
            "HTTP/1.1 204 No Content",
            "",
        )])
        .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host), delete(true), Output::Table, &mut prompter)
            .await
            .expect("delete");

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/jwt-verification-strategies/j-1 HTTP/1.1"]);
    }
}
