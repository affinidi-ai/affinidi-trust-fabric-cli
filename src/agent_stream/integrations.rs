//! `fabric agent-stream integrations`: the integrations of an Agent Stream,
//! run through the integration commands Agent Gateway uses, plus the two
//! read-only routes only Agent Stream has. Testing and triggering an
//! integration sends a real message, so those routes are left to `api`.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Subcommand;

use crate::commands::{self, CrudCommand, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum IntegrationCommand {
    /// List integrations.
    ///
    /// An access token limited to a tenant lists only that tenant's
    /// integrations, and one limited to listed resources only those
    /// integrations. A governance audit integration (category `audit`) is
    /// listed only to a caller holding the audit.view permission. Needs the
    /// integrations.view permission.
    List,
    /// Get an integration by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream integrations list`. It
    /// is sent as given: a name is not looked up. Needs the integrations.view
    /// permission, and without the audit.view permission an audit integration
    /// (category `audit`) answers "not found".
    Get {
        /// Integration ID, as `list` prints it.
        id: String,
    },
    /// Create an integration from a JSON document.
    ///
    /// The document carries `name`, `description`, `type`, `configuration`,
    /// `content`, and `status` (`active` or `disabled`), and optionally
    /// `category` and `tenant_id`; `configuration` and `content` are JSON
    /// objects. `type` and
    /// `category` take a value `fabric agent-stream integrations config`
    /// lists, and `content` may use only the runtime variables of its
    /// category, which `integrations runtime-variables` lists, or custom ones
    /// starting with `_`. A top-level `configuration` key holds a credential
    /// when it is `url`, `webhook_url`, or `redis_url`, or ends in
    /// `password`, `secret`, `secret_key`, `api_key`, `apikey`, `token`,
    /// `private_key`, `access_key`, or `credentials`, and so does an entry of
    /// `headers` whose name contains `auth`, `cookie`, `cred`, `key`, `pass`,
    /// `secret`, `session`, or `token`. A credential is sent as a reference:
    /// `<key>_secret_id` names a secret by its id or `secret_id`, and
    /// `headers_secret_id` maps header names to secrets. Only
    /// `signing_secret`, of at least 32 characters, may be sent as a value,
    /// and so may a value made only of `${VARIABLE}` placeholders. Agent
    /// Stream does not check names, so a second create makes a copy: when a
    /// create's answer was lost, check `fabric agent-stream integrations list`
    /// before running it again.
    ///
    /// From a session login, `tenant_id` names the tenant that owns the new
    /// integration. An access token limited to a tenant always uses its own
    /// tenant and refuses another, and an appliance-wide access token refuses
    /// `tenant_id`. An `audit` category needs the audit.view permission and
    /// cannot carry a `tenant_id`. Needs the integrations.edit permission. A
    /// secret reference also needs the secrets.view permission, and where
    /// `secrets.reveal_values` is off, Agent Stream refuses any reference
    /// other than the delivery URL: `url` for a webhook, `webhook_url` for
    /// Slack, and `redis_url` for a Redis stream.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update an integration from a JSON document.
    ///
    /// The document replaces the integration's `name`, `description`,
    /// `type`, `category`, `configuration`, `content`, and `status`, so send
    /// them all: a `category` left out is cleared. A stored credential at
    /// the top level of `configuration`, or a credential entry of its
    /// top-level `headers`, that the document leaves out is kept, and `null`
    /// clears it, but any other nested value that the document leaves out is
    /// deleted. `fabric agent-stream api get /v1/integrations/<ID>` prints the
    /// stored configuration as Agent Stream returns it, nested values
    /// included. Agent Stream refuses to keep a credential when the update
    /// changes where the integration sends, so send its reference again then.
    /// A new or moved secret reference needs the secrets.view permission, and
    /// where `secrets.reveal_values` is off, Agent Stream refuses any
    /// reference other than the delivery URL. An audit integration, or a
    /// change to the `audit` category, needs the audit.view permission, and
    /// an `audit` integration cannot belong to a tenant. The tenant does not
    /// change here; `fabric agent-stream tenant-ownership set integrations
    /// <ID> --tenant <TENANT>` changes it. Needs the integrations.edit
    /// permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Integration ID, as `list` prints it.
        id: String,
        /// JSON document carrying every field of the integration. Use '-' to
        /// read from standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete an integration by ID.
    ///
    /// The command asks for confirmation first unless you pass --yes. Agent
    /// Stream also removes the integration from the trigger lists of
    /// `/v1/users/integrations`, `/v1/identities/integrations`, and
    /// `/v1/gateways/<ID>/integrations`. Needs the integrations.delete
    /// permission, and an audit integration also needs the audit.view
    /// permission.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Integration ID, as `list` prints it.
        id: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Show the integration types and categories this Agent Stream offers.
    ///
    /// Prints `types` and `categories`, each entry with its `enum_value`, the
    /// value a document's `type` or `category` takes, and `metadata`, such as
    /// a type's fields, and the `variable_pattern` placeholders in `content`
    /// follow. Needs a signed-in user, and an access token with explicit
    /// scopes needs the integrations.view permission.
    Config,
    /// List the runtime variables an integration's `content` can use, by
    /// category.
    ///
    /// Needs a signed-in user, and an access token with explicit scopes needs
    /// the integrations.view permission.
    #[command(name = "runtime-variables")]
    RuntimeVariables,
}

/// Examples shown at the bottom of `integrations create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Add an email integration whose SMTP password is the secret with secret_id
  smtp-key:
    fabric agent-stream integrations config
    fabric agent-stream integrations create --file integration.json
  where integration.json is:
    {
      "name": "mailer",
      "description": "",
      "type": "email",
      "category": "general",
      "configuration": {
        "smtp_host": "smtp.example.com",
        "smtp_password_secret_id": "smtp-key"
      },
      "content": {},
      "status": "active"
    }"#;

/// Examples shown at the bottom of `integrations update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Change an integration: save it, edit it, send it back. The saved copy leaves
  the stored credentials at the top level of `configuration` out, and sending
  it back keeps them. A credential nested deeper is saved as a placeholder:
  put the real value back in its place first, or update refuses the file.
  `fabric agent-stream api get /v1/integrations/<id>` prints the stored
  configuration as Agent Stream returns it, nested values included.
  Agent Stream replaces with no version check, so a change saved by someone
  else between the get and the update is lost:
    fabric agent-stream integrations get <id> --output json > integration.json
    fabric agent-stream integrations update <id> --file integration.json"#;

/// Examples shown at the bottom of `integrations delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Find the integration's ID, then delete it after the prompt:
    fabric agent-stream integrations list
    fabric agent-stream integrations delete <id>

  Delete it from a script, with no prompt:
    fabric agent-stream integrations delete <id> --yes"#;

/// Paths under `/v1/integrations` that are Agent Stream routes of their own,
/// so an integration ID never names them: `get`, `update`, or `delete` on one
/// would reach that route instead of an integration.
const SIBLING_ROUTES: [&str; 4] = ["config", "runtime-variables", "test", "trigger-multiple"];

impl IntegrationCommand {
    /// Whether this is a delete that asks for confirmation first, because
    /// --yes was not given.
    fn asks_before_deleting(&self) -> bool {
        matches!(self, Self::Delete { yes: false, .. })
    }
}

impl commands::SharedIntegrationCommand {
    /// Fails for a `get`, `update`, or `delete` whose ID is empty or names
    /// one of the [`SIBLING_ROUTES`], before anything is sent.
    pub(crate) fn refuse_sibling_route(&self) -> Result<()> {
        let Self::Crud(CrudCommand::Get { id } | CrudCommand::Update { id, .. } | CrudCommand::Delete { id }) = self
        else {
            return Ok(());
        };
        if id.is_empty() {
            bail!("the integration ID is empty. Nothing was sent");
        }
        if SIBLING_ROUTES.contains(&id.as_str()) {
            bail!(
                "'{id}' is a reserved route, not an integration ID; `fabric agent-stream integrations list` lists \
                 the IDs. Nothing was sent"
            );
        }
        Ok(())
    }
}

impl commands::SharedCommand {
    /// The shared form of an Agent Stream integration command, which
    /// remembers whether a delete asks for confirmation first.
    pub(crate) fn integrations(command: IntegrationCommand) -> Self {
        Self::Integrations {
            ask_first: command.asks_before_deleting(),
            command: command.into(),
        }
    }
}

impl From<IntegrationCommand> for commands::SharedIntegrationCommand {
    fn from(command: IntegrationCommand) -> Self {
        match command {
            IntegrationCommand::List => Self::Crud(CrudCommand::List),
            IntegrationCommand::Get { id } => Self::Crud(CrudCommand::Get { id }),
            IntegrationCommand::Create(args) => Self::Crud(CrudCommand::Create(args)),
            IntegrationCommand::Update { id, file } => Self::Crud(CrudCommand::Update { id, file }),
            IntegrationCommand::Delete { id, .. } => Self::Crud(CrudCommand::Delete { id }),
            IntegrationCommand::Config => Self::Config,
            IntegrationCommand::RuntimeVariables => Self::RuntimeVariables,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{
            ScriptedPrompter, json_file, run_stream, saved_login, scripted_agent_stream, start_lines,
        },
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared, run_shared_with},
    };

    const TOKEN: &str = "aspat_test";

    const INTEGRATION: &str = r#"{"id":"in-1","name":"mailer","description":"","type":"email","category":"general","configuration":{"smtp_host":"smtp.example.com","smtp_password_secret_id":"smtp-key"},"content":{},"status":"active"}"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_integration_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/integrations/config", "HTTP/1.1 200 OK", r#"{"types":[],"categories":[]}"#),
            ("GET /api/v1/integrations/runtime-variables", "HTTP/1.1 200 OK", r#"{"categories":[]}"#),
            ("GET /api/v1/integrations/in-1", "HTTP/1.1 200 OK", INTEGRATION),
            ("PUT /api/v1/integrations/in-1", "HTTP/1.1 200 OK", INTEGRATION),
            ("DELETE /api/v1/integrations/in-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/integrations", "HTTP/1.1 201 Created", INTEGRATION),
            ("GET /api/v1/integrations", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = json_file(INTEGRATION);
        let file = || document.path().to_path_buf();

        for command in [
            IntegrationCommand::List,
            IntegrationCommand::Get { id: "in-1".to_owned() },
            IntegrationCommand::Create(JsonFileArgs { file: file() }),
            IntegrationCommand::Update {
                id: "in-1".to_owned(),
                file: file(),
            },
            IntegrationCommand::Delete {
                id: "in-1".to_owned(),
                yes: true,
            },
            IntegrationCommand::Config,
            IntegrationCommand::RuntimeVariables,
        ] {
            run_shared(&client, SharedCommand::integrations(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/integrations HTTP/1.1",
                "GET /api/v1/integrations/in-1 HTTP/1.1",
                "POST /api/v1/integrations HTTP/1.1",
                "PUT /api/v1/integrations/in-1 HTTP/1.1",
                "DELETE /api/v1/integrations/in-1 HTTP/1.1",
                "GET /api/v1/integrations/config HTTP/1.1",
                "GET /api/v1/integrations/runtime-variables HTTP/1.1",
            ]
        );
    }

    fn delete(yes: bool) -> SharedCommand {
        SharedCommand::integrations(IntegrationCommand::Delete { id: "in-1".to_owned(), yes })
    }

    #[tokio::test]
    async fn a_declined_delete_names_the_integration_and_host_and_sends_no_delete() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/integrations/in-1", "HTTP/1.1 200 OK", INTEGRATION)]).await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), delete(false), Output::Table, &mut prompter)
            .await
            .expect("a declined delete is not an error");

        assert_eq!(prompter.questions, [format!("Delete integration 'mailer' (in-1) on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. Integration 'in-1' was not deleted."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/integrations/in-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_confirmed_delete_sends_the_delete_after_asking() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/integrations/in-1", "HTTP/1.1 200 OK", INTEGRATION),
            ("DELETE /api/v1/integrations/in-1", "HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let mut prompter = ScriptedPrompter::answering(true);

        run_shared_with(&client(host), delete(false), Output::Table, &mut prompter)
            .await
            .expect("the delete is confirmed");

        assert_eq!(prompter.questions.len(), 1, "{:?}", prompter.questions);
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/integrations/in-1 HTTP/1.1", "DELETE /api/v1/integrations/in-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn a_delete_with_yes_sends_the_delete_without_asking() {
        let (host, requests) =
            scripted_agent_stream(vec![("DELETE /api/v1/integrations/in-1", "HTTP/1.1 204 No Content", "")]).await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host), delete(true), Output::Table, &mut prompter)
            .await
            .expect("delete");

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/integrations/in-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn an_id_naming_a_sibling_route_or_empty_is_refused_before_anything_is_sent() {
        let (host, requests) = scripted_agent_stream(Vec::new()).await;

        for words in [
            &["integrations", "get", "config"][..],
            &["integrations", "get", "runtime-variables"],
            &["integrations", "update", "test", "--file", "integration.json"],
            &["integrations", "delete", "trigger-multiple", "--yes"],
            &["integrations", "get", ""],
        ] {
            let (saved, credentials) = saved_login(&host, TOKEN);
            let error = run_stream(words, saved, &credentials)
                .await
                .expect_err("the ID is not an integration");

            assert!(
                error
                    .to_string()
                    .ends_with("Nothing was sent"),
                "{words:?}: {error:#}"
            );
        }
        assert!(start_lines(&requests).is_empty(), "{:?}", start_lines(&requests));
    }

    #[test]
    fn an_ordinary_id_and_the_commands_without_one_pass_the_route_check() {
        for command in [
            IntegrationCommand::List,
            IntegrationCommand::Get { id: "in-1".to_owned() },
            IntegrationCommand::Config,
            IntegrationCommand::RuntimeVariables,
        ] {
            assert!(
                commands::SharedIntegrationCommand::from(command)
                    .refuse_sibling_route()
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn a_terms_gate_failure_on_an_integration_route_gets_the_terms_hint() {
        let body = r#"{"code":"TERMS_OPERATIONAL_FAILURE"}"#;
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/integrations/config", "HTTP/1.1 503 Service Unavailable", body)])
                .await;
        let (saved, credentials) = saved_login(&host, TOKEN);

        let error = run_stream(&["integrations", "config"], saved, &credentials)
            .await
            .expect_err("the Terms gate refuses the read");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "the upstream terms provider is unavailable; check `fabric agent-stream terms provider-health`: {body}"
            )
        );
    }
}
