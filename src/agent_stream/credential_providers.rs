//! `fabric agent-stream credential-providers`: the OAuth 2.0 and API-key
//! providers of an Agent Stream, run through the credential provider commands
//! Agent Gateway uses.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{CrudCommand, JsonFileArgs, SharedCommand};

#[derive(Debug, Subcommand)]
pub enum CredentialProviderCommand {
    /// List credential providers.
    ///
    /// Needs the credential_providers.view permission.
    List,
    /// Get a credential provider by ID.
    ///
    /// The ID is the ID column of `fabric agent-stream credential-providers
    /// list`. It is sent as given: a name is not looked up. Needs the
    /// credential_providers.view permission.
    Get {
        /// Credential provider ID, as `list` prints it.
        id: String,
    },
    /// Create a credential provider from a JSON document.
    ///
    /// The document carries `name`, `provider_id`, a machine name that goes
    /// into the OAuth callback path and cannot change later, and
    /// `provider_type`: `oauth2_authorization_code` (the default),
    /// `oauth2_client_credentials`, or `api_key`. An OAuth provider needs
    /// `token_endpoint`, `client_id_secret_ref` and
    /// `client_secret_secret_ref`, and an `oauth2_authorization_code` one also
    /// `authorization_endpoint`: Agent Stream saves a provider without it, but
    /// its first consent then fails. An `api_key` provider needs
    /// `api_key_secret_ref`. Each secret reference is a `secret_id` this token
    /// can reach. From a session login, `tenant_id` names the tenant that owns
    /// the new provider. An access token limited to a tenant always uses its
    /// own tenant and refuses another, and an appliance-wide access token
    /// refuses `tenant_id`. Needs the credential_providers.edit permission.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a credential provider from a JSON document.
    ///
    /// Agent Stream changes only the fields the document sets and keeps the
    /// rest. It checks every secret reference the provider ends up with, sent
    /// or kept, on each update, so even a rename is refused with "Secret
    /// reference is not accessible" once one of them is out of this token's
    /// reach. `provider_id` and the tenant do not change here; `fabric
    /// agent-stream tenant-ownership set credential-providers <ID> --tenant
    /// <TENANT>` changes the tenant. Needs the credential_providers.edit
    /// permission.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// Credential provider ID, as `list` prints it.
        id: String,
        /// JSON document carrying the fields to change. Use '-' to read from
        /// standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a credential provider by ID.
    ///
    /// The command asks for confirmation first unless you pass --yes, and
    /// Agent Stream does not check whether anything still uses the provider.
    /// Needs the credential_providers.delete permission.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Credential provider ID, as `list` prints it.
        id: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `credential-providers create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Add an API-key provider whose key is the secret with secret_id stripe-key:
    echo '{"name": "Stripe", "provider_id": "stripe", "provider_type": "api_key", "api_key_secret_ref": "stripe-key"}' \
      | fabric agent-stream credential-providers create --file -"#;

/// Examples shown at the bottom of `credential-providers update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Point a provider at another client secret:
    echo '{"client_secret_secret_ref": "github-client-secret-2"}' | fabric \
      agent-stream credential-providers update <id> --file -"#;

/// Examples shown at the bottom of `credential-providers delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Find the provider's ID, then delete it after the prompt:
    fabric agent-stream credential-providers list
    fabric agent-stream credential-providers delete <id>

  Delete it from a script, with no prompt:
    fabric agent-stream credential-providers delete <id> --yes"#;

impl CredentialProviderCommand {
    /// Whether this is a delete that asks for confirmation first, because
    /// --yes was not given.
    fn asks_before_deleting(&self) -> bool {
        matches!(self, Self::Delete { yes: false, .. })
    }
}

impl SharedCommand {
    /// The shared form of an Agent Stream credential provider command, which
    /// remembers whether a delete asks for confirmation first.
    pub(crate) fn credential_providers(command: CredentialProviderCommand) -> Self {
        Self::CredentialProviders {
            ask_first: command.asks_before_deleting(),
            command: command.into(),
        }
    }
}

impl From<CredentialProviderCommand> for CrudCommand {
    fn from(command: CredentialProviderCommand) -> Self {
        match command {
            CredentialProviderCommand::List => Self::List,
            CredentialProviderCommand::Get { id } => Self::Get { id },
            CredentialProviderCommand::Create(args) => Self::Create(args),
            CredentialProviderCommand::Update { id, file } => Self::Update { id, file },
            CredentialProviderCommand::Delete { id, .. } => Self::Delete { id },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{ScriptedPrompter, json_file, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, run_shared, run_shared_with},
    };

    const TOKEN: &str = "aspat_test";

    const PROVIDER: &str = r#"{"id":"cp-1","name":"Stripe","provider_id":"stripe","provider_type":"api_key","api_key_secret_ref":"stripe-key"}"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_credential_provider_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/credential-providers/cp-1", "HTTP/1.1 200 OK", PROVIDER),
            ("PUT /api/v1/credential-providers/cp-1", "HTTP/1.1 200 OK", PROVIDER),
            ("DELETE /api/v1/credential-providers/cp-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/credential-providers", "HTTP/1.1 201 Created", PROVIDER),
            ("GET /api/v1/credential-providers", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"name":"Stripe"}"#);
        let file = || document.path().to_path_buf();

        for command in [
            CredentialProviderCommand::List,
            CredentialProviderCommand::Get { id: "cp-1".to_owned() },
            CredentialProviderCommand::Create(JsonFileArgs { file: file() }),
            CredentialProviderCommand::Update {
                id: "cp-1".to_owned(),
                file: file(),
            },
            CredentialProviderCommand::Delete {
                id: "cp-1".to_owned(),
                yes: true,
            },
        ] {
            run_shared(&client, SharedCommand::credential_providers(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/credential-providers HTTP/1.1",
                "GET /api/v1/credential-providers/cp-1 HTTP/1.1",
                "POST /api/v1/credential-providers HTTP/1.1",
                "PUT /api/v1/credential-providers/cp-1 HTTP/1.1",
                "DELETE /api/v1/credential-providers/cp-1 HTTP/1.1",
            ]
        );
    }

    fn delete(yes: bool) -> SharedCommand {
        SharedCommand::credential_providers(CredentialProviderCommand::Delete { id: "cp-1".to_owned(), yes })
    }

    #[tokio::test]
    async fn a_declined_delete_names_the_provider_and_host_and_sends_no_delete() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/credential-providers/cp-1", "HTTP/1.1 200 OK", PROVIDER)]).await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), delete(false), Output::Table, &mut prompter)
            .await
            .expect("a declined delete is not an error");

        assert_eq!(prompter.questions, [format!("Delete credential provider 'Stripe' (cp-1) on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. Credential provider 'cp-1' was not deleted."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/credential-providers/cp-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_delete_answered_yes_sends_the_delete_after_the_question() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/credential-providers/cp-1", "HTTP/1.1 200 OK", PROVIDER),
            ("DELETE /api/v1/credential-providers/cp-1", "HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let mut prompter = ScriptedPrompter::answering(true);

        run_shared_with(&client(host.clone()), delete(false), Output::Table, &mut prompter)
            .await
            .expect("delete");

        assert_eq!(prompter.questions, [format!("Delete credential provider 'Stripe' (cp-1) on {host}?")]);
        assert!(prompter.aborted.is_empty(), "{:?}", prompter.aborted);
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/credential-providers/cp-1 HTTP/1.1", "DELETE /api/v1/credential-providers/cp-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn a_delete_with_yes_sends_the_delete_without_asking() {
        let (host, requests) =
            scripted_agent_stream(vec![("DELETE /api/v1/credential-providers/cp-1", "HTTP/1.1 204 No Content", "")])
                .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host), delete(true), Output::Table, &mut prompter)
            .await
            .expect("delete");

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/credential-providers/cp-1 HTTP/1.1"]);
    }
}
