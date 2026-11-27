//! `fabric agent-stream delegation-vault`: the delegated credential grants of
//! an Agent Stream, run through the delegation vault commands Agent Gateway
//! uses.

use clap::Subcommand;

use crate::commands;

#[derive(Debug, Subcommand)]
pub enum DelegationVaultCommand {
    /// List delegated credential grants.
    ///
    /// A grant's access and refresh tokens are never printed: Agent Stream
    /// answers with the grant's details only, and the CLI removes either token
    /// should one appear. Needs the delegation_vault.view permission.
    List,
    /// Get a grant by ID.
    ///
    /// A grant's access and refresh tokens are never printed: Agent Stream
    /// answers with the grant's details only, and the CLI removes either token
    /// should one appear. Needs the delegation_vault.view permission.
    Get {
        /// Grant ID, from the ID column of `fabric agent-stream
        /// delegation-vault list`.
        id: String,
    },
    /// Revoke a single grant by ID.
    ///
    /// The command asks for confirmation first unless you pass --yes, and a
    /// revoke cannot be undone. To revoke every grant a user holds, use
    /// `revoke-user`. Needs the delegation_vault.delete permission.
    #[command(after_long_help = REVOKE_EXAMPLES)]
    Revoke {
        /// Grant ID, from the ID column of `fabric agent-stream
        /// delegation-vault list`.
        id: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Revoke every grant held for one user identity hash.
    ///
    /// Revokes all of that user's grants at once, and a revoke cannot be
    /// undone. Unless you pass --yes, the command first counts the grants the
    /// grant list shows for the hash and names that number in its question;
    /// when it shows none, the command says so and revokes nothing. The revoke
    /// itself removes every grant the hash has when it runs, so the result
    /// line reports the real number. Counting needs
    /// the delegation_vault.view permission: without it, the question names
    /// every grant of the hash instead. With --yes nothing is counted, and a
    /// hash no grant carries revokes nothing. Table output reports how many
    /// grants were revoked; `--output json` prints {"revoked": N}. Needs the
    /// delegation_vault.delete permission.
    #[command(name = "revoke-user")]
    #[command(after_long_help = REVOKE_USER_EXAMPLES)]
    RevokeUser {
        /// The user's identity hash, as the user_identity_hash field of
        /// `delegation-vault list --output json` shows it.
        user_hash: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `delegation-vault revoke --help`.
const REVOKE_EXAMPLES: &str = r#"Examples:
  Find the grant's ID, then revoke it after the prompt:
    fabric agent-stream delegation-vault list
    fabric agent-stream delegation-vault revoke <grant-id>

  Revoke it from a script, with no prompt:
    fabric agent-stream delegation-vault revoke <grant-id> --yes"#;

/// Examples shown at the bottom of `delegation-vault revoke-user --help`.
const REVOKE_USER_EXAMPLES: &str = r#"Examples:
  Show each grant's ID, agent and user hash, then revoke every grant one user
  holds after the prompt:
    fabric agent-stream delegation-vault list --output json | jq \
      -r '.[] | [.id, .agent_did, .user_identity_hash] | @tsv'
    fabric agent-stream delegation-vault revoke-user <user-hash>

  Revoke them from a script, with no prompt:
    fabric agent-stream delegation-vault revoke-user <user-hash> --yes"#;

impl DelegationVaultCommand {
    /// Whether this is a revoke that asks for confirmation first, because
    /// --yes was not given.
    fn asks_before_revoking(&self) -> bool {
        matches!(self, Self::Revoke { yes: false, .. } | Self::RevokeUser { yes: false, .. })
    }
}

impl commands::SharedCommand {
    /// The shared form of an Agent Stream delegation vault command, which
    /// remembers whether a revoke asks for confirmation first.
    pub(crate) fn delegation_vault(command: DelegationVaultCommand) -> Self {
        Self::DelegationVault {
            ask_first: command.asks_before_revoking(),
            command: command.into(),
        }
    }
}

impl From<DelegationVaultCommand> for commands::DelegationVaultCommand {
    fn from(command: DelegationVaultCommand) -> Self {
        match command {
            DelegationVaultCommand::List => Self::List,
            DelegationVaultCommand::Get { id } => Self::Get { id },
            DelegationVaultCommand::Revoke { id, .. } => Self::Revoke { id },
            DelegationVaultCommand::RevokeUser { user_hash, .. } => Self::RevokeUser { user_hash },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{ScriptedPrompter, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared, run_shared_with},
    };

    const TOKEN: &str = "aspat_test";

    const USER_HASH: &str = "3f9a0c";

    /// A grant list with three grants of [`USER_HASH`], one of another user,
    /// and one whose hash only starts with [`USER_HASH`].
    const THREE_GRANTS_OF_USER_HASH: &str = r#"[
        {"id":"g-1","user_identity_hash":"3f9a0c"},
        {"id":"g-2","user_identity_hash":"77ab01"},
        {"id":"g-3","user_identity_hash":"3f9a0c"},
        {"id":"g-4","user_identity_hash":"3f9a0c0"},
        {"id":"g-5","user_identity_hash":"3f9a0c"}
    ]"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_delegation_vault_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("DELETE /api/v1/delegation-vault/by-user/3f9a0c", "HTTP/1.1 200 OK", r#"{"revoked":2}"#),
            ("GET /api/v1/delegation-vault/g-1", "HTTP/1.1 200 OK", r#"{"id":"g-1"}"#),
            ("DELETE /api/v1/delegation-vault/g-1", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/delegation-vault", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);

        for command in [
            DelegationVaultCommand::List,
            DelegationVaultCommand::Get { id: "g-1".to_owned() },
            DelegationVaultCommand::Revoke {
                id: "g-1".to_owned(),
                yes: true,
            },
            DelegationVaultCommand::RevokeUser {
                user_hash: USER_HASH.to_owned(),
                yes: true,
            },
        ] {
            run_shared(&client, SharedCommand::delegation_vault(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/delegation-vault HTTP/1.1",
                "GET /api/v1/delegation-vault/g-1 HTTP/1.1",
                "DELETE /api/v1/delegation-vault/g-1 HTTP/1.1",
                "DELETE /api/v1/delegation-vault/by-user/3f9a0c HTTP/1.1",
            ]
        );
    }

    fn revoke(yes: bool) -> SharedCommand {
        SharedCommand::delegation_vault(DelegationVaultCommand::Revoke { id: "g-1".to_owned(), yes })
    }

    fn revoke_user(yes: bool) -> SharedCommand {
        SharedCommand::delegation_vault(DelegationVaultCommand::RevokeUser {
            user_hash: USER_HASH.to_owned(),
            yes,
        })
    }

    #[tokio::test]
    async fn a_declined_revoke_names_the_grant_and_host_and_sends_no_revoke() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/delegation-vault/g-1", "HTTP/1.1 200 OK", r#"{"id":"g-1"}"#)])
                .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), revoke(false), Output::Table, &mut prompter)
            .await
            .expect("a declined revoke is not an error");

        assert_eq!(prompter.questions, [format!("Revoke grant g-1 on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. Grant 'g-1' was not revoked."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/delegation-vault/g-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_declined_revoke_user_says_how_many_grants_the_hash_has_and_sends_no_revoke() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/delegation-vault", "HTTP/1.1 200 OK", THREE_GRANTS_OF_USER_HASH)])
                .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), revoke_user(false), Output::Table, &mut prompter)
            .await
            .expect("a declined revoke is not an error");

        assert_eq!(prompter.questions, [format!("Revoke 3 grants of user hash 3f9a0c on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. The grants of user hash '3f9a0c' were not revoked."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/delegation-vault HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_revoke_user_whose_hash_has_no_grants_says_so_without_asking_or_revoking() {
        let (host, requests) = scripted_agent_stream(vec![(
            "GET /api/v1/delegation-vault",
            "HTTP/1.1 200 OK",
            r#"[{"id":"g-9","user_identity_hash":"3f9a0c0"}]"#,
        )])
        .await;
        let mut prompter = ScriptedPrompter::answering(true);

        run_shared_with(&client(host.clone()), revoke_user(false), Output::Table, &mut prompter)
            .await
            .expect("a hash with no grants is not an error");

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(prompter.aborted, [format!("No grants of user hash '3f9a0c' on {host}; nothing was revoked.")]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/delegation-vault HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_revoke_user_question_shows_the_typed_hash_without_terminal_controls() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/delegation-vault", "HTTP/1.1 200 OK", "[]")]).await;
        let mut prompter = ScriptedPrompter::answering(true);
        let command = SharedCommand::delegation_vault(DelegationVaultCommand::RevokeUser {
            user_hash: "3f9a\u{1b}[2J0c\n".to_owned(),
            yes: false,
        });

        run_shared_with(&client(host.clone()), command, Output::Table, &mut prompter)
            .await
            .expect("a hash with no grants is not an error");

        assert_eq!(prompter.aborted, [format!("No grants of user hash '3f9a[2J0c ' on {host}; nothing was revoked.")]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/delegation-vault HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_revoke_user_whose_grant_list_is_refused_still_asks_about_every_grant() {
        let (host, requests) = scripted_agent_stream(vec![(
            "GET /api/v1/delegation-vault",
            "HTTP/1.1 403 Forbidden",
            r#"{"error":"access token scope does not include 'delegation_vault.view'","required_permission":"delegation_vault.view"}"#,
        )])
        .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), revoke_user(false), Output::Table, &mut prompter)
            .await
            .expect("a declined revoke is not an error");

        assert_eq!(prompter.questions, [format!("Revoke every grant of user hash 3f9a0c on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. The grants of user hash '3f9a0c' were not revoked."]);
        assert_eq!(start_lines(&requests), ["GET /api/v1/delegation-vault HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_revoke_or_revoke_user_answered_yes_sends_it_after_the_question() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/delegation-vault/g-1", "HTTP/1.1 200 OK", r#"{"id":"g-1"}"#),
            ("DELETE /api/v1/delegation-vault/g-1", "HTTP/1.1 204 No Content", ""),
            (
                "GET /api/v1/delegation-vault",
                "HTTP/1.1 200 OK",
                r#"[{"id":"g-1","user_identity_hash":"3f9a0c"},{"id":"g-2","user_identity_hash":"77ab01"}]"#,
            ),
            ("DELETE /api/v1/delegation-vault/by-user/3f9a0c", "HTTP/1.1 200 OK", r#"{"revoked":1}"#),
        ])
        .await;
        let client = client(host.clone());
        let mut prompter = ScriptedPrompter::answering(true);

        for command in [revoke(false), revoke_user(false)] {
            run_shared_with(&client, command, Output::Json, &mut prompter)
                .await
                .expect("revoke");
        }

        assert_eq!(
            prompter.questions,
            [format!("Revoke grant g-1 on {host}?"), format!("Revoke 1 grant of user hash 3f9a0c on {host}?")]
        );
        assert!(prompter.aborted.is_empty(), "{:?}", prompter.aborted);
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/delegation-vault/g-1 HTTP/1.1",
                "DELETE /api/v1/delegation-vault/g-1 HTTP/1.1",
                "GET /api/v1/delegation-vault HTTP/1.1",
                "DELETE /api/v1/delegation-vault/by-user/3f9a0c HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn a_revoke_or_revoke_user_with_yes_sends_it_without_asking() {
        let (host, requests) = scripted_agent_stream(vec![
            ("DELETE /api/v1/delegation-vault/by-user/3f9a0c", "HTTP/1.1 200 OK", r#"{"revoked":2}"#),
            ("DELETE /api/v1/delegation-vault/g-1", "HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let client = client(host);
        let mut prompter = ScriptedPrompter::answering(false);

        for command in [revoke(true), revoke_user(true)] {
            run_shared_with(&client, command, Output::Json, &mut prompter)
                .await
                .expect("revoke");
        }

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(
            start_lines(&requests),
            ["DELETE /api/v1/delegation-vault/g-1 HTTP/1.1", "DELETE /api/v1/delegation-vault/by-user/3f9a0c HTTP/1.1",]
        );
    }
}
