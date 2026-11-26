//! `fabric agent-stream tokens`: the access tokens of an Agent Stream, run
//! through the access token commands Agent Gateway uses.

use anyhow::Result;
use clap::Subcommand;

use crate::{
    client::GatewayClient,
    commands::{
        AccessTokenCommand, AccessTokenCreateArgs, AccessTokenRevokeArgs, AccessTokenRotateArgs, Output,
        run_access_tokens,
    },
};

/// The help of a token ID argument, in place of the Agent Gateway one.
const ID_HELP: &str = "ID of the access token (see `fabric agent-stream tokens list`)";

/// The help of `tokens create --scope`, in place of the Agent Gateway one.
const SCOPE_HELP: &str = "Scope to grant the token. Repeat for multiple scopes. Required unless --full-role is given; \
                          run `fabric agent-stream tokens scopes` to see what you can grant";

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// List access tokens.
    ///
    /// STATUS is REVOKED for a token that has been revoked or has expired, and
    /// ACTIVE otherwise. SCOPES is shortened to fit and ends with "+N more" for
    /// the scopes left out; a token with no scope list holds its creator's
    /// whole role and shows "full role". EXPIRES is "never" for a token
    /// without an expiry. Use `tokens get` or --output json for the full scope
    /// list.
    List,
    /// Get an access token by ID.
    Get {
        /// ID of the access token (see `fabric agent-stream tokens list`).
        id: String,
    },
    /// Create an access token using flags or a complete JSON document.
    ///
    /// Give at least one --scope (or a `scopes` list in --file), or --full-role
    /// for your whole role. The token expires after 90 days unless you set
    /// --expires-at, at most 3650 days ahead; it can't be made to never expire.
    ///
    /// The secret is shown only once. In table output it is printed alone on
    /// standard output, so `ASPAT=$(...)` captures it; with --output json the
    /// whole response is printed.
    #[command(after_long_help = CREATE_EXAMPLES, mut_arg("scopes", |arg| arg.help(SCOPE_HELP)))]
    Create(AccessTokenCreateArgs),
    /// Revoke an access token.
    ///
    /// Takes the token's ID, not its name. There is no command to undo a
    /// revoke, and if this CLI is logged in with the token, its saved
    /// connection stops working too. You are asked to confirm, and only `y` or
    /// `yes` revokes. Without a terminal the command refuses before sending
    /// anything unless --yes is given.
    #[command(after_long_help = REVOKE_EXAMPLES, mut_arg("id", |arg| arg.help(ID_HELP)))]
    Revoke(AccessTokenRevokeArgs),
    /// List the scopes this login holds, which you can give a new token.
    ///
    /// With a session, the list is what your role can do. With an access
    /// token that has its own scope list, Agent Stream narrows it to the
    /// scopes that token holds as well.
    Scopes,
    /// Replace an access token's secret, keeping its ID, name, and scopes.
    ///
    /// The current secret stops working immediately, so update every script
    /// that uses it; if this CLI is logged in with the token, log in again with
    /// the new secret. The new secret is shown only once: in table output it is
    /// printed alone on standard output, and the "Rotated access token" line
    /// goes to standard error. You are asked to confirm; without a terminal the
    /// command refuses unless --yes is given.
    #[command(after_long_help = ROTATE_EXAMPLES, mut_arg("id", |arg| arg.help(ID_HELP)))]
    Rotate(AccessTokenRotateArgs),
}

/// Examples shown at the bottom of `tokens create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a token for a CI job and capture its secret:
    ASPAT=$(fabric agent-stream tokens create --name ci-deploy \
      --scope pipes.view --scope pipes.edit \
      --expires-at 2027-01-01T00:00:00Z)

  Create a token from a JSON document on standard input:
    echo '{"name": "ci-read", "scopes": ["pipes.view"]}' | fabric \
      agent-stream tokens create --file -"#;

/// Examples shown at the bottom of `tokens revoke --help`.
const REVOKE_EXAMPLES: &str = r#"Examples:
  Find the token's ID, then revoke it after confirming:
    fabric agent-stream tokens list
    fabric agent-stream tokens revoke <token-id>

  Revoke without the prompt, for scripts:
    fabric agent-stream tokens revoke <token-id> --yes"#;

/// Examples shown at the bottom of `tokens rotate --help`.
const ROTATE_EXAMPLES: &str = r#"Examples:
  Rotate a token after confirming:
    fabric agent-stream tokens rotate <token-id>

  Rotate from a script and capture the new secret:
    ASPAT=$(fabric agent-stream tokens rotate <token-id> --yes)"#;

/// Runs one `tokens` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: TokenCommand,
    output: Output,
) -> Result<()> {
    run_access_tokens(client, command.into(), output).await
}

impl From<TokenCommand> for AccessTokenCommand {
    fn from(command: TokenCommand) -> Self {
        match command {
            TokenCommand::List => Self::List,
            TokenCommand::Get { id } => Self::Get { id },
            TokenCommand::Create(args) => Self::Create(args),
            TokenCommand::Revoke(args) => Self::Revoke(args),
            TokenCommand::Scopes => Self::Scopes,
            TokenCommand::Rotate(args) => Self::Rotate(args),
        }
    }
}
