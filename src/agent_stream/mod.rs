//! `fabric agent-stream`: the commands addressed to Affinidi Agent Stream.
//! Only compiled with the `agent-stream` Cargo feature while the group is
//! being built. Each command group lives in its own file here.
//!
//! Agent Stream connections are kept apart from the Agent Gateway ones: in
//! their own file (`agent-stream.toml`) and under their own keyring service,
//! so each product can have a connection named `default`.

mod config;
mod login;
#[cfg(test)]
mod test_support;
mod tokens;
mod whoami;

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};

use crate::{
    client::GatewayClient,
    commands::{
        AccessTokenCommand, ApiArgs, CommandTarget, DEFAULT_CONNECTION, HostFlags, Output, ShellGlobals, ShellText,
        command_target, given_host_and_token, new_hash_name_warnings, print_value, run_access_tokens, run_api,
        shell_prefix,
    },
    config::Config,
    credentials::{CredentialStore, OsCredentialStore, add_no_keyring_hint},
    product::{self, Given, Product},
};

/// What the interactive shell shows when it was opened with
/// `fabric agent-stream shell`, and how `fabric agent-stream login` asks for a token
/// on the terminal.
pub const SHELL_TEXT: ShellText = ShellText {
    product: Product::AgentStream,
    banner: "Fabric Agent Stream interactive shell. Type `help` for commands; `exit` or `quit` to leave.",
    prompt: "fabric agent-stream> ",
    already_open: "note: already in the interactive shell; type a command such as `whoami`",
    paste_prompt: "Agent Stream token: ",
    token_name: "token",
};

#[derive(Debug, Args)]
pub struct AgentStreamArgs {
    /// Named Agent Stream connection. On `login` this names the connection
    /// being saved; on commands that talk to an Agent Stream it selects which
    /// saved connection to use. It has no environment variable, so
    /// FABRIC_CONNECTION, which names an Agent Gateway connection, is not read.
    #[arg(short, long, global = true)]
    connection: Option<String>,

    /// Agent Stream host for this command, and on `login` the Agent Stream to
    /// sign in to. Overrides the host of the selected saved connection; with
    /// no saved connection, set it together with --token to run a command
    /// without `login`.
    #[arg(long, global = true, env = "FABRIC_HOST")]
    host: Option<String>,

    /// Token for this command, and on `login` the token to sign in with: an
    /// access token (`aspat_...`) or the session token of a signed-in browser.
    /// Overrides the token of the selected saved connection; with no saved
    /// connection, set it together with --host to run a command without
    /// `login`. Prefer the FABRIC_TOKEN environment variable, or --token-stdin
    /// on `login`, since a value typed here stays in shell history and shows in
    /// the process list.
    #[arg(long, global = true, env = "FABRIC_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Allow a plain http:// host other than this machine, typed with --host or
    /// set in FABRIC_HOST.
    /// The token is then sent unencrypted, so only use this on a network you
    /// trust.
    #[arg(long, global = true)]
    allow_http: bool,

    /// Send the saved token to a --host other than the one it was saved for.
    /// Without this the CLI refuses, so a mistyped host cannot receive your
    /// token. It has no environment variable, so it must be typed.
    #[arg(long, global = true)]
    allow_host_override: bool,

    /// Output format for commands that return data.
    #[arg(short, long, global = true, value_enum, default_value_t = Output::Table)]
    output: Output,

    #[command(subcommand)]
    command: AgentStreamCommand,
}

#[derive(Debug, Subcommand)]
enum AgentStreamCommand {
    /// Sign in to an Agent Stream with a token and save the connection.
    ///
    /// Takes an access token (`aspat_...`, or the older `atgpat_...`), or the
    /// session token of a browser signed in to Agent Stream. There is no
    /// browser sign-in from the CLI. The token comes from --token or
    /// FABRIC_TOKEN, --token-stdin, --paste, or piped standard input; with none
    /// of them on a terminal, you are asked for it without echo.
    ///
    /// The token is checked with the Agent Stream before anything is saved:
    /// an access token must read your profile, and a session token must be a
    /// signed-in session. A session whose user has not accepted the Terms and
    /// Conditions yet is saved with a warning, and works once they are
    /// accepted in the Agent Stream dashboard. The token is saved in the OS
    /// credential store only, never in a file. The connection is saved under
    /// --connection (or `default`) and becomes current; logging in again under
    /// the same name replaces it.
    ///
    /// A session ends after a while without use, and by default 12 hours
    /// after sign-in, so an access token suits scripts and long work.
    #[command(after_long_help = LOGIN_EXAMPLES)]
    Login(login::LoginArgs),
    /// Sign out and remove a saved Agent Stream connection.
    ///
    /// Removes the connection's name, host, and token from this machine.
    /// Without --connection it removes the current connection, and the first
    /// remaining one by name becomes current.
    ///
    /// A session token's session also ends on the Agent Stream, if reachable.
    /// An access token stays valid until you revoke it, because Agent Stream
    /// cannot tell the CLI which token it is; logout prints how to revoke it.
    #[command(after_long_help = LOGOUT_EXAMPLES)]
    Logout,
    /// Show the current login and the connected Agent Stream.
    ///
    /// Checks the token live and shows the connection, host, the Agent
    /// Stream's version (`agent_stream_version`), whether the token was read
    /// from the OS credential store (`token_stored`, false for one given with
    /// --token or FABRIC_TOKEN), whether the Agent Stream accepts it
    /// (`authenticated`), and the signed-in user. A failed check, or a
    /// signed-in user's profile that cannot be read, is shown as `error`. A
    /// version that cannot be read shows `unknown` (`null` in JSON), with a
    /// warning on standard error unless the Agent Stream has no version route.
    ///
    /// The command exits 0 even when the token is rejected, so scripts should
    /// read `authenticated`.
    #[command(after_long_help = WHOAMI_EXAMPLES)]
    Whoami,
    /// Manage local Agent Stream profiles.
    ///
    /// Profiles are the saved Agent Stream connections on this machine. These
    /// commands never contact an Agent Stream, and never touch the Agent
    /// Gateway profiles of `fabric agent-gateway config`.
    Config {
        #[command(subcommand)]
        command: config::ConfigCommand,
    },
    /// Manage access tokens.
    Tokens {
        #[command(subcommand)]
        command: tokens::TokenCommand,
    },
    /// Call any Agent Stream management API endpoint.
    ///
    /// Reaches the endpoints no other command covers, with the current
    /// connection's token. Paths are written without `/api`, which is added,
    /// so `/v1/pipes` goes to `/api/v1/pipes`. Give a body with --data or
    /// --file, not both; `patch` needs one and sends it as a JSON Merge Patch.
    /// A body still carrying the masked placeholder is refused.
    ///
    /// Responses print as the Agent Stream sent them. In table mode a JSON
    /// array prints as a NAME ID DESCRIPTION table, anything else as JSON.
    #[command(after_long_help = API_EXAMPLES)]
    Api(ApiArgs),
    /// Open the interactive shell.
    ///
    /// Type commands without the `fabric agent-stream` prefix, such as
    /// `whoami`. Global options given when the shell starts, such as
    /// --connection or --output, become defaults that a single command can
    /// override. A failed command prints its error and the shell keeps running.
    ///
    /// Type `help` to list commands, and `exit`, `quit` or Ctrl-D to leave.
    /// History lasts for the session only and skips any line that types a
    /// secret, such as a --token value.
    #[command(after_long_help = SHELL_EXAMPLES)]
    Shell,
}

/// Examples shown at the bottom of `login --help`.
const LOGIN_EXAMPLES: &str = r#"Examples:
  Sign in with an access token, asked for without echo:
    fabric agent-stream login --host https://stream.example.com

  Sign in from a script, with the token on standard input:
    printf '%s' "$ASPAT" | fabric agent-stream login \
      --host https://stream.example.com --token-stdin

  Save another connection, named "production":
    fabric agent-stream --connection production login \
      --host https://stream.example.com --token-stdin < token.txt"#;

/// Examples shown at the bottom of `logout --help`.
const LOGOUT_EXAMPLES: &str = r#"Examples:
  Sign out of the current connection:
    fabric agent-stream logout

  Sign out of a named connection:
    fabric agent-stream --connection production logout"#;

/// Examples shown at the bottom of `whoami --help`.
const WHOAMI_EXAMPLES: &str = r#"Examples:
  Check the current connection:
    fabric agent-stream whoami

  Fail a script when the saved token no longer works:
    fabric agent-stream whoami --output json | jq -e .authenticated"#;

/// Examples shown at the bottom of `api --help`.
const API_EXAMPLES: &str = r#"Examples:
  Read the Agent Stream version:
    fabric agent-stream api get /v1/version

  Send a body from a file, or from standard input with '-':
    fabric agent-stream api post /v1/access-tokens --file token.json"#;

/// Examples shown at the bottom of `shell --help`.
const SHELL_EXAMPLES: &str = r#"Examples:
  Open the shell with a saved connection and JSON output as defaults:
    fabric agent-stream --connection production --output json shell

  Then type commands without the prefix:
    fabric agent-stream> whoami
    fabric agent-stream> tokens list --output table
    fabric agent-stream> exit"#;

/// The global flags of one `fabric agent-stream` run, apart from the command.
struct Globals {
    connection: Option<String>,
    host: Option<String>,
    token: Option<String>,
    flags: HostFlags,
    output: Output,
}

impl Globals {
    /// Which of the host and token were given on this run, for
    /// [`product::check_product`].
    fn given(&self) -> Given {
        Given {
            host: self.host.is_some(),
            token: self.token.is_some(),
        }
    }
}

impl AgentStreamArgs {
    /// Whether this is `fabric agent-stream shell`.
    pub fn is_shell(&self) -> bool {
        matches!(self.command, AgentStreamCommand::Shell)
    }

    /// Arguments every line typed in a shell opened with
    /// `fabric agent-stream shell` is parsed after: `fabric agent-stream`
    /// plus the global flags the shell was started with.
    pub fn interactive_prefix(&self) -> Vec<String> {
        shell_prefix(
            Product::AgentStream,
            ShellGlobals {
                connection: self.connection.as_deref(),
                host: self.host.as_deref(),
                token: self.token.as_deref(),
                flags: HostFlags {
                    allow_http: self.allow_http,
                    allow_host_override: self.allow_host_override,
                },
                output: self.output,
            },
        )
    }

    /// Whether this is `login --paste` with no token given, which the
    /// interactive shell asks for at its own prompt.
    pub fn login_wants_paste_prompt(&self) -> bool {
        matches!(&self.command, AgentStreamCommand::Login(args) if args.paste && self.token.is_none() && !args.token_stdin)
    }

    /// Gives a `login --paste` the token the interactive shell read for it at
    /// its own prompt. The token takes the place of --paste, which login would
    /// otherwise refuse beside a given token.
    pub fn set_login_token(
        &mut self,
        token: String,
    ) {
        if let AgentStreamCommand::Login(args) = &mut self.command {
            args.paste = false;
            self.token = Some(token);
        }
    }

    /// Whether this run never reads or writes the credential store: a command
    /// other than `login`, `logout` and `config` that was given both a host and
    /// a token. It sends the given token to the given host, so it also works on
    /// a server with no desktop session to reach the OS keyring.
    fn skips_the_credential_store(&self) -> bool {
        !matches!(
            self.command,
            AgentStreamCommand::Login(_) | AgentStreamCommand::Logout | AgentStreamCommand::Config { .. }
        ) && given_host_and_token(self.host.as_deref(), self.token.as_deref()).is_some()
    }
}

/// Runs one `fabric agent-stream` command against the saved Agent Stream
/// connections and their keyring entries.
pub async fn dispatch(args: AgentStreamArgs) -> Result<()> {
    let path = crate::config::agent_stream_config_path()?;
    let saved = Config::load_from(&path)?;
    dispatch_with(args, saved, &OsCredentialStore::agent_stream(), &path).await
}

/// Runs a command with the `saved` connections read from the file at `path`
/// and the `credentials` store already in hand, so a test can supply all
/// three. As on an Agent Gateway command, a connection name containing `#`
/// is warned about first, and a `token` line found in the file is moved into
/// `credentials` and removed from the file before the command runs, so that
/// rewriting the file never drops a token. A command given both a host and a
/// token, other than `login`, `logout` and `config`, skips that move and never
/// touches `credentials`.
///
/// An error from a keyring that cannot be reached gets one hint, as on an
/// Agent Gateway command: the move of a `token` line adds its own, which
/// names the connection, and the command's error gets the general one.
async fn dispatch_with(
    args: AgentStreamArgs,
    mut saved: Config,
    credentials: &impl CredentialStore,
    path: &Path,
) -> Result<()> {
    for warning in new_hash_name_warnings(&saved) {
        eprintln!("{warning}");
    }
    if !args.skips_the_credential_store() {
        saved.migrate_legacy_tokens_to(credentials, path)?;
    }
    let globals = Globals {
        connection: args.connection,
        host: args.host,
        token: args.token,
        flags: HostFlags {
            allow_http: args.allow_http,
            allow_host_override: args.allow_host_override,
        },
        output: args.output,
    };
    run_command(args.command, globals, &mut saved, credentials, path)
        .await
        .map_err(add_no_keyring_hint)
}

async fn run_command(
    command: AgentStreamCommand,
    globals: Globals,
    saved: &mut Config,
    credentials: &impl CredentialStore,
    path: &Path,
) -> Result<()> {
    match command {
        AgentStreamCommand::Shell => bail!("the interactive shell is already open"),
        AgentStreamCommand::Config { command } => config::run(saved, credentials, command, path, globals.output),
        AgentStreamCommand::Login(args) => login::login(saved, credentials, path, &globals, args).await,
        AgentStreamCommand::Logout => login::logout(saved, credentials, path, globals.connection.as_deref()).await,
        AgentStreamCommand::Whoami => whoami::whoami(saved, credentials, &globals).await,
        AgentStreamCommand::Tokens { command } => {
            let command = AccessTokenCommand::from(command);
            command.refuse_without_terminal()?;
            let client = connect(saved, credentials, &globals).await?;
            run_access_tokens(&client, command, globals.output).await
        }
        AgentStreamCommand::Api(args) => {
            let client = connect(saved, credentials, &globals).await?;
            let value = run_api(&client, args).await?;
            print_value(&value, globals.output)
        }
    }
}

/// The client for a command that needs a token: the host and token of
/// [`command_target`], once [`product::check_product`] has confirmed the
/// command is aimed at an Agent Stream.
async fn connect(
    saved: &Config,
    credentials: &impl CredentialStore,
    globals: &Globals,
) -> Result<GatewayClient> {
    let CommandTarget { connection, host, token, .. } = command_target(
        saved,
        credentials,
        globals.connection.as_deref(),
        globals.host.as_deref(),
        globals.flags,
        globals.token.as_deref(),
    )?;
    let token = token.with_context(|| {
        let name = connection
            .as_deref()
            .unwrap_or(DEFAULT_CONNECTION);
        format!(
            "no token stored for Agent Stream connection '{name}'; run `fabric agent-stream login --connection \
             {name} --host {host}`"
        )
    })?;
    product::check_product(Product::AgentStream, &host, Some(&token), globals.given()).await?;
    GatewayClient::for_agent_stream(host, token)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[cfg(target_os = "linux")]
    use super::test_support::NoKeyring;
    use super::{
        test_support::{MemoryCredentials, Route, UnusedKeyring, scripted_agent_stream, start_lines},
        *,
    };
    use crate::{commands::Cli, config::Connection};

    const STREAM_HOST: &str = "https://stream.example";
    const HANDWRITTEN_TOKEN: &str = "aspat_handwritten";
    const ACCESS_TOKEN: &str = "aspat_live-secret";
    const OLD_ACCESS_TOKEN: &str = "atgpat_live-secret";
    const SESSION_TOKEN: &str = "session-live-secret";
    const GATEWAY_TOKEN: &str = "agpat_live-secret";
    const TOKEN_ID: &str = "asat_0a75";

    const PROFILE: Route = (
        "GET /api/v1/profile",
        "HTTP/1.1 200 OK",
        r#"{"username":"ada","role":"administrator","email":"ada@example.test","user_id":"u-1"}"#,
    );
    const PROFILE_REFUSED: Route = ("GET /api/v1/profile", "HTTP/1.1 401 Unauthorized", "");
    const STREAM_PERMISSIONS: Route =
        ("GET /api/v1/permissions/public", "HTTP/1.1 200 OK", r#"{"pipes.view":false,"users.view":false}"#);
    const GATEWAY_PERMISSIONS: Route =
        ("GET /api/v1/permissions/public", "HTTP/1.1 200 OK", r#"{"surfaces.view":false,"users.view":false}"#);
    const SIGNED_IN: Route =
        ("GET /api/auth/check", "HTTP/1.1 200 OK", r#"{"authenticated":true,"username":"ada","terms_enabled":false}"#);
    const SIGNED_IN_TERMS_PENDING: Route = (
        "GET /api/auth/check",
        "HTTP/1.1 200 OK",
        r#"{"authenticated":true,"username":"ada","consent_required":true,"terms_enabled":true}"#,
    );
    const NOT_SIGNED_IN: Route =
        ("GET /api/auth/check", "HTTP/1.1 200 OK", r#"{"authenticated":false,"username":null,"terms_enabled":false}"#);
    const TOKEN_LIST: Route = ("GET /api/v1/access-tokens", "HTTP/1.1 200 OK", r#"{"access_tokens":[]}"#);

    /// The Agent Stream arguments of `fabric agent-stream <words>`.
    fn stream_args(words: &[&str]) -> AgentStreamArgs {
        Cli::try_parse_from(
            ["fabric", "agent-stream"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .unwrap_or_else(|error| panic!("{words:?}: {error}"))
        .into_agent_stream()
    }

    /// One saved Agent Stream connection, `default`, current, at `host`, with
    /// `token` bound to that host.
    fn saved_login(
        host: &str,
        token: &str,
    ) -> (Config, MemoryCredentials) {
        let mut saved = Config {
            current: Some("default".to_owned()),
            ..Config::default()
        };
        saved
            .connections
            .insert("default".to_owned(), Connection::new(host.to_owned()));
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("default", token)
            .unwrap();
        credentials
            .set_bound_host("default", host)
            .unwrap();
        (saved, credentials)
    }

    /// Runs `fabric agent-stream <words>` against `saved` and `credentials`,
    /// with the connections file in a fresh directory.
    async fn run_stream(
        words: &[&str],
        saved: Config,
        credentials: &impl CredentialStore,
    ) -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        dispatch_with(
            stream_args(words),
            saved,
            credentials,
            &dir.path()
                .join("agent-stream.toml"),
        )
        .await
    }

    /// Whether a recorded request carried `token` as its bearer token.
    fn sends_bearer(
        request: &str,
        token: &str,
    ) -> bool {
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {}", token.to_ascii_lowercase()))
    }

    #[tokio::test]
    async fn login_with_an_access_token_asks_the_host_reads_the_profile_and_saves_the_token_in_the_store_only() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, PROFILE]).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let credentials = MemoryCredentials::default();

        dispatch_with(
            stream_args(&["--connection", "local", "login", "--host", &host, "--token", ACCESS_TOKEN]),
            Config::default(),
            &credentials,
            &path,
        )
        .await
        .expect("the access token reads the profile");

        assert_eq!(start_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/v1/profile HTTP/1.1"]);
        assert!(!sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN), "the probe carries no token");
        assert!(sends_bearer(&requests.lock().unwrap()[1], ACCESS_TOKEN));
        assert_eq!(
            credentials
                .get_token("local")
                .unwrap()
                .as_deref(),
            Some(ACCESS_TOKEN)
        );
        assert_eq!(
            credentials
                .get_bound_host("local")
                .unwrap()
                .as_deref(),
            Some(host.as_str())
        );
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains(ACCESS_TOKEN), "{written}");
        let saved = Config::load_from(&path).unwrap();
        assert_eq!(saved.current.as_deref(), Some("local"));
        assert_eq!(saved.connections["local"].host, host);
    }

    #[tokio::test]
    async fn login_accepts_an_access_token_with_the_older_prefix() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, PROFILE]).await;
        let credentials = MemoryCredentials::default();

        run_stream(&["login", "--host", &host, "--token", OLD_ACCESS_TOKEN], Config::default(), &credentials)
            .await
            .expect("an atgpat_ token is an Agent Stream access token");

        assert_eq!(start_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/v1/profile HTTP/1.1"]);
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(OLD_ACCESS_TOKEN)
        );
    }

    #[tokio::test]
    async fn login_with_a_session_token_asks_the_host_then_checks_the_session() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, SIGNED_IN]).await;
        let credentials = MemoryCredentials::default();

        run_stream(&["login", "--host", &host, "--token", SESSION_TOKEN], Config::default(), &credentials)
            .await
            .expect("a signed-in session is accepted");

        assert_eq!(start_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/auth/check HTTP/1.1"]);
        assert!(!sends_bearer(&requests.lock().unwrap()[0], SESSION_TOKEN), "the probe carries no token");
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(SESSION_TOKEN)
        );
    }

    #[tokio::test]
    async fn login_with_a_token_that_is_not_a_signed_in_session_saves_nothing() {
        let (host, _) = scripted_agent_stream(vec![STREAM_PERMISSIONS, NOT_SIGNED_IN]).await;
        let credentials = MemoryCredentials::default();

        let error = run_stream(&["login", "--host", &host, "--token", SESSION_TOKEN], Config::default(), &credentials)
            .await
            .expect_err("Agent Stream does not know the session");

        let text = format!("{error:#}");
        assert!(text.contains("not accept this token as a signed-in session"), "{text}");
        assert!(text.contains("`aspat_` access token"), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn login_with_an_access_token_agent_stream_refuses_saves_nothing_and_says_why() {
        let (host, _) = scripted_agent_stream(vec![STREAM_PERMISSIONS, PROFILE_REFUSED]).await;
        let credentials = MemoryCredentials::default();

        let error = run_stream(&["login", "--host", &host, "--token", ACCESS_TOKEN], Config::default(), &credentials)
            .await
            .expect_err("a refused token is not saved");

        let text = format!("{error:#}");
        assert!(text.contains("did not accept the access token"), "{text}");
        assert!(!text.contains(ACCESS_TOKEN), "{text}");
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn login_with_a_gateway_token_is_refused_before_anything_is_sent() {
        let (host, requests) = scripted_agent_stream(vec![PROFILE]).await;
        let credentials = MemoryCredentials::default();

        let error = run_stream(&["login", "--host", &host, "--token", GATEWAY_TOKEN], Config::default(), &credentials)
            .await
            .expect_err("an agpat_ token belongs to Agent Gateway");

        let text = format!("{error:#}");
        assert!(text.contains("issued by Agent Gateway"), "{text}");
        assert!(!text.contains(GATEWAY_TOKEN), "{text}");
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[test]
    fn login_takes_one_token_source_at_a_time() {
        for words in [
            ["login", "--token", ACCESS_TOKEN, "--token-stdin"],
            ["login", "--token", ACCESS_TOKEN, "--paste"],
            ["login", "--token-stdin", "--paste", "--host=https://stream.example"],
        ] {
            assert!(
                Cli::try_parse_from(
                    ["fabric", "agent-stream"]
                        .into_iter()
                        .chain(words)
                )
                .is_err(),
                "{words:?}"
            );
        }
    }

    #[tokio::test]
    async fn login_with_a_session_waiting_for_terms_saves_it() {
        let (host, _) = scripted_agent_stream(vec![STREAM_PERMISSIONS, SIGNED_IN_TERMS_PENDING]).await;
        let credentials = MemoryCredentials::default();

        run_stream(&["login", "--host", &host, "--token", SESSION_TOKEN], Config::default(), &credentials)
            .await
            .expect("accepting the terms later makes the same session work");

        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(SESSION_TOKEN)
        );
    }

    #[tokio::test]
    async fn login_with_an_access_token_whose_profile_answers_another_success_saves_nothing() {
        let (host, _) =
            scripted_agent_stream(vec![STREAM_PERMISSIONS, ("GET /api/v1/profile", "HTTP/1.1 204 No Content", "")])
                .await;
        let credentials = MemoryCredentials::default();

        let error = run_stream(&["login", "--host", &host, "--token", ACCESS_TOKEN], Config::default(), &credentials)
            .await
            .expect_err("only a 200 counts");

        let text = format!("{error:#}");
        assert!(
            text.ends_with(
                "Agent Stream answered 204 No Content when checking the token; make sure --host is an Agent Stream \
                 address and it is healthy"
            ),
            "{text}"
        );
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn logout_of_an_access_token_sends_nothing_and_removes_the_local_copy() {
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        run_stream(&["logout"], saved, &credentials)
            .await
            .expect("logout");

        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
        assert_eq!(
            credentials
                .get_bound_host("default")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn logout_of_a_session_ends_it_on_the_agent_stream_and_removes_the_local_copy() {
        let (host, requests) = scripted_agent_stream(vec![("POST /api/auth/logout", "HTTP/1.1 200 OK", "")]).await;
        let (saved, credentials) = saved_login(&host, SESSION_TOKEN);

        run_stream(&["logout"], saved, &credentials)
            .await
            .expect("logout");

        assert_eq!(start_lines(&requests), ["POST /api/auth/logout HTTP/1.1"]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], SESSION_TOKEN));
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn logout_with_nothing_selected_names_the_agent_stream_connections() {
        let error = run_stream(&["logout"], Config::default(), &MemoryCredentials::default())
            .await
            .expect_err("there is no connection to sign out of");

        assert_eq!(error.to_string(), "no Agent Stream connection selected");
    }

    #[tokio::test]
    async fn the_token_commands_reach_the_access_token_routes_with_the_saved_token() {
        let rotated = r#"{"id":"asat_0a75","token":"aspat_rotated"}"#;
        let created = r#"{"id":"asat_new","token":"aspat_created"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            TOKEN_LIST,
            ("GET /api/v1/permissions", "HTTP/1.1 200 OK", r#"{"pipes.view":true,"users.view":false}"#),
            ("POST /api/v1/access-tokens/asat_0a75/rotate", "HTTP/1.1 200 OK", rotated),
            ("POST /api/v1/access-tokens", "HTTP/1.1 201 Created", created),
            ("DELETE /api/v1/access-tokens/asat_0a75", "HTTP/1.1 204 No Content", ""),
        ])
        .await;

        for words in [
            vec!["tokens", "list"],
            vec!["tokens", "scopes"],
            vec!["tokens", "create", "--name", "ci", "--scope", "pipes.view"],
            vec!["tokens", "rotate", TOKEN_ID, "--yes"],
            vec!["tokens", "revoke", TOKEN_ID, "--yes"],
        ] {
            let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);
            run_stream(&words, saved, &credentials)
                .await
                .unwrap_or_else(|error| panic!("{words:?}: {error:#}"));
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/access-tokens HTTP/1.1",
                "GET /api/v1/permissions HTTP/1.1",
                "POST /api/v1/access-tokens HTTP/1.1",
                "POST /api/v1/access-tokens/asat_0a75/rotate HTTP/1.1",
                "DELETE /api/v1/access-tokens/asat_0a75 HTTP/1.1",
            ]
        );
        let requests = requests.lock().unwrap();
        assert!(
            requests
                .iter()
                .all(|request| sends_bearer(request, ACCESS_TOKEN))
        );
        assert!(requests[2].contains(r#""scopes":["pipes.view"]"#), "{}", requests[2]);
    }

    #[tokio::test]
    async fn tokens_create_without_a_scope_names_the_agent_stream_scopes_command() {
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        let error = run_stream(&["tokens", "create", "--name", "ci"], saved, &credentials)
            .await
            .expect_err("a token needs scopes or --full-role");

        assert!(
            error
                .to_string()
                .contains("(see `fabric agent-stream tokens scopes`)"),
            "{error}"
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn tokens_get_reads_one_access_token_by_id() {
        let (host, requests) = scripted_agent_stream(vec![(
            "GET /api/v1/access-tokens/asat_0a75",
            "HTTP/1.1 200 OK",
            r#"{"id":"asat_0a75","name":"ci","scopes":["pipes.view"]}"#,
        )])
        .await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        run_stream(&["tokens", "get", TOKEN_ID], saved, &credentials)
            .await
            .expect("tokens get");

        assert_eq!(start_lines(&requests), ["GET /api/v1/access-tokens/asat_0a75 HTTP/1.1"]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN));
    }

    #[tokio::test]
    async fn a_given_gateway_token_is_refused_before_tokens_or_api_send_anything() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, TOKEN_LIST]).await;

        for words in [vec!["tokens", "list"], vec!["api", "get", "/v1/access-tokens"]] {
            let line: Vec<&str> = ["--host", host.as_str(), "--token", GATEWAY_TOKEN]
                .into_iter()
                .chain(words.iter().copied())
                .collect();
            let error = run_stream(&line, Config::default(), &UnusedKeyring)
                .await
                .expect_err("an agpat_ token belongs to Agent Gateway");

            let text = format!("{error:#}");
            assert!(text.contains("issued by Agent Gateway"), "{words:?}: {text}");
            assert!(!text.contains(GATEWAY_TOKEN), "{words:?}: {text}");
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_given_access_token_never_reaches_a_given_gateway_host() {
        let (gateway, requests) = scripted_agent_stream(vec![GATEWAY_PERMISSIONS, PROFILE, TOKEN_LIST]).await;
        let (saved, credentials) = saved_login(STREAM_HOST, ACCESS_TOKEN);

        for words in [vec!["tokens", "list"], vec!["api", "get", "/v1/access-tokens"], vec!["whoami"], vec!["login"]] {
            let line: Vec<&str> = ["--host", gateway.as_str(), "--token", ACCESS_TOKEN]
                .into_iter()
                .chain(words.iter().copied())
                .collect();
            let error = run_stream(&line, Config::default(), &MemoryCredentials::default())
                .await
                .expect_err("an Agent Gateway host must be refused");

            let text = format!("{error:#}");
            assert!(text.contains(&format!("{gateway} is an Agent Gateway, not an Agent Stream")), "{words:?}: {text}");
            assert!(!text.contains(ACCESS_TOKEN), "{words:?}: {text}");
        }
        let error = run_stream(&["--host", &gateway, "--allow-host-override", "tokens", "list"], saved, &credentials)
            .await
            .expect_err("a saved token sent to a given Agent Gateway host must be refused");
        assert!(format!("{error:#}").contains("is an Agent Gateway, not an Agent Stream"), "{error:#}");

        let requests = requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert!(request.starts_with("GET /api/v1/permissions/public HTTP/1.1"), "{request}");
            assert!(!sends_bearer(request, ACCESS_TOKEN), "{request}");
        }
    }

    #[tokio::test]
    async fn a_given_session_token_never_reaches_a_saved_connection_that_answers_as_agent_gateway() {
        let (gateway, requests) = scripted_agent_stream(vec![GATEWAY_PERMISSIONS, PROFILE, TOKEN_LIST]).await;

        for words in [vec!["tokens", "list"], vec!["api", "get", "/v1/access-tokens"], vec!["whoami"]] {
            let (saved, credentials) = saved_login(&gateway, ACCESS_TOKEN);
            let line: Vec<&str> = ["--token", SESSION_TOKEN]
                .into_iter()
                .chain(words.iter().copied())
                .collect();
            let error = run_stream(&line, saved, &credentials)
                .await
                .expect_err("a given session token must not reach a saved Agent Gateway host");

            let text = format!("{error:#}");
            assert!(text.contains(&format!("{gateway} is an Agent Gateway, not an Agent Stream")), "{words:?}: {text}");
            assert!(!text.contains(SESSION_TOKEN), "{words:?}: {text}");
        }

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests.iter() {
            assert!(request.starts_with("GET /api/v1/permissions/public HTTP/1.1"), "{request}");
            assert!(!sends_bearer(request, SESSION_TOKEN), "{request}");
            assert!(!sends_bearer(request, ACCESS_TOKEN), "{request}");
        }
    }

    #[tokio::test]
    async fn a_given_session_token_on_a_saved_agent_stream_is_sent_after_the_host_answers() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, TOKEN_LIST]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        run_stream(&["--token", SESSION_TOKEN, "tokens", "list"], saved, &credentials)
            .await
            .expect("the saved host answers as Agent Stream");

        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/v1/access-tokens HTTP/1.1"]
        );
        let requests = requests.lock().unwrap();
        assert!(!sends_bearer(&requests[0], SESSION_TOKEN), "{}", requests[0]);
        assert!(sends_bearer(&requests[1], SESSION_TOKEN), "{}", requests[1]);
    }

    #[tokio::test]
    async fn a_given_access_token_on_a_saved_agent_stream_is_sent_without_asking_the_host() {
        let (host, requests) = scripted_agent_stream(vec![TOKEN_LIST]).await;
        let (saved, credentials) = saved_login(&host, SESSION_TOKEN);

        run_stream(&["--token", ACCESS_TOKEN, "tokens", "list"], saved, &credentials)
            .await
            .expect("the access token's prefix says Agent Stream");

        assert_eq!(start_lines(&requests), ["GET /api/v1/access-tokens HTTP/1.1"]);
    }

    #[tokio::test]
    async fn api_reaches_any_route_under_the_api_prefix() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/version", "HTTP/1.1 200 OK", r#"{"version":"1.0.2"}"#)]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        run_stream(&["api", "get", "/v1/version"], saved, &credentials)
            .await
            .expect("api get");

        assert_eq!(start_lines(&requests), ["GET /api/v1/version HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_given_host_and_token_with_no_saved_connection_never_touch_the_keyring() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, TOKEN_LIST]).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let written = format!("[connections.old]\nhost = \"{STREAM_HOST}\"\ntoken = \"{HANDWRITTEN_TOKEN}\"\n");
        std::fs::write(&path, &written).unwrap();
        let saved = Config::load_from(&path).unwrap();

        dispatch_with(
            stream_args(&["--host", &host, "--token", ACCESS_TOKEN, "tokens", "list"]),
            saved,
            &UnusedKeyring,
            &path,
        )
        .await
        .expect("the given host and token need no keyring");

        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/v1/access-tokens HTTP/1.1"]
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written, "the token line is not moved");
    }

    #[tokio::test]
    async fn a_command_with_no_saved_connection_and_no_token_names_the_agent_stream_login() {
        let error = run_stream(&["tokens", "list"], Config::default(), &MemoryCredentials::default())
            .await
            .expect_err("there is nothing to send");

        assert_eq!(
            error.to_string(),
            "no Agent Stream connection configured; run `fabric agent-stream login --host <URL>`, or set both \
             FABRIC_HOST and FABRIC_TOKEN"
        );
    }

    #[tokio::test]
    async fn a_saved_connection_without_a_token_names_the_agent_stream_login() {
        let (host, _) = scripted_agent_stream(vec![]).await;
        let mut saved = Config {
            current: Some("default".to_owned()),
            ..Config::default()
        };
        saved
            .connections
            .insert("default".to_owned(), Connection::new(host.clone()));

        let error = run_stream(&["tokens", "list"], saved, &MemoryCredentials::default())
            .await
            .expect_err("no token is saved");

        assert_eq!(
            error.to_string(),
            format!(
                "no token stored for Agent Stream connection 'default'; run `fabric agent-stream login --connection \
                 default --host {host}`"
            )
        );
    }

    #[tokio::test]
    async fn a_saved_token_is_not_sent_to_another_host_and_the_refusal_names_the_agent_stream_login() {
        let (host, requests) = scripted_agent_stream(vec![TOKEN_LIST]).await;
        let (saved, credentials) = saved_login(STREAM_HOST, ACCESS_TOKEN);

        let error = run_stream(&["--host", &host, "tokens", "list"], saved, &credentials)
            .await
            .expect_err("the token belongs to another host");

        let text = error.to_string();
        assert!(text.contains("run `fabric agent-stream login --connection default"), "{text}");
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_ended_session_says_so_and_suggests_an_access_token() {
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/access-tokens", "HTTP/1.1 401 Unauthorized", "")]).await;
        let (saved, credentials) = saved_login(&host, SESSION_TOKEN);

        let error = run_stream(&["tokens", "list"], saved, &credentials)
            .await
            .expect_err("the session has ended");

        let text = format!("{error:#}");
        assert!(text.contains("the session has ended"), "{text}");
        assert!(text.contains("by default 12 hours after sign-in"), "{text}");
        assert!(text.contains("`aspat_` access token"), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
    }

    #[tokio::test]
    async fn a_refused_access_token_says_to_log_in_again() {
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/access-tokens", "HTTP/1.1 401 Unauthorized", "")]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        let error = run_stream(&["tokens", "list"], saved, &credentials)
            .await
            .expect_err("the token is revoked");

        let text = format!("{error:#}");
        assert!(text.contains("did not accept the access token"), "{text}");
        assert!(text.contains("`fabric agent-stream login`"), "{text}");
        assert!(!text.contains("12 hours"), "{text}");
    }

    #[tokio::test]
    async fn a_missing_permission_names_the_role_the_token_scopes_and_a_missing_required_header() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/access-tokens", "HTTP/1.1 403 Forbidden", "")]).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        let error = run_stream(&["tokens", "list"], saved, &credentials)
            .await
            .expect_err("the token lacks access_tokens.view");

        assert_eq!(
            error.to_string(),
            "Agent Stream answered 403 Forbidden, so your role or the scopes of the access token in use do not \
             allow this request, or the access token is limited to a resource and the request lacks a header it \
             requires; `fabric agent-stream tokens scopes` lists the scopes this login holds"
        );
    }

    #[tokio::test]
    async fn a_session_waiting_for_terms_gets_the_dashboard_sentence_instead_of_the_raw_answer() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/v1/access-tokens",
            "HTTP/1.1 403 Forbidden",
            r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#,
        )])
        .await;
        let (saved, credentials) = saved_login(&host, SESSION_TOKEN);

        let error = run_stream(&["tokens", "list"], saved, &credentials)
            .await
            .expect_err("the terms are not accepted");

        assert_eq!(
            error.to_string(),
            "Agent Stream refused the request because the signed-in user has not accepted its Terms and Conditions; \
             accept them in the Agent Stream dashboard, then run the command again"
        );
    }

    #[tokio::test]
    async fn an_access_token_waiting_for_terms_shows_the_message_agent_stream_sent() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/v1/access-tokens",
            "HTTP/1.1 403 Forbidden",
            r#"{"code":"TERMS_ACCEPTANCE_REQUIRED","message":"Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."}"#,
        )])
        .await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);

        let error = run_stream(&["tokens", "list"], saved, &credentials)
            .await
            .expect_err("the owner has not accepted the terms");

        assert_eq!(
            error.to_string(),
            "Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then \
             retry."
        );
    }

    #[test]
    fn the_agent_stream_shell_keeps_its_own_prefix_and_prompt() {
        let cli = Cli::try_parse_from(["fabric", "agent-stream", "--connection", "local", "--output", "json", "shell"])
            .expect("shell parses with global flags");

        assert!(cli.is_interactive());
        assert_eq!(cli.interactive_prefix(), ["fabric", "agent-stream", "--connection", "local", "--output", "json"]);
        assert_eq!(cli.shell_text().prompt, "fabric agent-stream> ");
        assert_eq!(cli.shell_text().paste_prompt, "Agent Stream token: ");
        assert_eq!(cli.shell_text().token_name, "token");
        let gateway_line = cli
            .interactive_prefix()
            .into_iter()
            .chain(["surfaces".to_owned(), "list".to_owned()]);
        assert!(Cli::try_parse_from(gateway_line).is_err(), "an Agent Gateway command is not an Agent Stream one");
    }

    #[tokio::test]
    async fn login_paste_in_the_shell_signs_in_with_the_token_the_shell_read() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, SIGNED_IN]).await;
        let mut cli = Cli::try_parse_from(["fabric", "agent-stream", "login", "--paste", "--host", &host])
            .expect("login --paste parses");
        assert!(cli.login_wants_paste_prompt());

        cli.set_login_token(SESSION_TOKEN.to_owned());

        assert!(!cli.login_wants_paste_prompt());
        let dir = tempfile::tempdir().unwrap();
        let credentials = MemoryCredentials::default();
        dispatch_with(
            cli.into_agent_stream(),
            Config::default(),
            &credentials,
            &dir.path()
                .join("agent-stream.toml"),
        )
        .await
        .expect("the pasted session signs in");
        assert_eq!(start_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1", "GET /api/auth/check HTTP/1.1"]);
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(SESSION_TOKEN)
        );
    }

    #[tokio::test]
    async fn login_with_a_token_typed_before_it_refuses_paste_and_token_stdin_before_anything_is_sent() {
        let (host, requests) = scripted_agent_stream(vec![STREAM_PERMISSIONS, PROFILE]).await;
        let credentials = MemoryCredentials::default();

        for (flag, expected) in [
            ("--paste", "the argument '--paste' cannot be used with '--token <TOKEN>'"),
            ("--token-stdin", "the argument '--token-stdin' cannot be used with '--token <TOKEN>'"),
        ] {
            let error =
                run_stream(&["--token", ACCESS_TOKEN, "login", flag, "--host", &host], Config::default(), &credentials)
                    .await
                    .expect_err("two token sources");

            assert_eq!(error.to_string(), expected);
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
    }

    #[test]
    fn login_paste_in_a_shell_opened_with_a_token_does_not_prompt() {
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-stream",
            "--token",
            ACCESS_TOKEN,
            "login",
            "--paste",
            "--host",
            STREAM_HOST,
        ])
        .expect("clap lets a global --token typed before login through");

        assert!(!cli.login_wants_paste_prompt());
    }

    #[test]
    fn only_the_host_and_token_flags_read_the_environment() {
        use clap::CommandFactory;

        let command = Cli::command();
        let stream = command
            .find_subcommand("agent-stream")
            .expect("the feature build has agent-stream");
        let env_of = |id: &str| {
            stream
                .get_arguments()
                .find(|argument| argument.get_id() == id)
                .unwrap_or_else(|| panic!("{id}"))
                .get_env()
                .map(|name| {
                    name.to_string_lossy()
                        .into_owned()
                })
        };

        assert_eq!(env_of("connection"), None);
        assert_eq!(env_of("host").as_deref(), Some("FABRIC_HOST"));
        assert_eq!(env_of("token").as_deref(), Some("FABRIC_TOKEN"));
    }

    #[test]
    fn the_token_commands_name_agent_stream_in_the_help_they_share_with_agent_gateway() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        command.build();
        let tokens = command
            .find_subcommand("agent-stream")
            .and_then(|stream| stream.find_subcommand("tokens"))
            .expect("the feature build has agent-stream tokens");
        let help_of = |subcommand: &str, id: &str| {
            tokens
                .find_subcommand(subcommand)
                .and_then(|command| {
                    command
                        .get_arguments()
                        .find(|argument| argument.get_id() == id)
                })
                .and_then(|argument| argument.get_help())
                .map(ToString::to_string)
                .unwrap_or_else(|| panic!("{subcommand} {id}"))
        };

        assert_eq!(
            help_of("create", "scopes"),
            "Scope to grant the token. Repeat for multiple scopes. Required unless --full-role is given; run \
             `fabric agent-stream tokens scopes` to see what you can grant"
        );
        for subcommand in ["revoke", "rotate"] {
            assert_eq!(help_of(subcommand, "id"), "ID of the access token (see `fabric agent-stream tokens list`)");
        }
    }

    #[tokio::test]
    async fn the_shell_command_inside_the_shell_is_refused() {
        let error = run_stream(&["shell"], Config::default(), &MemoryCredentials::default())
            .await
            .expect_err("the shell is already open");

        assert_eq!(error.to_string(), "the interactive shell is already open");
    }

    /// How every hint for a keyring that cannot be reached starts.
    #[cfg(target_os = "linux")]
    const NO_KEYRING_HINT: &str = "no OS keyring can be reached";

    fn config_command(command: config::ConfigCommand) -> AgentStreamArgs {
        AgentStreamArgs {
            connection: None,
            host: None,
            token: None,
            allow_http: false,
            allow_host_override: false,
            output: Output::Table,
            command: AgentStreamCommand::Config { command },
        }
    }

    #[tokio::test]
    async fn a_token_written_in_the_file_moves_to_the_store_before_a_command_rewrites_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(
            &path,
            format!(
                "[connections.default]\nhost = \"{STREAM_HOST}/\"\ntoken = \"{HANDWRITTEN_TOKEN}\"\n\n[connections.other]\nhost = \"{STREAM_HOST}\"\n"
            ),
        )
        .unwrap();
        let saved = Config::load_from(&path).unwrap();
        let credentials = MemoryCredentials::default();

        dispatch_with(
            config_command(config::ConfigCommand::Use { name: "other".to_owned() }),
            saved,
            &credentials,
            &path,
        )
        .await
        .unwrap();

        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(HANDWRITTEN_TOKEN)
        );
        assert_eq!(
            credentials
                .get_bound_host("default")
                .unwrap()
                .as_deref(),
            Some(STREAM_HOST)
        );
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains(HANDWRITTEN_TOKEN), "{written}");
        assert_eq!(
            Config::load_from(&path)
                .unwrap()
                .current
                .as_deref(),
            Some("other")
        );
    }

    #[tokio::test]
    async fn a_file_without_a_token_line_leaves_the_store_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(&path, format!("[connections.default]\nhost = \"{STREAM_HOST}\"\n")).unwrap();
        let saved = Config::load_from(&path).unwrap();
        let credentials = MemoryCredentials::default();

        dispatch_with(config_command(config::ConfigCommand::List), saved, &credentials, &path)
            .await
            .unwrap();

        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
        assert_eq!(
            credentials
                .get_bound_host("default")
                .unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_token_line_that_cannot_be_moved_without_a_keyring_gets_one_hint_and_stays_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let written = format!("[connections.default]\nhost = \"{STREAM_HOST}\"\ntoken = \"{HANDWRITTEN_TOKEN}\"\n");
        std::fs::write(&path, &written).unwrap();
        let saved = Config::load_from(&path).unwrap();

        let error = dispatch_with(config_command(config::ConfigCommand::List), saved, &NoKeyring, &path)
            .await
            .expect_err("the token cannot be moved without a keyring");

        let text = format!("{error:#}");
        assert_eq!(
            text.matches(NO_KEYRING_HINT)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("the plaintext token of connection 'default'"), "{text}");
        assert!(!text.contains(HANDWRITTEN_TOKEN), "{text}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_command_that_cannot_reach_the_keyring_gets_one_hint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(&path, format!("[connections.default]\nhost = \"{STREAM_HOST}\"\n")).unwrap();
        let saved = Config::load_from(&path).unwrap();

        let error = dispatch_with(
            config_command(config::ConfigCommand::Remove { name: "default".to_owned() }),
            saved,
            &NoKeyring,
            &path,
        )
        .await
        .expect_err("the saved token cannot be deleted without a keyring");

        let text = format!("{error:#}");
        assert_eq!(
            text.matches(NO_KEYRING_HINT)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("saved connections can't be used"), "{text}");
    }
}
