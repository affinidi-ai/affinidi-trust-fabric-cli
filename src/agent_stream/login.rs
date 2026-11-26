//! `fabric agent-stream login` and `logout`: signing in to an Agent Stream
//! with a token, and signing out again.

use std::{
    io::{self, IsTerminal},
    path::Path,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use reqwest::{Method, StatusCode};
use serde_json::Value;

use super::Globals;
use crate::{
    client::{GatewayClient, RawAuth, response_status, status_error},
    commands::{
        DEFAULT_CONNECTION, checked_connection_name, end_session_note, non_empty_token, prompt_token, read_stdin_token,
        remove_connection, save_login,
    },
    config::{Config, Connection, normalize_user_host, saved_host_http_warning},
    credentials::CredentialStore,
    product::{self, Given, Product},
};

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Read the token from standard input. Safer than --token, which stays in
    /// shell history.
    #[arg(long, conflicts_with = "token")]
    pub(super) token_stdin: bool,
    /// Ask for the token on this terminal, without echo, even when standard
    /// input is piped.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    pub(super) paste: bool,
}

/// What `login` says when Agent Stream does not know a token without an access
/// token prefix as a signed-in session.
const NOT_A_SESSION: &str = "Agent Stream did not accept this token as a signed-in session, so nothing was saved; log \
                             in with an `aspat_` access token instead";

/// What `login` says when Agent Stream refuses an access token with a 401.
const ACCESS_TOKEN_REFUSED: &str = "Agent Stream did not accept the access token, so nothing was saved; check that \
                                    it was copied in full, that it is not revoked or expired, and that its owner is \
                                    still approved";

/// What `login` says on standard error after saving a session whose user has
/// not accepted the Agent Stream Terms and Conditions yet.
const TERMS_PENDING_WARNING: &str = "warning: this session's user has not accepted the Agent Stream Terms and \
                                     Conditions yet, so Agent Stream refuses every command made with it; accept them \
                                     in the Agent Stream dashboard, after which the same session works. Until then \
                                     `fabric agent-stream whoami` can still report it signed in";

/// Signs in to the Agent Stream at `--host` and saves the connection, under
/// `--connection` or `default`, in `saved`, the file at `path`, and
/// `credentials`. A name that is empty once trimmed or contains `#` is refused
/// first, and so is a plain http host that is not local unless --allow-http is
/// set, and so is a token given with --token or FABRIC_TOKEN together with
/// --token-stdin or --paste (see [`token_source`]).
///
/// The host is asked which product it is before the token is read, whatever
/// token is given, and a token read afterwards is refused when its prefix says
/// Agent Gateway issued it (see [`product::check_product`]). The token is then
/// checked with the Agent Stream (see [`check_token`]), and only a token it
/// accepts is saved, in `credentials` beside the host it is bound to. A session
/// whose user still has to accept the Terms and Conditions is saved too, with a
/// warning on standard error, because accepting them in the dashboard makes the
/// same session work.
pub async fn login(
    saved: &mut Config,
    credentials: &impl CredentialStore,
    path: &Path,
    globals: &Globals,
    args: LoginArgs,
) -> Result<()> {
    let connection = checked_connection_name(
        globals
            .connection
            .as_deref()
            .unwrap_or(DEFAULT_CONNECTION),
    )?;
    let host = normalize_user_host(
        globals
            .host
            .as_deref()
            .context("--host is required for login")?,
        globals.flags.allow_http,
    )?;
    let source = token_source(globals.token.as_deref(), &args, io::stdin().is_terminal())?;
    product::check_product(Product::AgentStream, &host, globals.token.as_deref(), globals.given()).await?;
    let token = acquire_token(source)?;
    // The host has answered by now, so only the token's prefix is left to check.
    product::check_product(Product::AgentStream, &host, Some(&token), Given::default()).await?;
    let client = GatewayClient::for_agent_stream(&host, &token)?;
    let checked = check_token(&client, &token)
        .await
        .context("validate login")?;
    let note = save_login(saved, credentials, connection, &host, &token, path)?;
    println!("Logged in to '{connection}'");
    if let Some(note) = note {
        eprintln!("{note}");
    }
    if checked == TokenCheck::TermsPending {
        eprintln!("{TERMS_PENDING_WARNING}");
    }
    Ok(())
}

/// Where a login reads its token from. Its `Debug` output never shows the
/// given token.
#[derive(PartialEq, Eq)]
enum TokenSource {
    /// The token given with --token or FABRIC_TOKEN.
    Given(String),
    /// Standard input.
    Stdin,
    /// The terminal, without echo.
    Prompt,
}

impl std::fmt::Debug for TokenSource {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Given(_) => f.write_str("Given(<redacted>)"),
            Self::Stdin => f.write_str("Stdin"),
            Self::Prompt => f.write_str("Prompt"),
        }
    }
}

/// Where a login with `args` reads its token from: the one given with --token
/// or FABRIC_TOKEN (`given`), else standard input for --token-stdin, else the
/// terminal for --paste, else standard input when it is piped
/// (`stdin_is_terminal` false), else the terminal.
///
/// A given token together with --token-stdin or --paste is refused, as clap
/// refuses `login --token ... --paste`: --token is a global flag here, so clap
/// lets it through when it is typed before `login` or comes from the shell's
/// own flags.
fn token_source(
    given: Option<&str>,
    args: &LoginArgs,
    stdin_is_terminal: bool,
) -> Result<TokenSource> {
    if let Some(token) = given {
        if args.token_stdin {
            bail!("the argument '--token-stdin' cannot be used with '--token <TOKEN>'");
        }
        if args.paste {
            bail!("the argument '--paste' cannot be used with '--token <TOKEN>'");
        }
        return Ok(TokenSource::Given(token.to_owned()));
    }
    Ok(if args.token_stdin {
        TokenSource::Stdin
    } else if args.paste || stdin_is_terminal {
        TokenSource::Prompt
    } else {
        TokenSource::Stdin
    })
}

/// The token for a login, read from `source`.
fn acquire_token(source: TokenSource) -> Result<String> {
    match source {
        TokenSource::Given(token) => non_empty_token(token, &super::SHELL_TEXT),
        TokenSource::Stdin => read_stdin_token(&super::SHELL_TEXT),
        TokenSource::Prompt => prompt_token(&super::SHELL_TEXT),
    }
}

/// What Agent Stream said about a login token it accepts.
#[derive(Debug, PartialEq, Eq)]
enum TokenCheck {
    /// The token works for every command its role and scopes allow.
    Accepted,
    /// A signed-in session whose user has not accepted the Terms and
    /// Conditions yet, so Agent Stream refuses its commands until they do.
    TermsPending,
}

/// Checks that the Agent Stream behind `client` accepts `token`. A token with
/// an access token prefix must read the caller's profile (see [`profile`]),
/// and a 401 there is reported as [`ACCESS_TOKEN_REFUSED`]. Any other token is
/// a session token, which `/auth/check` must call authenticated; that route
/// reads sessions only, so it is never asked about an access token, and its
/// `consent_required` tells whether the session's user still has to accept the
/// Terms and Conditions.
async fn check_token(
    client: &GatewayClient,
    token: &str,
) -> Result<TokenCheck> {
    if product::token_product(token).is_some() {
        return match profile(client).await {
            Ok(_) => Ok(TokenCheck::Accepted),
            Err(error) if response_status(&error) == Some(StatusCode::UNAUTHORIZED) => {
                Err(status_error(StatusCode::UNAUTHORIZED, ACCESS_TOKEN_REFUSED.to_owned()))
            }
            Err(error) => Err(error),
        };
    }
    let check = client
        .request(Method::GET, "/auth/check", None)
        .await?;
    if !authenticated(&check) {
        bail!(NOT_A_SESSION)
    }
    let terms_pending = check
        .get("consent_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(if terms_pending {
        TokenCheck::TermsPending
    } else {
        TokenCheck::Accepted
    })
}

/// Whether an `/auth/check` answer says the session is signed in.
pub(super) fn authenticated(check: &Value) -> bool {
    check
        .get("authenticated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The caller's profile from `GET /v1/profile`, which answers any signed-in
/// caller, a scoped access token included. Only a 200 counts: another success
/// or a redirect means the host is not an Agent Stream that is working, and an
/// error answer is reported as the client reports it, so a 401 says what to do.
pub(super) async fn profile(client: &GatewayClient) -> Result<Value> {
    let (status, body) = client
        .request_bytes(Method::GET, "/v1/profile", RawAuth::Bearer)
        .await?;
    if status == StatusCode::OK {
        return serde_json::from_slice(&body).context("Agent Stream profile answer is not JSON");
    }
    if status.is_client_error() || status.is_server_error() {
        return Err(client.response_error(status, &body));
    }
    bail!(
        "Agent Stream answered {status} when checking the token; make sure --host is an Agent Stream address and it \
         is healthy"
    )
}

/// Signs out of a saved connection, `requested` or the current one: ends the
/// session on the Agent Stream when the saved token is a session token (see
/// [`end_remote_session`]), then removes the connection, its token and its
/// bound host from this machine. The Agent Stream part is best effort, so an
/// unreachable host never stops the local removal.
pub async fn logout(
    saved: &mut Config,
    credentials: &impl CredentialStore,
    path: &Path,
    requested: Option<&str>,
) -> Result<()> {
    let name = requested
        .or(saved.current.as_deref())
        .context("no Agent Stream connection selected")?
        .to_owned();
    let note = match saved.connections.get(&name) {
        Some(connection) => end_remote_session(credentials, &name, connection).await,
        None => None,
    };
    remove_connection(saved, credentials, &name, path)?;
    if let Some(note) = note {
        eprintln!("{note}");
    }
    Ok(())
}

/// Ends the session behind the token saved for `name`, sent only to the host
/// it was saved for, and returns the line to show about it. An access token is
/// not sent at all: Agent Stream has no route that says which token is in use,
/// so the note says how to find and revoke it. Neither is a token whose prefix
/// says Agent Gateway issued it.
async fn end_remote_session(
    credentials: &impl CredentialStore,
    name: &str,
    connection: &Connection,
) -> Option<String> {
    let token = credentials
        .get_token(name)
        .ok()
        .flatten()?;
    let host = credentials
        .get_bound_host(name)
        .ok()
        .flatten()
        .unwrap_or_else(|| connection.host.clone());
    match product::token_product(&token) {
        Some(Product::AgentStream) => return Some(access_token_still_valid_note(&host)),
        Some(Product::AgentGateway) => return Some(gateway_token_kept_note(&host)),
        None => {}
    }
    if let Some(warning) = saved_host_http_warning(&host) {
        eprintln!("{warning}");
    }
    let client = GatewayClient::for_agent_stream(&host, &token).ok()?;
    Some(end_session_note(&client).await)
}

/// What to tell a user who logged out of an access token, which logging out
/// cannot revoke.
fn access_token_still_valid_note(host: &str) -> String {
    format!(
        "note: this access token is still valid on {host}; logging out only removed the local copy. To revoke it, \
         log in again, find its ID with `fabric agent-stream tokens list`, and run: fabric agent-stream tokens \
         revoke <token-id>"
    )
}

/// What to tell a user who logged out of an Agent Stream connection whose
/// saved token was issued by Agent Gateway: nothing was sent to `host`.
fn gateway_token_kept_note(host: &str) -> String {
    format!(
        "note: the saved token was issued by Agent Gateway, so nothing was sent to {host}; logging out only removed \
         the local copy, and the token stays valid on the Agent Gateway that issued it until it is revoked or expires"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_stream::test_support::{MemoryCredentials, scripted_agent_stream};

    /// The line logout shows for the connection `default` at `host` holding
    /// `token`, and whether anything was sent to `host`.
    async fn logout_note(token: &str) -> (Option<String>, bool, String) {
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("default", token)
            .unwrap();
        credentials
            .set_bound_host("default", &host)
            .unwrap();

        let note = end_remote_session(&credentials, "default", &Connection::new(host.clone())).await;

        let sent = !requests
            .lock()
            .unwrap()
            .is_empty();
        (note, sent, host)
    }

    #[tokio::test]
    async fn logout_of_an_access_token_says_how_to_find_and_revoke_it() {
        let (note, sent, host) = logout_note("aspat_secret").await;

        assert!(!sent);
        assert_eq!(
            note.as_deref(),
            Some(
                format!(
                    "note: this access token is still valid on {host}; logging out only removed the local copy. To \
                     revoke it, log in again, find its ID with `fabric agent-stream tokens list`, and run: fabric \
                     agent-stream tokens revoke <token-id>"
                )
                .as_str()
            )
        );
    }

    #[tokio::test]
    async fn logout_of_a_gateway_token_saved_for_agent_stream_sends_nothing() {
        let (note, sent, host) = logout_note("agpat_secret").await;

        assert!(!sent);
        let note = note.expect("a note");
        assert!(note.starts_with("note: the saved token was issued by Agent Gateway"), "{note}");
        assert!(note.contains(&format!("nothing was sent to {host}")), "{note}");
        assert!(!note.contains("agpat_secret"), "{note}");
    }

    #[tokio::test]
    async fn logout_of_a_session_on_a_host_that_cannot_be_reached_still_gives_a_note() {
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("default", "session-secret")
            .unwrap();

        let note = end_remote_session(&credentials, "default", &Connection::new("http://127.0.0.1:1".to_owned()))
            .await
            .expect("a note");

        assert!(note.starts_with("warning: could not reach http://127.0.0.1:1 to end the session"), "{note}");
    }

    /// A token given with --token or FABRIC_TOKEN.
    const GIVEN_TOKEN: &str = "aspat_secret";

    /// The login arguments with --token-stdin and --paste set as given.
    fn login_args(
        token_stdin: bool,
        paste: bool,
    ) -> LoginArgs {
        LoginArgs { token_stdin, paste }
    }

    #[test]
    fn a_given_token_comes_first_then_token_stdin_then_paste_then_piped_input_then_the_terminal() {
        for (given, token_stdin, paste, stdin_is_terminal, expected) in [
            (Some(GIVEN_TOKEN), false, false, true, TokenSource::Given(GIVEN_TOKEN.to_owned())),
            (Some(GIVEN_TOKEN), false, false, false, TokenSource::Given(GIVEN_TOKEN.to_owned())),
            (None, true, false, true, TokenSource::Stdin),
            (None, false, true, false, TokenSource::Prompt),
            (None, false, false, false, TokenSource::Stdin),
            (None, false, false, true, TokenSource::Prompt),
        ] {
            assert_eq!(
                token_source(given, &login_args(token_stdin, paste), stdin_is_terminal).unwrap(),
                expected,
                "given {given:?}, --token-stdin {token_stdin}, --paste {paste}, terminal {stdin_is_terminal}"
            );
        }
    }

    #[test]
    fn a_given_token_with_token_stdin_or_paste_is_refused() {
        for (args, flag) in [(login_args(true, false), "--token-stdin"), (login_args(false, true), "--paste")] {
            for stdin_is_terminal in [true, false] {
                let error = token_source(Some(GIVEN_TOKEN), &args, stdin_is_terminal).expect_err("two token sources");

                assert_eq!(error.to_string(), format!("the argument '{flag}' cannot be used with '--token <TOKEN>'"));
            }
        }
    }

    #[test]
    fn a_given_token_is_trimmed_and_an_empty_one_is_refused() {
        assert_eq!(acquire_token(TokenSource::Given("  aspat_secret \n".to_owned())).unwrap(), "aspat_secret");
        let error = acquire_token(TokenSource::Given("   ".to_owned())).expect_err("an empty token");
        assert_eq!(error.to_string(), "token must not be empty");
    }

    #[tokio::test]
    async fn a_session_whose_user_has_not_accepted_the_terms_is_accepted_as_terms_pending() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/auth/check",
            "HTTP/1.1 200 OK",
            r#"{"authenticated":true,"username":"ada","consent_required":true,"terms_enabled":true}"#,
        )])
        .await;
        let client = GatewayClient::for_agent_stream(&host, "session-secret").unwrap();

        let checked = check_token(&client, "session-secret")
            .await
            .expect("a signed-in session");

        assert_eq!(checked, TokenCheck::TermsPending);
    }

    #[tokio::test]
    async fn a_session_with_no_terms_to_accept_is_accepted() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/auth/check",
            "HTTP/1.1 200 OK",
            r#"{"authenticated":true,"username":"ada","consent_required":false,"terms_enabled":true}"#,
        )])
        .await;
        let client = GatewayClient::for_agent_stream(&host, "session-secret").unwrap();

        assert_eq!(
            check_token(&client, "session-secret")
                .await
                .unwrap(),
            TokenCheck::Accepted
        );
    }

    #[tokio::test]
    async fn an_access_token_refused_at_login_says_nothing_was_saved_and_what_to_check() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/profile", "HTTP/1.1 401 Unauthorized", "")]).await;
        let client = GatewayClient::for_agent_stream(&host, "aspat_secret").unwrap();

        let error = check_token(&client, "aspat_secret")
            .await
            .expect_err("refused");

        assert_eq!(
            error.to_string(),
            "Agent Stream did not accept the access token, so nothing was saved; check that it was copied in full, \
             that it is not revoked or expired, and that its owner is still approved"
        );
        assert_eq!(response_status(&error), Some(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn only_an_answer_that_says_authenticated_true_is_a_signed_in_session() {
        assert!(authenticated(&serde_json::json!({"authenticated": true})));
        assert!(!authenticated(&serde_json::json!({"authenticated": false})));
        assert!(!authenticated(&serde_json::json!({"authenticated": "true"})));
        assert!(!authenticated(&serde_json::json!({})));
    }
}
