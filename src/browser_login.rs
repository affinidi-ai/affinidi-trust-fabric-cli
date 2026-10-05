//! Browser-based login for the `fabric` CLI (RFC 8252 loopback + PKCE).
//!
//! The CLI binds a loopback listener, opens the gateway's `/auth/cli/authorize`
//! page in the browser, and waits for the gateway to redirect back to
//! `http://127.0.0.1:<port>/callback` with a single-use code. It then exchanges
//! the code plus its PKCE verifier for the session token over a direct back
//! channel, so the token never appears in a browser URL or history.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::client::{TOTAL_TIMEOUT, build_http_client, sanitize_for_terminal};

/// How long to wait for the browser to complete authentication and redirect
/// back to the loopback listener.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Deserialize)]
struct ExchangeResponse {
    session_token: String,
}

/// Run the browser login against `host` (an origin such as `https://gw.example`)
/// and return the captured session token.
pub async fn browser_login(host: &str) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback listener for browser login")?;
    let port = listener
        .local_addr()
        .context("read loopback listener address")?
        .port();

    let verifier = random_token();
    let challenge = pkce_challenge_s256(&verifier);
    let state = random_token();

    let authorize_url = format!("{host}/api/auth/cli/authorize?port={port}&state={state}&challenge={challenge}");

    eprintln!("Opening your browser to sign in...");
    if open::that(&authorize_url).is_err() {
        eprintln!("warning: could not open a browser automatically");
    }
    eprintln!("If the browser did not open, visit this URL to continue:\n  {authorize_url}");

    let expected_state = state.clone();
    let code = tokio::task::spawn_blocking(move || wait_for_callback(&listener, &expected_state, CALLBACK_TIMEOUT))
        .await
        .context("browser login listener task failed")??;

    exchange_code(host, &code, &verifier).await
}

/// Block until the gateway redirects the browser to `/callback`, returning the
/// authorization code once the `state` matches.
fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String> {
    listener
        .set_nonblocking(true)
        .context("configure loopback listener")?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .context("configure loopback connection")?;
                if let Some(code) = handle_connection(stream, expected_state)? {
                    return Ok(code);
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    bail!("timed out waiting for the browser login to complete");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error).context("accept loopback connection"),
        }
    }
}

/// Parse one loopback HTTP request. Returns the code on a valid `/callback`
/// hit, `None` for unrelated requests (e.g. a browser favicon probe).
fn handle_connection(
    mut stream: TcpStream,
    expected_state: &str,
) -> Result<Option<String>> {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .context("clone loopback stream")?,
    );
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("read loopback request line")?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("");
    let (route, query) = path
        .split_once('?')
        .unwrap_or((path, ""));

    if route != "/callback" {
        write_response(&mut stream, "404 Not Found", "text/plain; charset=utf-8", "Not found")?;
        return Ok(None);
    }

    let params = parse_query(query);
    if let Some(error) = params.get("error") {
        write_response(
            &mut stream,
            "400 Bad Request",
            "text/html; charset=utf-8",
            &result_page("Sign-in failed", error),
        )?;
        // The gateway's redirect carries only `code` and `state`, and this
        // check runs before the state is verified, so `error` can come from
        // anything that reached the port.
        bail!("the login callback reported an error: {}", sanitize_for_terminal(error));
    }
    if params
        .get("state")
        .map(String::as_str)
        != Some(expected_state)
    {
        write_response(
            &mut stream,
            "400 Bad Request",
            "text/html; charset=utf-8",
            &result_page("Sign-in failed", "state mismatch"),
        )?;
        bail!("browser login state mismatch (possible CSRF); aborting");
    }
    let code = params
        .get("code")
        .cloned()
        .context("browser login callback did not include a code")?;

    write_response(
        &mut stream,
        "200 OK",
        "text/html; charset=utf-8",
        &result_page("Signed in", "You can close this tab and return to the terminal."),
    )?;
    Ok(Some(code))
}

/// Exchange the authorization code plus PKCE verifier for the session token.
async fn exchange_code(
    host: &str,
    code: &str,
    verifier: &str,
) -> Result<String> {
    exchange_code_within(host, code, verifier, TOTAL_TIMEOUT).await
}

/// [`exchange_code`] with the limit on the whole exchange passed in, so a test
/// can use a short one.
async fn exchange_code_within(
    host: &str,
    code: &str,
    verifier: &str,
    total_timeout: Duration,
) -> Result<String> {
    let response = build_http_client()?
        .post(format!("{host}/api/auth/cli/exchange"))
        .timeout(total_timeout)
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .context("exchange authorization code")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("read exchange response")?;
    if !status.is_success() {
        bail!("code exchange failed ({status}): {}", sanitize_for_terminal(&body));
    }
    let parsed: ExchangeResponse = serde_json::from_str(&body).context("parse exchange response")?;
    Ok(parsed.session_token)
}

fn parse_query(query: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream
        .write_all(response.as_bytes())
        .context("write loopback response")?;
    stream
        .flush()
        .context("flush loopback response")
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn result_page(
    title: &str,
    message: &str,
) -> String {
    let title = escape_html(title);
    let message = escape_html(message);
    format!(
        "<!DOCTYPE html><html><head><title>{title}</title></head>\
         <body style=\"font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; text-align: center;\">\
         <h1>{title}</h1><p>{message}</p></body></html>"
    )
}

/// Generate a 256-bit random value encoded as base64url (a valid PKCE verifier).
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute the PKCE S256 challenge for `verifier`.
fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_known_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(pkce_challenge_s256(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn random_token_is_url_safe_and_long_enough() {
        let token = random_token();
        assert!(token.len() >= 43);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    /// The exchange error inlines the gateway's body, so it gets the same
    /// control-character stripping and length cap as every other error.
    #[tokio::test]
    async fn a_failed_code_exchange_sanitizes_the_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let body = format!("bad code\u{1b}[31m\rFAKE OK{}", "x".repeat(600));
                let response = format!(
                    "HTTP/1.1 400 Bad Request\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });

        let error = exchange_code(&format!("http://{addr}"), "code", "verifier")
            .await
            .expect_err("a 400 fails the exchange");

        let message = error.to_string();
        let detail = message
            .strip_prefix("code exchange failed (400 Bad Request): ")
            .expect("the status leads the message");
        assert!(
            !message
                .chars()
                .any(char::is_control),
            "control character leaked into: {message:?}"
        );
        assert!(detail.starts_with("bad code[31mFAKE OK"), "got: {detail}");
        assert_eq!(detail.chars().count(), 500);
    }

    /// The exchange sends the PKCE verifier, so a gateway that answers with a
    /// redirect to another host must not be followed there.
    #[tokio::test]
    async fn the_code_exchange_does_not_follow_a_redirect_to_another_host() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let elsewhere_port = elsewhere
            .local_addr()
            .expect("local addr")
            .port();
        let gateway = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = gateway
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = gateway.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://localhost:{elsewhere_port}/steal\r\ncontent-length: \
                     0\r\nconnection: close\r\n\r\n"
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });

        let error = exchange_code(&format!("http://{addr}"), "code", "verifier")
            .await
            .expect_err("a redirect is not a successful exchange");

        assert!(
            error
                .to_string()
                .starts_with("code exchange failed (307 Temporary Redirect)"),
            "{error}"
        );
        let reached = tokio::time::timeout(Duration::from_millis(300), elsewhere.accept()).await;
        assert!(reached.is_err(), "the other host must not be contacted");
    }

    #[tokio::test]
    async fn a_server_that_drips_the_exchange_answer_is_cut_off_by_the_total_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let gateway = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = gateway
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = gateway.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000\r\n\r\n";
                if socket
                    .write_all(head.as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                for _ in 0..1000 {
                    if socket
                        .write_all(b" ")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });

        let started = Instant::now();
        let result =
            exchange_code_within(&format!("http://{addr}"), "code", "verifier", Duration::from_millis(400)).await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    /// `error=` arrives before the state check, from whatever reached the
    /// loopback port, so a terminal escape sequence in it must not survive
    /// into the error the CLI prints.
    #[test]
    fn a_callback_error_is_sanitized() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener
            .local_addr()
            .expect("local addr");
        let mut browser = TcpStream::connect(address).expect("connect");
        browser
            .write_all(b"GET /callback?error=denied%1B%5D0%3Bpwned%07%1B%5B2J HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("send the callback");
        let (stream, _) = listener
            .accept()
            .expect("accept");

        let error = handle_connection(stream, "expected-state").expect_err("an error callback fails the login");

        // Only the printable remainder of the sequences is left, which a
        // terminal shows as text rather than acting on.
        assert_eq!(error.to_string(), "the login callback reported an error: denied]0;pwned[2J");
    }

    #[test]
    fn parses_callback_query() {
        let params = parse_query("code=abc%20123&state=xyz");
        assert_eq!(
            params
                .get("code")
                .map(String::as_str),
            Some("abc 123")
        );
        assert_eq!(
            params
                .get("state")
                .map(String::as_str),
            Some("xyz")
        );
    }
}
