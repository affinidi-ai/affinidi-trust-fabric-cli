//! What the tests of the `fabric agent-stream` command groups share.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Result, bail};
use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{AgentStreamArgs, dispatch_with};
use crate::{
    commands::Cli,
    config::{Config, Connection},
    credentials::CredentialStore,
    product::Product,
};

/// An Agent Stream credential store kept in memory, so a test never reads or
/// writes the OS keyring.
#[derive(Default)]
pub struct MemoryCredentials(Mutex<HashMap<String, String>>);

impl CredentialStore for MemoryCredentials {
    fn product(&self) -> Product {
        Product::AgentStream
    }

    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(connection)
            .cloned())
    }

    fn set_token(
        &self,
        connection: &str,
        token: &str,
    ) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(connection.to_owned(), token.to_owned());
        Ok(())
    }

    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .remove(connection);
        Ok(())
    }
}

/// A credential store whose every call fails as the OS keyring does on a
/// Linux machine with no D-Bus session to reach a Secret Service over, such
/// as a server with no desktop session.
#[cfg(target_os = "linux")]
pub struct NoKeyring;

#[cfg(target_os = "linux")]
impl NoKeyring {
    fn unreachable<T>(action: &str) -> Result<T> {
        Err(anyhow::Error::new(keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable)))
            .context(format!("{action} in OS keyring")))
    }
}

#[cfg(target_os = "linux")]
impl CredentialStore for NoKeyring {
    fn product(&self) -> Product {
        Product::AgentStream
    }

    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        Self::unreachable(&format!("read connection '{connection}' token"))
    }

    fn set_token(
        &self,
        connection: &str,
        _token: &str,
    ) -> Result<()> {
        Self::unreachable(&format!("store connection '{connection}' token"))
    }

    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()> {
        Self::unreachable(&format!("delete connection '{connection}' token"))
    }
}

/// An Agent Stream credential store whose every call fails, on every system,
/// for a test that proves a command never touches the keyring.
pub struct UnusedKeyring;

impl CredentialStore for UnusedKeyring {
    fn product(&self) -> Product {
        Product::AgentStream
    }

    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        bail!("the keyring was asked for the token of '{connection}'")
    }

    fn set_token(
        &self,
        connection: &str,
        _token: &str,
    ) -> Result<()> {
        bail!("the keyring was asked to save a token for '{connection}'")
    }

    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()> {
        bail!("the keyring was asked to delete the token of '{connection}'")
    }
}

/// One answer of a [`scripted_agent_stream`]: the request start it answers,
/// such as `GET /api/v1/profile`, its status line, [`HANG_UP`], or
/// [`CUT_OFF`], and its body.
pub type Route = (&'static str, &'static str, &'static str);

/// The status line of a [`Route`] that closes the connection after reading
/// the request, without any answer.
pub const HANG_UP: &str = "hang up";

/// The status line of a [`Route`] that answers `200 OK` with a
/// `content-length` one byte longer than its body, then closes the
/// connection, so the answer is cut off while it is read.
pub const CUT_OFF: &str = "cut off";

/// Answers each request with the route whose request start it begins with,
/// and `404 Not Found` with an empty body to any other, until the test ends.
/// When several routes share one request start, the first request gets the
/// first of them, the next request the next, and the last one answers every
/// request after that. A route whose status line is [`HANG_UP`] closes the
/// connection with no answer, and one whose status line is [`CUT_OFF`] sends
/// only part of its answer. Records each whole request, headers and body
/// included. Returns its base URL and the recording.
pub async fn scripted_agent_stream(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let mut answered: HashMap<&'static str, usize> = HashMap::new();
    serve(move |request| {
        let matching: Vec<&Route> = routes
            .iter()
            .filter(|(start, _, _)| request.starts_with(&format!("{start} ")))
            .collect();
        let (start, _, _) = matching.first()?;
        let count = answered
            .entry(start)
            .or_default();
        let (_, status_line, body) = matching[(*count).min(matching.len() - 1)];
        *count += 1;
        Some((*status_line, *body))
    })
    .await
}

/// Like [`scripted_agent_stream`], but each route answers once: a request
/// gets the first unused route it begins with, which is then used up, so the
/// same request can get a different answer each time it is sent.
pub async fn scripted_agent_stream_in_order(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let mut remaining = routes;
    serve(move |request| {
        let index = remaining
            .iter()
            .position(|(start, _, _)| request.starts_with(&format!("{start} ")))?;
        let (_, status_line, body) = remaining.remove(index);
        Some((status_line, body))
    })
    .await
}

/// Answers each request with the status line and body `answer` picks for it,
/// or `404 Not Found` with an empty body when it picks none, until the test
/// ends, recording each whole request.
async fn serve(
    mut answer: impl FnMut(&str) -> Option<(&'static str, &'static str)> + Send + 'static
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener
        .local_addr()
        .expect("local addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let request = read_request(&mut socket).await;
            let (status_line, body) = answer(&request).unwrap_or(("HTTP/1.1 404 Not Found", ""));
            recorded
                .lock()
                .unwrap()
                .push(request);
            if status_line == HANG_UP {
                continue;
            }
            let (status_line, length) = if status_line == CUT_OFF {
                ("HTTP/1.1 200 OK", body.len() + 1)
            } else {
                (status_line, body.len())
            };
            let response = format!("{status_line}\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n{body}");
            let _ = socket
                .write_all(response.as_bytes())
                .await;
            let _ = socket.shutdown().await;
        }
    });
    (format!("http://{addr}"), requests)
}

/// Reads one request: its head, then as many body bytes as its
/// `content-length` says.
async fn read_request(socket: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = socket
            .read(&mut buf)
            .await
            .unwrap_or(0);
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&bytes);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| {
                            value
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .flatten()
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The start line of each recorded request, such as
/// `GET /api/v1/profile HTTP/1.1`.
pub fn start_lines(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| {
            request
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// The body of a recorded request: what follows its head.
pub fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
}

/// The Agent Stream arguments of `fabric agent-stream <words>`.
pub fn stream_args(words: &[&str]) -> AgentStreamArgs {
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
pub fn saved_login(
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
pub async fn run_stream(
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
pub fn sends_bearer(
    request: &str,
    token: &str,
) -> bool {
    request
        .to_ascii_lowercase()
        .contains(&format!("authorization: bearer {}", token.to_ascii_lowercase()))
}

/// Writes `contents` to a temporary JSON file kept alive by the returned
/// handle.
pub fn json_file(contents: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), contents).expect("write JSON file");
    file
}
