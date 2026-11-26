//! What the tests of the `fabric agent-stream` command groups share.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{credentials::CredentialStore, product::Product};

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
/// such as `GET /api/v1/profile`, its status line, and its body.
pub type Route = (&'static str, &'static str, &'static str);

/// Answers each request with the route whose request start it begins with,
/// and `404 Not Found` with an empty body to any other, until the test ends.
/// Records each whole request, headers and body included. Returns its base URL
/// and the recording.
pub async fn scripted_agent_stream(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
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
            let (status_line, body) = routes
                .iter()
                .find(|(start, _, _)| request.starts_with(&format!("{start} ")))
                .map_or(("HTTP/1.1 404 Not Found", ""), |(_, status_line, body)| (*status_line, *body));
            recorded
                .lock()
                .unwrap()
                .push(request);
            let response =
                format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
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
