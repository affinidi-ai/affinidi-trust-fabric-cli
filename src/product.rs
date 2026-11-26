//! Telling Agent Gateway and Agent Stream apart, so a command written for one
//! never sends a token to, or writes anything on, the other.
//!
//! The stop only acts in a binary built with the `agent-stream` Cargo feature.
//! A binary built without it, as every release is, has one product to talk to,
//! so [`check_product`] returns at once there: it refuses nothing and sends
//! nothing. The whole file is compiled in both builds, so its tests run in
//! both.

use std::{cell::RefCell, collections::BTreeMap, future::Future, time::Duration};

use anyhow::{Result, bail};
use reqwest::StatusCode;
use serde_json::Value;

use crate::{client::build_http_client, config::normalize_host};

/// Prefix of every Agent Gateway personal access token, matching
/// `access_tokens::TOKEN_PREFIX` on the gateway.
pub const AGENT_GATEWAY_PAT_PREFIX: &str = "agpat_";

/// Prefixes of an Agent Stream personal access token: the current one, and the
/// one tokens were issued with before the product was renamed.
pub const AGENT_STREAM_PAT_PREFIXES: [&str; 2] = ["aspat_", "atgpat_"];

/// Public route both products answer to anonymous callers with a JSON object
/// of permission name to `false`. Only Agent Stream's object has the key
/// [`AGENT_STREAM_ONLY_PERMISSION`].
const PUBLIC_PERMISSIONS_PATH: &str = "/api/v1/permissions/public";

/// A permission that exists on Agent Stream and not on Agent Gateway.
const AGENT_STREAM_ONLY_PERMISSION: &str = "pipes.view";

/// How long the whole probe may take. It is a small extra before a command,
/// so a slow host must not hold the command for long.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest permission list the probe reads. Both products answer with a few
/// dozen keys, so anything bigger is refused before it is held in memory.
const MAX_PROBE_BODY_BYTES: usize = 64 * 1024;

tokio::task_local! {
    /// The product each host answered as, under the host as [`normalize_host`]
    /// writes it, for as long as [`remembering_probes`] runs. A host whose
    /// product could not be read is never in it.
    static REMEMBERED_PRODUCTS: RefCell<BTreeMap<String, Product>>;
}

/// An Affinidi product the CLI talks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    AgentGateway,
    AgentStream,
}

impl Product {
    /// The product's name as shown to the user.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::AgentGateway => "Agent Gateway",
            Self::AgentStream => "Agent Stream",
        }
    }

    /// The `fabric` command group that talks to this product.
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::AgentGateway => "fabric agent-gateway",
            Self::AgentStream => "fabric agent-stream",
        }
    }

    /// How a message about a request names the product that answered it:
    /// `gateway`, the word the Agent Gateway messages used before there was a
    /// second product, or `Agent Stream`.
    pub(crate) fn message_name(self) -> &'static str {
        match self {
            Self::AgentGateway => "gateway",
            Self::AgentStream => "Agent Stream",
        }
    }

    /// How a message names one of this product's saved connections:
    /// `gateway connection`, as the Agent Gateway messages always have, or
    /// `Agent Stream connection`.
    pub(crate) fn connection_noun(self) -> &'static str {
        match self {
            Self::AgentGateway => "gateway connection",
            Self::AgentStream => "Agent Stream connection",
        }
    }

    /// The name of the file this product's connections are saved in, under
    /// the `fabric` configuration directory.
    pub(crate) fn config_file_name(self) -> &'static str {
        match self {
            Self::AgentGateway => "config.toml",
            Self::AgentStream => "agent-stream.toml",
        }
    }
}

/// The product that issued `token`, read from its prefix. Whitespace around
/// the token is not part of it, so a token typed with a leading space is read
/// the same. `None` for a token with neither product's prefix, such as a
/// browser session token.
pub fn token_product(token: &str) -> Option<Product> {
    let token = token.trim();
    if token.starts_with(AGENT_GATEWAY_PAT_PREFIX) {
        Some(Product::AgentGateway)
    } else if AGENT_STREAM_PAT_PREFIXES
        .iter()
        .any(|prefix| token.starts_with(prefix))
    {
        Some(Product::AgentStream)
    } else {
        None
    }
}

/// Runs `session` and, for as long as it runs, asks each host which product
/// it is at most once: the answer [`check_product`] gets is remembered for the
/// host and used for every later command in `session`. The interactive shell
/// runs under this, because it runs every typed line as a command against the
/// same host. Only a product the host named is remembered. A host that could
/// not be read is asked again by the next command, so a host that later
/// answers as the other product is still refused. Outside `session` nothing
/// is remembered and every command asks. In a binary built without the
/// `agent-stream` Cargo feature no host is asked, so there is nothing to
/// remember and `session` runs as it would by itself.
pub async fn remembering_probes<F: Future>(session: F) -> F::Output {
    REMEMBERED_PRODUCTS
        .scope(RefCell::new(BTreeMap::new()), session)
        .await
}

/// What showed that a command is aimed at the other product.
enum Mismatch<'a> {
    /// The prefix of the token the command was given.
    TokenPrefix,
    /// The answer of the host the command was given, as the user wrote it.
    Host(&'a str),
}

/// The message for a command of `expected` that was stopped because
/// `mismatch` showed it is aimed at `found`. It ends with the command group
/// to use for `found`. The token is not an input, so no part of it can be in
/// the message.
fn wrong_product_message(
    expected: Product,
    found: Product,
    mismatch: Mismatch<'_>,
) -> String {
    let reason = match mismatch {
        Mismatch::TokenPrefix => {
            format!("this token was issued by {}, so `{}` cannot use it", found.name(), expected.command())
        }
        Mismatch::Host(host) => format!("{host} is an {}, not an {}", found.name(), expected.name()),
    };
    format!("{reason}; run the command as `{} ...` instead", found.command())
}

/// Stops a command of `expected` that is aimed at the other product, before
/// anything is sent with the token or written, in a binary built with the
/// `agent-stream` Cargo feature (see [`stop_if_other_product`] for the rules).
///
/// In a binary built without the feature, as every release is, this returns
/// `Ok` at once: no token is refused and no host is asked, so an Agent Gateway
/// command sends exactly the requests it sent before the stop existed.
pub async fn check_product(
    expected: Product,
    host: &str,
    token: Option<&str>,
    host_given: bool,
) -> Result<()> {
    if !cfg!(feature = "agent-stream") {
        return Ok(());
    }
    stop_if_other_product(expected, host, token, host_given).await
}

/// The stop behind [`check_product`], whatever the binary was built with.
///
/// A `token` with the other product's prefix is refused on the spot, without a
/// request. Any other token, including one with the command's own prefix, is
/// checked against the host when `host_given` says the host was typed with
/// `--host` or set in FABRIC_HOST: `host` is asked which product it is,
/// without the token, and the other product is refused, so an Agent Gateway
/// access token is not sent to a typed host that answers as Agent Stream, nor
/// an Agent Stream access token to one that answers as Agent Gateway. A saved
/// connection is not asked,
/// because it already belongs to its product's store. Inside
/// [`remembering_probes`] a host that has named its product is not asked
/// again. When the host cannot be read, an Agent Gateway command carries on
/// and an Agent Stream command stops.
///
/// A refusal is worded by [`wrong_product_message`], which names the command
/// group of the other product. Neither the token nor any part of it is ever
/// put in a message.
async fn stop_if_other_product(
    expected: Product,
    host: &str,
    token: Option<&str>,
    host_given: bool,
) -> Result<()> {
    if let Some(product) = token
        .and_then(token_product)
        .filter(|product| *product != expected)
    {
        bail!(wrong_product_message(expected, product, Mismatch::TokenPrefix));
    }
    if !host_given {
        return Ok(());
    }
    match host_product(host).await {
        Some(product) if product == expected => Ok(()),
        Some(product) => bail!(wrong_product_message(expected, product, Mismatch::Host(host))),
        None if expected == Product::AgentGateway => Ok(()),
        None => bail!(
            "could not confirm that {host} is an {}, because its public permission list at {PUBLIC_PERMISSIONS_PATH} \
             could not be read, so nothing was sent; check that the host is right and can be reached",
            expected.name()
        ),
    }
}

/// Which product runs at `host`: the answer remembered for it inside
/// [`remembering_probes`], else what [`probe_product`] finds now, which is
/// then remembered. Hosts are compared as [`normalize_host`] writes them, so
/// a different case, a default port or a trailing slash is the same host.
async fn host_product(host: &str) -> Option<Product> {
    let key = normalize_host(host).unwrap_or_else(|_| host.to_owned());
    let remembered = REMEMBERED_PRODUCTS
        .try_with(|products| {
            products
                .borrow()
                .get(&key)
                .copied()
        })
        .ok()
        .flatten();
    if remembered.is_some() {
        return remembered;
    }
    let product = probe_product(host).await?;
    // Outside `remembering_probes` there is nowhere to keep the answer, and a
    // command that runs on its own asks only once anyway.
    let _ = REMEMBERED_PRODUCTS.try_with(|products| {
        products
            .borrow_mut()
            .insert(key, product)
    });
    Some(product)
}

/// Which product runs at `host`, asked without a token through the public
/// permission list: an object with [`AGENT_STREAM_ONLY_PERMISSION`] among its
/// keys is Agent Stream, any other object is Agent Gateway. `None` when the
/// host could not be reached in [`PROBE_TIMEOUT`], answered anything but 200,
/// or answered with something other than a JSON object within
/// [`MAX_PROBE_BODY_BYTES`].
async fn probe_product(host: &str) -> Option<Product> {
    let url = format!("{host}{PUBLIC_PERMISSIONS_PATH}");
    let mut response = build_http_client()
        .ok()?
        .get(&url)
        .timeout(PROBE_TIMEOUT)
        .send()
        .await
        .ok()?;
    if response.status() != StatusCode::OK {
        return None;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROBE_BODY_BYTES as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > MAX_PROBE_BODY_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    let permissions: Value = serde_json::from_slice(&body).ok()?;
    let permissions = permissions.as_object()?;
    Some(if permissions.contains_key(AGENT_STREAM_ONLY_PERMISSION) {
        Product::AgentStream
    } else {
        Product::AgentGateway
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const GATEWAY_PERMISSIONS: &str = r#"{"surfaces.view":false,"users.view":false}"#;
    const STREAM_PERMISSIONS: &str = r#"{"pipes.view":false,"users.view":false}"#;
    const SESSION_TOKEN: &str = "session-token-with-no-prefix";
    const GATEWAY_TOKEN: &str = "agpat_secret-value";
    const STREAM_TOKEN: &str = "aspat_secret-value";
    const OLD_STREAM_TOKEN: &str = "atgpat_secret-value";
    const STREAM_HOST: &str = "https://stream.example";
    const GATEWAY_HOST: &str = "https://gateway.example";

    /// Answers every request with `status_line` and `body` until the test
    /// ends, and records each request. Returns its base URL and the recording.
    async fn answering_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        scripted_server(vec![(status_line, body)]).await
    }

    /// Answers the requests it gets with `answers`, one each in order, and
    /// every request after those with the last one, until the test ends.
    /// Records each request. Returns its base URL and the recording.
    async fn scripted_server(answers: Vec<(&'static str, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
        whole_answer_server(
            answers
                .into_iter()
                .map(|(status_line, body)| {
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                })
                .collect(),
        )
        .await
    }

    /// Like [`scripted_server`], with each of `answers` written to the
    /// connection as it is, status line and headers included, so a test
    /// decides whether the answer says how long its body is.
    async fn whole_answer_server(answers: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            let mut served = 0;
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..read]).into_owned());
                let Some(answer) = answers
                    .get(served)
                    .or(answers.last())
                else {
                    return;
                };
                served += 1;
                let _ = socket
                    .write_all(answer.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), requests)
    }

    /// Answers one request with a 200 whose headers state a body of
    /// `stated_length` bytes, then sends no body and keeps the connection
    /// open until the test ends. Returns its base URL.
    async fn head_only_server(stated_length: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {stated_length}\r\n\r\n");
            let _ = socket
                .write_all(head.as_bytes())
                .await;
            std::future::pending::<()>().await;
        });
        format!("http://{addr}")
    }

    /// A loopback address with nothing listening, so every connection is refused.
    fn refusing_host() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener
            .local_addr()
            .expect("local addr");
        drop(listener);
        format!("http://{address}")
    }

    fn request_lines(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
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

    /// An Agent Stream permission list that is exactly `bytes` long.
    fn stream_permissions_of(bytes: usize) -> String {
        let (start, end) = (r#"{"pipes.view":false,"padding":""#, r#""}"#);
        format!("{start}{}{end}", "a".repeat(bytes - start.len() - end.len()))
    }

    #[test]
    fn a_token_prefix_names_the_product_that_issued_it() {
        assert_eq!(token_product(GATEWAY_TOKEN), Some(Product::AgentGateway));
        assert_eq!(token_product(STREAM_TOKEN), Some(Product::AgentStream));
        assert_eq!(token_product(OLD_STREAM_TOKEN), Some(Product::AgentStream));
        assert_eq!(token_product(SESSION_TOKEN), None);
        assert_eq!(token_product(""), None);
    }

    #[test]
    fn whitespace_around_a_token_does_not_hide_its_prefix() {
        assert_eq!(token_product(&format!(" {STREAM_TOKEN}")), Some(Product::AgentStream));
        assert_eq!(token_product(&format!("\t{OLD_STREAM_TOKEN}\n")), Some(Product::AgentStream));
        assert_eq!(token_product(&format!(" {GATEWAY_TOKEN} ")), Some(Product::AgentGateway));
        assert_eq!(token_product(&format!(" {SESSION_TOKEN}")), None);
    }

    #[test]
    fn a_stopped_token_names_the_command_of_the_product_that_issued_it() {
        assert_eq!(
            wrong_product_message(Product::AgentGateway, Product::AgentStream, Mismatch::TokenPrefix),
            "this token was issued by Agent Stream, so `fabric agent-gateway` cannot use it; \
             run the command as `fabric agent-stream ...` instead"
        );
        assert_eq!(
            wrong_product_message(Product::AgentStream, Product::AgentGateway, Mismatch::TokenPrefix),
            "this token was issued by Agent Gateway, so `fabric agent-stream` cannot use it; \
             run the command as `fabric agent-gateway ...` instead"
        );
    }

    #[test]
    fn a_stopped_host_names_the_command_of_the_product_it_answered_as() {
        assert_eq!(
            wrong_product_message(Product::AgentGateway, Product::AgentStream, Mismatch::Host(STREAM_HOST)),
            "https://stream.example is an Agent Stream, not an Agent Gateway; \
             run the command as `fabric agent-stream ...` instead"
        );
        assert_eq!(
            wrong_product_message(Product::AgentStream, Product::AgentGateway, Mismatch::Host(GATEWAY_HOST)),
            "https://gateway.example is an Agent Gateway, not an Agent Stream; \
             run the command as `fabric agent-gateway ...` instead"
        );
    }

    #[cfg(not(feature = "agent-stream"))]
    #[tokio::test]
    async fn a_build_without_the_feature_refuses_nothing_and_asks_no_host() {
        let (stream, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        for token in [GATEWAY_TOKEN, STREAM_TOKEN, OLD_STREAM_TOKEN, SESSION_TOKEN] {
            check_product(Product::AgentGateway, &stream, Some(token), true)
                .await
                .expect("the stop is off in a build without the feature");
        }
        check_product(Product::AgentGateway, &stream, None, true)
            .await
            .expect("the stop is off in a build without the feature");

        assert!(request_lines(&requests).is_empty());
    }

    #[cfg(feature = "agent-stream")]
    #[tokio::test]
    async fn a_build_with_the_feature_stops_a_command_aimed_at_the_other_product() {
        let (stream, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        let by_prefix = check_product(Product::AgentGateway, &stream, Some(STREAM_TOKEN), true)
            .await
            .expect_err("an Agent Stream token must be refused");
        assert!(request_lines(&requests).is_empty());
        let by_host = check_product(Product::AgentGateway, &stream, Some(SESSION_TOKEN), true)
            .await
            .expect_err("an Agent Stream host must be refused");

        assert!(
            by_prefix
                .to_string()
                .contains("issued by Agent Stream"),
            "{by_prefix}"
        );
        assert!(
            by_host
                .to_string()
                .contains("is an Agent Stream, not an Agent Gateway"),
            "{by_host}"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1"]);
    }

    #[tokio::test]
    async fn an_agent_stream_token_on_a_gateway_command_stops_without_a_request() {
        let (host, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        for token in [STREAM_TOKEN, OLD_STREAM_TOKEN] {
            let error = stop_if_other_product(Product::AgentGateway, &host, Some(token), true)
                .await
                .expect_err("an Agent Stream token must be refused");

            let text = error.to_string();
            assert!(text.contains("issued by Agent Stream"), "{text}");
            assert!(text.contains("`fabric agent-stream ...`"), "{text}");
            assert!(!text.contains("secret-value"), "{text}");
        }
        assert!(request_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn a_gateway_token_on_an_agent_stream_command_stops_without_a_request() {
        let (host, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        let error = stop_if_other_product(Product::AgentStream, &host, Some(GATEWAY_TOKEN), true)
            .await
            .expect_err("an Agent Gateway token must be refused");

        let text = error.to_string();
        assert!(text.contains("issued by Agent Gateway"), "{text}");
        assert!(text.contains("`fabric agent-gateway ...`"), "{text}");
        assert!(!text.contains("secret-value"), "{text}");
        assert!(request_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn an_agent_stream_token_typed_with_a_leading_space_stops_without_a_request() {
        let (host, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        let error = stop_if_other_product(Product::AgentGateway, &host, Some(&format!(" {STREAM_TOKEN}")), true)
            .await
            .expect_err("the space must not hide the Agent Stream prefix");

        let text = error.to_string();
        assert!(text.contains("issued by Agent Stream"), "{text}");
        assert!(!text.contains("secret-value"), "{text}");
        assert!(request_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn a_token_with_the_expected_prefix_on_a_saved_connection_is_not_probed() {
        let (host, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        stop_if_other_product(Product::AgentGateway, &host, Some(GATEWAY_TOKEN), false)
            .await
            .expect("the prefix says Agent Gateway and the host is saved");
        stop_if_other_product(Product::AgentStream, &host, Some(STREAM_TOKEN), false)
            .await
            .expect("the prefix says Agent Stream and the host is saved");

        assert!(request_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn a_gateway_token_with_a_given_host_of_agent_stream_stops_after_a_probe_without_the_token() {
        let (stream, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        let error = stop_if_other_product(Product::AgentGateway, &stream, Some(GATEWAY_TOKEN), true)
            .await
            .expect_err("an Agent Gateway token must not reach an Agent Stream host");

        let text = error.to_string();
        assert!(text.contains(&format!("{stream} is an Agent Stream, not an Agent Gateway")), "{text}");
        assert!(text.contains("`fabric agent-stream ...`"), "{text}");
        assert!(!text.contains("secret-value"), "{text}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /api/v1/permissions/public HTTP/1.1"), "{}", requests[0]);
        assert!(!requests[0].contains("secret-value"), "{}", requests[0]);
    }

    #[tokio::test]
    async fn a_gateway_token_with_a_given_host_of_agent_gateway_carries_on_after_a_probe() {
        let (gateway, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        stop_if_other_product(Product::AgentGateway, &gateway, Some(GATEWAY_TOKEN), true)
            .await
            .expect("an Agent Gateway host");

        assert_eq!(request_lines(&requests), ["GET /api/v1/permissions/public HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_gateway_token_with_a_given_host_that_cannot_be_read_carries_on() {
        stop_if_other_product(Product::AgentGateway, &refusing_host(), Some(GATEWAY_TOKEN), true)
            .await
            .expect("an Agent Gateway command carries on when the host cannot be read");
    }

    #[tokio::test]
    async fn an_agent_stream_token_with_a_given_host_of_agent_gateway_stops_after_a_probe_without_the_token() {
        let (gateway, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        for token in [STREAM_TOKEN, OLD_STREAM_TOKEN] {
            let error = stop_if_other_product(Product::AgentStream, &gateway, Some(token), true)
                .await
                .expect_err("an Agent Stream token must not reach an Agent Gateway host");

            let text = error.to_string();
            assert!(text.contains(&format!("{gateway} is an Agent Gateway, not an Agent Stream")), "{text}");
            assert!(text.contains("`fabric agent-gateway ...`"), "{text}");
            assert!(!text.contains("secret-value"), "{text}");
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert!(request.starts_with("GET /api/v1/permissions/public HTTP/1.1"), "{request}");
            assert!(!request.contains("secret-value"), "{request}");
        }
    }

    #[tokio::test]
    async fn an_agent_stream_token_with_a_given_host_that_cannot_be_read_stops() {
        let host = refusing_host();

        let error = stop_if_other_product(Product::AgentStream, &host, Some(STREAM_TOKEN), true)
            .await
            .expect_err("an Agent Stream command needs a known host");

        let text = error.to_string();
        assert!(text.contains(&format!("could not confirm that {host} is an Agent Stream")), "{text}");
        assert!(!text.contains("secret-value"), "{text}");
    }

    #[tokio::test]
    async fn an_agent_stream_token_with_a_given_host_of_agent_stream_carries_on() {
        let (stream, _) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        stop_if_other_product(Product::AgentStream, &stream, Some(STREAM_TOKEN), true)
            .await
            .expect("an Agent Stream host");
    }

    #[tokio::test]
    async fn a_saved_connection_is_not_probed() {
        let (host, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        stop_if_other_product(Product::AgentGateway, &host, Some(SESSION_TOKEN), false)
            .await
            .expect("a saved connection already belongs to its product's store");

        assert!(request_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn the_probe_tells_the_products_apart_by_the_pipes_permission() {
        let (stream, stream_requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;
        let (gateway, _) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        assert_eq!(probe_product(&stream).await, Some(Product::AgentStream));
        assert_eq!(probe_product(&gateway).await, Some(Product::AgentGateway));

        let requests = stream_requests
            .lock()
            .unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /api/v1/permissions/public HTTP/1.1"), "{}", requests[0]);
        assert!(
            !requests[0]
                .to_ascii_lowercase()
                .contains("authorization"),
            "{}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn the_probe_gives_up_on_an_error_a_non_object_or_a_host_it_cannot_reach() {
        let (failing, _) = answering_server("HTTP/1.1 500 Internal Server Error", "{}").await;
        let (not_json, _) = answering_server("HTTP/1.1 200 OK", "<html>").await;
        let (list, _) = answering_server("HTTP/1.1 200 OK", r#"["pipes.view"]"#).await;

        assert_eq!(probe_product(&failing).await, None);
        assert_eq!(probe_product(&not_json).await, None);
        assert_eq!(probe_product(&list).await, None);
        assert_eq!(probe_product(&refusing_host()).await, None);
    }

    #[tokio::test]
    async fn the_probe_reads_an_answer_of_the_largest_size_and_gives_up_on_one_byte_more() {
        let with_length = |body: String| {
            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
        };
        let (largest, _) = whole_answer_server(vec![with_length(stream_permissions_of(MAX_PROBE_BODY_BYTES))]).await;
        let (too_large, _) =
            whole_answer_server(vec![with_length(stream_permissions_of(MAX_PROBE_BODY_BYTES + 1))]).await;

        assert_eq!(probe_product(&largest).await, Some(Product::AgentStream));
        assert_eq!(probe_product(&too_large).await, None);
    }

    #[tokio::test]
    async fn the_probe_gives_up_on_a_stated_length_over_the_largest_size_without_waiting_for_the_body() {
        let host = head_only_server(MAX_PROBE_BODY_BYTES + 1).await;

        let answer = tokio::time::timeout(PROBE_TIMEOUT / 2, probe_product(&host))
            .await
            .expect("the stated length is enough to give up");

        assert_eq!(answer, None);
    }

    #[tokio::test]
    async fn the_probe_gives_up_on_a_too_large_answer_that_does_not_say_its_length() {
        let without_length = |body: String| format!("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}");
        let (largest, _) = whole_answer_server(vec![without_length(stream_permissions_of(MAX_PROBE_BODY_BYTES))]).await;
        let (too_large, _) =
            whole_answer_server(vec![without_length(stream_permissions_of(MAX_PROBE_BODY_BYTES + 1))]).await;

        assert_eq!(probe_product(&largest).await, Some(Product::AgentStream));
        assert_eq!(probe_product(&too_large).await, None);
    }

    #[tokio::test]
    async fn a_session_token_with_a_given_host_of_the_other_product_stops() {
        let (stream, _) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;
        let (gateway, _) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        let error = stop_if_other_product(Product::AgentGateway, &stream, Some(SESSION_TOKEN), true)
            .await
            .expect_err("an Agent Stream host must be refused");
        let text = error.to_string();
        assert!(text.contains(&format!("{stream} is an Agent Stream, not an Agent Gateway")), "{text}");
        assert!(text.contains("`fabric agent-stream ...`"), "{text}");

        let error = stop_if_other_product(Product::AgentStream, &gateway, Some(SESSION_TOKEN), true)
            .await
            .expect_err("an Agent Gateway host must be refused");
        let text = error.to_string();
        assert!(text.contains(&format!("{gateway} is an Agent Gateway, not an Agent Stream")), "{text}");
        assert!(text.contains("`fabric agent-gateway ...`"), "{text}");
    }

    #[tokio::test]
    async fn a_session_token_with_a_given_host_of_the_same_product_carries_on() {
        let (stream, _) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;
        let (gateway, _) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        stop_if_other_product(Product::AgentGateway, &gateway, Some(SESSION_TOKEN), true)
            .await
            .expect("an Agent Gateway host");
        stop_if_other_product(Product::AgentStream, &stream, Some(SESSION_TOKEN), true)
            .await
            .expect("an Agent Stream host");
        stop_if_other_product(Product::AgentGateway, &gateway, None, true)
            .await
            .expect("no token yet, an Agent Gateway host");
    }

    #[tokio::test]
    async fn an_unknown_host_stops_an_agent_stream_command_and_lets_a_gateway_command_through() {
        let host = refusing_host();

        stop_if_other_product(Product::AgentGateway, &host, Some(SESSION_TOKEN), true)
            .await
            .expect("an Agent Gateway command runs as it did before the probe");
        let error = stop_if_other_product(Product::AgentStream, &host, Some(SESSION_TOKEN), true)
            .await
            .expect_err("an Agent Stream command needs a known host");

        let text = error.to_string();
        assert!(text.contains(&format!("could not confirm that {host} is an Agent Stream")), "{text}");
        assert!(text.contains("nothing was sent"), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
    }

    #[tokio::test]
    async fn a_session_asks_a_host_once_however_the_host_is_written() {
        let (gateway, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;
        let written_differently = format!("{}/", gateway.replacen("http", "HTTP", 1));

        remembering_probes(async {
            for host in [&gateway, &written_differently, &gateway] {
                stop_if_other_product(Product::AgentGateway, host, Some(SESSION_TOKEN), true)
                    .await
                    .expect("an Agent Gateway host");
            }
        })
        .await;

        assert_eq!(request_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn a_session_keeps_refusing_a_host_that_answered_as_the_other_product() {
        let (stream, requests) = answering_server("HTTP/1.1 200 OK", STREAM_PERMISSIONS).await;

        remembering_probes(async {
            for _ in 0..2 {
                let error = stop_if_other_product(Product::AgentGateway, &stream, Some(SESSION_TOKEN), true)
                    .await
                    .expect_err("an Agent Stream host must be refused every time");
                assert!(
                    error
                        .to_string()
                        .contains("is an Agent Stream, not an Agent Gateway"),
                    "{error}"
                );
            }
        })
        .await;

        assert_eq!(request_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn a_session_asks_again_after_a_host_could_not_be_read_and_then_refuses_the_other_product() {
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 500 Internal Server Error", "{}"),
            ("HTTP/1.1 200 OK", STREAM_PERMISSIONS),
        ])
        .await;

        remembering_probes(async {
            stop_if_other_product(Product::AgentGateway, &host, Some(SESSION_TOKEN), true)
                .await
                .expect("an Agent Gateway command carries on when the host cannot be read");
            let error = stop_if_other_product(Product::AgentGateway, &host, Some(SESSION_TOKEN), true)
                .await
                .expect_err("the unreadable answer must not be remembered as a pass");
            assert!(
                error
                    .to_string()
                    .contains("is an Agent Stream, not an Agent Gateway"),
                "{error}"
            );
        })
        .await;

        assert_eq!(request_lines(&requests).len(), 2);
    }

    #[tokio::test]
    async fn outside_a_session_every_check_asks_the_host() {
        let (gateway, requests) = answering_server("HTTP/1.1 200 OK", GATEWAY_PERMISSIONS).await;

        for _ in 0..2 {
            stop_if_other_product(Product::AgentGateway, &gateway, Some(SESSION_TOKEN), true)
                .await
                .expect("an Agent Gateway host");
        }

        assert_eq!(request_lines(&requests).len(), 2);
    }
}
