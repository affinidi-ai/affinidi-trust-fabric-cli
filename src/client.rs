use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{CONTENT_TYPE, HeaderMap};
use reqwest::{Method, RequestBuilder, StatusCode, redirect};
use serde_json::Value;

/// Stand-in printed for a credential or a credential-bearing field.
pub(crate) const REDACTED: &str = "[redacted]";

/// Content type `PATCH /v1/surfaces/{id}` requires; it answers 415 to any other.
const MERGE_PATCH_CONTENT_TYPE: &str = "application/merge-patch+json";

/// How long to wait for the gateway to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a request may go without receiving any data, including the wait
/// for the first byte. It is not a limit on the whole request, so a large
/// download that keeps arriving, such as the log archive, is never cut off,
/// while a gateway that stops answering still ends the call. The archive is
/// built in memory by the gateway before it is sent, hence the generous value.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a whole request may take, from sending it to the last byte of its
/// answer, for every call except the log archive download. It stops a gateway
/// that sends one byte at a time from holding the CLI forever, which the
/// inactivity timeout alone does not.
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Most redirects one request follows, and only to the same scheme, host and
/// port, so the token never goes anywhere the user did not point the CLI at.
const MAX_REDIRECTS: usize = 5;

/// How long the whole version request may take. The version is a small extra
/// on `whoami`, so a gateway that is slow to give it must not hold the command
/// for the full [`TOTAL_TIMEOUT`].
pub(crate) const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Most characters of the gateway's version the CLI keeps. A version is a
/// short label such as `1.0.0`, so a longer answer is cut.
pub(crate) const MAX_VERSION_CHARS: usize = 64;

/// Largest version answer the CLI reads. The answer is a tiny JSON object, so
/// anything bigger is refused before it is held in memory.
pub(crate) const MAX_VERSION_BODY_BYTES: usize = 4 * 1024;

#[derive(Clone)]
pub struct GatewayClient {
    host: String,
    token: String,
    http: reqwest::Client,
    total_timeout: Duration,
    version_timeout: Duration,
}

impl GatewayClient {
    pub fn new(
        host: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            host: host.into(),
            token: token.into(),
            http: build_http_client()?,
            total_timeout: TOTAL_TIMEOUT,
            version_timeout: VERSION_TIMEOUT,
        })
    }

    /// The gateway address every request of this client goes to.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn check_auth(&self) -> Result<()> {
        let response = self
            .request(Method::GET, "/auth/check", None)
            .await?;
        if response
            .get("authenticated")
            .and_then(Value::as_bool)
            != Some(true)
        {
            bail!("gateway did not accept the bearer token");
        }
        Ok(())
    }

    /// Validate a personal access token by calling `/v1/token-info`, which
    /// answers any caller holding a token the gateway accepts, whatever role
    /// or scopes it has, and which the session-based `/auth/check` route does
    /// not cover (it only consults the browser/session store). Only a 200
    /// counts: a 404 from a server that is not the gateway, a redirect or a
    /// server error must not be taken for an accepted token.
    pub async fn check_pat_auth(&self) -> Result<()> {
        let url = self.url("/v1/token-info")?;
        let response = self
            .http
            .get(&url)
            .timeout(self.total_timeout)
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("request {url}"))?;
        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::UNAUTHORIZED => bail!("gateway did not accept the bearer token"),
            status => bail!(
                "gateway answered {status} when checking the token; make sure --host is a gateway address and the \
                 gateway is healthy"
            ),
        }
    }

    /// The version the gateway reports at `/v1/version`. The route is public,
    /// so no token is sent, and the request is held to [`VERSION_TIMEOUT`].
    /// The answer is read up to [`MAX_VERSION_BODY_BYTES`]; from the version
    /// text only ASCII letters, digits, `.`, `-` and `+` are kept, cut to
    /// [`MAX_VERSION_CHARS`]. Fails when the request times out or does not
    /// complete, the gateway answers anything but 200 (with the status kept
    /// for [`response_status`]), the answer is too large or not JSON, or
    /// `version` is missing, not text, or empty once filtered.
    pub async fn gateway_version(&self) -> Result<String> {
        let url = self.url("/v1/version")?;
        let read_error = |error: reqwest::Error, action: &str| {
            if error.is_timeout() {
                anyhow::anyhow!("the gateway version request timed out after {:?}", self.version_timeout)
            } else {
                anyhow::Error::new(error).context(format!("{action} {url}"))
            }
        };
        let mut response = self
            .http
            .get(&url)
            .timeout(self.version_timeout)
            .send()
            .await
            .map_err(|error| read_error(error, "request"))?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(status_error(status, format!("gateway answered {status}")));
        }
        let too_large = || anyhow::anyhow!("gateway version answer too large (over {MAX_VERSION_BODY_BYTES} bytes)");
        if response
            .content_length()
            .is_some_and(|length| length > MAX_VERSION_BODY_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| read_error(error, "read the version answer from"))?
        {
            if body.len() + chunk.len() > MAX_VERSION_BODY_BYTES {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&body).context("gateway version answer is not JSON")?;
        let version: String = body
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
            .take(MAX_VERSION_CHARS)
            .collect();
        if version.is_empty() {
            bail!("gateway version answer has no version text");
        }
        Ok(version)
    }

    /// End the session behind a session token on the gateway, so a copy of it
    /// stops working. A personal access token has no session, so this is for
    /// session logins only.
    pub async fn end_session(&self) -> Result<()> {
        self.request(Method::POST, "/auth/logout", None)
            .await
            .map(|_| ())
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let url = self.url(path)?;
        let mut request = self
            .http
            .request(method, &url)
            .timeout(self.total_timeout)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        self.send_json(request, &url)
            .await
    }

    /// `GET path`, handled like [`Self::request`], also handing back the
    /// response headers for a caller that needs one of them.
    pub async fn get_with_headers(
        &self,
        path: &str,
    ) -> Result<(Value, HeaderMap)> {
        let url = self.url(path)?;
        let request = self
            .http
            .get(&url)
            .timeout(self.total_timeout)
            .bearer_auth(&self.token);
        self.send_json_with_headers(request, &url)
            .await
    }

    /// Send `patch` as a JSON Merge Patch
    /// (https://www.rfc-editor.org/rfc/rfc7396). The gateway's PATCH routes
    /// (surfaces and variants) accept only the `application/merge-patch+json`
    /// content type, which [`Self::request`] cannot set. The response is handled the same way.
    pub async fn merge_patch(
        &self,
        path: &str,
        patch: Value,
    ) -> Result<Value> {
        let url = self.url(path)?;
        let body = serde_json::to_vec(&patch).context("serialize merge patch")?;
        let request = self
            .http
            .request(Method::PATCH, &url)
            .timeout(self.total_timeout)
            .bearer_auth(&self.token)
            .header(CONTENT_TYPE, MERGE_PATCH_CONTENT_TYPE)
            .body(body);
        self.send_json(request, &url)
            .await
    }

    /// Send a bearer-authenticated request and read its answer as JSON: an
    /// empty body is `null` and a non-success status becomes [`gateway_error`].
    async fn send_json(
        &self,
        request: RequestBuilder,
        url: &str,
    ) -> Result<Value> {
        let (value, _) = self
            .send_json_with_headers(request, url)
            .await?;
        Ok(value)
    }

    /// [`Self::send_json`], also handing back the response headers.
    async fn send_json_with_headers(
        &self,
        request: RequestBuilder,
        url: &str,
    ) -> Result<(Value, HeaderMap)> {
        let response = request
            .send()
            .await
            .with_context(|| format!("request {url}"))?;
        let status = response.status();
        let headers = response.headers().clone();
        let text = response
            .text()
            .await
            .context("read gateway response")?;
        if !status.is_success() {
            return Err(gateway_error(status, text.as_bytes(), &self.secrets(RawAuth::Bearer)));
        }
        if text.trim().is_empty() {
            return Ok((Value::Null, headers));
        }
        let value = serde_json::from_str(&text).with_context(|| {
            let secrets = self.secrets(RawAuth::Bearer);
            format!("gateway returned non-JSON content: {}", sanitize_for_terminal(&redact(&text, &secrets)))
        })?;
        Ok((value, headers))
    }

    /// Perform a request whose success body is not JSON — a ZIP archive or a
    /// Prometheus exposition — and hand back the raw bytes with the status.
    /// [`Self::request`] cannot serve these routes: it decodes the body as
    /// UTF-8 text and parses it as JSON, so a ZIP fails to decode and the
    /// Prometheus exposition is reported as non-JSON content.
    ///
    /// The status is returned rather than turned into an error, because a
    /// caller may need to read it (an unmounted admin route answering 404 is
    /// not a failure to report verbatim). Use [`gateway_error`], with
    /// [`Self::secrets`] for the same `auth`, to build the same message
    /// [`Self::request`] would produce; error bodies on these routes are JSON
    /// even though their success bodies are not.
    pub async fn request_bytes(
        &self,
        method: Method,
        path: &str,
        auth: RawAuth<'_>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        self.send_bytes(method, path, auth, Some(self.total_timeout))
            .await
    }

    /// [`Self::request_bytes`] for the log archive, which the gateway builds
    /// in memory before sending and which can be large, so only the
    /// inactivity timeout applies and not the limit on the whole request.
    pub async fn download_bytes(
        &self,
        path: &str,
    ) -> Result<(StatusCode, Vec<u8>)> {
        self.send_bytes(Method::GET, path, RawAuth::Bearer, None)
            .await
    }

    async fn send_bytes(
        &self,
        method: Method,
        path: &str,
        auth: RawAuth<'_>,
        total_timeout: Option<Duration>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let url = self.url(path)?;
        let mut request = self
            .http
            .request(method, &url);
        if let Some(limit) = total_timeout {
            request = request.timeout(limit);
        }
        let request = match auth {
            RawAuth::Bearer => request.bearer_auth(&self.token),
            RawAuth::Basic { username, password } => request.basic_auth(username, Some(password)),
        };
        let response = request
            .send()
            .await
            .with_context(|| format!("request {url}"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("read gateway response")?;
        Ok((status, body.to_vec()))
    }

    /// The credentials a request made with `auth` carries in its
    /// `Authorization` header, in each form an echo of that header can show
    /// them, longest first so a form that contains another is replaced whole.
    /// [`gateway_error`] replaces them, because a gateway or an upstream proxy
    /// can echo the request's headers back in an error body.
    pub fn secrets(
        &self,
        auth: RawAuth<'_>,
    ) -> Vec<String> {
        match auth {
            RawAuth::Bearer => vec![self.token.clone()],
            RawAuth::Basic { username, password } => {
                let pair = format!("{username}:{password}");
                vec![STANDARD.encode(&pair), pair, password.to_owned()]
            }
        }
    }

    pub fn read_json_file(path: &Path) -> Result<Value> {
        let contents = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&contents).with_context(|| format!("parse {} as JSON", path.display()))
    }

    fn url(
        &self,
        path: &str,
    ) -> Result<String> {
        if !path.starts_with('/') || has_unsafe_segments(path) {
            bail!(
                "API path must start with '/' and must not contain '..', a '.' segment, a backslash, a control character or an \
                 encoded slash"
            );
        }
        if path.starts_with("/api/") {
            Ok(format!("{}{}", self.host, path))
        } else {
            Ok(format!("{}/api{}", self.host, path))
        }
    }
}

/// The HTTP client every call to the gateway uses: connect and request
/// timeouts, and redirects only within the origin the request went to. Shared
/// with the browser login so the code exchange gets the same limits.
pub(crate) fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("affinidi-trust-fabric-cli/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .redirect(same_origin_redirects())
        .build()
        .context("build HTTP client")
}

/// Redirects are followed only within the origin the request went to, so a
/// gateway that moves a route keeps working but the `Authorization` header is
/// never sent to another host. Any other redirect is left unfollowed and the
/// 3xx answer is reported as an error.
fn same_origin_redirects() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        let same_origin = attempt
            .previous()
            .last()
            .is_some_and(|previous| previous.origin() == attempt.url().origin());
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if same_origin {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// Percent-decoding rounds tried before a path is refused as hiding something.
const MAX_DECODE_ROUNDS: usize = 5;

/// Whether the path part of `path` (the query is not looked at) could reach
/// outside the API once a server or proxy decodes it: a `..` anywhere, a `.`
/// or empty-looking dot segment, a backslash, or a slash that arrives encoded
/// (`%2f`). Percent-encoding is undone again and again, so `%2e%2e` and
/// `%252e%252e` are caught like the plain form.
fn has_unsafe_segments(path: &str) -> bool {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    // The URL parser drops tab, newline and carriage return before it resolves
    // dot segments, so `.<tab>.` would become `..` after this check.
    if path
        .chars()
        .any(char::is_control)
    {
        return true;
    }
    let mut current = path.to_owned();
    for _ in 0..MAX_DECODE_ROUNDS {
        if current.contains("..")
            || current.contains('\\')
            || current
                .split('/')
                .any(|segment| segment == ".")
        {
            return true;
        }
        let decoded = percent_decode_once(&current);
        if decoded == current {
            return false;
        }
        if decoded.matches('/').count() != current.matches('/').count() {
            return true;
        }
        current = decoded;
    }
    true
}

/// Undo one layer of `%XX` escapes, leaving anything that is not a valid
/// escape as it is.
fn percent_decode_once(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .filter(|pair| {
                pair.iter()
                    .all(u8::is_ascii_hexdigit)
            })
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// A gateway response with a non-success status. It renders as the message
/// alone, and keeps the status so a caller can branch on it: many bodies, such
/// as a plain-text "User not found", say nothing about the status themselves.
#[derive(Debug)]
pub struct GatewayStatusError {
    status: StatusCode,
    message: String,
}

impl std::fmt::Display for GatewayStatusError {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GatewayStatusError {}

fn status_error(
    status: StatusCode,
    message: String,
) -> anyhow::Error {
    GatewayStatusError { status, message }.into()
}

/// The HTTP status a failed gateway request was answered with, or `None` when
/// it failed before the gateway answered.
pub fn response_status(error: &anyhow::Error) -> Option<StatusCode> {
    error
        .downcast_ref::<GatewayStatusError>()
        .map(|error| error.status)
}

/// Authentication to attach to a [`GatewayClient::request_bytes`] call.
#[derive(Clone, Copy, Debug)]
pub enum RawAuth<'a> {
    /// The stored gateway bearer token, as every JSON request uses.
    Bearer,
    /// HTTP Basic credentials. `/v1/metrics/prometheus` requires Basic in the
    /// same `Authorization` header the bearer token would occupy whenever
    /// Prometheus authentication is enabled, so the two cannot both be sent.
    Basic { username: &'a str, password: &'a str },
}

/// Build the error every failed response reports, whether it was read as JSON
/// by [`GatewayClient::request`] or as raw bytes by
/// [`GatewayClient::request_bytes`], so both produce one consistent message.
/// `secrets` are the credentials the request carried, from
/// [`GatewayClient::secrets`]; each is replaced wherever the body repeats it.
pub fn gateway_error(
    status: StatusCode,
    body: &[u8],
    secrets: &[String],
) -> anyhow::Error {
    // Secrets are replaced before the length cap, which could otherwise cut
    // one in two and print the half it kept, and in decoded JSON strings
    // rather than raw JSON text, which can carry a secret escaped.
    let clean = |text: &str| clean_for_terminal(text, secrets);
    let text = String::from_utf8_lossy(body);
    let parsed = serde_json::from_str::<Value>(&text).ok();
    let required_permission = parsed
        .as_ref()
        .and_then(|value| value.get("required_permission"))
        .and_then(Value::as_str)
        .map(&clean);
    let required_permission = required_permission.as_deref();
    let message = parsed
        .as_ref()
        .and_then(|value| error_detail(value, status))
        .map(|message| clean(&message));
    let message = message.as_deref();
    if let Some(permission) = required_permission {
        // Prefer the gateway's own wording when it sent one: it
        // distinguishes an RBAC role denial ("missing permission")
        // from a PAT whose scope excludes the permission ("access
        // token scope does not include"), which a single generic
        // message would collapse into one case.
        return match message {
            Some(message) => status_error(status, message.to_owned()),
            None => status_error(status, format!("missing required scope '{permission}'")),
        };
    }
    // A JSON body with no reason field is shown whole, re-serialised from its
    // redacted strings: `\"`, `\/` or `\u002b` inside the raw text hides a
    // secret from a plain match.
    let redacted_json = parsed
        .as_ref()
        .map(|value| redact_json(value, secrets).to_string());
    let shown_body = redacted_json
        .as_deref()
        .unwrap_or(&text);
    let sanitized_body = clean(shown_body);
    let body_is_empty = sanitized_body
        .trim()
        .is_empty();
    let detail = message
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if body_is_empty {
                "no additional detail from server".to_owned()
            } else {
                sanitized_body
            }
        });
    if status == StatusCode::UNAUTHORIZED {
        return status_error(status, format!("gateway rejected the bearer token: {detail}"));
    }
    // A real server message (JSON `message`/`error`/`details`, or a
    // non-empty plain-text body) already reads as a full sentence on its
    // own ("unknown scope: X"); only prefix the HTTP status when there
    // was nothing better for the server to say.
    if message.is_some() || !body_is_empty {
        return status_error(status, detail);
    }
    status_error(status, format!("gateway returned {status}: {detail}"))
}

/// The reason to report out of a gateway error body. The handlers use two
/// shapes: a lone `message`, or an `error` beside an optional `details`. The
/// settings, config and metrics handlers put the whole reason in `details` and
/// set `error` to the status's own reason phrase, which carries nothing of its
/// own, so only `details` is reported; elsewhere the two halves are joined,
/// because each carries part of it (`Failed to create DID` and its cause).
/// Every key is read through `as_str` rather than by presence, so a
/// `details: null` — which the handlers that do not skip the field serialise —
/// falls through to the next key instead of collapsing the whole body to its
/// raw text. An empty or blank string, or one left blank once its control
/// characters are stripped, falls through the same way, so it cannot stand in
/// for the reason and leave the reported error empty.
fn error_detail(
    value: &Value,
    status: StatusCode,
) -> Option<String> {
    let field = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| {
                !sanitize_for_terminal(text)
                    .trim()
                    .is_empty()
            })
    };
    if let Some(message) = field("message") {
        return Some(message.to_owned());
    }
    match (field("error"), field("details")) {
        (Some(error), Some(details)) if Some(error) == status.canonical_reason() => Some(details.to_owned()),
        (Some(error), Some(details)) => Some(format!("{error}: {details}")),
        (Some(error), None) => Some(error.to_owned()),
        (None, Some(details)) => Some(details.to_owned()),
        (None, None) => None,
    }
}

/// Make gateway-supplied text safe to print: `secrets` replaced by
/// [`REDACTED`] first, then [`sanitize_for_terminal`], so its length cap cannot
/// cut a secret in two. Pass [`GatewayClient::secrets`] for the request the
/// text came back on.
pub(crate) fn clean_for_terminal(
    text: &str,
    secrets: &[String],
) -> String {
    sanitize_for_terminal(&redact(text, secrets))
}

/// Replace every occurrence of each of `secrets` in `text` with [`REDACTED`].
/// An empty secret is skipped: replacing it would put the placeholder between
/// every character.
fn redact(
    text: &str,
    secrets: &[String],
) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(text.to_owned(), |text, secret| text.replace(secret.as_str(), REDACTED))
}

/// A copy of `value` with every string in it, object keys included, passed
/// through [`redact`] in its decoded form.
fn redact_json(
    value: &Value,
    secrets: &[String],
) -> Value {
    match value {
        Value::String(text) => Value::String(redact(text, secrets)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_json(item, secrets))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| (redact(key, secrets), redact_json(field, secrets)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Strips control characters (ANSI escape codes, carriage-return overwrite
/// tricks, etc.), turns newlines, tabs and the Unicode line and paragraph separators (U+2028, U+2029) into spaces so a value cannot start a
/// line of its own, and strips the Unicode bidirectional controls that reorder how text
/// is displayed (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) from
/// gateway-supplied text, such as an error body or a table cell, before it
/// reaches the operator's terminal, and caps its length. The gateway is
/// normally trusted, but this is the last line of defense if a misconfigured
/// or compromised backend ever puts something unexpected in a response.
pub(crate) fn sanitize_for_terminal(input: &str) -> String {
    folded(input)
        .take(500)
        .collect()
}

/// Like [`sanitize_for_terminal`] without the length cap, for an identifier
/// the user typed that has to be shown whole.
pub(crate) fn sanitize_whole(input: &str) -> String {
    folded(input).collect()
}

/// Like [`sanitize_whole`] but keeps newlines and tabs and drops U+2028 and
/// U+2029, for a multi-line body such as a metrics scrape.
pub(crate) fn sanitize_multiline(input: &str) -> String {
    printable(input)
        .filter(|c| !matches!(c, '\u{2028}' | '\u{2029}'))
        .collect()
}

fn folded(input: &str) -> impl Iterator<Item = char> + '_ {
    printable(input).map(|c| {
        if matches!(c, '\n' | '\t' | '\u{2028}' | '\u{2029}') {
            ' '
        } else {
            c
        }
    })
}

fn printable(input: &str) -> impl Iterator<Item = char> + '_ {
    input
        .chars()
        .filter(|c| !is_hidden_control(*c) || *c == '\n' || *c == '\t')
}

/// The characters a terminal can act on without showing them: control
/// characters (C0, DEL and C1) and the Unicode bidirectional controls that
/// reorder how text is displayed (U+061C, U+200E, U+200F, U+202A-U+202E,
/// U+2066-U+2069). The one definition behind [`sanitize_for_terminal`] and
/// [`pretty_json_for_terminal`].
fn is_hidden_control(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `value` as pretty JSON with every character a terminal can act on written
/// as a `\uXXXX` escape: the hidden controls of [`is_hidden_control`] and the
/// line and paragraph separators U+2028 and U+2029. serde_json already escapes
/// the C0 controls, and the newlines and spaces of the layout stay. The text
/// parses back to the same value.
pub(crate) fn pretty_json_for_terminal(value: &Value) -> Result<String> {
    let pretty = serde_json::to_string_pretty(value)?;
    let mut escaped = String::with_capacity(pretty.len());
    for c in pretty.chars() {
        let hidden = is_hidden_control(c) && (!c.is_ascii() || c == '\u{7f}');
        if hidden || matches!(c, '\u{2028}' | '\u{2029}') {
            escaped.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            escaped.push(c);
        }
    }
    Ok(escaped)
}

pub fn id_from_response(value: &Value) -> Option<&str> {
    // `id` comes before `gateway_id`: a connection point carries both, and its own id is the first.
    const ID_KEYS: &[&str] = &["surface_id", "connection_point_id", "policy_id", "id", "gateway_id"];
    let object = value.as_object()?;
    for key in ID_KEYS {
        if let Some(id) = object
            .get(*key)
            .and_then(Value::as_str)
        {
            return Some(id);
        }
    }
    for child in object.values() {
        if let Some(id) = id_from_response(child) {
            return Some(id);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn extracts_nested_entity_id() {
        let value = serde_json::json!({"connection_point": {"id": "cp-1"}});
        assert_eq!(id_from_response(&value), Some("cp-1"));
    }

    #[test]
    fn a_connection_point_answer_gives_its_own_id_not_its_gateways() {
        let value = serde_json::json!({"connection_point": {"id": "cp-1", "gateway_id": "gw-9", "name": "Door"}});
        assert_eq!(id_from_response(&value), Some("cp-1"));
    }

    #[test]
    fn the_other_create_answers_keep_giving_their_ids() {
        let surface = serde_json::json!({"surface_id": "s-1", "name": "Sales"});
        let gateway = serde_json::json!({"id": "g-1", "name": "Partner", "did": "did:x"});
        let policy = serde_json::json!({"id": "p-1", "name": "Header"});
        assert_eq!(id_from_response(&surface), Some("s-1"));
        assert_eq!(id_from_response(&gateway), Some("g-1"));
        assert_eq!(id_from_response(&policy), Some("p-1"));
    }

    /// Starts a one-shot HTTP server that replies with the given status line
    /// to the first request it receives, then returns its base URL.
    async fn one_shot_server(status_line: &'static str) -> String {
        one_shot_server_with_body(status_line, "").await
    }

    /// Starts a one-shot HTTP server that replies with the given status line
    /// and response body to the first request it receives, then returns its
    /// base URL.
    async fn one_shot_server_with_body(
        status_line: &'static str,
        body: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let content_length = body.len();
                let response =
                    format!("{status_line}\r\ncontent-length: {content_length}\r\nconnection: close\r\n\r\n{body}");
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn check_pat_auth_accepts_valid_token() {
        let host = one_shot_server("HTTP/1.1 200 OK").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        client
            .check_pat_auth()
            .await
            .expect("valid token should be accepted");
    }

    #[tokio::test]
    async fn check_pat_auth_asks_the_token_info_route() {
        let (host, request) = capturing_server().await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        client
            .check_pat_auth()
            .await
            .expect("a 200 should be accepted");
        let request = request
            .await
            .expect("request");
        assert!(request.starts_with("GET /api/v1/token-info HTTP/1.1"), "{request}");
    }

    #[tokio::test]
    async fn check_pat_auth_rejects_every_status_but_200() {
        for status_line in [
            "HTTP/1.1 404 Not Found",
            "HTTP/1.1 403 Forbidden",
            "HTTP/1.1 204 No Content",
            "HTTP/1.1 302 Found",
            "HTTP/1.1 500 Internal Server Error",
        ] {
            let host = one_shot_server(status_line).await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let error = client
                .check_pat_auth()
                .await
                .expect_err(status_line);
            assert!(
                error
                    .to_string()
                    .contains("make sure --host is a gateway address"),
                "{status_line}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn check_pat_auth_rejects_invalid_token() {
        let host = one_shot_server("HTTP/1.1 401 Unauthorized").await;
        let client = GatewayClient::new(host, "agpat_invalid").expect("client");
        let error = client
            .check_pat_auth()
            .await
            .expect_err("invalid token should be rejected");
        assert!(
            error
                .to_string()
                .contains("gateway did not accept the bearer token")
        );
    }

    /// Starts a one-shot HTTP server that replies with the given status line,
    /// content type, and body, then returns its base URL.
    async fn one_shot_body_server(
        status_line: &'static str,
        content_type: &'static str,
        body: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: \
                     close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    /// Starts a one-shot HTTP server that replies 200 with an empty body and
    /// hands the request head it received back over the returned channel.
    async fn capturing_server() -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let _ = sender.send(String::from_utf8_lossy(&buf[..read]).into_owned());
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), receiver)
    }

    #[tokio::test]
    async fn gateway_version_reads_the_version_text() {
        let host = one_shot_body_server("HTTP/1.1 200 OK", "application/json", r#"{"version":"1.0.0"}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let version = client
            .gateway_version()
            .await
            .expect("version");

        assert_eq!(version, "1.0.0");
    }

    #[tokio::test]
    async fn gateway_version_asks_the_public_route_without_the_token() {
        let (host, request) = capturing_server().await;
        let client = GatewayClient::new(host, "agpat_secret").expect("client");

        let _ = client.gateway_version().await;

        let request = request
            .await
            .expect("request");
        assert!(request.starts_with("GET /api/v1/version HTTP/1.1"), "{request}");
        assert!(!request.contains("agpat_secret"), "{request}");
        assert!(
            !request
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn gateway_version_fails_on_a_gateway_without_the_route() {
        let host = one_shot_server_with_body("HTTP/1.1 404 Not Found", r#"{"error":"not found"}"#).await;
        let client = GatewayClient::new(host, "").expect("client");

        let error = client
            .gateway_version()
            .await
            .expect_err("a 404 has no version");

        assert_eq!(response_status(&error), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn gateway_version_fails_on_an_answer_without_version_text() {
        for body in
            ["<html>not json</html>", r#"{"version":7}"#, r#"{"version":null}"#, "{}", r#"{"version":" \u001b "}"#]
        {
            let host = one_shot_body_server("HTTP/1.1 200 OK", "application/json", body).await;
            let client = GatewayClient::new(host, "").expect("client");

            client
                .gateway_version()
                .await
                .expect_err(body);
        }
    }

    #[tokio::test]
    async fn gateway_version_keeps_only_version_characters_and_is_cut_to_the_cap() {
        let unsafe_body = r#"{"version":"1.0\u001b[2J\u202e\n-beta\u0007"}"#;
        let host = one_shot_body_server("HTTP/1.1 200 OK", "application/json", unsafe_body).await;
        let client = GatewayClient::new(host, "").expect("client");
        let long_body: &'static str = Box::leak(format!(r#"{{"version":"{}"}}"#, "9".repeat(500)).into_boxed_str());
        let long_host = one_shot_body_server("HTTP/1.1 200 OK", "application/json", long_body).await;
        let long_client = GatewayClient::new(long_host, "").expect("client");

        let version = client
            .gateway_version()
            .await
            .expect("version");
        let long_version = long_client
            .gateway_version()
            .await
            .expect("version");

        assert_eq!(version, "1.02J-beta");
        assert_eq!(long_version, "9".repeat(MAX_VERSION_CHARS));
    }

    #[tokio::test]
    async fn gateway_version_drops_invisible_characters() {
        let host =
            one_shot_body_server("HTTP/1.1 200 OK", "application/json", r#"{"version":"\ufeff1.0\u200b.0 "}"#).await;
        let client = GatewayClient::new(host, "").expect("client");

        let version = client
            .gateway_version()
            .await
            .expect("version");

        assert_eq!(version, "1.0.0");
    }

    #[tokio::test]
    async fn gateway_version_refuses_an_answer_over_the_size_cap() {
        let body = format!(r#"{{"version":"1.0.0","pad":"{}"}}"#, "x".repeat(MAX_VERSION_BODY_BYTES));
        let with_length =
            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        let without_length = format!("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}");
        for response in [with_length, without_length] {
            let client = GatewayClient::new(raw_response_server(response).await, "").expect("client");

            let error = client
                .gateway_version()
                .await
                .expect_err("an oversized answer is refused");

            assert!(format!("{error:#}").contains("gateway version answer too large"), "{error:#}");
        }
    }

    /// Starts a one-shot HTTP server that writes `response` exactly as given,
    /// then closes, and returns its base URL.
    async fn raw_response_server(response: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn basic_credentials_replace_the_bearer_token() {
        let (host, request) = capturing_server().await;
        let client = GatewayClient::new(host, "agpat_secret").expect("client");
        let auth = RawAuth::Basic {
            username: "prometheus",
            password: "hunter2",
        };

        client
            .request_bytes(Method::GET, "/v1/metrics/prometheus", auth)
            .await
            .expect("request");

        let head = request
            .await
            .expect("captured request");
        let lowercase = head.to_lowercase();
        assert!(lowercase.contains("authorization: basic "), "Basic credentials must be sent");
        assert!(!lowercase.contains("bearer"), "the bearer token must not accompany Basic credentials");
        assert!(!lowercase.contains("agpat_secret"), "the token must not leak onto this route");
        // Redaction only works if the encoded form it looks for is the one
        // actually put on the wire.
        let encoded = &client.secrets(auth)[0];
        assert!(head.contains(&format!("Basic {encoded}")), "{encoded} is not in the request: {head}");
    }

    /// Serves a 200 answer one byte every 50 ms, so no single wait is long but
    /// the whole answer takes a long time.
    async fn dripping_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
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
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_server_that_drips_bytes_is_cut_off_by_the_total_timeout() {
        let mut client = GatewayClient::new(dripping_server().await, "agpat_valid").expect("client");
        client.total_timeout = Duration::from_millis(400);

        let started = std::time::Instant::now();
        let result = client
            .request(Method::GET, "/v1/limits", None)
            .await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    /// Accepts connections and never answers, so only a limit on the whole
    /// request ends a call, not the 120 second inactivity limit.
    async fn silent_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        format!("http://{addr}")
    }

    async fn silent_client() -> GatewayClient {
        let mut client = GatewayClient::new(silent_server().await, "agpat_valid").expect("client");
        client.total_timeout = Duration::from_millis(300);
        client
    }

    /// The call must fail on its own total timeout, well before the test's
    /// own wait of 5 seconds runs out.
    async fn assert_cut_off<T>(call: impl std::future::Future<Output = Result<T>>) {
        let outcome = tokio::time::timeout(Duration::from_secs(5), call).await;
        match outcome {
            Ok(result) => assert!(result.is_err(), "the call should have failed"),
            Err(_) => panic!("the call was not cut off by the total timeout"),
        }
    }

    #[tokio::test]
    async fn the_version_timeout_cuts_off_a_gateway_that_never_answers() {
        let mut client = GatewayClient::new(silent_server().await, "").expect("client");
        client.version_timeout = Duration::from_millis(300);

        let outcome = tokio::time::timeout(Duration::from_secs(5), client.gateway_version()).await;

        let error = outcome
            .expect("the version request was not cut off by its timeout")
            .expect_err("a silent gateway has no version");
        assert_eq!(response_status(&error), None);
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    }

    #[tokio::test]
    async fn the_version_timeout_cuts_off_a_version_answer_that_drips_in() {
        let mut client = GatewayClient::new(dripping_server().await, "").expect("client");
        client.version_timeout = Duration::from_millis(300);

        let outcome = tokio::time::timeout(Duration::from_secs(5), client.gateway_version()).await;

        let error = outcome
            .expect("the version request was not cut off by its timeout")
            .expect_err("a dripping gateway has no version in time");
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    }

    #[test]
    fn the_version_timeout_is_shorter_than_the_total_timeout() {
        let client = GatewayClient::new("http://127.0.0.1:1", "").expect("client");

        assert_eq!(client.version_timeout, VERSION_TIMEOUT);
        assert!(VERSION_TIMEOUT < TOTAL_TIMEOUT);
    }

    #[tokio::test]
    async fn the_total_timeout_reaches_check_pat_auth() {
        let client = silent_client().await;
        assert_cut_off(client.check_pat_auth()).await;
    }

    #[tokio::test]
    async fn the_total_timeout_reaches_get_with_headers() {
        let client = silent_client().await;
        assert_cut_off(client.get_with_headers("/v1/limits")).await;
    }

    #[tokio::test]
    async fn the_total_timeout_reaches_merge_patch() {
        let client = silent_client().await;
        assert_cut_off(client.merge_patch("/v1/surfaces/s1", serde_json::json!({"a": 1}))).await;
    }

    #[tokio::test]
    async fn the_total_timeout_reaches_request_bytes() {
        let client = silent_client().await;
        assert_cut_off(client.request_bytes(Method::GET, "/v1/metrics/prometheus", RawAuth::Bearer)).await;
    }

    #[tokio::test]
    async fn the_log_download_is_not_held_to_the_total_timeout() {
        let mut client = GatewayClient::new(dripping_server().await, "agpat_valid").expect("client");
        client.total_timeout = Duration::from_millis(100);

        let started = std::time::Instant::now();
        let slow = tokio::time::timeout(Duration::from_millis(600), client.download_bytes("/v1/logs/download")).await;

        assert!(slow.is_err(), "the download should still be running, not cut off after the total timeout");
        assert!(started.elapsed() >= Duration::from_millis(600));
    }

    #[tokio::test]
    async fn bearer_is_sent_when_no_credentials_are_given() {
        let (host, request) = capturing_server().await;
        let client = GatewayClient::new(host, "agpat_secret").expect("client");

        client
            .request_bytes(Method::GET, "/v1/logs/download", RawAuth::Bearer)
            .await
            .expect("request");

        let head = request
            .await
            .expect("captured request");
        assert!(
            head.contains("authorization: Bearer agpat_secret") || head.contains("Authorization: Bearer agpat_secret")
        );
    }

    #[tokio::test]
    async fn request_bytes_returns_non_json_body_verbatim() {
        let exposition = "# HELP up\n# TYPE up gauge\nup 1\n";
        let host = one_shot_body_server("HTTP/1.1 200 OK", "text/plain; version=0.0.4", exposition).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let (status, body) = client
            .request_bytes(Method::GET, "/v1/metrics/prometheus", RawAuth::Bearer)
            .await
            .expect("a text/plain body must not be parsed as JSON");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(String::from_utf8(body).expect("utf-8"), exposition);
    }

    #[tokio::test]
    async fn request_bytes_reports_the_status_instead_of_failing() {
        let host = one_shot_body_server("HTTP/1.1 404 Not Found", "application/json", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let (status, _) = client
            .request_bytes(Method::GET, "/admin/x402/stats", RawAuth::Bearer)
            .await
            .expect("a non-success status is reported, not raised");

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn gateway_error_uses_the_json_error_field() {
        let error = gateway_error(StatusCode::INTERNAL_SERVER_ERROR, br#"{"error":"Transaction not found"}"#, &[]);
        assert!(
            error
                .to_string()
                .contains("Transaction not found")
        );
    }

    /// The reason a write was rejected reaches the user in every body shape the
    /// gateway's handlers produce, not just the two that carry it at the top
    /// level.
    #[test]
    fn gateway_error_reads_every_error_body_shape() {
        // The settings, config and metrics handlers answer with the status's
        // own reason phrase in `error` and the reason in `details`. Reporting
        // `error` alone says only "Bad Request" and loses it.
        let error = gateway_error(
            StatusCode::BAD_REQUEST,
            br#"{"error":"Bad Request","details":"Trace sample rate must be between 0.0 and 1.0"}"#,
            &[],
        );
        assert_eq!(error.to_string(), "Trace sample rate must be between 0.0 and 1.0");

        // Where `error` is not the status's reason phrase both halves are kept:
        // the DID handlers split the summary from its cause across them.
        let error = gateway_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"Failed to create DID","details":"signing key unavailable"}"#,
            &[],
        );
        assert_eq!(error.to_string(), "Failed to create DID: signing key unavailable");

        // `message` alone is what the proxy and API-key handlers send.
        let error = gateway_error(
            StatusCode::FORBIDDEN,
            br#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
            &[],
        );
        assert!(
            error
                .to_string()
                .contains("Agent trust policy denied the request")
        );

        // A `details` the handler serialised as null must not swallow the
        // `error` beside it and send the whole body to the raw-text fallback.
        let error = gateway_error(StatusCode::NOT_FOUND, br#"{"error":"Identity not found","details":null}"#, &[]);
        assert_eq!(error.to_string(), "Identity not found");
    }

    /// An empty `details` says nothing, so it must not replace the `error`
    /// beside it; otherwise the error the caller sees is itself empty.
    #[test]
    fn gateway_error_ignores_empty_fields() {
        let error = gateway_error(StatusCode::BAD_REQUEST, br#"{"error":"Bad Request","details":""}"#, &[]);
        assert_eq!(error.to_string(), "Bad Request");
    }

    /// A field made only of control characters is empty once sanitised, so it
    /// must fall through like an empty one rather than become the whole error.
    #[test]
    fn gateway_error_ignores_fields_made_only_of_control_characters() {
        let error = gateway_error(StatusCode::BAD_REQUEST, br#"{"error":"Bad Request","details":"\u001b"}"#, &[]);
        assert_eq!(error.to_string(), "Bad Request");

        let error = gateway_error(
            StatusCode::BAD_REQUEST,
            br#"{"error":"Bad Request","details":"\u001b","required_permission":"metrics.view"}"#,
            &[],
        );
        assert_eq!(error.to_string(), "Bad Request");

        let error = gateway_error(
            StatusCode::FORBIDDEN,
            br#"{"details":"\u0007\u0000","required_permission":"metrics.view"}"#,
            &[],
        );
        assert_eq!(error.to_string(), "missing required scope 'metrics.view'");
    }

    /// A bidirectional override would reorder what the operator reads, and a
    /// JSON body decodes `\u202e` into a live one.
    #[test]
    fn gateway_error_strips_bidirectional_controls() {
        let error = gateway_error(StatusCode::BAD_GATEWAY, br#"{"detail":"txt.\u202eexe"}"#, &[]);
        assert_eq!(error.to_string(), r#"{"detail":"txt.exe"}"#);

        let text = "a\u{061C}b\u{200E}c\u{200F}d\u{202A}e\u{202E}f\u{2066}g\u{2069}h";
        assert_eq!(sanitize_for_terminal(text), "abcdefgh");
    }

    /// A newline or tab in a name would start a line of its own in whoami or a
    /// confirmation prompt, so single-value text folds them into spaces.
    #[test]
    fn single_value_text_folds_newlines_and_tabs_into_spaces() {
        assert_eq!(sanitize_for_terminal("bob\nrole: Administrator"), "bob role: Administrator");
        assert_eq!(sanitize_for_terminal("a\tb\r\nc"), "a b c");
        assert_eq!(sanitize_whole("x\ny\tz"), "x y z");
        assert_eq!(sanitize_multiline("x\ny\tz\u{1b}"), "x\ny\tz");
    }

    #[test]
    fn line_and_paragraph_separators_are_folded_or_dropped() {
        assert_eq!(sanitize_for_terminal("a\u{2028}b\u{2029}c"), "a b c");
        assert_eq!(sanitize_whole("a\u{2028}b\u{2029}c"), "a b c");
        assert_eq!(sanitize_multiline("a\u{2028}b\u{2029}c\nd"), "abc\nd");
    }

    /// A plain-text body made only of control characters says nothing, so it
    /// gets the same wording as an empty body instead of an empty error.
    #[test]
    fn gateway_error_treats_a_control_character_body_as_empty() {
        let error = gateway_error(StatusCode::BAD_GATEWAY, b"\x00", &[]);
        assert_eq!(error.to_string(), "gateway returned 502 Bad Gateway: no additional detail from server");

        let error = gateway_error(StatusCode::UNAUTHORIZED, b"\x1b\x7f", &[]);
        assert_eq!(error.to_string(), "gateway rejected the bearer token: no additional detail from server");
    }

    #[test]
    fn gateway_error_falls_back_to_the_raw_body() {
        let error = gateway_error(StatusCode::BAD_GATEWAY, b"<html>upstream down</html>", &[]);
        assert!(
            error
                .to_string()
                .contains("upstream down")
        );
    }

    /// Starts a one-shot HTTP server that replies with the given status line,
    /// content type, and `template` with `{authorization}` replaced by the
    /// request's own `Authorization` header, as an upstream that echoes request
    /// headers into its error page would, then returns its base URL.
    async fn echoing_server(
        status_line: &'static str,
        content_type: &'static str,
        template: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..read]).into_owned();
                let authorization = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap_or_default();
                let body = template.replace("{authorization}", &authorization);
                let response = format!(
                    "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: \
                     close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    /// Sends one JSON request with `token` to a server that echoes its
    /// `Authorization` header into the body, and returns the error reported.
    async fn echoed_request_error(
        status_line: &'static str,
        content_type: &'static str,
        template: &'static str,
        token: &str,
    ) -> String {
        let host = echoing_server(status_line, content_type, template).await;
        let client = GatewayClient::new(host, token).expect("client");
        let error = client
            .request(Method::GET, "/v1/audit", None)
            .await
            .expect_err("the request should fail");
        format!("{error:#}")
    }

    #[tokio::test]
    async fn request_redacts_a_bearer_token_echoed_in_a_plain_text_body() {
        let message = echoed_request_error(
            "HTTP/1.1 502 Bad Gateway",
            "text/plain",
            "upstream error; request carried Authorization: {authorization}",
            "agpat_echoed_secret",
        )
        .await;
        assert_eq!(message, "upstream error; request carried Authorization: Bearer [redacted]");
    }

    #[tokio::test]
    async fn request_redacts_a_bearer_token_echoed_in_a_json_error() {
        let message = echoed_request_error(
            "HTTP/1.1 500 Internal Server Error",
            "application/json",
            r#"{"error":"upstream refused {authorization}"}"#,
            "agpat_echoed_secret",
        )
        .await;
        assert_eq!(message, "upstream refused Bearer [redacted]");
    }

    #[tokio::test]
    async fn request_redacts_a_bearer_token_echoed_in_a_json_message() {
        let message = echoed_request_error(
            "HTTP/1.1 403 Forbidden",
            "application/json",
            r#"{"error":"Forbidden","message":"policy denied {authorization}"}"#,
            "agpat_echoed_secret",
        )
        .await;
        assert_eq!(message, "policy denied Bearer [redacted]");
    }

    #[tokio::test]
    async fn request_redacts_a_bearer_token_echoed_in_a_401_body() {
        let message = echoed_request_error(
            "HTTP/1.1 401 Unauthorized",
            "application/json",
            r#"{"error":"session for {authorization} expired"}"#,
            "agpat_echoed_secret",
        )
        .await;
        assert_eq!(message, "gateway rejected the bearer token: session for Bearer [redacted] expired");
    }

    #[tokio::test]
    async fn request_redacts_a_bearer_token_echoed_in_non_json_success_content() {
        let message = echoed_request_error(
            "HTTP/1.1 200 OK",
            "text/html",
            "<html>signed in as {authorization}</html>",
            "agpat_echoed_secret",
        )
        .await;
        assert!(message.contains("<html>signed in as Bearer [redacted]</html>"), "got: {message}");
        assert!(!message.contains("agpat_echoed_secret"), "got: {message}");
    }

    #[tokio::test]
    async fn request_bytes_errors_redact_echoed_basic_credentials() {
        let host = echoing_server(
            "HTTP/1.1 502 Bad Gateway",
            "text/plain",
            "upstream error; request carried Authorization: {authorization}",
        )
        .await;
        let client = GatewayClient::new(host, "agpat_unused").expect("client");
        let auth = RawAuth::Basic {
            username: "prometheus",
            password: "hunter2",
        };

        let (status, body) = client
            .request_bytes(Method::GET, "/v1/metrics/prometheus", auth)
            .await
            .expect("request");
        let error = gateway_error(status, &body, &client.secrets(auth));

        assert_eq!(error.to_string(), "upstream error; request carried Authorization: Basic [redacted]");
    }

    #[test]
    fn gateway_error_redacts_every_form_of_basic_credentials() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_unused").expect("client");
        let secrets = client.secrets(RawAuth::Basic {
            username: "prometheus",
            password: "hunter2",
        });
        let encoded = STANDARD.encode("prometheus:hunter2");
        let body = format!("upstream error: sent {encoded} for prometheus:hunter2, password hunter2");

        let error = gateway_error(StatusCode::BAD_GATEWAY, body.as_bytes(), &secrets);

        assert_eq!(error.to_string(), "upstream error: sent [redacted] for [redacted], password [redacted]");
    }

    /// A JSON string carries a `"` in the password escaped, so only the
    /// decoded field matches the password the request sent.
    #[test]
    fn gateway_error_redacts_a_password_the_json_body_escapes() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_unused").expect("client");
        let secrets = client.secrets(RawAuth::Basic {
            username: "prometheus",
            password: "hun\"ter2",
        });

        let error = gateway_error(StatusCode::BAD_REQUEST, br#"{"error":"password hun\"ter2 rejected"}"#, &secrets);

        assert_eq!(error.to_string(), "password [redacted] rejected");
    }

    /// A JSON body with no top-level reason is shown whole. A `"` in the
    /// password is escaped in its raw text, where a plain match misses it.
    #[test]
    fn gateway_error_redacts_an_escaped_password_in_a_json_fallback() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_unused").expect("client");
        let secrets = client.secrets(RawAuth::Basic {
            username: "prometheus",
            password: "hun\"ter2",
        });

        let error = gateway_error(StatusCode::BAD_REQUEST, br#"{"detail":"bad password hun\"ter2"}"#, &secrets);

        assert_eq!(error.to_string(), r#"{"detail":"bad password [redacted]"}"#);
    }

    /// A serialiser may escape the `/` and `+` of a base64 credential, which a
    /// plain match against the raw text of a nested error body then misses.
    #[test]
    fn gateway_error_redacts_an_escaped_base64_credential_in_a_json_fallback() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_unused").expect("client");
        let auth = RawAuth::Basic {
            username: "prometheus",
            password: "?>?>",
        };
        let encoded = STANDARD.encode("prometheus:?>?>");
        assert!(encoded.contains('/') && encoded.contains('+'), "{encoded} exercises neither escape");
        let escaped = encoded
            .replace('/', r"\/")
            .replace('+', r"\u002b");
        let body = format!(r#"{{"error":{{"message":"denied Basic {escaped}"}},"errors":["Basic {escaped}"]}}"#);

        let error = gateway_error(StatusCode::FORBIDDEN, body.as_bytes(), &client.secrets(auth));

        assert_eq!(
            error.to_string(),
            r#"{"error":{"message":"denied Basic [redacted]"},"errors":["Basic [redacted]"]}"#
        );
    }

    /// The 500-character cap applies after redaction, so it cannot cut a
    /// secret in two and print the half it kept.
    #[test]
    fn gateway_error_redacts_a_secret_the_length_cap_would_cut() {
        let token = "agpat_straddles_the_cap";
        let body = format!("{} {token}", "x".repeat(490));

        let error = gateway_error(StatusCode::BAD_GATEWAY, body.as_bytes(), &[token.to_owned()]);

        let message = error.to_string();
        assert!(!message.contains("agpat_"), "part of the token survived: {message}");
        assert!(message.starts_with("xxxxx"));
    }

    #[test]
    fn an_empty_password_redacts_nothing_but_the_credentials() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_unused").expect("client");
        let secrets = client.secrets(RawAuth::Basic {
            username: "prometheus",
            password: "",
        });

        let error = gateway_error(StatusCode::BAD_GATEWAY, b"upstream error", &secrets);

        assert_eq!(error.to_string(), "upstream error");
    }

    #[tokio::test]
    async fn request_prefers_gateway_message_when_required_permission_has_one() {
        // The gateway's own wording distinguishes an RBAC role denial from a
        // PAT scope exclusion; the CLI should show it as-is rather than
        // collapsing both into one generic message.
        let body = r#"{"error": "access token scope does not include 'access_tokens.view'", "required_permission": "access_tokens.view"}"#;
        let host = one_shot_server_with_body("HTTP/1.1 403 Forbidden", body).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("forbidden request should error");
        assert_eq!(error.to_string(), "access token scope does not include 'access_tokens.view'");
    }

    #[tokio::test]
    async fn request_falls_back_to_generic_message_when_required_permission_has_no_gateway_message() {
        let body = r#"{"required_permission": "access_tokens.view"}"#;
        let host = one_shot_server_with_body("HTTP/1.1 403 Forbidden", body).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("forbidden request should error");
        assert_eq!(error.to_string(), "missing required scope 'access_tokens.view'");
    }

    #[tokio::test]
    async fn request_gives_clear_message_for_empty_body() {
        let host = one_shot_server("HTTP/1.1 403 Forbidden").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("forbidden request should error");
        let message = error.to_string();
        assert!(message.contains("no additional detail from server"));
        assert!(
            !message
                .trim_end()
                .ends_with(':')
        );
    }

    #[tokio::test]
    async fn request_keeps_the_status_of_a_plain_text_failure() {
        // The message is the body alone, so only the typed error says 404.
        let host = one_shot_server_with_body("HTTP/1.1 404 Not Found", "User not found").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/users/nobody", None)
            .await
            .expect_err("not found should error");
        assert_eq!(error.to_string(), "User not found");
        assert_eq!(response_status(&error), Some(StatusCode::NOT_FOUND));
        let wrapped = error.context("while looking the user up");
        assert_eq!(response_status(&wrapped), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn request_reports_no_status_when_the_gateway_never_answered() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        drop(listener);
        let client = GatewayClient::new(format!("http://{addr}"), "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/users/nobody", None)
            .await
            .expect_err("a refused connection should error");
        assert_eq!(response_status(&error), None);
    }

    #[tokio::test]
    async fn request_preserves_plain_text_body() {
        let host = one_shot_server_with_body("HTTP/1.1 400 Bad Request", "malformed query parameter").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("bad request should error");
        assert!(
            error
                .to_string()
                .contains("malformed query parameter")
        );
    }

    #[tokio::test]
    async fn request_strips_control_characters_from_gateway_message() {
        // A malicious or misconfigured gateway could put terminal escape
        // sequences in an error string; the CLI must not print them verbatim.
        let body = r#"{"error": "bad request\u001b[31mFAKE ERROR\u001b[0m", "code": "BAD_REQUEST"}"#;
        let host = one_shot_server_with_body("HTTP/1.1 400 Bad Request", body).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("bad request should error");
        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "escape character leaked into: {message}");
        assert!(message.contains("bad request"));
        assert!(message.contains("FAKE ERROR"));
    }

    #[tokio::test]
    async fn request_strips_control_characters_from_plain_text_body() {
        let body = "line one\u{1b}[2Jline two";
        let host = one_shot_server_with_body("HTTP/1.1 400 Bad Request", body).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let error = client
            .request(Method::GET, "/v1/access-tokens", None)
            .await
            .expect_err("bad request should error");
        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "escape character leaked into: {message}");
    }

    /// Starts a one-shot HTTP server that reads the whole request, head and
    /// `content-length` body, hands it back over the returned channel, and
    /// replies with the given status line and JSON body.
    async fn full_request_capturing_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let read = socket
                        .read(&mut buf)
                        .await
                        .unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..read]);
                    let text = String::from_utf8_lossy(&received).into_owned();
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let content_length = text[..head_end]
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
                    if received.len() >= head_end + 4 + content_length {
                        break;
                    }
                }
                let _ = sender.send(String::from_utf8_lossy(&received).into_owned());
                let response = format!(
                    "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
                     close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), receiver)
    }

    #[tokio::test]
    async fn merge_patch_sends_a_patch_with_the_merge_patch_content_type() {
        let (host, request) =
            full_request_capturing_server("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Sales"}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let patch = serde_json::json!({"access_point": {"rate_limit": {"requests": 100}}, "description": null});

        let surface = client
            .merge_patch("/v1/surfaces/s-1", patch.clone())
            .await
            .expect("merge patch");

        assert_eq!(surface, serde_json::json!({"surface_id": "s-1", "name": "Sales"}));
        let raw = request
            .await
            .expect("captured request");
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .expect("request head and body");
        assert!(head.starts_with("PATCH /api/v1/surfaces/s-1 HTTP/1.1"), "{head}");
        assert!(
            head.to_lowercase()
                .contains("content-type: application/merge-patch+json"),
            "{head}"
        );
        assert_eq!(serde_json::from_str::<Value>(body).expect("JSON body"), patch);
    }

    #[tokio::test]
    async fn merge_patch_reports_a_rejected_patch_like_any_other_request() {
        let body =
            r#"{"error":"Bad Request","details":"Merged surface failed to deserialise: missing field `endpoint`"}"#;
        let host = one_shot_server_with_body("HTTP/1.1 400 Bad Request", body).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = client
            .merge_patch("/v1/surfaces/s-1", serde_json::json!({"target": {"endpoint": null}}))
            .await
            .expect_err("a rejected patch should error");

        assert_eq!(error.to_string(), "Merged surface failed to deserialise: missing field `endpoint`");
        assert_eq!(response_status(&error), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn url_refuses_percent_encoded_dot_segments() {
        let client = GatewayClient::new("https://gateway.example.com", "agpat_valid").expect("client");
        for path in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2E%2E/admin",
            "/v1/%2e./admin",
            "/v1/.%2E/admin",
            "/v1/%252e%252e/admin",
            "/v1/%25252e%25252e/admin",
            "/v1/%2e/admin",
            "/v1/./admin",
            "/v1/%2E",
        ] {
            assert!(client.url(path).is_err(), "{path} should be refused");
        }
    }

    /// The URL parser drops tab, newline and carriage return before it resolves
    /// dot segments, so `.<tab>.` would turn into `..` behind the check.
    #[test]
    fn url_refuses_control_characters_hiding_a_dot_segment() {
        let client = GatewayClient::new("https://gateway.example.com", "agpat_valid").expect("client");
        for path in [
            "/v1/.\t./admin",
            "/v1/.\n./admin",
            "/v1/.\r./admin",
            "/v1/.\t/admin",
            "/v1/%2e\n%2e/admin",
            "/v1/a\u{1b}b",
            "/v1/a\0b",
            "/v1/a\u{7f}b",
            "/v1/a\u{85}b",
            "/v1/a\u{9b}b",
            "/v1/\n",
        ] {
            assert!(client.url(path).is_err(), "{path:?} should be refused");
        }
        assert!(
            client
                .url("/v1/a?filter=x%0Ay")
                .is_ok()
        );
    }

    #[test]
    fn url_refuses_encoded_slashes_and_backslashes() {
        let client = GatewayClient::new("https://gateway.example.com", "agpat_valid").expect("client");
        for path in ["/v1/a%2fb", "/v1/a%2Fb", "/v1/a%252fb", "/v1/a\\b", "/v1/a%5cb", "/v1/a%5Cb", "/v1/a%255cb"] {
            assert!(client.url(path).is_err(), "{path} should be refused");
        }
    }

    #[test]
    fn url_refuses_a_path_that_keeps_decoding() {
        let client = GatewayClient::new("https://gateway.example.com", "agpat_valid").expect("client");
        let path = format!("/v1/{}2e%{}2e", "%25".repeat(8), "25".repeat(8));
        assert!(client.url(&path).is_err());
    }

    #[test]
    fn url_keeps_ordinary_paths_and_encoded_query_dots() {
        let client = GatewayClient::new("https://gateway.example.com", "agpat_valid").expect("client");
        assert_eq!(
            client
                .url("/v1/secrets/a%20b.c?filter=a%2E%2Eb")
                .unwrap(),
            "https://gateway.example.com/api/v1/secrets/a%20b.c?filter=a%2E%2Eb"
        );
        assert_eq!(
            client
                .url("/api/v1/limits")
                .unwrap(),
            "https://gateway.example.com/api/v1/limits"
        );
        assert!(
            client
                .url("v1/limits")
                .is_err()
        );
    }

    #[test]
    fn percent_decoding_leaves_bad_escapes_alone() {
        assert_eq!(percent_decode_once("%2e%2E%zz%+f%4"), "..%zz%+f%4");
    }

    #[tokio::test]
    async fn a_redirect_to_another_host_is_not_followed_and_never_gets_the_token() {
        let (other_host, other_request) = capturing_server().await;
        let location: &'static str = Box::leak(format!("{other_host}/steal").into_boxed_str());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let client = GatewayClient::new(format!("http://{addr}"), "agpat_secret").expect("client");
        let error = client
            .request(Method::GET, "/v1/limits", None)
            .await
            .expect_err("a redirect to another host must fail");
        assert_eq!(response_status(&error), Some(StatusCode::FOUND), "{error:#}");
        let reached = tokio::time::timeout(Duration::from_millis(300), other_request).await;
        assert!(reached.is_err(), "the other host must never be called");
    }

    #[tokio::test]
    async fn a_redirect_within_the_same_host_is_followed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut sender = Some(sender);
            for round in 0..2 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let response: &[u8] = if round == 0 {
                    b"HTTP/1.1 302 Found\r\nlocation: /api/v1/moved\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                } else {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(String::from_utf8_lossy(&buf[..read]).into_owned());
                    }
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
                };
                let _ = socket
                    .write_all(response)
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let client = GatewayClient::new(format!("http://{addr}"), "agpat_secret").expect("client");
        client
            .request(Method::GET, "/v1/limits", None)
            .await
            .expect("a same-host redirect should be followed");
        let request = receiver
            .await
            .expect("second request");
        assert!(request.starts_with("GET /api/v1/moved HTTP/1.1"), "{request}");
    }

    #[tokio::test]
    async fn end_session_posts_to_the_logout_route_with_the_token() {
        let (host, request) = capturing_server().await;
        let client = GatewayClient::new(host, "session-token").expect("client");
        client
            .end_session()
            .await
            .expect("logout");
        let request = request
            .await
            .expect("request")
            .to_ascii_lowercase();
        assert!(request.starts_with("post /api/auth/logout http/1.1"), "{request}");
        assert!(request.contains("authorization: bearer session-token"), "{request}");
    }
}
