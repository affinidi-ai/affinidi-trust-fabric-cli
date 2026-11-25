//! Runs the built `fabric` binary with a host and a token given to it, and
//! checks every request the host gets.
//!
//! A binary built with the `agent-stream` Cargo feature first asks a host
//! which product it is, once and without the token, and sends nothing more
//! when the host answers as Agent Stream. A binary built without the feature,
//! as every release is, never asks and sends only the command's own requests.
//! Each test is compiled for one of the two builds only.

// Only the runner is taken from `common`, because these commands are given
// their host and token, so its saved-connection helper would go unused here.
#[path = "common/fresh_home.rs"]
mod fresh_home;

use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Output,
    sync::{Arc, Mutex},
    thread,
};

use fresh_home::fabric_in_fresh_home;

const SESSION_TOKEN: &str = "session-token-value";
const AGENT_STREAM_PERMISSIONS: &str = r#"{"pipes.view":false}"#;
const PROBE_REQUEST: &str = "GET /api/v1/permissions/public HTTP/1.1";
const LIST_REQUEST: &str = "GET /api/v1/gateways HTTP/1.1";

/// Starts a host that answers a request for the public permission list with
/// `permissions` and any other request with an empty list, until the test
/// process ends. Returns its base URL and every request it received, headers
/// included.
fn host_answering(permissions: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener
        .local_addr()
        .expect("local addr");
    let requests: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let body = if request.starts_with(PROBE_REQUEST) {
                permissions
            } else {
                "[]"
            };
            recorded
                .lock()
                .expect("recorded requests")
                .push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{address}"), requests)
}

/// The request line of every request the host received, in order.
fn request_lines(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    requests
        .lock()
        .expect("recorded requests")
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// What a binary built with the `agent-stream` Cargo feature asks a host
/// before the token goes anywhere.
#[cfg(feature = "agent-stream")]
mod with_the_agent_stream_feature {
    use super::*;

    const GATEWAY_PERMISSIONS: &str = r#"{"surfaces.view":false}"#;

    #[test]
    fn a_gateway_command_with_host_and_token_from_the_environment_stops_at_an_agent_stream_host() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "surfaces", "list"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(text.contains(&format!("{host} is an Agent Stream, not an Agent Gateway")), "{text}");
        assert!(text.contains("`fabric agent-stream ...`"), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
        assert_eq!(request_lines(&requests), [PROBE_REQUEST]);
        let probe = requests
            .lock()
            .expect("recorded requests")[0]
            .to_ascii_lowercase();
        assert!(!probe.contains("authorization"), "{probe}");
        assert!(!probe.contains(SESSION_TOKEN), "{probe}");
    }

    #[test]
    fn login_with_host_and_token_from_the_environment_stops_at_an_agent_stream_host() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "login"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(text.contains(&format!("{host} is an Agent Stream, not an Agent Gateway")), "{text}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Logged in"), "{text}");
        assert_eq!(request_lines(&requests), [PROBE_REQUEST]);
    }

    #[test]
    fn the_interactive_shell_asks_a_given_host_which_product_it_is_once() {
        let (host, requests) = host_answering(GATEWAY_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "--host", &host, "shell"],
            &[],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "api get /v1/gateways\napi get /v1/gateways\n",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [PROBE_REQUEST, LIST_REQUEST, LIST_REQUEST]);
    }
}

/// A binary built without the `agent-stream` Cargo feature sends what the
/// releases before the stop sent, even to a host that would answer as Agent
/// Stream: it never asks which product the host is and refuses no token.
#[cfg(not(feature = "agent-stream"))]
mod without_the_agent_stream_feature {
    use super::*;

    const AGENT_STREAM_TOKEN: &str = "aspat_token-value";
    const TOKEN_CHECK_REQUEST: &str = "GET /api/auth/check HTTP/1.1";

    #[test]
    fn a_gateway_command_with_host_and_token_from_the_environment_sends_only_its_own_request() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "api", "get", "/v1/gateways"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_REQUEST]);
        let request = requests
            .lock()
            .expect("recorded requests")[0]
            .to_ascii_lowercase();
        assert!(request.contains(&format!("authorization: bearer {SESSION_TOKEN}")), "{request}");
    }

    #[test]
    fn a_gateway_command_given_a_token_with_the_agent_stream_prefix_sends_it_as_before() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "api", "get", "/v1/gateways"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", AGENT_STREAM_TOKEN)],
            "",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_REQUEST]);
        let request = requests
            .lock()
            .expect("recorded requests")[0]
            .to_ascii_lowercase();
        assert!(request.contains(&format!("authorization: bearer {AGENT_STREAM_TOKEN}")), "{request}");
    }

    #[test]
    fn login_with_a_host_and_a_session_token_sends_only_the_token_check() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "login", "--host", &host],
            &[],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        // The host answers the token check with an empty list, which is not an
        // accepted token, so the login ends there and never opens the credential
        // store.
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(text.contains("gateway did not accept the bearer token"), "{text}");
        assert_eq!(request_lines(&requests), [TOKEN_CHECK_REQUEST]);
    }

    #[test]
    fn the_interactive_shell_sends_only_the_typed_commands() {
        let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "--host", &host, "shell"],
            &[],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "api get /v1/gateways\napi get /v1/gateways\n",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_REQUEST, LIST_REQUEST]);
    }
}
