//! Runs the built `fabric` binary with a token given to it, and a host given
//! too or read from a saved connection, and checks every request the host gets.
//!
//! A binary built with the `agent-stream` Cargo feature first asks the host
//! which product it is, once and without the token, when the host was given
//! or the given token has no product's prefix, and sends nothing more when the
//! host answers as the other product. A binary built without the feature, as
//! every release is, never asks and sends only the command's own requests.
//! Each test is compiled for one of the two builds only.

// The runner and the recording host are taken from `common`, but not its
// saved-connection helper, which is for Agent Gateway only: a test here that
// needs a saved connection writes it itself, for whichever product it is about.
#[path = "common/fresh_home.rs"]
mod fresh_home;

#[path = "common/recording_host.rs"]
mod recording_host;

use std::process::Output;

use fresh_home::fabric_in_fresh_home;
use recording_host::{Requests, host_answering, request_lines, request_lowercase};

const SESSION_TOKEN: &str = "session-token-value";
const AGENT_STREAM_PERMISSIONS: &str = r#"{"pipes.view":false}"#;
const LIST_REQUEST: &str = "GET /api/v1/gateways HTTP/1.1";
/// What the host answers to any request but the probe: an empty list.
const EMPTY_LIST: &str = "[]";

/// Starts a host that answers the probe with `permissions` and any other
/// request with [`EMPTY_LIST`].
fn host_listing_nothing(permissions: &'static str) -> (String, Requests) {
    host_answering(permissions, EMPTY_LIST)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// What a binary built with the `agent-stream` Cargo feature asks a host
/// before the token goes anywhere.
#[cfg(feature = "agent-stream")]
mod with_the_agent_stream_feature {
    use super::{recording_host::PROBE_REQUEST, *};

    const GATEWAY_PERMISSIONS: &str = r#"{"surfaces.view":false}"#;

    #[test]
    fn a_gateway_command_with_host_and_token_from_the_environment_stops_at_an_agent_stream_host() {
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

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
        let probe = request_lowercase(&requests, 0);
        assert!(!probe.contains("authorization"), "{probe}");
        assert!(!probe.contains(SESSION_TOKEN), "{probe}");
    }

    #[test]
    fn login_with_host_and_token_from_the_environment_stops_at_an_agent_stream_host() {
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

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
    fn a_gateway_command_given_a_session_token_stops_at_a_saved_connection_that_answers_as_agent_stream() {
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);
        let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

        let output = fabric_in_fresh_home(
            &["agent-gateway", "api", "get", "/v1/gateways"],
            &[("config.toml", &config)],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(text.contains(&format!("{host} is an Agent Stream, not an Agent Gateway")), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
        assert_eq!(request_lines(&requests), [PROBE_REQUEST]);
        let probe = request_lowercase(&requests, 0);
        assert!(!probe.contains("authorization"), "{probe}");
        assert!(!probe.contains(SESSION_TOKEN), "{probe}");
    }

    #[test]
    fn an_agent_stream_command_given_a_session_token_stops_at_a_saved_connection_that_answers_as_agent_gateway() {
        let (host, requests) = host_listing_nothing(GATEWAY_PERMISSIONS);
        let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

        let output = fabric_in_fresh_home(
            &["agent-stream", "tokens", "list"],
            &[("agent-stream.toml", &config)],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(text.contains(&format!("{host} is an Agent Gateway, not an Agent Stream")), "{text}");
        assert!(!text.contains(SESSION_TOKEN), "{text}");
        assert_eq!(request_lines(&requests), [PROBE_REQUEST]);
        let probe = request_lowercase(&requests, 0);
        assert!(!probe.contains("authorization"), "{probe}");
        assert!(!probe.contains(SESSION_TOKEN), "{probe}");
    }

    #[test]
    fn revoking_or_rotating_a_token_with_a_typed_host_and_no_terminal_sends_nothing() {
        for product in ["agent-stream", "agent-gateway"] {
            for verb in ["revoke", "rotate"] {
                let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

                let output = fabric_in_fresh_home(
                    &[product, "--host", &host, "tokens", verb, "t-1"],
                    &[],
                    &[("FABRIC_TOKEN", SESSION_TOKEN)],
                    "",
                );

                let text = stderr(&output);
                assert_eq!(output.status.code(), Some(1), "{product} {verb}: {text}");
                assert!(
                    text.contains(&format!(
                        "refusing to {verb} 't-1' without confirmation in a non-interactive session"
                    )),
                    "{product} {verb}: {text}"
                );
                assert!(request_lines(&requests).is_empty(), "{product} {verb}");
            }
        }
    }

    #[test]
    fn the_interactive_shell_asks_a_given_host_which_product_it_is_once() {
        let (host, requests) = host_listing_nothing(GATEWAY_PERMISSIONS);

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
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "api", "get", "/v1/gateways"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_REQUEST]);
        let request = request_lowercase(&requests, 0);
        assert!(request.contains(&format!("authorization: bearer {SESSION_TOKEN}")), "{request}");
    }

    #[test]
    fn a_gateway_command_given_a_token_with_the_agent_stream_prefix_sends_it_as_before() {
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

        let output = fabric_in_fresh_home(
            &["agent-gateway", "api", "get", "/v1/gateways"],
            &[],
            &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", AGENT_STREAM_TOKEN)],
            "",
        );

        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_REQUEST]);
        let request = request_lowercase(&requests, 0);
        assert!(request.contains(&format!("authorization: bearer {AGENT_STREAM_TOKEN}")), "{request}");
    }

    #[test]
    fn login_with_a_host_and_a_session_token_sends_only_the_token_check() {
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

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
        let (host, requests) = host_listing_nothing(AGENT_STREAM_PERMISSIONS);

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
