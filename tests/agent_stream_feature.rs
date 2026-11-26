//! Runs the built `fabric` binary to check that `fabric agent-stream` exists
//! only when the binary was built with the `agent-stream` Cargo feature, that
//! its saved connections stay apart from the Agent Gateway ones, and what its
//! commands send when the host or the token comes from the environment.

// The runner and the recording host are taken from `common`, but not its
// saved-connection helper, which is for Agent Gateway commands and would go
// unused here.
#[path = "common/fresh_home.rs"]
mod fresh_home;
#[cfg(feature = "agent-stream")]
#[path = "common/recording_host.rs"]
mod recording_host;

#[cfg(feature = "agent-stream")]
use std::path::{Path, PathBuf};
use std::process::Output;

use fresh_home::fabric_in_fresh_home;
#[cfg(feature = "agent-stream")]
use fresh_home::fabric_in_home;
#[cfg(feature = "agent-stream")]
use recording_host::{PROBE_REQUEST, Requests, host_answering, request_lines, request_lowercase};

/// Exit status clap uses for a command line it cannot parse.
#[cfg(not(feature = "agent-stream"))]
const USAGE_EXIT_CODE: i32 = 2;

/// A `config.toml` as the 0.1.4 CLI wrote it, with one Agent Gateway connection.
#[cfg(feature = "agent-stream")]
const GATEWAY_CONFIG: &str = "current = \"default\"\n\n[connections.default]\nhost = \"https://gateway.example\"\n";

/// An `agent-stream.toml` with one Agent Stream connection of the same name.
#[cfg(feature = "agent-stream")]
const AGENT_STREAM_CONFIG: &str = "current = \"default\"\n\n[connections.default]\nhost = \"https://stream.example\"\n";

/// An `agent-stream.toml` whose one connection has a `#` in its name.
#[cfg(feature = "agent-stream")]
const HASH_NAME_CONFIG: &str = "[connections.\"prod#1\"]\nhost = \"https://stream.example\"\n";

/// Runs `fabric <args>` in a fresh home holding `files`, with no `FABRIC_*`
/// variable set and nothing on standard input.
fn fabric(
    args: &[&str],
    files: &[(&str, &str)],
) -> Output {
    fabric_in_fresh_home(args, files, &[], "")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(not(feature = "agent-stream"))]
#[test]
fn the_default_build_does_not_know_agent_stream() {
    let output = fabric(&["agent-stream"], &[]);

    assert_eq!(output.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&output));
    assert!(stderr(&output).contains("unrecognized subcommand"), "{}", stderr(&output));
    assert!(!stdout(&fabric(&["--help"], &[])).contains("agent-stream"));
}

#[cfg(feature = "agent-stream")]
#[test]
fn the_feature_build_lists_agent_stream_connections_apart_from_the_gateway_ones() {
    let files = [("config.toml", GATEWAY_CONFIG), ("agent-stream.toml", AGENT_STREAM_CONFIG)];

    let gateway = fabric(&["agent-gateway", "config", "list"], &files);
    let stream = fabric(&["agent-stream", "config", "list"], &files);

    assert!(gateway.status.success(), "{}", stderr(&gateway));
    assert!(stream.status.success(), "{}", stderr(&stream));
    assert!(stdout(&gateway).contains("https://gateway.example"), "{}", stdout(&gateway));
    assert!(!stdout(&gateway).contains("https://stream.example"), "{}", stdout(&gateway));
    assert!(stdout(&stream).contains("https://stream.example"), "{}", stdout(&stream));
    assert!(!stdout(&stream).contains("https://gateway.example"), "{}", stdout(&stream));
}

#[cfg(feature = "agent-stream")]
#[test]
fn the_feature_build_starts_with_no_agent_stream_connections_beside_a_gateway_one() {
    let output = fabric(&["agent-stream", "config", "list"], &[("config.toml", GATEWAY_CONFIG)]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "No Agent Stream connections yet.");
}

#[cfg(feature = "agent-stream")]
#[test]
fn an_agent_stream_command_naming_a_gateway_only_connection_says_it_does_not_exist() {
    let output = fabric(&["agent-stream", "config", "use", "default"], &[("config.toml", GATEWAY_CONFIG)]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("Agent Stream connection 'default' does not exist"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn an_agent_stream_connection_with_a_hash_in_its_name_gets_the_warning() {
    let output = fabric(&["agent-stream", "config", "list"], &[("agent-stream.toml", HASH_NAME_CONFIG)]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("warning: connection 'prod#1' has a '#' in its name"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn a_token_and_host_both_from_the_environment_get_the_note_on_an_agent_stream_command() {
    let token = "aspat_secret-value";
    let output = fabric_in_fresh_home(
        &["agent-stream", "config", "list"],
        &[],
        &[("FABRIC_TOKEN", token), ("FABRIC_HOST", "https://stream.example")],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stderr(&output)
            .matches("note: sending the token from FABRIC_TOKEN to the host from FABRIC_HOST (https://stream.example)")
            .count(),
        1,
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(token), "{}", stderr(&output));
    assert!(!stdout(&output).contains(token), "{}", stdout(&output));
}

/// Agent Stream's public permission list, which has `pipes.view`.
#[cfg(feature = "agent-stream")]
const AGENT_STREAM_PERMISSIONS: &str = r#"{"pipes.view":false,"users.view":false}"#;

/// What Agent Stream answers to `tokens list` when there are no tokens.
#[cfg(feature = "agent-stream")]
const NO_ACCESS_TOKENS: &str = r#"{"access_tokens":[]}"#;

#[cfg(feature = "agent-stream")]
const TOKENS_LIST_REQUEST: &str = "GET /api/v1/access-tokens HTTP/1.1";

#[cfg(feature = "agent-stream")]
const ACCESS_TOKEN: &str = "aspat_secret-value";

#[cfg(feature = "agent-stream")]
const SESSION_TOKEN: &str = "session-secret-value";

/// A D-Bus session address nothing listens on. On Linux the keyring is the
/// Secret Service over D-Bus, so a command that opened it with this set would
/// fail instead of carrying on.
#[cfg(feature = "agent-stream")]
const UNREACHABLE_DBUS: (&str, &str) = ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/fabric-test-bus");

/// Starts an Agent Stream that answers the probe and `tokens list`.
#[cfg(feature = "agent-stream")]
fn agent_stream_host() -> (String, Requests) {
    host_answering(AGENT_STREAM_PERMISSIONS, NO_ACCESS_TOKENS)
}

/// Every file under `directory`, at any depth, in sorted order.
#[cfg(feature = "agent-stream")]
fn files_under(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("read directory") {
            let path = entry
                .expect("directory entry")
                .path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Asserts that `requests` is the anonymous probe, then one `tokens list`
/// request that carries `token` as its bearer.
#[cfg(feature = "agent-stream")]
fn assert_probe_then_bearer_list(
    requests: &Requests,
    token: &str,
) {
    assert_eq!(request_lines(requests), [PROBE_REQUEST, TOKENS_LIST_REQUEST]);
    let probe = request_lowercase(requests, 0);
    assert!(!probe.contains("authorization"), "{probe}");
    assert!(!probe.contains(token), "{probe}");
    let list = request_lowercase(requests, 1);
    assert!(list.contains(&format!("authorization: bearer {token}")), "{list}");
}

/// The host and the token both come from the environment, and nothing is
/// saved, so the command must not open the credential store. On Linux that is
/// proven by [`UNREACHABLE_DBUS`], which makes any keyring call fail the run.
/// An empty home only shows that no config file was written, because a keyring
/// read writes nothing and the system store lives outside this home, so on
/// macOS the proof is the unit test
/// `a_given_host_and_token_with_no_saved_connection_never_touch_the_keyring` in
/// `agent_stream/mod.rs`, whose store fails every call.
#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_host_and_token_from_the_environment_asks_the_host_then_sends_the_token_and_saves_nothing() {
    let (host, requests) = agent_stream_host();
    let home = tempfile::TempDir::new().expect("temp dir");

    let output = fabric_in_home(
        home.path(),
        &["agent-stream", "tokens", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stderr(&output);
    assert!(output.status.success(), "{text}");
    assert!(!text.contains("keyring"), "{text}");
    assert!(!text.contains(ACCESS_TOKEN), "{text}");
    assert_probe_then_bearer_list(&requests, ACCESS_TOKEN);
    assert!(files_under(home.path()).is_empty(), "{:?}", files_under(home.path()));
}

#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_a_session_token_from_the_environment_asks_a_saved_agent_stream_then_sends_the_token() {
    let (host, requests) = agent_stream_host();
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

    let output = fabric_in_fresh_home(
        &["agent-stream", "tokens", "list"],
        &[("agent-stream.toml", &config)],
        &[("FABRIC_TOKEN", SESSION_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_probe_then_bearer_list(&requests, SESSION_TOKEN);
}

#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_an_access_token_from_the_environment_sends_it_to_a_saved_agent_stream_without_asking() {
    let (host, requests) = agent_stream_host();
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

    let output = fabric_in_fresh_home(
        &["agent-stream", "tokens", "list"],
        &[("agent-stream.toml", &config)],
        &[("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(request_lines(&requests), [TOKENS_LIST_REQUEST]);
}
