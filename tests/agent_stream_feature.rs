//! Runs the built `fabric` binary to check that `fabric agent-stream` exists
//! only when the binary was built with the `agent-stream` Cargo feature, and
//! that its saved connections stay apart from the Agent Gateway ones.

// Only the runner is taken from `common`, because its saved-connection helper
// is for Agent Gateway commands and would go unused here.
#[path = "common/fresh_home.rs"]
mod fresh_home;

use std::process::Output;

use fresh_home::fabric_in_fresh_home;

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
