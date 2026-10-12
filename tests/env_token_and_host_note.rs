//! Runs the built `fabric` binary with the token and host set in the
//! environment and checks the note printed on standard error.

mod common;

use std::process::Output;

use common::fabric_with_saved_host;

const ENV_HOST: &str = "http://127.0.0.1:1";
const SAVED_HOST: &str = "http://127.0.0.1:2";
const TOKEN: &str = "secret-token-value";

/// Runs `fabric agent-gateway <args>` with a saved connection to
/// `SAVED_HOST` and exactly the environment variables in `environment`.
fn fabric(
    args: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    fabric_with_saved_host(SAVED_HOST, args, environment)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn note_count(output: &Output) -> usize {
    stderr(output)
        .matches("note: sending the token from FABRIC_TOKEN")
        .count()
}

#[test]
fn token_and_host_both_from_the_environment_print_one_note_naming_the_host() {
    let output = fabric(&["--allow-http", "surfaces", "list"], &[("FABRIC_TOKEN", TOKEN), ("FABRIC_HOST", ENV_HOST)]);

    let text = stderr(&output);
    assert_eq!(note_count(&output), 1, "{text}");
    assert!(text.contains(ENV_HOST), "{text}");
    assert!(!text.contains(TOKEN), "{text}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
}

#[test]
fn a_typed_token_with_a_host_from_the_environment_prints_no_note() {
    let output = fabric(&["--allow-http", "--token", TOKEN, "surfaces", "list"], &[("FABRIC_HOST", ENV_HOST)]);

    assert_eq!(note_count(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_typed_host_with_a_token_from_the_environment_prints_no_note() {
    let output = fabric(&["--allow-http", "--host", ENV_HOST, "surfaces", "list"], &[("FABRIC_TOKEN", TOKEN)]);

    assert_eq!(note_count(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_token_from_the_environment_with_the_saved_host_prints_no_note() {
    let output = fabric(&["--allow-http", "surfaces", "list"], &[("FABRIC_TOKEN", TOKEN)]);

    assert_eq!(note_count(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_host_from_the_environment_alone_prints_no_note() {
    let output = fabric(&["--allow-http", "surfaces", "list"], &[("FABRIC_HOST", ENV_HOST)]);

    assert_eq!(note_count(&output), 0, "{}", stderr(&output));
}

#[test]
fn login_with_token_and_host_from_the_environment_prints_the_note() {
    let output = fabric(&["--allow-http", "login"], &[("FABRIC_TOKEN", TOKEN), ("FABRIC_HOST", ENV_HOST)]);

    assert_eq!(note_count(&output), 1, "{}", stderr(&output));
}

#[test]
fn the_interactive_shell_prints_the_note_once_at_start() {
    let output = fabric(&["shell"], &[("FABRIC_TOKEN", TOKEN), ("FABRIC_HOST", ENV_HOST)]);

    assert_eq!(note_count(&output), 1, "{}", stderr(&output));
    assert!(output.status.success(), "{}", stderr(&output));
}
