//! Runs the built `fabric` binary with the token and host set in the
//! environment and checks the note printed on standard error.

use std::process::{Command, Output};

use tempfile::TempDir;

const ENV_HOST: &str = "http://127.0.0.1:1";
const SAVED_HOST: &str = "http://127.0.0.1:2";
const TOKEN: &str = "secret-token-value";

/// Runs `fabric agent-gateway <args>` with a saved connection and exactly the
/// environment variables in `environment`.
fn fabric(
    args: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    let home = TempDir::new().expect("temp dir");
    for directory in [
        home.path()
            .join("Library/Application Support/fabric"),
        home.path().join("xdg/fabric"),
    ] {
        std::fs::create_dir_all(&directory).expect("config directory");
        std::fs::write(
            directory.join("config.toml"),
            format!("current = \"test\"\n\n[connections.test]\nhost = \"{SAVED_HOST}\"\n"),
        )
        .expect("config file");
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_fabric"));
    command
        .arg("agent-gateway")
        .args(args)
        .stdin(std::process::Stdio::null())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg"))
        .env_remove("FABRIC_TOKEN")
        .env_remove("FABRIC_HOST")
        .env_remove("FABRIC_CONNECTION");
    for (name, value) in environment {
        command.env(name, value);
    }
    command
        .output()
        .expect("run fabric")
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
