//! Shared setup for tests that run the built `fabric` binary.

use std::process::{Command, Output};

use tempfile::TempDir;

/// Runs `fabric agent-gateway <args>` in a fresh home whose saved connection
/// points at `host`, with no `FABRIC_*` variable inherited and exactly the
/// variables in `environment` set.
pub fn fabric_with_saved_host(
    host: &str,
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
            format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n"),
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
