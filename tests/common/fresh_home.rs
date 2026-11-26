//! Runs the built `fabric` binary in a home of its own, so a test never reads
//! or writes the configuration of the person running it.

use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use tempfile::TempDir;

/// Runs `fabric <args>` in a fresh home holding `files` in the `fabric`
/// configuration directory of macOS and of Linux, the two systems these tests
/// run on. `FABRIC_TOKEN`, `FABRIC_HOST`, and `FABRIC_CONNECTION` are not
/// inherited, every variable in `environment` is set, and any other variable
/// is inherited as it is. `stdin` is what the command reads on standard input
/// before that ends.
pub fn fabric_in_fresh_home(
    args: &[&str],
    files: &[(&str, &str)],
    environment: &[(&str, &str)],
    stdin: &str,
) -> Output {
    let home = TempDir::new().expect("temp dir");
    fabric_in_home(home.path(), args, files, environment, stdin)
}

/// Like [`fabric_in_fresh_home`], in `home`, which the caller made and can
/// look into once the command has ended.
pub fn fabric_in_home(
    home: &Path,
    args: &[&str],
    files: &[(&str, &str)],
    environment: &[(&str, &str)],
    stdin: &str,
) -> Output {
    for directory in [home.join("Library/Application Support/fabric"), home.join("xdg/fabric")] {
        std::fs::create_dir_all(&directory).expect("config directory");
        for (name, contents) in files {
            std::fs::write(directory.join(name), contents).expect("config file");
        }
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_fabric"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env_remove("FABRIC_TOKEN")
        .env_remove("FABRIC_HOST")
        .env_remove("FABRIC_CONNECTION");
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .spawn()
        .expect("run fabric");
    // A command that ends without reading its input closes the pipe first,
    // which is not a failure of the test.
    let _ = child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(stdin.as_bytes());
    child
        .wait_with_output()
        .expect("wait for fabric")
}
