//! `fabric agent-stream`: the commands addressed to Affinidi Agent Stream.
//! Only compiled with the `agent-stream` Cargo feature while the group is
//! being built. Each command group lives in its own file here.
//!
//! Agent Stream connections are kept apart from the Agent Gateway ones: in
//! their own file (`agent-stream.toml`) and under their own keyring service,
//! so each product can have a connection named `default`.

mod config;
#[cfg(test)]
mod test_support;

use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{
    commands::{Output, new_hash_name_warnings},
    config::Config,
    credentials::{CredentialStore, OsCredentialStore, add_no_keyring_hint},
};

#[derive(Debug, Args)]
pub struct AgentStreamArgs {
    /// Output format for commands that return data.
    #[arg(short, long, global = true, value_enum, default_value_t = Output::Table)]
    output: Output,

    #[command(subcommand)]
    command: AgentStreamCommand,
}

#[derive(Debug, Subcommand)]
enum AgentStreamCommand {
    /// Manage local Agent Stream profiles.
    ///
    /// Profiles are the saved Agent Stream connections on this machine. These
    /// commands never contact an Agent Stream, and never touch the Agent
    /// Gateway profiles of `fabric agent-gateway config`.
    Config {
        #[command(subcommand)]
        command: config::ConfigCommand,
    },
}

/// Runs one `fabric agent-stream` command against the saved Agent Stream
/// connections and their keyring entries.
pub fn dispatch(args: AgentStreamArgs) -> Result<()> {
    let path = crate::config::agent_stream_config_path()?;
    let saved = Config::load_from(&path)?;
    dispatch_with(args, saved, &OsCredentialStore::agent_stream(), &path)
}

/// Runs a command with the `saved` connections read from the file at `path`
/// and the `credentials` store already in hand, so a test can supply all
/// three. As on an Agent Gateway command, a connection name containing `#`
/// is warned about first, and a `token` line found in the file is moved into
/// `credentials` and removed from the file before the command runs, so that
/// rewriting the file never drops a token.
///
/// An error from a keyring that cannot be reached gets one hint, as on an
/// Agent Gateway command: the move of a `token` line adds its own, which
/// names the connection, and the command's error gets the general one.
fn dispatch_with(
    args: AgentStreamArgs,
    mut saved: Config,
    credentials: &impl CredentialStore,
    path: &Path,
) -> Result<()> {
    for warning in new_hash_name_warnings(&saved) {
        eprintln!("{warning}");
    }
    saved.migrate_legacy_tokens_to(credentials, path)?;
    match args.command {
        AgentStreamCommand::Config { command } => config::run(&mut saved, credentials, command, path, args.output),
    }
    .map_err(add_no_keyring_hint)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::test_support::NoKeyring;
    use super::{test_support::MemoryCredentials, *};

    const STREAM_HOST: &str = "https://stream.example";
    const HANDWRITTEN_TOKEN: &str = "aspat_handwritten";

    /// How every hint for a keyring that cannot be reached starts.
    #[cfg(target_os = "linux")]
    const NO_KEYRING_HINT: &str = "no OS keyring can be reached";

    fn config_command(command: config::ConfigCommand) -> AgentStreamArgs {
        AgentStreamArgs {
            output: Output::Table,
            command: AgentStreamCommand::Config { command },
        }
    }

    #[test]
    fn a_token_written_in_the_file_moves_to_the_store_before_a_command_rewrites_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(
            &path,
            format!(
                "[connections.default]\nhost = \"{STREAM_HOST}/\"\ntoken = \"{HANDWRITTEN_TOKEN}\"\n\n[connections.other]\nhost = \"{STREAM_HOST}\"\n"
            ),
        )
        .unwrap();
        let saved = Config::load_from(&path).unwrap();
        let credentials = MemoryCredentials::default();

        dispatch_with(
            config_command(config::ConfigCommand::Use { name: "other".to_owned() }),
            saved,
            &credentials,
            &path,
        )
        .unwrap();

        assert_eq!(
            credentials
                .get_token("default")
                .unwrap()
                .as_deref(),
            Some(HANDWRITTEN_TOKEN)
        );
        assert_eq!(
            credentials
                .get_bound_host("default")
                .unwrap()
                .as_deref(),
            Some(STREAM_HOST)
        );
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains(HANDWRITTEN_TOKEN), "{written}");
        assert_eq!(
            Config::load_from(&path)
                .unwrap()
                .current
                .as_deref(),
            Some("other")
        );
    }

    #[test]
    fn a_file_without_a_token_line_leaves_the_store_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(&path, format!("[connections.default]\nhost = \"{STREAM_HOST}\"\n")).unwrap();
        let saved = Config::load_from(&path).unwrap();
        let credentials = MemoryCredentials::default();

        dispatch_with(config_command(config::ConfigCommand::List), saved, &credentials, &path).unwrap();

        assert_eq!(
            credentials
                .get_token("default")
                .unwrap(),
            None
        );
        assert_eq!(
            credentials
                .get_bound_host("default")
                .unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_token_line_that_cannot_be_moved_without_a_keyring_gets_one_hint_and_stays_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let written = format!("[connections.default]\nhost = \"{STREAM_HOST}\"\ntoken = \"{HANDWRITTEN_TOKEN}\"\n");
        std::fs::write(&path, &written).unwrap();
        let saved = Config::load_from(&path).unwrap();

        let error = dispatch_with(config_command(config::ConfigCommand::List), saved, &NoKeyring, &path)
            .expect_err("the token cannot be moved without a keyring");

        let text = format!("{error:#}");
        assert_eq!(
            text.matches(NO_KEYRING_HINT)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("the plaintext token of connection 'default'"), "{text}");
        assert!(!text.contains(HANDWRITTEN_TOKEN), "{text}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_that_cannot_reach_the_keyring_gets_one_hint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(&path, format!("[connections.default]\nhost = \"{STREAM_HOST}\"\n")).unwrap();
        let saved = Config::load_from(&path).unwrap();

        let error = dispatch_with(
            config_command(config::ConfigCommand::Remove { name: "default".to_owned() }),
            saved,
            &NoKeyring,
            &path,
        )
        .expect_err("the saved token cannot be deleted without a keyring");

        let text = format!("{error:#}");
        assert_eq!(
            text.matches(NO_KEYRING_HINT)
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("saved connections can't be used"), "{text}");
    }
}
