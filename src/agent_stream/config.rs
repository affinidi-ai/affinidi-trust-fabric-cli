//! `fabric agent-stream config`: the saved Agent Stream connections on this
//! machine.

use std::path::Path;

use anyhow::Result;
use clap::Subcommand;

use crate::{
    commands::{self, Output},
    config::Config,
    credentials::CredentialStore,
};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// List saved Agent Stream profiles, with their hosts and which one is
    /// current.
    List,
    /// Select the default Agent Stream profile.
    ///
    /// Commands not given a connection use this profile from now on.
    Use {
        /// Name of a saved profile (see `fabric agent-stream config list`).
        name: String,
    },
    /// Remove an Agent Stream profile and its saved token, without contacting
    /// the Agent Stream.
    ///
    /// The token is deleted from the OS credential store only, so it stays
    /// valid on the Agent Stream. When the removed profile was current,
    /// another saved profile, if any, becomes current (the first by name).
    Remove {
        /// Name of the saved profile to remove.
        name: String,
    },
}

/// Runs one `config` command on `saved`, the Agent Stream connections read
/// from the file at `path`, and the Agent Stream `credentials`, through the
/// commands Agent Gateway uses, so the two products list, select, and remove
/// connections the same way. Messages name the Agent Stream connections,
/// because `credentials` is the Agent Stream store.
pub fn run(
    saved: &mut Config,
    credentials: &impl CredentialStore,
    command: ConfigCommand,
    path: &Path,
    output: Output,
) -> Result<()> {
    let command = match command {
        ConfigCommand::List => commands::ConfigCommand::List,
        ConfigCommand::Use { name } => commands::ConfigCommand::Use { name },
        ConfigCommand::Remove { name } => commands::ConfigCommand::Remove { name },
    };
    commands::run_config(saved, credentials, command, path, output)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{agent_stream::test_support::MemoryCredentials, commands::Cli, config::Connection};

    const STREAM_HOST: &str = "https://stream.example";
    const OTHER_STREAM_HOST: &str = "https://other-stream.example";
    const STREAM_TOKEN: &str = "aspat_saved";

    /// Two saved Agent Stream connections, `default` (current) and `other`,
    /// with a token and bound host for `default`.
    fn two_connections() -> (Config, MemoryCredentials) {
        let mut saved = Config {
            current: Some("default".to_owned()),
            ..Config::default()
        };
        saved
            .connections
            .insert("default".to_owned(), Connection::new(STREAM_HOST.to_owned()));
        saved
            .connections
            .insert("other".to_owned(), Connection::new(OTHER_STREAM_HOST.to_owned()));
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("default", STREAM_TOKEN)
            .unwrap();
        credentials
            .set_bound_host("default", STREAM_HOST)
            .unwrap();
        (saved, credentials)
    }

    #[test]
    fn the_config_commands_parse_under_agent_stream() {
        for arguments in [
            vec!["fabric", "agent-stream", "config", "list"],
            vec!["fabric", "agent-stream", "config", "use", "default"],
            vec!["fabric", "agent-stream", "config", "remove", "default"],
            vec!["fabric", "agent-stream", "--output", "json", "config", "list"],
        ] {
            Cli::try_parse_from(arguments.iter().copied()).unwrap_or_else(|error| panic!("{arguments:?}: {error}"));
        }
    }

    #[test]
    fn use_makes_a_saved_connection_current_and_writes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let (mut saved, credentials) = two_connections();

        run(&mut saved, &credentials, ConfigCommand::Use { name: "other".to_owned() }, &path, Output::Table).unwrap();

        assert_eq!(saved.current.as_deref(), Some("other"));
        assert_eq!(
            Config::load_from(&path)
                .unwrap()
                .current
                .as_deref(),
            Some("other")
        );
    }

    #[test]
    fn use_of_a_name_saved_only_for_the_gateway_says_the_agent_stream_connection_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let (mut saved, credentials) = two_connections();

        let error = run(&mut saved, &credentials, ConfigCommand::Use { name: "prod".to_owned() }, &path, Output::Table)
            .expect_err("a name the Agent Stream store does not have");

        assert_eq!(error.to_string(), "Agent Stream connection 'prod' does not exist");
        assert_eq!(saved.current.as_deref(), Some("default"));
        assert!(!path.exists(), "nothing is written for a refused name");
    }

    #[test]
    fn remove_deletes_the_token_and_bound_host_and_makes_the_next_connection_current() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let (mut saved, credentials) = two_connections();

        run(&mut saved, &credentials, ConfigCommand::Remove { name: "default".to_owned() }, &path, Output::Table)
            .unwrap();

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
        let written = Config::load_from(&path).unwrap();
        assert_eq!(written.current.as_deref(), Some("other"));
        assert_eq!(
            written
                .connections
                .keys()
                .collect::<Vec<_>>(),
            ["other"]
        );
    }

    #[test]
    fn remove_of_an_unknown_name_says_the_agent_stream_connection_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("agent-stream.toml");
        let (mut saved, credentials) = two_connections();

        let error =
            run(&mut saved, &credentials, ConfigCommand::Remove { name: "ghost".to_owned() }, &path, Output::Table)
                .expect_err("a name the Agent Stream store does not have");

        assert_eq!(error.to_string(), "Agent Stream connection 'ghost' does not exist");
        assert_eq!(saved.connections.len(), 2);
    }
}
