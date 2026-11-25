//! `fabric agent-stream config`: the saved Agent Stream connections on this
//! machine.

use std::path::Path;

use anyhow::{Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    commands::{Output, print_list},
    config::Config,
    credentials::CredentialStore,
    tables::{AGENT_STREAM_CONNECTIONS, Scope},
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
/// from the file at `path`, and the Agent Stream `credentials`.
pub fn run(
    saved: &mut Config,
    credentials: &impl CredentialStore,
    command: ConfigCommand,
    path: &Path,
    output: Output,
) -> Result<()> {
    match command {
        ConfigCommand::List => {
            let rows: Vec<Value> = saved
                .connections
                .iter()
                .map(|(name, connection)| {
                    json!({
                        "name": name,
                        "host": connection.host,
                        "current": saved.current.as_deref() == Some(name),
                    })
                })
                .collect();
            print_list(&Value::Array(rows), output, &AGENT_STREAM_CONNECTIONS, Scope::All)
        }
        ConfigCommand::Use { name } => {
            if !saved
                .connections
                .contains_key(&name)
            {
                bail!("{}", missing_connection(&name));
            }
            saved.current = Some(name.clone());
            saved.save_to(path)?;
            println!("Using '{name}'");
            Ok(())
        }
        ConfigCommand::Remove { name } => remove_connection(saved, credentials, &name, path),
    }
}

/// Removes an Agent Stream connection and its token from this machine only.
/// The keyring entries go first, so an entry left behind by a connection that
/// is already gone from the file is cleaned up too.
fn remove_connection(
    saved: &mut Config,
    credentials: &impl CredentialStore,
    name: &str,
    path: &Path,
) -> Result<()> {
    credentials.delete_token(name)?;
    credentials.delete_bound_host(name)?;
    if saved
        .connections
        .remove(name)
        .is_none()
    {
        bail!("{}", missing_connection(name));
    }
    if saved.current.as_deref() == Some(name) {
        saved.current = saved
            .connections
            .keys()
            .next()
            .cloned();
    }
    saved.save_to(path)?;
    println!("Removed local credentials for '{name}'");
    Ok(())
}

/// The error for a name that is not a saved Agent Stream connection, which
/// says which product's store was searched, since the same name may well be
/// an Agent Gateway connection.
fn missing_connection(name: &str) -> String {
    format!("Agent Stream connection '{name}' does not exist")
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
