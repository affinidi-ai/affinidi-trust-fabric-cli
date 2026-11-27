//! `fabric agent-stream user-settings`: the signed-in user's own settings
//! overrides on an Agent Stream, run through the user settings commands Agent
//! Gateway uses.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::commands::{self, GuardedJsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum UserSettingsCommand {
    /// Show this user's settings.
    ///
    /// Without --overrides this is the effective document: appliance defaults
    /// merged with this user's overrides, so a field that was never set still
    /// looks set. Appliance-wide fields, such as `audit_categories` and
    /// `appliance_id`, always come from the appliance settings. Pass
    /// --overrides to see only what is stored for your account, the view to
    /// start a `set` document from. Agent Stream blanks
    /// `prometheus_auth_password_hash`, and the CLI leaves it out. An access
    /// token with its own scope list needs settings.view for the effective
    /// document, and nothing more for --overrides.
    Show {
        /// Show only this user's stored overrides, without appliance defaults
        /// merged in.
        #[arg(long)]
        overrides: bool,
    },
    /// Apply a partial update from a JSON document.
    ///
    /// Every field present becomes a personal override. Omitting a field or
    /// sending null leaves it alone, so a single override cannot be cleared;
    /// only `reset` clears them. `feature_flags` is the exception: it replaces
    /// your stored flags, so a flag missing from it is cleared.
    ///
    /// A plain `show` document is refused without --force, because sending it
    /// would save the current value of every per-user field and flag as a
    /// personal override. Agent Stream refuses an access token with its own
    /// scope list here: use a session, or a token without one.
    #[command(after_long_help = SET_EXAMPLES)]
    Set(SetArgs),
    /// Clear every personal override and show the resulting settings.
    ///
    /// Runs without a prompt and needs no --force. It deletes only this
    /// account's overrides and touches no appliance setting or other account.
    /// A `show --overrides` copy taken beforehand restores them through `set`.
    /// Agent Stream refuses an access token with its own scope list here.
    #[command(after_long_help = RESET_EXAMPLES)]
    Reset,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// JSON document. Use '-' to read from standard input.
    #[arg(short, long)]
    file: PathBuf,
    /// Submit a document carrying fields a per-user update cannot store, such
    /// as a plain `show` document. Agent Stream ignores those fields.
    #[arg(long)]
    force: bool,
}

/// Examples shown at the bottom of `user-settings set --help`.
const SET_EXAMPLES: &str = r#"Examples:
  Set one personal override:
    echo '{"refresh_interval_seconds": 30}' | fabric agent-stream \
      user-settings set --file -

  Change several overrides at once, starting from --overrides (a plain `show`
  document is refused). A field you delete from the file stays stored; only
  `reset` clears overrides:
    fabric agent-stream user-settings show --overrides --output json > \
      overrides.json
    fabric agent-stream user-settings set --file overrides.json

Fields a personal override can hold: refresh_interval_seconds (1 to 300),
log_timestamp_format (utc, local, relative, or compact), bucket_seconds,
badge_threshold_minutes (at least 1), payments_min_display, feature_flags."#;

/// Examples shown at the bottom of `user-settings reset --help`.
const RESET_EXAMPLES: &str = r#"Examples:
  Keep a copy of your overrides, clear them, and restore them later:
    fabric agent-stream user-settings show --overrides --output json > \
      overrides.json
    fabric agent-stream user-settings reset
    fabric agent-stream user-settings set --file overrides.json"#;

impl From<UserSettingsCommand> for commands::UserSettingsCommand {
    fn from(command: UserSettingsCommand) -> Self {
        match command {
            UserSettingsCommand::Show { overrides } => Self::Show { overrides },
            UserSettingsCommand::Set(SetArgs { file, force }) => Self::Set(GuardedJsonFileArgs { file, force }),
            UserSettingsCommand::Reset => Self::Reset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{json_file, request_body, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    /// What Agent Stream answers a user settings read or write with.
    const EFFECTIVE: &str = r#"{"refresh_interval_seconds":30,"audit_enabled":false,"audit_categories":{"policies":false},"appliance_id":"","feature_flags":{},"prometheus_auth_password_hash":""}"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn set(
        file: &tempfile::NamedTempFile,
        force: bool,
    ) -> UserSettingsCommand {
        UserSettingsCommand::Set(SetArgs {
            file: file.path().to_path_buf(),
            force,
        })
    }

    #[tokio::test]
    async fn each_command_reaches_its_user_settings_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/user-settings/overrides", "HTTP/1.1 200 OK", r#"{"refresh_interval_seconds":30}"#),
            ("GET /api/v1/user-settings", "HTTP/1.1 200 OK", EFFECTIVE),
            ("POST /api/v1/user-settings", "HTTP/1.1 200 OK", EFFECTIVE),
            ("DELETE /api/v1/user-settings", "HTTP/1.1 200 OK", EFFECTIVE),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"refresh_interval_seconds":30}"#);

        for command in [
            UserSettingsCommand::Show { overrides: false },
            UserSettingsCommand::Show { overrides: true },
            set(&document, false),
            UserSettingsCommand::Reset,
        ] {
            run_shared(&client, SharedCommand::UserSettings(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/user-settings HTTP/1.1",
                "GET /api/v1/user-settings/overrides HTTP/1.1",
                "POST /api/v1/user-settings HTTP/1.1",
                "DELETE /api/v1/user-settings HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn set_sends_a_terms_flag_because_agent_stream_stores_it_like_any_other() {
        let (host, requests) =
            scripted_agent_stream(vec![("POST /api/v1/user-settings", "HTTP/1.1 200 OK", EFFECTIVE)]).await;
        let document = json_file(r#"{"feature_flags":{"terms":true}}"#);

        run_shared(&client(host), SharedCommand::UserSettings(set(&document, false).into()), Output::Json)
            .await
            .expect("the flag is written");

        let requests = requests.lock().unwrap();
        assert_eq!(request_body(&requests[0]), r#"{"feature_flags":{"terms":true}}"#);
    }

    #[tokio::test]
    async fn set_refuses_a_merged_show_document_without_force_and_sends_nothing() {
        let (host, requests) = scripted_agent_stream(Vec::new()).await;
        let document = json_file(EFFECTIVE);

        let error = run_shared(&client(host), SharedCommand::UserSettings(set(&document, false).into()), Output::Json)
            .await
            .expect_err("a merged document would store every default as an override");

        assert!(
            error
                .to_string()
                .contains("`fabric agent-stream user-settings show --overrides`"),
            "{error}"
        );
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn set_with_force_sends_a_merged_show_document() {
        let (host, requests) =
            scripted_agent_stream(vec![("POST /api/v1/user-settings", "HTTP/1.1 200 OK", EFFECTIVE)]).await;
        let document = json_file(EFFECTIVE);

        run_shared(&client(host), SharedCommand::UserSettings(set(&document, true).into()), Output::Json)
            .await
            .expect("--force sends it");

        assert_eq!(start_lines(&requests), ["POST /api/v1/user-settings HTTP/1.1"]);
    }
}
