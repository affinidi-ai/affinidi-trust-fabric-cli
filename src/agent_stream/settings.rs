//! `fabric agent-stream settings`: the appliance-wide settings of an Agent
//! Stream, run through the settings commands Agent Gateway uses.

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    /// Show the appliance-wide settings.
    ///
    /// Agent Stream blanks `prometheus_auth_password_hash` on every response.
    Show,
    /// Apply a partial update from a JSON document.
    ///
    /// Absent fields are left unchanged, but `feature_flags` and
    /// `audit_categories` each replace the stored value whole: a flag missing
    /// from `feature_flags` is removed, and a category missing from
    /// `audit_categories` is switched off. `payments_min_display` is ignored
    /// here, because it is a per-user setting: set it with
    /// `fabric agent-stream api post /v1/user-settings --file <file>`, which
    /// refuses an access token with explicit scopes. Prints the settings as
    /// read back after the write.
    #[command(after_long_help = SET_EXAMPLES)]
    Set(JsonFileArgs),
    /// Overwrite the whole document with the built-in defaults and show them.
    ///
    /// This clears settings rather than restoring omitted ones: Prometheus
    /// authentication and the recording of policy decisions are switched off,
    /// `feature_flags` is emptied, `appliance_id` is cleared, and every
    /// window, interval and threshold goes back to its default. Refused
    /// without --force, because the Prometheus password it erases cannot be
    /// restored from a `fabric agent-stream settings show` backup.
    #[command(after_long_help = RESET_EXAMPLES)]
    Reset {
        /// Confirm the reset. Without it the command lists what it would
        /// clear and sends nothing.
        #[arg(long)]
        force: bool,
    },
}

/// Examples shown at the bottom of `settings set --help`.
const SET_EXAMPLES: &str = r#"Examples:
  Record policy decisions in the audit log. audit_categories replaces the
  stored categories, so name every one to keep on:
    echo '{"audit_enabled": true, "audit_categories": {"policies": true}}' \
      | fabric agent-stream settings set --file -

  Edit a full copy:
    fabric agent-stream settings show --output json > settings.json
    fabric agent-stream settings set --file settings.json

  Change the Prometheus password, from a file holding
  {"prometheus_auth_password": "<password>"} so it stays out of shell history.
  It is sent as plaintext and hashed by Agent Stream:
    fabric agent-stream settings set --file prometheus-password.json

Fields Agent Stream will not store as sent (payments_min_display,
prometheus_auth_password_hash, audit_events) and a feature_flags map or an
audit_categories object that replaces the stored one draw a warning on stderr."#;

/// Examples shown at the bottom of `settings reset --help`.
const RESET_EXAMPLES: &str = r#"Examples:
  Keep a copy, then reset (a copy does not bring back the Prometheus password):
    fabric agent-stream settings show --output json > settings-backup.json
    fabric agent-stream settings reset --force"#;

impl From<SettingsCommand> for commands::SettingsCommand {
    fn from(command: SettingsCommand) -> Self {
        match command {
            SettingsCommand::Show => Self::Show,
            SettingsCommand::Set(args) => Self::Set(args),
            SettingsCommand::Reset { force } => Self::Reset { force },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    /// What Agent Stream answers a settings read with.
    const SETTINGS: &str = r#"{"audit_enabled":true,"audit_categories":{"policies":true,"trust_checks":false,"identity":false},"prometheus_auth_password_hash":""}"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn document(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), contents).expect("write the document");
        file
    }

    #[tokio::test]
    async fn each_command_reaches_its_settings_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/settings", "HTTP/1.1 200 OK", SETTINGS),
            ("POST /api/v1/settings", "HTTP/1.1 200 OK", SETTINGS),
            ("DELETE /api/v1/settings", "HTTP/1.1 200 OK", SETTINGS),
        ])
        .await;
        let client = client(host);
        let set = document(r#"{"audit_enabled":true}"#);

        for command in [
            SettingsCommand::Show,
            SettingsCommand::Set(JsonFileArgs { file: set.path().to_path_buf() }),
            SettingsCommand::Reset { force: true },
        ] {
            run_shared(&client, SharedCommand::Settings(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/settings HTTP/1.1",
                "POST /api/v1/settings HTTP/1.1",
                "GET /api/v1/settings HTTP/1.1",
                "DELETE /api/v1/settings HTTP/1.1",
                "GET /api/v1/settings HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn set_sends_a_terms_flag_because_agent_stream_stores_it_like_any_other() {
        let (host, requests) = scripted_agent_stream(vec![
            ("POST /api/v1/settings", "HTTP/1.1 200 OK", SETTINGS),
            ("GET /api/v1/settings", "HTTP/1.1 200 OK", SETTINGS),
        ])
        .await;
        let set = document(r#"{"feature_flags":{"terms":true}}"#);

        run_shared(
            &client(host),
            SharedCommand::Settings(SettingsCommand::Set(JsonFileArgs { file: set.path().to_path_buf() }).into()),
            Output::Json,
        )
        .await
        .expect("the flag is written");

        assert_eq!(start_lines(&requests)[0], "POST /api/v1/settings HTTP/1.1");
    }

    #[tokio::test]
    async fn an_unforced_reset_names_what_agent_stream_clears_and_sends_nothing() {
        let (host, requests) = scripted_agent_stream(Vec::new()).await;

        let error = run_shared(
            &client(host),
            SharedCommand::Settings(SettingsCommand::Reset { force: false }.into()),
            Output::Json,
        )
        .await
        .expect_err("an unforced reset");

        assert_eq!(
            error.to_string(),
            "`settings reset` overwrites the whole appliance settings document with the built-in defaults. It \
             clears: 'prometheus_auth_enabled', so /v1/metrics/prometheus stops checking credentials; \
             'prometheus_auth_username' and the stored password hash; 'audit_enabled' and 'audit_categories', so \
             policy decisions are no longer recorded in the audit log; 'appliance_id'; every entry in \
             'feature_flags'; and every window, interval and threshold. A `fabric agent-stream settings show` \
             backup does not undo it: the password hash is blanked on read, and re-enabling Prometheus \
             authentication without a plaintext 'prometheus_auth_password' is refused with 400. Keep that \
             password elsewhere, or re-run with --force"
        );
        assert!(start_lines(&requests).is_empty());
    }
}
