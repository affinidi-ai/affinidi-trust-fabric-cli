//! `fabric agent-stream logs`: the log files of an Agent Stream, run through
//! the logs commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

use crate::{
    client::GatewayClient,
    commands::{self, Output, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    /// Download every log file as one ZIP archive.
    ///
    /// Needs the logs.view permission. Agent Stream builds the whole archive
    /// in memory before sending it, so this is expensive on a large log
    /// directory. An existing file at --output-file is overwritten without
    /// asking.
    ///
    /// There is no overall time limit: the download stops only if Agent
    /// Stream sends nothing for 120 seconds.
    #[command(after_long_help = DOWNLOAD_EXAMPLES)]
    Download {
        /// Where to write the archive. '-' is standard output.
        #[arg(long, default_value = "logs.zip")]
        output_file: PathBuf,
    },
    /// Delete every rotated log file, keeping the current one.
    ///
    /// Agent Stream keeps agent-stream.log and removes the other
    /// agent-stream*.log* files. Needs the settings.edit permission. Pass
    /// --yes to confirm: there is no prompt, and without --yes the command
    /// refuses. Download the logs first if you may need them.
    #[command(after_long_help = TRUNCATE_EXAMPLES)]
    Truncate {
        /// Confirm the deletion. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `logs download --help`.
const DOWNLOAD_EXAMPLES: &str = r#"Examples:
  Save the archive under a dated name:
    fabric agent-stream logs download \
      --output-file "agent-stream-logs-$(date +%F).zip""#;

/// Examples shown at the bottom of `logs truncate --help`.
const TRUNCATE_EXAMPLES: &str = r#"Examples:
  Keep a copy, then delete the rotated log files:
    fabric agent-stream logs download --output-file logs.zip
    fabric agent-stream logs truncate --yes"#;

/// Runs one `logs` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: LogsCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::Logs(command.into()), output).await
}

impl From<LogsCommand> for commands::LogsCommand {
    fn from(command: LogsCommand) -> Self {
        match command {
            LogsCommand::Download { output_file } => Self::Download { output_file },
            LogsCommand::Truncate { yes } => Self::Truncate { yes },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_stream::test_support::{scripted_agent_stream, start_lines};

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_logs_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/logs/download", "HTTP/1.1 200 OK", "PK-archive"),
            (
                "POST /api/v1/logs/truncate",
                "HTTP/1.1 200 OK",
                r#"{"files_removed":2,"bytes_freed":10,"current_log_kept":true}"#,
            ),
        ])
        .await;
        let client = client(host);
        let directory = tempfile::tempdir().expect("temp dir");
        let archive = directory
            .path()
            .join("logs.zip");

        for command in [LogsCommand::Download { output_file: archive.clone() }, LogsCommand::Truncate { yes: true }] {
            run(&client, command, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/logs/download HTTP/1.1", "POST /api/v1/logs/truncate HTTP/1.1"]
        );
        assert_eq!(std::fs::read(&archive).expect("the archive"), b"PK-archive");
    }

    #[tokio::test]
    async fn a_refused_download_reads_as_an_agent_stream_answer() {
        let (host, _requests) =
            scripted_agent_stream(vec![("GET /api/v1/logs/download", "HTTP/1.1 403 Forbidden", "")]).await;
        let directory = tempfile::tempdir().expect("temp dir");
        let archive = directory
            .path()
            .join("logs.zip");

        let error = run(&client(host), LogsCommand::Download { output_file: archive.clone() }, Output::Json)
            .await
            .expect_err("the role lacks logs.view");

        assert!(
            error
                .to_string()
                .starts_with("Agent Stream answered 403 Forbidden"),
            "{error}"
        );
        assert!(!archive.exists(), "a refused download writes no archive");
    }

    #[tokio::test]
    async fn truncate_without_yes_sends_nothing() {
        let (host, requests) = scripted_agent_stream(Vec::new()).await;

        let error = run(&client(host), LogsCommand::Truncate { yes: false }, Output::Json)
            .await
            .expect_err("--yes is required");

        assert_eq!(error.to_string(), "pass --yes to confirm deleting every rotated log file; this cannot be undone");
        assert!(start_lines(&requests).is_empty());
    }
}
