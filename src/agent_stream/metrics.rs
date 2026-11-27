//! `fabric agent-stream metrics`: the metrics configuration, Prometheus
//! exposition, and stored metrics of an Agent Stream, run through the metrics
//! commands Agent Gateway uses. Agent Stream has no OpenTelemetry export
//! status route, so there is no `status` command.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::commands::{self, MetricsFileArgs};

#[derive(Debug, Subcommand)]
pub enum MetricsCommand {
    /// Manage the metrics configuration.
    Config {
        #[command(subcommand)]
        command: MetricsConfigCommand,
    },
    /// Fetch the Prometheus exposition.
    ///
    /// When Agent Stream has Prometheus authentication on, pass --username and
    /// --password; they are sent as HTTP Basic credentials instead of the
    /// bearer token. The CLI reads the same FABRIC_METRICS_USERNAME and
    /// FABRIC_METRICS_PASSWORD for every product, so a password exported for
    /// another appliance is sent to this Agent Stream too.
    ///
    /// On standard output, control characters are removed from the
    /// exposition; a file named with --output-file gets it exactly as sent.
    #[command(after_long_help = SCRAPE_EXAMPLES)]
    Scrape(MetricsScrapeArgs),
    /// Check whether Agent Stream can reach an OTLP endpoint.
    ///
    /// Agent Stream only opens a TCP connection to the endpoint, with a
    /// 5-second timeout, and sends no telemetry. A connection that fails is
    /// reported only once the 5 seconds have passed, and the command then
    /// exits non-zero. Agent Stream refuses a URL whose scheme is not http or
    /// https, and one that does not resolve to a public address unless it is
    /// the endpoint the saved metrics configuration exports to.
    #[command(name = "test-endpoint")]
    TestEndpoint {
        /// OTLP endpoint to open a connection to, including the scheme.
        url: String,
    },
    /// Delete stored metrics older than the retention period.
    ///
    /// Removes connection records and rule validation events older than the
    /// `metrics_retention_minutes` appliance setting Agent Stream started
    /// with. Pass --yes to confirm: there is no prompt, and without --yes the
    /// command refuses. Deleted metrics cannot be recovered.
    #[command(after_long_help = TRUNCATE_EXAMPLES)]
    Truncate {
        /// Confirm the truncation. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `metrics scrape --help`.
const SCRAPE_EXAMPLES: &str = r#"Examples:
  Check the exposition with promtool:
    fabric agent-stream metrics scrape | promtool check metrics

  With Prometheus authentication on, read the password without echoing it and
  save to a file:
    export FABRIC_METRICS_USERNAME=prometheus
    read -rs FABRIC_METRICS_PASSWORD && export FABRIC_METRICS_PASSWORD
    fabric agent-stream metrics scrape --output-file metrics.txt"#;

/// Examples shown at the bottom of `metrics truncate --help`.
const TRUNCATE_EXAMPLES: &str = r#"Examples:
  Delete metrics older than the retention period Agent Stream started with:
    fabric agent-stream metrics truncate --yes

  A new metrics_retention_minutes from `settings set` is used only once Agent
  Stream restarts."#;

#[derive(Debug, Subcommand)]
pub enum MetricsConfigCommand {
    /// Show the metrics configuration.
    ///
    /// Agent Stream leaves out the id of the secret that holds the collector
    /// credential, `opentelemetry.auth.secret_id`.
    Show,
    /// Replace the whole metrics configuration from a JSON document.
    ///
    /// This is not a patch: leaving out `opentelemetry.auth` removes it, which
    /// switches collector export to unauthenticated, and leaving out
    /// `retention`, `advanced` or `opentelemetry.protocol` resets it to its
    /// default. So the CLI first compares the document with the live
    /// configuration and refuses one that would drop a stored setting.
    ///
    /// An `opentelemetry.auth` without `secret_id`, as `show` prints it, keeps
    /// the stored secret. Sending the collector credential from another
    /// secret, or to another endpoint, needs the secrets.view permission. A
    /// new export endpoint must resolve to a public address, and an access
    /// token bound to a tenant cannot change this configuration.
    /// The document can also set `opentelemetry.instance_id`, which is
    /// exported as `service.instance.id`.
    ///
    /// Agent Stream reports success once the file is saved, even if applying
    /// it to the running collector failed, so read the `message` it returns.
    #[command(after_long_help = CONFIG_SET_EXAMPLES)]
    Set(MetricsFileArgs),
}

/// Examples shown at the bottom of `metrics config set --help`.
const CONFIG_SET_EXAMPLES: &str = r#"Examples:
  Edit the live configuration and send it back whole:
    fabric agent-stream metrics config show --output json > metrics.json
    fabric agent-stream metrics config set --file metrics.json

  Remove a stored setting on purpose, such as opentelemetry.auth, by skipping
  the check:
    fabric agent-stream metrics config set --file metrics.json --force"#;

#[derive(Debug, Args)]
pub struct MetricsScrapeArgs {
    /// Prometheus Basic-auth user, `prometheus_auth_username` in the
    /// appliance settings.
    #[arg(long, requires = "password", env = "FABRIC_METRICS_USERNAME")]
    username: Option<String>,
    /// Password for --username. Prefer FABRIC_METRICS_PASSWORD over passing it
    /// on the command line, where it lands in shell history.
    #[arg(long, requires = "username", env = "FABRIC_METRICS_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Where to write the exposition. '-' is standard output.
    #[arg(long, default_value = "-")]
    output_file: PathBuf,
}

impl From<MetricsCommand> for commands::MetricsCommand {
    fn from(command: MetricsCommand) -> Self {
        match command {
            MetricsCommand::Config {
                command: MetricsConfigCommand::Show,
            } => Self::Config {
                command: commands::MetricsConfigCommand::Show,
            },
            MetricsCommand::Config {
                command: MetricsConfigCommand::Set(args),
            } => Self::Config {
                command: commands::MetricsConfigCommand::Set(args),
            },
            MetricsCommand::Scrape(args) => Self::Scrape(commands::MetricsScrapeArgs {
                username: args.username,
                password: args.password,
                output_file: args.output_file,
            }),
            MetricsCommand::TestEndpoint { url } => Self::TestEndpoint { url },
            MetricsCommand::Truncate { yes } => Self::Truncate { yes },
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{
        agent_stream::test_support::{scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Cli, Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[test]
    fn there_is_no_status_command() {
        let status = Cli::try_parse_from(["fabric", "agent-stream", "metrics", "status"])
            .expect_err("Agent Stream has no OpenTelemetry export status route");

        assert_eq!(status.kind(), clap::error::ErrorKind::InvalidSubcommand, "{status}");
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "metrics", "scrape"]).is_ok());
    }

    #[tokio::test]
    async fn each_command_reaches_its_metrics_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/metrics/config", "HTTP/1.1 200 OK", r#"{"opentelemetry":{"enabled":false}}"#),
            ("PUT /api/v1/metrics/config", "HTTP/1.1 200 OK", r#"{"success":true,"message":"Saved."}"#),
            ("GET /api/v1/metrics/prometheus", "HTTP/1.1 200 OK", "agent_stream_up 1\n"),
            ("POST /api/v1/metrics/test-connection", "HTTP/1.1 200 OK", r#"{"success":true,"message":"Reached."}"#),
            ("POST /api/v1/metrics/truncate", "HTTP/1.1 200 OK", r#"{"connections_removed":0}"#),
        ])
        .await;
        let client = client(host);
        let document = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(document.path(), r#"{"opentelemetry":{"enabled":true}}"#).expect("write the document");
        let scrape = tempfile::NamedTempFile::new().expect("temp file");

        for command in [
            MetricsCommand::Config {
                command: MetricsConfigCommand::Show,
            },
            MetricsCommand::Config {
                command: MetricsConfigCommand::Set(MetricsFileArgs {
                    file: document.path().to_path_buf(),
                    force: false,
                }),
            },
            MetricsCommand::Scrape(MetricsScrapeArgs {
                username: None,
                password: None,
                output_file: scrape.path().to_path_buf(),
            }),
            MetricsCommand::TestEndpoint {
                url: "https://collector.example:4317".to_owned(),
            },
            MetricsCommand::Truncate { yes: true },
        ] {
            run_shared(&client, SharedCommand::Metrics(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/metrics/config HTTP/1.1",
                // `config set` reads the live document first, to refuse one
                // that drops a stored setting.
                "GET /api/v1/metrics/config HTTP/1.1",
                "PUT /api/v1/metrics/config HTTP/1.1",
                "GET /api/v1/metrics/prometheus HTTP/1.1",
                "POST /api/v1/metrics/test-connection HTTP/1.1",
                "POST /api/v1/metrics/truncate HTTP/1.1",
            ]
        );
        assert_eq!(std::fs::read_to_string(scrape.path()).expect("the exposition"), "agent_stream_up 1\n");
    }

    #[tokio::test]
    async fn the_prometheus_refusals_name_agent_stream() {
        let (host, _requests) =
            scripted_agent_stream(vec![("GET /api/v1/metrics/prometheus", "HTTP/1.1 401 Unauthorized", "")]).await;
        let client = client(host);
        let scrape = |username: Option<&str>| {
            MetricsCommand::Scrape(MetricsScrapeArgs {
                username: username.map(str::to_owned),
                password: username.map(|_| "hunter2".to_owned()),
                output_file: PathBuf::from("-"),
            })
        };

        let anonymous = run_shared(&client, SharedCommand::Metrics(scrape(None).into()), Output::Json)
            .await
            .expect_err("credentials are needed");
        let named = run_shared(&client, SharedCommand::Metrics(scrape(Some("prom")).into()), Output::Json)
            .await
            .expect_err("the credentials are wrong");

        assert_eq!(
            anonymous.to_string(),
            "Agent Stream requires Prometheus credentials on /v1/metrics/prometheus; pass --username and \
             --password, which are sent instead of the bearer token"
        );
        assert_eq!(named.to_string(), "Agent Stream rejected the Prometheus credentials for --username 'prom'");
    }

    #[tokio::test]
    async fn a_dropped_metrics_setting_is_refused_as_one_agent_stream_stores() {
        let (host, requests) = scripted_agent_stream(vec![(
            "GET /api/v1/metrics/config",
            "HTTP/1.1 200 OK",
            r#"{"opentelemetry":{"enabled":true,"auth":{"header_name":"x-api-key"}}}"#,
        )])
        .await;
        let document = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(document.path(), r#"{"opentelemetry":{"enabled":true}}"#).expect("write the document");

        let error = run_shared(
            &client(host),
            SharedCommand::Metrics(
                MetricsCommand::Config {
                    command: MetricsConfigCommand::Set(MetricsFileArgs {
                        file: document.path().to_path_buf(),
                        force: false,
                    }),
                }
                .into(),
            ),
            Output::Json,
        )
        .await
        .expect_err("the document drops the collector auth");

        assert_eq!(
            error.to_string(),
            "this document drops 1 setting(s) Agent Stream currently stores: opentelemetry.auth. A metrics update \
             replaces the whole document, so each one would be removed and the live exporter reconfigured without \
             it. Add them, or re-run with --force"
        );
        assert_eq!(start_lines(&requests), ["GET /api/v1/metrics/config HTTP/1.1"]);
    }

    /// The Prometheus credentials the scrape tests send, and the Basic value
    /// they make, `base64("prom:hunter2-secret")`.
    const USERNAME: &str = "prom";
    const PASSWORD: &str = "hunter2-secret";
    const ENCODED: &str = "cHJvbTpodW50ZXIyLXNlY3JldA==";

    fn basic_scrape() -> MetricsCommand {
        MetricsCommand::Scrape(MetricsScrapeArgs {
            username: Some(USERNAME.to_owned()),
            password: Some(PASSWORD.to_owned()),
            output_file: PathBuf::from("-"),
        })
    }

    /// The error a Basic-auth scrape reports when Agent Stream answers with
    /// `status_line` and `body`, and the one request it sent.
    async fn basic_scrape_error(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, String) {
        let (host, requests) = scripted_agent_stream(vec![("GET /api/v1/metrics/prometheus", status_line, body)]).await;

        let error = run_shared(&client(host), SharedCommand::Metrics(basic_scrape().into()), Output::Json)
            .await
            .expect_err("the scrape fails");

        let sent = requests
            .lock()
            .unwrap()
            .clone();
        assert_eq!(sent.len(), 1, "{sent:?}");
        (error.to_string(), sent[0].clone())
    }

    #[tokio::test]
    async fn a_basic_scrape_sends_the_credentials_instead_of_the_access_token_and_redacts_their_echo() {
        let (header_echo, request) = basic_scrape_error(
            "HTTP/1.1 502 Bad Gateway",
            "upstream saw Authorization: Basic cHJvbTpodW50ZXIyLXNlY3JldA==",
        )
        .await;
        let (json_error, _) =
            basic_scrape_error("HTTP/1.1 502 Bad Gateway", r#"{"error":"wrong password hunter2-secret"}"#).await;

        let headers: Vec<&str> = request
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            })
            .collect();
        assert_eq!(headers, [format!("authorization: Basic {ENCODED}")], "{request}");
        assert!(!request.contains(TOKEN), "{request}");
        assert_eq!(header_echo, "upstream saw Authorization: Basic [redacted]");
        assert_eq!(json_error, "wrong password [redacted]");
    }

    #[tokio::test]
    async fn a_basic_scrape_refused_with_an_empty_403_does_not_blame_the_token_scopes() {
        let (error, _) = basic_scrape_error("HTTP/1.1 403 Forbidden", "").await;

        assert_eq!(error, "Agent Stream returned 403 Forbidden: no additional detail from server");
    }
}
