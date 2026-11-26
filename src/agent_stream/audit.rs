//! `fabric agent-stream audit`: the audit log of an Agent Stream, read
//! through the audit command Agent Gateway uses.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};

use crate::{
    client::GatewayClient,
    commands::{self, Output, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// List audit events, newest first.
    ///
    /// The log records delegation consent and tokens, policy decisions, and
    /// changes to the audit settings, but not other admin API calls (except
    /// revoking delegation tokens). Policy decisions are recorded only while
    /// `audit_enabled` and `audit_categories.policies` are both on.
    ///
    /// An empty result can also mean Agent Stream couldn't read its log. Each
    /// vp_jwt is redacted unless you pass --reveal.
    #[command(after_long_help = LIST_EXAMPLES)]
    List(AuditListArgs),
}

/// Examples shown at the bottom of `audit list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  Policy decisions only:
    fabric agent-stream audit list --category policy_decision

  Requests to LLM Surfaces denied by a policy, and by a policy error:
    fabric agent-stream audit list --scope pipe --decision deny
    fabric agent-stream audit list --scope pipe --decision error

  Events that mention "billing" anywhere, second page of 50:
    fabric agent-stream audit list --filter billing --limit 50 --page 2

  Export the whole log as JSON (redacted; add --reveal for the raw values):
    fabric agent-stream audit list --all --output json > audit.json"#;

#[derive(Debug, Args)]
pub struct AuditListArgs {
    /// Events per page. Agent Stream clamps this to 1-500.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Page to read, counting from 1.
    #[arg(long, default_value_t = 1, conflicts_with = "all")]
    page: usize,
    /// Case-insensitive substring, matched against each whole event as JSON,
    /// so field names and the base64 body of an embedded JWT match too.
    #[arg(long)]
    filter: Option<String>,
    /// Comma-separated event categories, for example
    /// policy_decision,consent_granted,token_injected,token_revoked.
    #[arg(long)]
    category: Option<String>,
    /// Only policy decisions from this request flow; other events are dropped.
    #[arg(long, value_enum)]
    flow: Option<AuditFlow>,
    /// Only policy decisions at this scope; other events are dropped.
    #[arg(long, value_enum)]
    scope: Option<AuditScope>,
    /// Only policy decisions with this outcome; other events are dropped.
    /// `deny` leaves out `error` and `missing_engine` decisions.
    #[arg(long, value_enum)]
    decision: Option<AuditDecision>,
    /// Read every page instead of one. With --output json the per-page
    /// counters are dropped and total is kept.
    #[arg(long)]
    all: bool,
    /// Print the full vp_jwt of each event instead of a placeholder.
    #[arg(long)]
    reveal: bool,
}

/// The request flow of a policy decision Agent Stream records.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuditFlow {
    /// Requests arriving at a Surface's Access Point.
    #[value(name = "access_point")]
    AccessPoint,
    /// Outbound requests through a Transit Point. Agent Stream does not
    /// record these yet.
    #[value(name = "transit_point")]
    TransitPoint,
    /// Requests checked by the appliance-wide `appliance` policy, or by the
    /// policy of a Trust Fabric connection.
    Fabric,
}

/// Where a policy decision Agent Stream records was made.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuditScope {
    /// An LLM Surface's policy, or the appliance-wide policy for LLM
    /// Surfaces.
    Pipe,
    /// An IDE Surface's policy, an IDE member's model policy, or the
    /// appliance-wide policy for IDE Surfaces.
    Ide,
    /// The appliance-wide `appliance` policy, or the policy of a Trust Fabric
    /// connection.
    Gateway,
    /// A fabric surface's policy.
    Surface,
}

/// The outcome of a policy decision Agent Stream records.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuditDecision {
    /// The policy allowed the request.
    Allow,
    /// The policy denied the request. A monitor-only appliance-wide policy
    /// records a deny but lets the request through.
    Deny,
    /// The policy could not decide, so the request was denied. A monitor-only
    /// appliance-wide policy records an error but lets the request through.
    Error,
    /// Policy enforcement is on, but Agent Stream had no compiled policy to
    /// run, so the request was denied.
    #[value(name = "missing_engine")]
    MissingEngine,
}

/// Runs one `audit` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: AuditCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::Audit(command.into()), output).await
}

impl From<AuditFlow> for commands::AuditFlow {
    fn from(flow: AuditFlow) -> Self {
        match flow {
            AuditFlow::AccessPoint => Self::AccessPoint,
            AuditFlow::TransitPoint => Self::TransitPoint,
            AuditFlow::Fabric => Self::Fabric,
        }
    }
}

impl From<AuditScope> for commands::AuditScope {
    fn from(scope: AuditScope) -> Self {
        match scope {
            AuditScope::Pipe => Self::Pipe,
            AuditScope::Ide => Self::Ide,
            AuditScope::Gateway => Self::Gateway,
            AuditScope::Surface => Self::Surface,
        }
    }
}

impl From<AuditDecision> for commands::AuditDecision {
    fn from(decision: AuditDecision) -> Self {
        match decision {
            AuditDecision::Allow => Self::Allow,
            AuditDecision::Deny => Self::Deny,
            AuditDecision::Error => Self::Error,
            AuditDecision::MissingEngine => Self::MissingEngine,
        }
    }
}

impl From<AuditCommand> for commands::AuditCommand {
    fn from(command: AuditCommand) -> Self {
        let AuditCommand::List(args) = command;
        Self::List(commands::AuditListArgs {
            limit: args.limit,
            page: args.page,
            filter: args.filter,
            category: args.category,
            flow: args.flow.map(Into::into),
            scope: args.scope.map(Into::into),
            decision: args.decision.map(Into::into),
            all: args.all,
            reveal: args.reveal,
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{
        agent_stream::test_support::{scripted_agent_stream, start_lines},
        commands::Cli,
    };

    const TOKEN: &str = "aspat_test";

    fn parses(words: &[&str]) -> bool {
        Cli::try_parse_from(
            ["fabric", "agent-stream", "audit", "list"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .is_ok()
    }

    fn list(words: &[&str]) -> AuditListArgs {
        #[derive(Parser)]
        struct Wrapper {
            #[command(subcommand)]
            command: AuditCommand,
        }

        let Wrapper {
            command: AuditCommand::List(args),
        } = Wrapper::try_parse_from(
            ["audit", "list"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .expect("parse");
        args
    }

    #[test]
    fn scope_and_decision_take_the_agent_stream_values() {
        for scope in ["pipe", "ide", "gateway", "surface"] {
            assert!(parses(&["--scope", scope]), "{scope}");
        }
        for scope in ["mcp_tool", "response", "mcp_tool_list"] {
            assert!(!parses(&["--scope", scope]), "{scope} is an Agent Gateway scope");
        }
        for decision in ["allow", "deny", "error", "missing_engine"] {
            assert!(parses(&["--decision", decision]), "{decision}");
        }
        for flow in ["access_point", "transit_point", "fabric"] {
            assert!(parses(&["--flow", flow]), "{flow}");
        }
    }

    #[test]
    fn the_list_help_names_only_what_agent_stream_records() {
        use clap::CommandFactory;

        let help = Cli::command()
            .find_subcommand_mut("agent-stream")
            .and_then(|stream| stream.find_subcommand_mut("audit"))
            .and_then(|audit| audit.find_subcommand_mut("list"))
            .expect("audit list")
            .render_long_help()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        for never_written in ["elicitation", "vp_injected", "VP injection", "pre_authorize"] {
            assert!(!help.contains(never_written), "{never_written}: {help}");
        }
        assert!(
            help.contains(
                "missing_engine: Policy enforcement is on, but Agent Stream had no compiled policy to run, so \
                 the request was denied"
            ),
            "{help}"
        );
    }

    #[tokio::test]
    async fn list_sends_the_agent_stream_filter_values() {
        const QUERY: &str = "GET /api/v1/audit?limit=100&page=1&flow=fabric&scope=pipe&decision=missing_engine";
        let (host, requests) = scripted_agent_stream(vec![(
            QUERY,
            "HTTP/1.1 200 OK",
            r#"{"events":[],"total":0,"page":1,"page_size":100,"total_pages":1,"category_counts":{}}"#,
        )])
        .await;

        run(
            &GatewayClient::for_agent_stream(host, TOKEN).expect("client"),
            AuditCommand::List(list(&["--flow", "fabric", "--scope", "pipe", "--decision", "missing_engine"])),
            Output::Json,
        )
        .await
        .expect("list");

        assert_eq!(start_lines(&requests), [format!("{QUERY} HTTP/1.1")]);
    }

    #[tokio::test]
    async fn each_scope_is_sent_by_the_name_agent_stream_records() {
        const PAGE: &str = r#"{"events":[],"total":0,"page":1,"page_size":100,"total_pages":1}"#;
        const SCOPES: [(&str, &str); 4] = [
            ("pipe", "GET /api/v1/audit?limit=100&page=1&scope=pipe"),
            ("ide", "GET /api/v1/audit?limit=100&page=1&scope=ide"),
            ("gateway", "GET /api/v1/audit?limit=100&page=1&scope=gateway"),
            ("surface", "GET /api/v1/audit?limit=100&page=1&scope=surface"),
        ];
        let (host, requests) = scripted_agent_stream(
            SCOPES
                .iter()
                .map(|(_, query)| (*query, "HTTP/1.1 200 OK", PAGE))
                .collect(),
        )
        .await;
        let client = GatewayClient::for_agent_stream(host, TOKEN).expect("client");

        for (scope, _) in SCOPES {
            run(&client, AuditCommand::List(list(&["--scope", scope])), Output::Json)
                .await
                .unwrap_or_else(|error| panic!("{scope}: {error:#}"));
        }

        assert_eq!(
            start_lines(&requests),
            SCOPES
                .iter()
                .map(|(_, query)| format!("{query} HTTP/1.1"))
                .collect::<Vec<_>>()
        );
    }
}
