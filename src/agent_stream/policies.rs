//! `fabric agent-stream policies`: the Rego policy definitions of an Agent
//! Stream, run through the policy commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Subcommand, ValueEnum};

use crate::{
    client::GatewayClient,
    commands::{self, Output, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// List policy definitions.
    List,
    /// Get a policy definition by ID.
    Get {
        /// Policy definition ID (see `fabric agent-stream policies list`).
        policy_id: String,
    },
    /// Create a policy definition from a Rego file.
    ///
    /// The file holds Rego source, not JSON, and must declare the package of
    /// its --policy-type: `package agentstream.policy` for `appliance`,
    /// `package llm.policy` for `llm`, or `package ide.policy` for `ide`.
    /// Agent Stream refuses any other package. The new policy is enabled as
    /// soon as it is created.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create {
        /// ID for the new policy definition, used to refer to it from other
        /// commands.
        #[arg(long)]
        id: String,
        /// Human-readable name.
        #[arg(long)]
        name: String,
        /// What the policy is for.
        #[arg(long, default_value = "")]
        description: String,
        /// What the policy applies to. It cannot be changed after creation.
        #[arg(long, value_enum)]
        policy_type: PolicyType,
        /// File holding the policy's Rego source.
        #[arg(long)]
        policy_file: PathBuf,
    },
    /// Replace a policy definition from a JSON document.
    ///
    /// The document replaces the stored definition. Its `id` must match
    /// POLICY_ID and its `policy_type` cannot change. Editing a policy that is
    /// enforced appliance-wide also needs the policies.publish permission.
    /// Start from the output of `fabric agent-stream policies get <policy-id>
    /// --output json`, where the Rego source is the `policy` field, as a
    /// string.
    Update {
        /// Policy definition ID.
        policy_id: String,
        /// Complete policy definition JSON. Use '-' to read from standard
        /// input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a policy definition.
    ///
    /// The definition is deleted as soon as the command runs. There is no
    /// confirmation prompt, and Agent Stream does not check whether anything
    /// still uses it. A Surface that enforces the policy then refuses its
    /// requests, because Agent Stream denies a request when a policy the
    /// Surface enforces is gone. When the policy is enforced appliance-wide,
    /// Agent Stream then refuses every request of that policy type, on every
    /// Surface. To see what uses it, run `fabric agent-stream policies impact
    /// <policy-id>` first.
    Delete {
        /// Policy definition ID.
        policy_id: String,
    },
    /// List the saved versions of a policy definition.
    ///
    /// Newest first, each with its number, content hash, time, author and
    /// note.
    Versions {
        /// Policy definition ID.
        policy_id: String,
    },
    /// Show what uses a policy definition.
    ///
    /// The answer counts each kind of object that uses the policy: LLM and
    /// IDE Surfaces in `pipes`, fabric surfaces in `surfaces`, and Trust
    /// Fabric connections in `gateways`. `globally_enforced` says whether the
    /// policy is enforced appliance-wide, and `global_types` lists the policy
    /// types that enforce it so. `total` adds up the three counts and the
    /// number of those types.
    Impact {
        /// Policy definition ID.
        policy_id: String,
    },
}

/// What an Agent Stream policy definition applies to.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PolicyType {
    /// The whole Agent Stream, checked before any Surface policy.
    Appliance,
    /// LLM Surfaces.
    Llm,
    /// IDE Surfaces.
    Ide,
}

/// Examples shown at the bottom of `policies create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a policy for LLM Surfaces from a Rego file that declares
  `package llm.policy`:
    fabric agent-stream policies create --id block-pii --name "Block PII" \
      --policy-type llm --policy-file block-pii.rego

  See what uses it before changing or deleting it:
    fabric agent-stream policies impact block-pii"#;

/// Runs one `policies` command on the Agent Stream behind `client`.
pub async fn run(
    client: &GatewayClient,
    command: PolicyCommand,
    output: Output,
) -> Result<()> {
    run_shared(client, SharedCommand::Policies(command.into()), output).await
}

impl From<PolicyType> for commands::PolicyType {
    fn from(policy_type: PolicyType) -> Self {
        match policy_type {
            PolicyType::Appliance => Self::Appliance,
            PolicyType::Llm => Self::Llm,
            PolicyType::Ide => Self::Ide,
        }
    }
}

impl From<PolicyCommand> for commands::PolicyCommand {
    fn from(command: PolicyCommand) -> Self {
        match command {
            PolicyCommand::List => Self::List,
            PolicyCommand::Get { policy_id } => Self::Get { policy_id },
            PolicyCommand::Create {
                id,
                name,
                description,
                policy_type,
                policy_file,
            } => Self::Create {
                id,
                name,
                description,
                policy_type: policy_type.into(),
                policy_file,
            },
            PolicyCommand::Update { policy_id, file } => Self::Update { policy_id, file },
            PolicyCommand::Delete { policy_id } => Self::Delete { policy_id },
            PolicyCommand::Versions { policy_id } => Self::Versions { policy_id },
            PolicyCommand::Impact { policy_id } => Self::Impact { policy_id },
        }
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

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn parses(words: &[&str]) -> bool {
        Cli::try_parse_from(
            ["fabric", "agent-stream", "policies"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .is_ok()
    }

    #[test]
    fn create_needs_one_of_the_agent_stream_policy_types() {
        let create = ["create", "--id", "p-1", "--name", "P", "--policy-file", "p.rego"];
        let with_type = |policy_type: &'static str| {
            let mut words = create.to_vec();
            words.extend(["--policy-type", policy_type]);
            words
        };

        assert!(!parses(&create), "--policy-type has no default");
        for policy_type in ["appliance", "llm", "ide"] {
            assert!(parses(&with_type(policy_type)), "{policy_type}");
        }
        for policy_type in ["gateway", "agent-surface"] {
            assert!(!parses(&with_type(policy_type)), "{policy_type} is an Agent Gateway type");
        }
    }

    #[tokio::test]
    async fn create_sends_the_agent_stream_policy_type_and_the_rego_source() {
        let rego = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(rego.path(), "package llm.policy\n").expect("write the Rego source");
        let (host, requests) =
            scripted_agent_stream(vec![("POST /api/v1/policy-definitions", "HTTP/1.1 201 Created", r#"{"id":"p-1"}"#)])
                .await;

        run(
            &client(host),
            PolicyCommand::Create {
                id: "p-1".to_owned(),
                name: "Block PII".to_owned(),
                description: String::new(),
                policy_type: PolicyType::Llm,
                policy_file: rego.path().to_path_buf(),
            },
            Output::Json,
        )
        .await
        .expect("create");

        let requests = requests.lock().unwrap();
        let body: serde_json::Value = serde_json::from_str(
            requests[0]
                .split_once("\r\n\r\n")
                .expect("a body")
                .1,
        )
        .expect("JSON body");
        assert_eq!(body["policy_type"], "llm");
        assert_eq!(body["policy"], "package llm.policy\n");
        assert_eq!(body["enabled"], true);
    }

    #[tokio::test]
    async fn each_other_command_reaches_its_policy_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/policy-definitions/p-1/versions", "HTTP/1.1 200 OK", "[]"),
            ("GET /api/v1/policy-definitions/p-1/impact", "HTTP/1.1 200 OK", r#"{"pipes":0,"global_types":[]}"#),
            ("GET /api/v1/policy-definitions/p-1", "HTTP/1.1 200 OK", r#"{"id":"p-1"}"#),
            ("PUT /api/v1/policy-definitions/p-1", "HTTP/1.1 200 OK", r#"{"id":"p-1"}"#),
            ("DELETE /api/v1/policy-definitions/p-1", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/policy-definitions", "HTTP/1.1 200 OK", "[]"),
        ])
        .await;
        let client = client(host);
        let document = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(document.path(), r#"{"id":"p-1"}"#).expect("write the document");
        let id = || "p-1".to_owned();

        for command in [
            PolicyCommand::List,
            PolicyCommand::Get { policy_id: id() },
            PolicyCommand::Update {
                policy_id: id(),
                file: document.path().to_path_buf(),
            },
            PolicyCommand::Versions { policy_id: id() },
            PolicyCommand::Impact { policy_id: id() },
            PolicyCommand::Delete { policy_id: id() },
        ] {
            run(&client, command, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/policy-definitions HTTP/1.1",
                "GET /api/v1/policy-definitions/p-1 HTTP/1.1",
                "PUT /api/v1/policy-definitions/p-1 HTTP/1.1",
                "GET /api/v1/policy-definitions/p-1/versions HTTP/1.1",
                "GET /api/v1/policy-definitions/p-1/impact HTTP/1.1",
                "DELETE /api/v1/policy-definitions/p-1 HTTP/1.1",
            ]
        );
    }
}
