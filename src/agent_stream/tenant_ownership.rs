//! `fabric agent-stream tenant-ownership`: which tenant owns a resource on an
//! Agent Stream, run through the tenant ownership requests Agent Gateway uses
//! with Agent Stream's own resource kinds.

use anyhow::{Result, bail};
use clap::{Subcommand, ValueEnum};

use crate::commands::{OwnershipChange, OwnershipTarget};

#[derive(Debug, Subcommand)]
pub enum TenantOwnershipCommand {
    /// Report what reassigning a resource would affect.
    ///
    /// Shows the resource's current tenant, whether it is system-owned
    /// (`immutable`, so it cannot be reassigned), and its references:
    /// `incoming` from resources that use it and `outgoing` to resources it
    /// uses. `set` refuses a move that would make one of these references
    /// cross tenants, or that leaves one pointing at a resource that no longer
    /// exists. Needs the tenant_ownership.manage permission.
    Impact {
        /// Resource family Agent Stream tracks ownership for. An id from
        /// `fabric agent-stream surfaces list` goes with `pipes`, and one from
        /// `fabric agent-stream policies list` with `policy-definitions`. API
        /// keys and connection points take their owner from their parent
        /// resource, so they are not offered.
        kind: OwnershipKind,
        /// ID of the resource. Names are not looked up.
        id: String,
    },
    /// Assign a resource to a tenant, or clear its tenant ownership.
    ///
    /// Pass exactly one of --tenant or --clear. The change applies at once,
    /// with no confirmation prompt. Agent Stream blocks a move that would make
    /// one of the resource's references cross tenants, and any move of a
    /// system-owned resource; the error then points to `impact`, which shows
    /// the blocking references, or that the resource is system-owned
    /// (`immutable`). An access token limited to a tenant or to listed
    /// resources cannot reassign ownership. Needs the tenant_ownership.manage
    /// permission.
    #[command(after_long_help = SET_EXAMPLES)]
    Set {
        /// Resource family Agent Stream tracks ownership for. An id from
        /// `fabric agent-stream surfaces list` goes with `pipes`, and one from
        /// `fabric agent-stream policies list` with `policy-definitions`. API
        /// keys and connection points take their owner from their parent
        /// resource, so they are not offered.
        kind: OwnershipKind,
        /// ID of the resource. Names are not looked up.
        id: String,
        /// Tenant to assign the resource to: 1 to 128 letters, digits, '.',
        /// '_', ':' or '-'.
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        tenant: Option<String>,
        /// Clear tenant ownership, so the resource belongs to no tenant. A
        /// token limited to a tenant can then no longer reach it.
        #[arg(long)]
        clear: bool,
    },
}

/// Examples shown at the bottom of `tenant-ownership set --help`.
const SET_EXAMPLES: &str = r#"Examples:
  Check what moving a pipe would cross, then move it to tenant acme:
    fabric agent-stream tenant-ownership impact pipes <pipe-id>
    fabric agent-stream tenant-ownership set pipes <pipe-id> --tenant acme

  Make a policy definition belong to no tenant again:
    fabric agent-stream tenant-ownership set policy-definitions <policy-id> \
      --clear"#;

/// The resource families an Agent Stream tracks tenant ownership for, named
/// as its routes take them. Agent Stream's own `surfaces` family is left out:
/// it is not what `fabric agent-stream surfaces` manages (those are `pipes`),
/// and no Agent Stream route lists its ids. `api-keys` and `connection-points`
/// are accepted but hidden, only to be refused before anything is sent:
/// Agent Stream always refuses them, because they take their owner from their
/// parent resource.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OwnershipKind {
    #[value(name = "secrets")]
    Secrets,
    #[value(name = "certificates")]
    Certificates,
    #[value(name = "pipes")]
    Pipes,
    #[value(name = "api-keys", hide = true)]
    ApiKeys,
    #[value(name = "connection-points", hide = true)]
    ConnectionPoints,
    #[value(name = "gateways")]
    Gateways,
    #[value(name = "mediators")]
    Mediators,
    #[value(name = "integrations")]
    Integrations,
    #[value(name = "policy-definitions")]
    PolicyDefinitions,
    #[value(name = "pipe-templates")]
    PipeTemplates,
    #[value(name = "credential-providers")]
    CredentialProviders,
    #[value(name = "jwt-verification-strategies")]
    JwtVerificationStrategies,
    #[value(name = "oauth-identifiers")]
    OauthIdentifiers,
    #[value(name = "prompts")]
    Prompts,
    #[value(name = "members")]
    Members,
    #[value(name = "teams")]
    Teams,
}

impl OwnershipKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Certificates => "certificates",
            Self::Pipes => "pipes",
            Self::ApiKeys => "api-keys",
            Self::ConnectionPoints => "connection-points",
            Self::Gateways => "gateways",
            Self::Mediators => "mediators",
            Self::Integrations => "integrations",
            Self::PolicyDefinitions => "policy-definitions",
            Self::PipeTemplates => "pipe-templates",
            Self::CredentialProviders => "credential-providers",
            Self::JwtVerificationStrategies => "jwt-verification-strategies",
            Self::OauthIdentifiers => "oauth-identifiers",
            Self::Prompts => "prompts",
            Self::Members => "members",
            Self::Teams => "teams",
        }
    }
}

impl OwnershipKind {
    /// Fails for a kind that takes its owner from its parent resource, which
    /// Agent Stream refuses to report or reassign on its own.
    fn tracked(self) -> Result<&'static str> {
        match self {
            Self::ApiKeys | Self::ConnectionPoints => bail!(
                "ownership of {} comes from the parent resource, so Agent Stream does not report or reassign it on \
                 its own; run the command on the parent resource instead. Nothing was sent",
                self.as_str()
            ),
            kind => Ok(kind.as_str()),
        }
    }
}

/// Refuses a kind Agent Stream does not track on its own. clap already takes
/// exactly one of --tenant and --clear; [`OwnershipTarget::from_flags`] keeps
/// Agent Gateway's rule and wording for a command built any other way, so it
/// is never read as a clear.
impl TryFrom<TenantOwnershipCommand> for OwnershipChange {
    type Error = anyhow::Error;

    fn try_from(command: TenantOwnershipCommand) -> Result<Self> {
        Ok(match command {
            TenantOwnershipCommand::Impact { kind, id } => Self::Impact { kind: kind.tracked()?, id },
            TenantOwnershipCommand::Set { kind, id, tenant, clear } => Self::Set {
                kind: kind.tracked()?,
                id,
                owner: OwnershipTarget::from_flags(tenant, clear)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{
        agent_stream::test_support::{request_body, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Cli, Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn parses(words: &[&str]) -> bool {
        Cli::try_parse_from(
            ["fabric", "agent-stream", "tenant-ownership"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .is_ok()
    }

    #[test]
    fn kind_value_names_match_their_paths() {
        for kind in OwnershipKind::value_variants() {
            let name = kind
                .to_possible_value()
                .expect("every kind is selectable");
            assert_eq!(name.get_name(), kind.as_str());
        }
    }

    #[test]
    fn agent_stream_only_kinds_are_accepted_and_agent_gateway_only_ones_refused() {
        for kind in ["pipes", "pipe-templates", "oauth-identifiers", "prompts", "members", "teams"] {
            assert!(parses(&["impact", kind, "r-1"]), "{kind}");
        }
        for kind in [
            "mcp-proxies",
            "a2a-proxies",
            "trust-registries",
            "issuers",
            "authorities",
            "surface-templates",
            "sts-clients",
            "surfaces",
        ] {
            assert!(!parses(&["impact", kind, "r-1"]), "{kind}");
        }
    }

    #[test]
    fn a_kind_that_takes_its_owner_from_its_parent_is_refused_by_name() {
        for kind in [OwnershipKind::ApiKeys, OwnershipKind::ConnectionPoints] {
            let error = OwnershipChange::try_from(TenantOwnershipCommand::Impact { kind, id: "k-1".to_owned() })
                .err()
                .expect("Agent Stream does not track this kind on its own");

            assert_eq!(
                error.to_string(),
                format!(
                    "ownership of {} comes from the parent resource, so Agent Stream does not report or reassign \
                     it on its own; run the command on the parent resource instead. Nothing was sent",
                    kind.as_str()
                )
            );
        }
    }

    #[test]
    fn the_parent_owned_kinds_parse_but_stay_out_of_the_help() {
        assert!(parses(&["impact", "api-keys", "k-1"]));
        assert!(parses(&["set", "connection-points", "c-1", "--clear"]));
        let help = Cli::try_parse_from(["fabric", "agent-stream", "tenant-ownership", "impact", "--help"])
            .expect_err("help stops the parse")
            .to_string();
        assert!(help.contains("pipes"), "{help}");
        assert!(!help.contains("api-keys"), "{help}");
        assert!(!help.contains("connection-points"), "{help}");
    }

    #[test]
    fn set_takes_exactly_one_of_tenant_and_clear() {
        assert!(parses(&["set", "pipes", "p-1", "--tenant", "acme"]));
        assert!(parses(&["set", "pipes", "p-1", "--clear"]));
        assert!(!parses(&["set", "pipes", "p-1"]));
        assert!(!parses(&["set", "pipes", "p-1", "--tenant", "acme", "--clear"]));
    }

    #[test]
    fn a_set_built_without_one_choice_is_refused_as_agent_gateway_refuses_it() {
        let refusal = |tenant: Option<&str>, clear: bool| {
            OwnershipChange::try_from(TenantOwnershipCommand::Set {
                kind: OwnershipKind::Pipes,
                id: "p-1".to_owned(),
                tenant: tenant.map(str::to_owned),
                clear,
            })
            .err()
            .expect("neither or both is refused before any request")
            .to_string()
        };

        assert_eq!(refusal(None, false), "provide --tenant <tenant-id>, or --clear to remove tenant ownership");
        assert_eq!(refusal(Some("acme"), true), "--tenant and --clear cannot be combined");
    }

    #[tokio::test]
    async fn each_command_reaches_its_tenant_ownership_route() {
        let (host, requests) = scripted_agent_stream(vec![
            (
                "GET /api/v1/tenant-ownership/teams/t-1/impact",
                "HTTP/1.1 200 OK",
                r#"{"kind":"teams","id":"t-1","incoming":[],"outgoing":[]}"#,
            ),
            ("PUT /api/v1/tenant-ownership/pipes/p-1", "HTTP/1.1 200 OK", r#"{"kind":"pipes","id":"p-1"}"#),
        ])
        .await;
        let client = client(host);

        for command in [
            TenantOwnershipCommand::Impact {
                kind: OwnershipKind::Teams,
                id: "t-1".to_owned(),
            },
            TenantOwnershipCommand::Set {
                kind: OwnershipKind::Pipes,
                id: "p-1".to_owned(),
                tenant: Some("acme".to_owned()),
                clear: false,
            },
            TenantOwnershipCommand::Set {
                kind: OwnershipKind::Pipes,
                id: "p-1".to_owned(),
                tenant: None,
                clear: true,
            },
        ] {
            let change = command
                .try_into()
                .expect("a tracked kind");
            run_shared(&client, SharedCommand::TenantOwnership(change), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/tenant-ownership/teams/t-1/impact HTTP/1.1",
                "PUT /api/v1/tenant-ownership/pipes/p-1 HTTP/1.1",
                "PUT /api/v1/tenant-ownership/pipes/p-1 HTTP/1.1",
            ]
        );
        let requests = requests.lock().unwrap();
        assert_eq!(request_body(&requests[1]), r#"{"tenant_id":"acme"}"#);
        assert_eq!(request_body(&requests[2]), r#"{"tenant_id":null}"#);
    }

    #[tokio::test]
    async fn a_blocked_move_points_at_the_agent_stream_impact_report() {
        let (host, _) = scripted_agent_stream(vec![(
            "PUT /api/v1/tenant-ownership/secrets/s-1",
            "HTTP/1.1 409 Conflict",
            r#"{"error":"tenant_ownership_conflict","kind":"secrets","id":"s-1","conflicts":[]}"#,
        )])
        .await;

        let error = run_shared(
            &client(host),
            SharedCommand::TenantOwnership(
                TenantOwnershipCommand::Set {
                    kind: OwnershipKind::Secrets,
                    id: "s-1".to_owned(),
                    tenant: Some("acme".to_owned()),
                    clear: false,
                }
                .try_into()
                .expect("a tracked kind"),
            ),
            Output::Table,
        )
        .await
        .expect_err("Agent Stream blocks the move");

        assert_eq!(
            error.to_string(),
            "run `fabric agent-stream tenant-ownership impact <kind> <id>` to see the references blocking this move"
        );
    }
}
