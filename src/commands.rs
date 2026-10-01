use std::{
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::{
    client::{GatewayClient, id_from_response, response_status},
    config::{Config, Connection, normalize_host, normalize_user_host},
    credentials::{CredentialStore, OsCredentialStore},
    features, surface_patch, surface_validate,
    tool_gate_preview::{self, Conditions, Gating, Preview, ToolPreview, Verdict},
};

/// Prefix that identifies a gateway personal access token, matching
/// `access_tokens::TOKEN_PREFIX` on the gateway.
const PAT_TOKEN_PREFIX: &str = "agpat_";

/// Connection name `login` saves under when --connection is not supplied.
const DEFAULT_CONNECTION: &str = "default";

#[derive(Debug, Parser)]
#[command(name = "fabric", version, about = "Manage Affinidi appliances", args_override_self = true)]
pub struct Cli {
    #[command(subcommand)]
    appliance: Appliance,
}

/// The Affinidi appliance a command is addressed to.
#[derive(Debug, Subcommand)]
enum Appliance {
    /// Manage Affinidi Agent Gateway.
    #[command(name = "agent-gateway")]
    AgentGateway(AgentGatewayArgs),
}

#[derive(Debug, Args)]
struct AgentGatewayArgs {
    /// Named gateway connection. On `login` this names the connection being
    /// saved; on commands that talk to a gateway it selects which saved
    /// connection to use.
    #[arg(short, long, global = true, env = "FABRIC_CONNECTION")]
    connection: Option<String>,

    /// Override the configured gateway host for this command.
    #[arg(long, global = true, env = "FABRIC_HOST")]
    host: Option<String>,

    /// Override the configured bearer token for this command.
    #[arg(long, global = true, env = "FABRIC_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Allow a plain http:// host that is not localhost. The session token is
    /// sent unencrypted, so only use this on a network you trust.
    #[arg(long, global = true)]
    allow_http: bool,

    /// Output format for commands that return data.
    #[arg(short, long, global = true, value_enum, default_value_t = Output::Table)]
    output: Output,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn agent_gateway(&self) -> &AgentGatewayArgs {
        let Appliance::AgentGateway(args) = &self.appliance;
        args
    }

    fn agent_gateway_mut(&mut self) -> &mut AgentGatewayArgs {
        let Appliance::AgentGateway(args) = &mut self.appliance;
        args
    }

    fn into_agent_gateway(self) -> AgentGatewayArgs {
        let Appliance::AgentGateway(args) = self.appliance;
        args
    }

    pub fn is_interactive(&self) -> bool {
        matches!(self.agent_gateway().command, Command::Shell)
    }

    /// Arguments every line typed in the interactive shell is parsed after:
    /// the appliance plus the global flags the shell was started with.
    pub fn interactive_prefix(&self) -> Vec<String> {
        let gateway = self.agent_gateway();
        let mut args = vec!["fabric".to_owned(), "agent-gateway".to_owned()];
        if let Some(connection) = &gateway.connection {
            args.extend(["--connection".to_owned(), connection.clone()]);
        }
        if let Some(host) = &gateway.host {
            args.extend(["--host".to_owned(), host.clone()]);
        }
        if let Some(token) = &gateway.token {
            args.extend(["--token".to_owned(), token.clone()]);
        }
        if gateway.allow_http {
            args.push("--allow-http".to_owned());
        }
        args.extend([
            "--output".to_owned(),
            gateway
                .output
                .as_str()
                .to_owned(),
        ]);
        args
    }

    pub fn login_wants_paste_prompt(&self) -> bool {
        matches!(&self.agent_gateway().command, Command::Login(args) if args.paste && args.token.is_none() && !args.token_stdin)
    }

    pub fn set_login_token(
        &mut self,
        token: String,
    ) {
        if let Command::Login(args) = &mut self
            .agent_gateway_mut()
            .command
        {
            args.token = Some(token);
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Json,
    Table,
}

impl Output {
    fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Table => "table",
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Authenticate and save a named gateway connection.
    ///
    /// Opens a browser to complete the gateway's passkey or SSO login and
    /// captures the token automatically. Use --paste, --token-stdin, or
    /// FABRIC_TOKEN to supply a token manually instead.
    Login(LoginArgs),
    /// Remove locally saved authentication.
    Logout,
    /// Manage local gateway profiles.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect and reload the gateway's own runtime configuration.
    ///
    /// Separate from `fabric agent-gateway config`, which manages local connection profiles
    /// and never contacts a gateway.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// Manage appliance-wide settings.
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    /// Manage the signed-in user's own settings overrides.
    #[command(name = "user-settings")]
    UserSettings {
        #[command(subcommand)]
        command: UserSettingsCommand,
    },
    /// Inspect and publish Terms of Use.
    ///
    /// Accepting terms is deliberately absent. When authenticated with a
    /// personal access token the gateway refuses every route until terms are
    /// accepted, including the acceptance route itself, so acceptance can only
    /// be completed in a browser. A session-token login is exempt on that one
    /// route and can accept with
    /// `fabric agent-gateway api post /v1/terms/acceptances --file <json>`.
    Terms {
        #[command(subcommand)]
        command: TermsCommand,
    },
    /// Manage welcome notifications.
    ///
    /// Reading a user's own notifications is deliberately absent. Those gateway
    /// handlers validate the bearer token against session storage only and
    /// never consult the personal access token authenticator, so when
    /// authenticated with a personal access token a listing would report an
    /// empty set even when notifications exist. A session-token login can reach
    /// them with `fabric agent-gateway api get /v1/notifications`.
    Notifications {
        #[command(subcommand)]
        command: NotificationCommand,
    },
    /// Show the current login session and connected gateway.
    Whoami,
    /// Manage Agent Surfaces.
    Surfaces {
        #[command(subcommand)]
        command: SurfaceCommand,
    },
    /// Manage gateway-to-gateway connections.
    Connections {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage connection points.
    #[command(name = "connection-points")]
    ConnectionPoints {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage policy definitions.
    Policies {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage Issuers.
    Issuers {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage Authorities.
    Authorities {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage Trust Registries.
    #[command(name = "trust-registries")]
    TrustRegistries {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage Mediators.
    Mediators {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage MCP Proxies.
    #[command(name = "mcp-proxies")]
    McpProxies {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage A2A Proxies.
    #[command(name = "a2a-proxies")]
    A2aProxies {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage STS clients.
    #[command(name = "sts-clients")]
    StsClients {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage credential providers.
    #[command(name = "credential-providers")]
    CredentialProviders {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage TLS certificates and their private keys.
    #[command(
        mut_subcommand("get", certificate_reference_help("Get a certificate by its id or name")),
        mut_subcommand("update", certificate_reference_help("Replace a certificate from a JSON document")),
        mut_subcommand("delete", certificate_reference_help("Delete a certificate by its id or name"))
    )]
    Certificates {
        #[command(subcommand)]
        command: CrudCommand,
        /// Print the stored private key instead of masking it.
        #[arg(long, global = true)]
        reveal: bool,
    },
    /// Manage secrets.
    Secrets {
        #[command(subcommand)]
        command: SecretCommand,
        /// Print secret values instead of masking them.
        #[arg(long, global = true)]
        reveal: bool,
    },
    /// Inspect and revoke delegated credential grants.
    #[command(name = "delegation-vault")]
    DelegationVault {
        #[command(subcommand)]
        command: DelegationVaultCommand,
    },
    /// Manage notification integrations.
    Integrations {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage gateway users.
    ///
    /// Users are created by passkey or SAML registration, so there is no
    /// create command.
    Users {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage did:webvh identities.
    Identities {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Manage the API keys an Agent Surface authenticates callers with.
    #[command(name = "api-keys")]
    ApiKeys {
        #[command(subcommand)]
        command: ApiKeyCommand,
    },
    /// Inspect and reassign which tenant owns a resource.
    #[command(name = "tenant-ownership")]
    TenantOwnership {
        #[command(subcommand)]
        command: TenantOwnershipCommand,
    },
    /// Manage JWT verification strategies.
    #[command(name = "jwt-verification-strategies")]
    JwtVerificationStrategies {
        #[command(subcommand)]
        command: JwtStrategyCommand,
    },
    /// Manage personal access tokens for non-interactive gateway access.
    #[command(name = "tokens")]
    AccessTokens {
        #[command(subcommand)]
        command: AccessTokenCommand,
    },
    /// Read the gateway audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Inspect x402 and MPP payment records.
    Payments {
        #[command(subcommand)]
        command: PaymentsCommand,
    },
    /// Scrape metrics and check metrics export health.
    Metrics {
        #[command(subcommand)]
        command: MetricsCommand,
    },
    /// Download and truncate gateway log files.
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    /// Call any authenticated management API endpoint.
    Api(ApiArgs),
    /// Open the interactive shell.
    Shell,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Gateway origin, for example https://gateway.example.com.
    #[arg(long, env = "FABRIC_HOST")]
    host: Option<String>,
    /// Read the bearer token from standard input.
    #[arg(long, conflicts_with = "token")]
    token_stdin: bool,
    /// Paste a bearer token manually instead of using the browser login.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    paste: bool,
    /// Bearer token produced by the existing passkey or SSO login.
    #[arg(long, env = "FABRIC_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Authenticate with a personal access token (agpat_...) instead of the
    /// browser login. Combine with --token-stdin to supply it
    /// non-interactively, or set FABRIC_PAT once --pat is passed.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "",
        conflicts_with_all = ["token", "paste"]
    )]
    pat: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// List configured gateway profiles.
    List,
    /// Select the default gateway profile.
    Use { name: String },
    /// Remove a gateway profile.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Show one of the gateway's read-only runtime configuration views.
    Show {
        #[arg(value_enum)]
        view: RuntimeView,
    },
    /// Reload surface configuration from the configured source.
    ///
    /// Nothing is written. Surfaces changed through this CLI or the dashboard
    /// already reload themselves; this covers configuration edited outside the
    /// gateway, such as a direct `_storage/` edit.
    Reload {
        /// Reload one surface by its configuration id, the id `fabric agent-gateway surfaces
        /// list` shows, instead of all of them. The gateway answers an id no
        /// surface has with a 500, not a 404, so after a server error the CLI
        /// checks the id itself and reports one it cannot find as not found.
        #[arg(long)]
        surface: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RuntimeView {
    /// Surface routes, listen addresses and the OAuth callback route.
    #[value(name = "surface-routing")]
    SurfaceRouting,
    /// x402 payment policy. The gateway answers 500, not 404, when it has no
    /// x402 configuration file.
    X402,
    /// Inbound client-certificate (mTLS) authentication. Read-only: it is
    /// applied at startup and has no counterpart that sets it.
    Networking,
}

impl RuntimeView {
    fn path(self) -> &'static str {
        match self {
            Self::SurfaceRouting => "/v1/config/surface-routing",
            Self::X402 => "/v1/config/x402",
            Self::Networking => "/v1/config/networking",
        }
    }
}

#[derive(Debug, Subcommand)]
enum SettingsCommand {
    /// Show the appliance-wide settings.
    ///
    /// The gateway blanks `prometheus_auth_password_hash` on every response,
    /// and reports `feature_flags.terms` as a live runtime value rather than a
    /// stored flag.
    Show,
    /// Apply a partial update from a JSON document.
    ///
    /// Absent fields are left unchanged, but `feature_flags` replaces the
    /// stored map wholesale. `payments_min_display` is ignored here — it is
    /// settable only per user, with `fabric agent-gateway user-settings set`. A
    /// `prometheus_auth_password` is sent as plaintext and hashed by the
    /// gateway. A document carrying `feature_flags.terms` is refused, because
    /// the gateway reports that flag from its configuration on every read.
    /// Prints the settings as read back after the write.
    Set(JsonFileArgs),
    /// Overwrite the whole document with the built-in defaults and show them.
    ///
    /// This clears settings rather than restoring omitted ones: Prometheus
    /// authentication and audit logging are switched off, `feature_flags` is
    /// emptied, and every window, interval and threshold goes back to its
    /// default. Refused without --force, because the Prometheus password it
    /// erases cannot be restored from a `fabric agent-gateway settings show` backup.
    Reset {
        /// Clear the appliance settings although the pre-flight check refuses
        /// the command.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum UserSettingsCommand {
    /// Show this user's settings.
    ///
    /// Without --overrides this is the effective document — appliance defaults
    /// merged with this user's overrides — so a field that was never set still
    /// looks set. Pass --overrides for the only honest view of what is stored
    /// against the account.
    Show {
        /// Show only this user's stored overrides, without appliance defaults
        /// merged in.
        #[arg(long)]
        overrides: bool,
    },
    /// Apply a partial update from a JSON document.
    ///
    /// Every field present becomes a personal override. Omitting a field, or
    /// sending null, is indistinguishable from leaving it alone, so a single
    /// override cannot be cleared — only `reset` clears, and it clears all of
    /// them. A document carrying fields a per-user update cannot store is
    /// refused, because it came from `show` without --overrides and would
    /// persist appliance defaults as personal overrides. A document carrying
    /// `feature_flags.terms` is refused even with --force, because the gateway
    /// reports that flag from its configuration on every read.
    Set(GuardedJsonFileArgs),
    /// Clear every personal override and show the resulting settings.
    Reset,
}

#[derive(Debug, Subcommand)]
enum TermsCommand {
    /// Show the Terms of Use definitions.
    Show,
    /// Show the terms that apply to this gateway.
    Applicable,
    /// Show whether the signed-in principal has accepted the current terms.
    Status,
    /// Show the health of the upstream terms provider.
    #[command(name = "provider-health")]
    ProviderHealth,
    /// Save the customer Terms of Use draft from a JSON document.
    Draft(JsonFileArgs),
    /// Publish the saved customer Terms of Use draft as a new version.
    Publish,
    /// Deactivate the published customer Terms of Use.
    Deactivate,
}

#[derive(Debug, Subcommand)]
enum NotificationCommand {
    /// Manage the welcome notification sent to new users.
    #[command(name = "welcome-template")]
    WelcomeTemplate {
        #[command(subcommand)]
        command: WelcomeTemplateCommand,
    },
    /// Send a welcome notification to a user.
    ///
    /// The gateway enforces no permission check here and takes the recipient
    /// from the request, so any authenticated caller can post a notification
    /// into any user's feed. It also never checks that the recipient exists,
    /// so the CLI looks the user up first and refuses an unknown id. A caller
    /// without the `users.view` permission cannot look another user up, and is
    /// warned that the recipient went unverified instead.
    #[command(name = "send-welcome")]
    SendWelcome(SendWelcomeArgs),
}

#[derive(Debug, Subcommand)]
enum WelcomeTemplateCommand {
    /// Show the welcome notification template.
    Show,
    /// Replace the welcome notification template from a JSON document with
    /// "title" and "message".
    ///
    /// The gateway enforces no permission check on this route despite the
    /// handler being documented as administrator-only, so any authenticated
    /// caller can replace the template every future user receives.
    Set(JsonFileArgs),
}

#[derive(Debug, Args)]
struct GuardedJsonFileArgs {
    /// JSON request body. Use '-' to read from standard input.
    #[arg(short, long)]
    file: PathBuf,
    /// Submit a document carrying fields a per-user update cannot store. A
    /// document carrying `feature_flags.terms` is still refused.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct SendWelcomeArgs {
    /// Gateway user id of the recipient.
    #[arg(long)]
    user_id: String,
    /// Heading shown in the recipient's notification feed.
    #[arg(long)]
    title: String,
    /// Body of the notification.
    #[arg(long)]
    message: String,
}

#[derive(Debug, Subcommand)]
enum CrudCommand {
    /// List entities.
    List,
    /// Get an entity by ID.
    Get { id: String },
    /// Create an entity from a JSON document.
    Create(JsonFileArgs),
    /// Replace an entity from a JSON document.
    Update {
        id: String,
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete an entity by ID.
    Delete { id: String },
}

#[derive(Debug, Args)]
struct JsonFileArgs {
    /// JSON request body. Use '-' to read from standard input.
    #[arg(short, long)]
    file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum SurfaceCommand {
    /// List Agent Surfaces.
    List,
    /// Get an Agent Surface by ID or name.
    Get {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: String,
    },
    /// Create an Agent Surface using flags or a complete JSON document.
    Create(SurfaceCreateArgs),
    /// Update an Agent Surface, either replacing it whole from a JSON document
    /// with --file or changing single fields and list items with --set,
    /// --unset, --add and --remove.
    ///
    /// All the single-field flags go to the gateway as one merge patch, so
    /// fields they do not name keep their current values. Setting an object
    /// merges it into the existing object, and setting a list replaces the
    /// whole list. The surface is read first, so --add and --remove send its
    /// list with only their items changed (a change someone else makes to
    /// that list between the read and the write is overwritten), and the
    /// edited surface is checked for its required fields before it is sent.
    #[command(group(ArgGroup::new("change").required(true).multiple(true).args(["file", "set", "unset", "add", "remove"])))]
    Update {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: String,
        /// Complete AgentSurface JSON that replaces the stored surface.
        #[arg(short, long, conflicts_with_all = ["set", "unset", "add", "remove"])]
        file: Option<PathBuf>,
        /// Set a field, as a dot path such as
        /// `access_point.rate_limit.requests` and a value read as JSON when
        /// it parses (`100`, `true`, `{"requests":100}`) and as plain text
        /// otherwise. Wrap a value in quotes (`'"1.0"'`) to send it as text.
        /// Repeatable.
        #[arg(long, value_name = "PATH=VALUE")]
        set: Vec<String>,
        /// Remove a field, as a dot path such as `access_point.rate_limit`.
        /// Repeatable.
        #[arg(long, value_name = "PATH")]
        unset: Vec<String>,
        /// Add one item to a list, as the list's dot path and the item, read
        /// the same way as a --set value (`tags=beta`,
        /// `access_point.trust_check_list='{"id":"tc-1",...}'`). An item
        /// already in the list is refused. Repeatable.
        #[arg(long, value_name = "PATH=ITEM")]
        add: Vec<String>,
        /// Remove one item from a list, named by its value for a list of text
        /// (`tags=beta`) and for a list of objects by its `id`, else its
        /// `alias` (`transit.points=billing`), else some of its fields as JSON.
        /// Removes run before adds, so removing an item and adding it back
        /// replaces it. Repeatable.
        #[arg(long, value_name = "PATH=ITEM")]
        remove: Vec<String>,
        /// Check the change with the gateway and show what it would change,
        /// without saving anything. Not available with --file, which
        /// replaces the whole surface.
        #[arg(long, conflicts_with = "file")]
        dry_run: bool,
    },
    /// Delete an Agent Surface by ID or name.
    Delete {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: String,
    },
    /// List the features that can be added to a surface, or with a surface
    /// given, show which of them it has and where each one is set.
    ///
    /// The names shown are the ones `add-feature` and `remove-feature` take.
    /// On or off reflects the surface itself, not what its variants override.
    Features {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: Option<String>,
    },
    /// Add a feature to an Agent Surface.
    ///
    /// Where the feature goes is worked out from its name, so no edge flags
    /// are needed, for example:
    /// `surfaces add-feature $ID tool-gating --json '{...}'`. A feature with one
    /// place uses it, and otherwise the request place is used unless you add
    /// --response. --transit-point picks one transit point, and --edge ma-tp
    /// picks the target leg of trust-check. --edge is otherwise only needed
    /// when the command asks you to choose.
    AddFeature(AddFeatureArgs),
    /// Remove a feature from an Agent Surface.
    ///
    /// Where the feature is found is worked out from its name, the same as
    /// for add-feature.
    RemoveFeature(FeaturePlacementArgs),
    /// Show which tools a set of MCP tool gates would allow or deny, and which
    /// gate decided, before anything is saved.
    ///
    /// The gates come from a surface (the ones it has saved) or from a JSON
    /// file, so gates that are not saved yet can be checked. Only the
    /// surface's own gating (`target.mcp_tool_gating`) is previewed, not the
    /// gating of its variants or transit points. Nothing is changed, and with
    /// --gates-file nothing is read from the gateway either.
    ///
    /// A gate's condition is a policy only the gateway can evaluate for a
    /// caller, so state what you know with --condition, such as
    /// `--condition admins=met`. Every other condition policy is tried both
    /// ways, and a tool whose result or deciding gate depends on it is shown
    /// once per combination. At most 3 can be left unpinned. A condition whose
    /// policy does not exist or is disabled acts as a block gate on and an
    /// allow gate off, and the preview cannot tell, so check the policy
    /// exists. A pattern matches anywhere in a tool name unless it is
    /// anchored, and with alternatives each one needs its own ^, or wrap them
    /// as ^(?:a|b).
    #[command(after_long_help = TOOL_GATE_PREVIEW_EXAMPLES)]
    ToolGatePreview(ToolGatePreviewArgs),
}

/// Examples shown at the bottom of `tool-gate-preview --help`.
const TOOL_GATE_PREVIEW_EXAMPLES: &str = r#"Examples:
  Check the gates a surface has saved, named by its name or ID:
    fabric agent-gateway surfaces tool-gate-preview my-agent --tool delete_user,get_user

  Check gates that are not saved yet, from a file:
    fabric agent-gateway surfaces tool-gate-preview --gates-file gates.json --tool delete_user

  Say what you know about the caller (an admin who is not a contractor):
    fabric agent-gateway surfaces tool-gate-preview my-agent --tool delete_user --condition admins=met --condition contractors=unmet

Reading the result:
  RESULT is ALLOW or DENY. DECIDED BY is the gate that decided, or the default when no gate matched. A tool gets one row per combination of conditions, named in a CONDITION column, only when its answer or deciding gate depends on them. Otherwise each tool gets a single row and the CONDITION column is left out."#;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("gates_source").required(true).args(["surface_id", "gates_file"])))]
struct ToolGatePreviewArgs {
    /// Surface ID or name whose saved MCP tool gates to check (see `fabric
    /// agent-gateway surfaces list`).
    surface_id: Option<String>,
    /// JSON file holding the MCP tool gating itself, as
    /// `{"default_effect": "allow", "gates": [...]}` ('-' for standard
    /// input).
    #[arg(long, value_name = "PATH")]
    gates_file: Option<PathBuf>,
    /// Tool name to check. Repeatable, or comma separated.
    #[arg(long = "tool", value_name = "NAME", value_delimiter = ',', required = true)]
    tools: Vec<String>,
    /// Whether the caller meets a gate's condition policy, as
    /// POLICY_ID=met or POLICY_ID=unmet. A policy no gate uses is refused.
    /// Repeatable.
    #[arg(long = "condition", value_name = "POLICY_ID=met|unmet")]
    conditions: Vec<String>,
}

#[derive(Debug, Args)]
struct SurfaceCreateArgs {
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    #[arg(long, default_value = "")]
    description: String,
    /// Complete AgentSurface JSON. Other creation flags are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen_address: String,
    /// Inbound route. Defaults to a URL-safe form of the name.
    #[arg(long)]
    route: Option<String>,
    #[arg(long, value_enum, default_value_t = Protocol::A2a)]
    protocol: Protocol,
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    target_endpoint: String,
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Protocol {
    A2a,
    Ap2,
    Mcp,
    Didcomm,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::A2a => "a2a",
            Self::Ap2 => "ap2",
            Self::Mcp => "mcp",
            Self::Didcomm => "didcomm",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EdgeOpt {
    ApMa,
    MaExternal,
    MaTp,
}

impl From<EdgeOpt> for features::Edge {
    fn from(edge: EdgeOpt) -> Self {
        match edge {
            EdgeOpt::ApMa => features::Edge::ApMa,
            EdgeOpt::MaExternal => features::Edge::MaExternal,
            EdgeOpt::MaTp => features::Edge::MaTp,
        }
    }
}

/// Where on the surface a feature goes. All optional, since the place is
/// worked out from the feature name.
#[derive(Debug, Args)]
struct PlacementFlags {
    /// Pipeline edge. Only needed when the command asks for it; it is worked
    /// out from the feature otherwise. Use ma-tp for a place with no transit
    /// point alias, such as the target leg of trust-check.
    #[arg(long, value_enum, conflicts_with = "transit_point")]
    edge: Option<EdgeOpt>,
    /// Put the feature on the transit point with this alias instead of on the
    /// whole surface (implies the ma-tp edge).
    #[arg(long)]
    transit_point: Option<String>,
    /// Use the response place instead of the request place, when the feature
    /// has both.
    #[arg(long)]
    response: bool,
}

#[derive(Debug, Args)]
struct AddFeatureArgs {
    /// Surface ID or name (see `fabric agent-gateway surfaces list`).
    surface_id: String,
    /// Feature key or alias (see `fabric agent-gateway surfaces features`).
    feature: String,
    #[command(flatten)]
    placement: PlacementFlags,
    /// Shortcut for policy features: the policy definition id.
    #[arg(long)]
    policy_id: Option<String>,
    /// Feature configuration as inline JSON.
    #[arg(long, conflicts_with = "file")]
    json: Option<String>,
    /// Feature configuration from a JSON file ('-' for standard input).
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Check the change with the gateway and show what it would change,
    /// without saving anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct FeaturePlacementArgs {
    /// Surface ID or name (see `fabric agent-gateway surfaces list`).
    surface_id: String,
    /// Feature key or alias (see `fabric agent-gateway surfaces features`).
    feature: String,
    #[command(flatten)]
    placement: PlacementFlags,
    /// Check the change with the gateway and show what it would change,
    /// without saving anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Subcommand)]
enum AccessTokenCommand {
    /// List personal access tokens.
    List,
    /// Get a personal access token by ID.
    Get { id: String },
    /// Create a personal access token using flags or a complete JSON document.
    Create(AccessTokenCreateArgs),
    /// Revoke a personal access token.
    Revoke(AccessTokenRevokeArgs),
    /// List the scopes you're allowed to grant a new token, based on your own role.
    Scopes,
    /// Replace a personal access token's secret, keeping its ID, name, and scopes.
    Rotate(AccessTokenRotateArgs),
}

#[derive(Debug, Args)]
struct AccessTokenRevokeArgs {
    /// ID of the personal access token to revoke.
    id: String,
    /// Skip the confirmation prompt. Required when running non-interactively.
    #[arg(short, long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct AccessTokenRotateArgs {
    /// ID of the personal access token to rotate.
    id: String,
    /// Skip the confirmation prompt. Required when running non-interactively.
    #[arg(short, long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct AccessTokenCreateArgs {
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    #[arg(long, default_value = "")]
    description: String,
    /// Scope to grant the token. Repeat for multiple scopes.
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// RFC 3339 expiry timestamp, for example 2027-01-01T00:00:00Z. Omit for
    /// a non-expiring token.
    #[arg(long)]
    expires_at: Option<String>,
    /// Resource the token is limited to, as
    /// TENANT:${header}:<resource-kind>:<id-pattern>, where ${header} names
    /// one of the --required-header flags. Omit for an appliance-wide token.
    #[arg(long)]
    resource_pattern: Option<String>,
    /// Header the caller must send, as name=pattern (pattern is a regex the
    /// header value must match). Repeat for multiple required headers.
    #[arg(long = "required-header", value_parser = parse_required_header)]
    required_headers: Vec<(String, String)>,
    /// Complete CreateAccessTokenRequest JSON. Other creation flags are
    /// ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

/// Parses a `--required-header` occurrence of the form `name=pattern` into
/// its two non-empty parts, rejecting malformed input before it ever reaches
/// the gateway.
fn parse_required_header(raw: &str) -> Result<(String, String), String> {
    let (name, pattern) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected name=pattern, got '{raw}'"))?;
    let name = name.trim();
    let pattern = pattern.trim();
    if name.is_empty() || pattern.is_empty() {
        return Err(format!("expected name=pattern with both non-empty, got '{raw}'"));
    }
    Ok((name.to_owned(), pattern.to_owned()))
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    List,
    Get {
        policy_id: String,
    },
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, value_enum, default_value_t = PolicyType::AgentSurface)]
        policy_type: PolicyType,
        #[arg(long)]
        policy_file: PathBuf,
    },
    Update {
        policy_id: String,
        #[arg(short, long)]
        file: PathBuf,
    },
    Delete {
        policy_id: String,
    },
    Versions {
        policy_id: String,
    },
    Impact {
        policy_id: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PolicyType {
    Gateway,
    AgentSurface,
}

#[derive(Debug, Args)]
struct ApiArgs {
    #[arg(value_enum)]
    method: ApiMethod,
    /// API path such as /v1/limits.
    path: String,
    /// Inline JSON request body.
    #[arg(long, conflicts_with = "file")]
    data: Option<String>,
    /// JSON request body file. Use '-' for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApiMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl ApiMethod {
    fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
            Self::Patch => Method::PATCH,
            Self::Delete => Method::DELETE,
        }
    }
}

/// Runs a command that needs no saved connection, token or gateway, before
/// any of those is looked up. Returns `None` for every other command.
fn run_offline(cli: &AgentGatewayArgs) -> Option<Result<()>> {
    let Command::Surfaces {
        command: SurfaceCommand::ToolGatePreview(args),
    } = &cli.command
    else {
        return None;
    };
    let file = args.gates_file.as_ref()?;
    Some(
        read_gates_file(file)
            .and_then(|gating| print_tool_gate_preview(&gating, &args.tools, &args.conditions, cli.output)),
    )
}

/// Runs one command. Both the one-shot CLI and the interactive shell print
/// what this returns, so every command's error passes through
/// `add_terms_hint` here, and only here: the gateway's Terms gate can refuse
/// any route, not only the terms ones.
pub async fn run(cli: Cli) -> Result<()> {
    dispatch(cli)
        .await
        .map_err(add_terms_hint)
}

async fn dispatch(cli: Cli) -> Result<()> {
    let cli = cli.into_agent_gateway();
    if let Some(result) = run_offline(&cli) {
        return result;
    }
    let credentials = OsCredentialStore::new();
    let mut config = Config::load()?;
    config.migrate_legacy_tokens(&credentials)?;
    dispatch_with(cli, config, &credentials).await
}

/// Runs a command that needs the gateway, with the saved `config` and the
/// `credentials` store already in hand, so a test can supply both and never
/// read or write the real ones.
async fn dispatch_with(
    cli: AgentGatewayArgs,
    mut config: Config,
    credentials: &impl CredentialStore,
) -> Result<()> {
    match cli.command {
        Command::Shell => bail!("the interactive shell is already open"),
        Command::Login(mut args) => {
            if args.host.is_none() {
                args.host = cli.host;
            }
            let connection = cli
                .connection
                .as_deref()
                .unwrap_or(DEFAULT_CONNECTION);
            login(&mut config, credentials, connection, args, cli.allow_http).await
        }
        Command::Logout => logout(&mut config, credentials, cli.connection.as_deref()),
        Command::Config { command } => run_config(&mut config, credentials, command, cli.output),
        Command::Whoami => {
            whoami(
                &config,
                credentials,
                cli.connection.as_deref(),
                cli.host.as_deref(),
                cli.allow_http,
                cli.token.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Surfaces {
            command: SurfaceCommand::Features { surface_id: None },
        } => write_features(cli.output, &mut io::stdout()).context("print the features"),
        command => {
            let (connection_name, saved) = config.resolve(cli.connection.as_deref())?;
            let host = cli
                .host
                .as_deref()
                .map(|host| normalize_user_host(host, cli.allow_http))
                .transpose()?
                .unwrap_or_else(|| saved.host.clone());
            let token = match cli.token {
                Some(token) => token,
                None => credentials
                    .get_token(connection_name)?
                    .with_context(|| format!("no token stored for connection '{connection_name}'; run `fabric agent-gateway login --connection {connection_name} --host {host}`"))?,
            };
            let client = GatewayClient::new(host, token)?;
            if let Command::AccessTokens { command } = command {
                return run_access_tokens(&client, command, cli.output).await;
            }
            let command = match command {
                Command::Surfaces { command } => Command::Surfaces {
                    command: resolve_surface_command(&client, command).await?,
                },
                command => command,
            };
            if let Command::Surfaces {
                command:
                    SurfaceCommand::ToolGatePreview(ToolGatePreviewArgs {
                        surface_id: Some(surface_id),
                        tools,
                        conditions,
                        ..
                    }),
            } = &command
            {
                return preview_saved_surface(&client, surface_id, tools, conditions, cli.output).await;
            }
            let created = is_create_command(&command);
            let deleted = delete_confirmation(&command);
            let value = match command {
                Command::Runtime { command } => run_runtime(&client, command).await?,
                Command::Settings { command } => run_settings(&client, command).await?,
                Command::UserSettings { command } => run_user_settings(&client, command).await?,
                Command::Terms { command } => match run_terms(&client, command, cli.output).await? {
                    Some(value) => value,
                    None => return Ok(()),
                },
                Command::Notifications { command } => match run_notifications(&client, command, cli.output).await? {
                    Some(value) => value,
                    None => return Ok(()),
                },
                Command::Surfaces { command } => match run_surfaces(&client, command, cli.output).await? {
                    Some(value) => value,
                    None => return Ok(()),
                },
                Command::Connections { command } => run_crud(&client, "/v1/gateways", command).await?,
                Command::ConnectionPoints { command } => run_crud(&client, "/v1/connection-points", command).await?,
                Command::Policies { command } => run_policies(&client, command).await?,
                Command::Issuers { command } => run_crud(&client, "/v1/issuers", command).await?,
                Command::Authorities { command } => run_crud(&client, "/v1/authorities", command).await?,
                Command::TrustRegistries { command } => run_crud(&client, "/v1/trust-registries", command).await?,
                Command::Mediators { command } => run_crud(&client, "/v1/mediators", command).await?,
                Command::McpProxies { command } => run_crud(&client, "/v1/mcp-proxies", command).await?,
                Command::A2aProxies { command } => run_crud(&client, "/v1/a2a-proxies", command).await?,
                Command::StsClients { command } => run_crud(&client, "/v1/sts/clients", command).await?,
                // These four render their own output — a bespoke audit row, a
                // merged payments table, raw bytes written to a file — so they
                // finish here instead of returning a value to `print_value`.
                Command::Audit { command } => return run_audit(&client, command, cli.output).await,
                Command::Payments { command } => return run_payments(&client, command, cli.output).await,
                Command::Metrics { command } => return run_metrics(&client, command, cli.output).await,
                Command::Logs { command } => return run_logs(&client, command, cli.output).await,
                Command::CredentialProviders { command } => {
                    run_crud(&client, "/v1/credential-providers", command).await?
                }
                Command::Certificates { command, reveal } => {
                    match run_certificates(&client, command, reveal, cli.output).await? {
                        Some(value) => value,
                        None => return Ok(()),
                    }
                }
                Command::Secrets { command, reveal } => {
                    match run_secrets(&client, command, reveal, cli.output).await? {
                        Some(value) => value,
                        None => return Ok(()),
                    }
                }
                Command::DelegationVault { command } => match run_delegation_vault(&client, command, cli.output).await?
                {
                    Some(value) => value,
                    None => return Ok(()),
                },
                Command::Integrations { command } => run_crud(&client, "/v1/integrations", command).await?,
                Command::Users { command } => run_users(&client, command).await?,
                Command::Identities { command } => run_identities(&client, command).await?,
                // API keys print themselves: create and rotate return a
                // one-time secret the shared printer would hide.
                Command::ApiKeys { command } => return run_api_keys(&client, command, cli.output).await,
                Command::TenantOwnership { command } => run_tenant_ownership(&client, command).await?,
                Command::JwtVerificationStrategies { command } => run_jwt_strategies(&client, command).await?,
                Command::Api(args) => run_api(&client, args).await?,
                Command::AccessTokens { .. }
                | Command::Login(_)
                | Command::Logout
                | Command::Config { .. }
                | Command::Whoami
                | Command::Shell => unreachable!(),
            };
            match deleted {
                Some(confirmation) => print_outcome(&value, cli.output, &confirmation),
                None => print_value(&value, cli.output, created),
            }
        }
    }
}

async fn login(
    config: &mut Config,
    credentials: &impl CredentialStore,
    connection: &str,
    args: LoginArgs,
    allow_http: bool,
) -> Result<()> {
    let note =
        login_and_save(config, credentials, connection, args, allow_http, &crate::config::config_path()?).await?;
    println!("Logged in to '{}'", connection.trim());
    if let Some(note) = note {
        eprintln!("{note}");
    }
    Ok(())
}

/// Validate a login and save it as `connection`, trimmed, in the configuration
/// file at `config_path`. A name that is empty once trimmed is refused before
/// the gateway, the credential store or the file is touched, and so is a plain
/// http host that is not local unless `allow_http` is set. Returns a note to
/// show the user when the login replaced a connection that already existed.
async fn login_and_save(
    config: &mut Config,
    credentials: &impl CredentialStore,
    connection: &str,
    args: LoginArgs,
    allow_http: bool,
    config_path: &Path,
) -> Result<Option<String>> {
    let connection = connection.trim();
    if connection.is_empty() {
        bail!("--connection must not be empty or only whitespace");
    }
    let host = normalize_user_host(
        &args
            .host
            .clone()
            .context("--host is required for login")?,
        allow_http,
    )?;
    let token = acquire_login_token(&host, &args).await?;
    let client = GatewayClient::new(&host, &token)?;
    if args.pat.is_some() {
        client
            .check_pat_auth()
            .await
            .context("validate login")?;
    } else {
        client
            .check_auth()
            .await
            .context("validate login")?;
    }
    let previous_token = credentials.get_token(connection)?;
    credentials.set_token(connection, &token)?;
    let previous = config
        .connections
        .insert(connection.to_owned(), Connection::new(host.clone()));
    config.current = Some(connection.to_owned());
    if let Err(error) = config.save_to(config_path) {
        if let Some(previous_token) = previous_token {
            credentials.set_token(connection, &previous_token)?;
        } else {
            credentials.delete_token(connection)?;
        }
        return Err(error);
    }
    Ok(previous.map(|previous| replaced_connection_note(connection, &previous.host, &host)))
}

fn replaced_connection_note(
    connection: &str,
    previous_host: &str,
    host: &str,
) -> String {
    let normalized_previous = normalize_host(previous_host);
    let normalized_previous = normalized_previous
        .as_deref()
        .unwrap_or(previous_host);
    if normalized_previous == host {
        format!("note: replaced the saved login for connection '{connection}'")
    } else {
        format!("note: connection '{connection}' now points at {host} (it pointed at {previous_host})")
    }
}

/// Resolve the bearer token for a login: an explicit token, standard input, a
/// manual paste prompt, a personal access token, or — by default — the
/// browser loopback flow.
async fn acquire_login_token(
    host: &str,
    args: &LoginArgs,
) -> Result<String> {
    if let Some(token) = &args.token {
        return non_empty_token(token.clone());
    }
    if args.pat.is_some() {
        return acquire_pat_token(args).await;
    }
    if args.token_stdin {
        return read_stdin_token();
    }
    if args.paste {
        return prompt_token();
    }
    if !io::stdin().is_terminal() {
        // Piped input without an explicit mode is treated as the token so
        // `printf %s "$TOKEN" | fabric agent-gateway login ...` keeps working in automation.
        return read_stdin_token();
    }
    crate::browser_login::browser_login(host).await
}

/// Resolve a personal access token for `fabric agent-gateway login --pat`: an inline value
/// on the flag itself, the FABRIC_PAT env var, standard input, or an
/// interactive prompt, in that order, once --pat has already selected PAT
/// mode.
async fn acquire_pat_token(args: &LoginArgs) -> Result<String> {
    let token = if let Some(token) = args
        .pat
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        non_empty_token(token.to_owned())?
    } else if let Some(token) = std::env::var("FABRIC_PAT")
        .ok()
        .filter(|token| !token.is_empty())
    {
        non_empty_token(token)?
    } else if args.token_stdin || !io::stdin().is_terminal() {
        read_stdin_token()?
    } else {
        rpassword::prompt_password("Personal access token: ")
            .context("read the personal access token from this terminal")
            .and_then(non_empty_token)?
    };
    if !token.starts_with(PAT_TOKEN_PREFIX) {
        bail!("personal access token must start with '{PAT_TOKEN_PREFIX}'");
    }
    Ok(token)
}

fn read_stdin_token() -> Result<String> {
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .context("read bearer token from standard input")?;
    non_empty_token(value)
}

fn prompt_token() -> Result<String> {
    let token = rpassword::prompt_password("Gateway bearer token: ").map_err(|error| {
        anyhow::anyhow!(
            "could not read the bearer token from this terminal ({error}). Run `fabric agent-gateway \
             shell` for the interactive shell, pipe the token with --token-stdin, or set FABRIC_TOKEN."
        )
    })?;
    non_empty_token(token)
}

fn non_empty_token(token: String) -> Result<String> {
    let token = token.trim().to_owned();
    if token.is_empty() {
        bail!("bearer token must not be empty");
    }
    Ok(token)
}

/// Report the active connection, its host, and the identity behind the stored
/// session token (validated live against the gateway).
async fn whoami(
    config: &Config,
    credentials: &impl CredentialStore,
    connection: Option<&str>,
    host_override: Option<&str>,
    allow_http: bool,
    token_override: Option<&str>,
    output: Output,
) -> Result<()> {
    let info = whoami_info(config, credentials, connection, host_override, allow_http, token_override).await?;
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&info)?),
        Output::Table => print_info_table(&info),
    }
    Ok(())
}

/// Resolve the active connection, its host, and the identity behind the
/// stored token (validated live against the gateway), as a JSON object.
async fn whoami_info(
    config: &Config,
    credentials: &impl CredentialStore,
    connection: Option<&str>,
    host_override: Option<&str>,
    allow_http: bool,
    token_override: Option<&str>,
) -> Result<Value> {
    let (name, saved_host) = {
        let (name, saved) = config.resolve(connection)?;
        (name.to_owned(), saved.host.clone())
    };
    let host = match host_override {
        Some(host) => normalize_user_host(host, allow_http)?,
        None => saved_host,
    };
    let token = match token_override {
        Some(token) => Some(token.to_owned()),
        None => credentials.get_token(&name)?,
    };

    let mut info = json!({
        "connection": name,
        "host": host,
        "token_stored": token.is_some(),
        "authenticated": false,
    });
    let fields = info
        .as_object_mut()
        .expect("whoami info is a JSON object");

    if let Some(token) = token {
        let client = GatewayClient::new(&host, &token)?;
        if token.starts_with(PAT_TOKEN_PREFIX) {
            // `/auth/check` only consults the browser/session store, so a
            // PAT bearer token always reports `authenticated: false` there
            // even when valid; validate it the same way `login --pat` does.
            match client.check_pat_auth().await {
                Ok(()) => {
                    fields.insert("authenticated".to_owned(), json!(true));
                    if let Ok(profile) = client
                        .request(Method::GET, "/v1/profile", None)
                        .await
                    {
                        for key in ["username", "role", "email", "user_id", "first_name", "last_name"] {
                            if let Some(value) = profile
                                .get(key)
                                .filter(|value| !value.is_null())
                            {
                                fields.insert(key.to_owned(), value.clone());
                            }
                        }
                    }
                    insert_token_scopes(fields, &client).await;
                }
                Err(error) => {
                    fields.insert("error".to_owned(), json!(error.to_string()));
                }
            }
        } else {
            match client
                .request(Method::GET, "/auth/check", None)
                .await
            {
                Ok(check) => {
                    let authenticated = check
                        .get("authenticated")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    fields.insert("authenticated".to_owned(), json!(authenticated));
                    if authenticated
                        && let Ok(profile) = client
                            .request(Method::GET, "/v1/profile", None)
                            .await
                    {
                        for key in ["username", "role", "email", "user_id", "first_name", "last_name"] {
                            if let Some(value) = profile
                                .get(key)
                                .filter(|value| !value.is_null())
                            {
                                fields.insert(key.to_owned(), value.clone());
                            }
                        }
                    }
                    if !fields.contains_key("username")
                        && let Some(username) = check
                            .get("username")
                            .filter(|value| !value.is_null())
                    {
                        fields.insert("username".to_owned(), username.clone());
                    }
                    if authenticated {
                        insert_token_scopes(fields, &client).await;
                    }
                }
                Err(error) => {
                    fields.insert("error".to_owned(), json!(error.to_string()));
                }
            }
        }
    }

    Ok(info)
}

/// Add the held token's own `scopes` to `fields` by calling `/v1/token-info`.
/// A session/passkey login reports `null` scopes there (it holds its full
/// role), so nothing is inserted; a personal access token's own granted
/// scopes are copied in as-is. If the call fails, a warning goes to stderr
/// and `fields` is left unchanged so `whoami` still reports the rest.
async fn insert_token_scopes(
    fields: &mut serde_json::Map<String, Value>,
    client: &GatewayClient,
) {
    match client
        .request(Method::GET, "/v1/token-info", None)
        .await
    {
        Ok(token_info) => {
            if let Some(scopes) = token_info
                .get("scopes")
                .filter(|value| !value.is_null())
            {
                fields.insert("scopes".to_owned(), scopes.clone());
            }
        }
        Err(error) => {
            eprintln!("warning: could not load token scopes: {error:#}");
        }
    }
}

fn print_info_table(value: &Value) {
    const ORDER: &[&str] = &[
        "connection",
        "host",
        "token_stored",
        "authenticated",
        "username",
        "role",
        "email",
        "user_id",
        "first_name",
        "last_name",
        "scopes",
        "error",
    ];
    let Some(object) = value.as_object() else {
        println!("{value}");
        return;
    };
    for key in ORDER {
        if let Some(field) = object.get(*key) {
            let rendered = match field {
                Value::String(text) => text.clone(),
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            println!("{key}: {rendered}");
        }
    }
}

fn logout(
    config: &mut Config,
    credentials: &impl CredentialStore,
    requested: Option<&str>,
) -> Result<()> {
    let name = requested
        .or(config.current.as_deref())
        .context("no gateway connection selected")?
        .to_owned();
    credentials.delete_token(&name)?;
    if config
        .connections
        .remove(&name)
        .is_none()
    {
        bail!("gateway connection '{name}' does not exist");
    }
    if config.current.as_deref() == Some(&name) {
        config.current = config
            .connections
            .keys()
            .next()
            .cloned();
    }
    config.save()?;
    println!("Removed local credentials for '{name}'");
    Ok(())
}

fn run_config(
    config: &mut Config,
    credentials: &impl CredentialStore,
    command: ConfigCommand,
    output: Output,
) -> Result<()> {
    match command {
        ConfigCommand::List => {
            let rows: Vec<Value> = config.connections.iter().map(|(name, connection)| json!({"name": name, "host": connection.host, "current": config.current.as_deref() == Some(name)})).collect();
            print_value(&Value::Array(rows), output, false)
        }
        ConfigCommand::Use { name } => {
            if !config
                .connections
                .contains_key(&name)
            {
                bail!("gateway connection '{name}' does not exist");
            }
            config.current = Some(name.clone());
            config.save()?;
            println!("Using '{name}'");
            Ok(())
        }
        ConfigCommand::Remove { name } => logout(config, credentials, Some(&name)),
    }
}

/// Reports the outcome of a request whose `204 No Content` body parses to null.
/// In table mode the confirmation replaces the response, so the caller skips
/// printing and `null` never reaches standard output; in JSON mode the empty
/// document is returned so output matches every other command. A response that
/// does carry a body is passed through untouched in both modes.
fn confirm_empty(
    value: Value,
    message: &str,
    output: Output,
) -> Option<Value> {
    if value.is_null() && matches!(output, Output::Table) {
        println!("{message}");
        return None;
    }
    Some(value)
}

async fn run_runtime(
    client: &GatewayClient,
    command: RuntimeCommand,
) -> Result<Value> {
    match command {
        RuntimeCommand::Show { view } => {
            client
                .request(Method::GET, view.path(), None)
                .await
        }
        RuntimeCommand::Reload { surface: None } => {
            client
                .request(Method::POST, "/v1/config/reload", None)
                .await
        }
        RuntimeCommand::Reload { surface: Some(surface) } => {
            match client
                .request(Method::POST, &entity_path("/v1/config/reload", &surface), None)
                .await
            {
                Ok(value) => Ok(value),
                Err(error) => Err(explain_failed_reload(client, &surface, error).await),
            }
        }
    }
}

/// Names an unknown surface id. The gateway answers a reload of an id nothing
/// is stored under with a 500, not a 404, so after a server error the id is
/// read straight from the surfaces API (`GET /v1/surfaces/<id>`), without the
/// name lookup `surfaces get` does, since a reload takes only an id. A 404
/// there is reported above the gateway's error, which stays as the cause: with
/// the DynamoDB configuration source the reload reads DynamoDB while the read
/// uses the gateway's own surface store, so the two can disagree. Any other
/// failure, or a read that does not answer 404, keeps the gateway's error
/// alone: a 403 in particular can come from a resource-scoped token that the
/// surfaces route also answers with 404.
async fn explain_failed_reload(
    client: &GatewayClient,
    surface: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    if !response_status(&error).is_some_and(|status| status.is_server_error()) {
        return error;
    }
    match client
        .request(Method::GET, &entity_path("/v1/surfaces", surface), None)
        .await
    {
        Err(lookup) if response_status(&lookup) == Some(StatusCode::NOT_FOUND) => error.context(format!(
            "Agent Surface '{surface}' not found: the surfaces API has no surface with that id, and `fabric agent-gateway surfaces list` shows every surface id. The reload failed with"
        )),
        _ => error,
    }
}

async fn run_settings(
    client: &GatewayClient,
    command: SettingsCommand,
) -> Result<Value> {
    match command {
        SettingsCommand::Show => {
            client
                .request(Method::GET, "/v1/settings", None)
                .await
        }
        SettingsCommand::Set(args) => {
            let body = read_json(&args.file)?;
            reject_runtime_terms_flag(&body, "settings show")?;
            warn_each(settings_write_warnings(&body));
            client
                .request(Method::POST, "/v1/settings", Some(body))
                .await?;
            read_back_settings(client, "saved").await
        }
        SettingsCommand::Reset { force } => {
            if !force {
                reject_settings_reset()?;
            }
            client
                .request(Method::DELETE, "/v1/settings", None)
                .await?;
            read_back_settings(client, "reset to the built-in defaults").await
        }
    }
}

/// Reads the appliance settings back after a write. The write routes answer
/// with the stored document, which lacks the `feature_flags.terms` every read
/// adds from the gateway's `network.terms` configuration, so printing that
/// answer would disagree with the next `settings show`.
async fn read_back_settings(
    client: &GatewayClient,
    done: &str,
) -> Result<Value> {
    client
        .request(Method::GET, "/v1/settings", None)
        .await
        .with_context(|| format!("the appliance settings were {done}, but reading them back failed"))
}

/// Refuses an unforced `settings reset`. The route writes the built-in defaults
/// over the whole document rather than restoring the fields nobody set, so it
/// silently switches off two security controls, and the Prometheus password it
/// erases cannot be put back from a `settings show` backup: the hash is blanked
/// on every read, and re-enabling authentication without a plaintext password
/// is rejected.
fn reject_settings_reset() -> Result<()> {
    bail!(
        "`settings reset` overwrites the whole appliance settings document with the built-in defaults. It clears: 'prometheus_auth_enabled', so /v1/metrics/prometheus stops checking credentials; 'prometheus_auth_username' and the stored password hash; 'audit_enabled' and 'audit_categories', so audit logging stops; every entry in 'feature_flags'; and every window, interval and threshold. A `fabric agent-gateway settings show` backup does not undo it — the password hash is blanked on read, and re-enabling Prometheus authentication without a plaintext 'prometheus_auth_password' is refused with 400. Keep that password elsewhere, or re-run with --force"
    )
}

/// Names the parts of an appliance settings document the gateway will not store
/// as sent, so a document round-tripped through `settings show` does not look
/// like it applied more than it did.
fn settings_write_warnings(body: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    if carries_value(body, "/payments_min_display") {
        warnings.push(
            "'payments_min_display' is not part of an appliance settings update and is ignored; set it per user with `fabric agent-gateway user-settings set`".to_owned(),
        );
    }
    if carries_value(body, "/prometheus_auth_password_hash") {
        warnings.push(
            "'prometheus_auth_password_hash' is blanked on every read and is ignored on write; send 'prometheus_auth_password' to change the password".to_owned(),
        );
    }
    if carries_value(body, "/feature_flags") {
        warnings
            .push("'feature_flags' replaces the stored map; any flag missing from this document is removed".to_owned());
    }
    warnings
}

/// Refuses a document carrying `feature_flags.terms`. Every read overwrites
/// that flag with the gateway's `network.terms` configuration, so a stored
/// value can never take effect. Any value is refused, `null` included: unlike
/// the top-level fields, a flag is a plain boolean, so the gateway answers a
/// null one with 422 rather than ignoring it. `user-settings set --force` does
/// not bypass this: `--force` overrides a judgement about what a write would
/// persist, and this write persists nothing that is ever read.
fn reject_runtime_terms_flag(
    body: &Value,
    show: &str,
) -> Result<()> {
    if body
        .pointer("/feature_flags/terms")
        .is_none()
    {
        return Ok(());
    }
    bail!(
        "'feature_flags.terms' cannot be written: the gateway reports it from its `network.terms` configuration on every read and ignores a stored value, so this write could never take effect. Delete \"terms\" from \"feature_flags\" (a `fabric agent-gateway {show}` document always carries it) and re-run. Terms of Use are switched on or off in the gateway's `network.terms` configuration, not here"
    )
}

/// Whether `body` carries a value at `pointer` the gateway will act on. Every
/// settings field deserialises into an `Option`, so an explicit `null` is
/// indistinguishable from an absent field and leaves the stored value alone.
/// Warning about one would describe a write that does not happen.
fn carries_value(
    body: &Value,
    pointer: &str,
) -> bool {
    body.pointer(pointer)
        .is_some_and(|value| !value.is_null())
}

async fn run_user_settings(
    client: &GatewayClient,
    command: UserSettingsCommand,
) -> Result<Value> {
    let response = match command {
        UserSettingsCommand::Show { overrides: false } => {
            client
                .request(Method::GET, "/v1/user-settings", None)
                .await
        }
        UserSettingsCommand::Show { overrides: true } => {
            client
                .request(Method::GET, "/v1/user-settings/overrides", None)
                .await
        }
        UserSettingsCommand::Set(args) => {
            let body = read_json(&args.file)?;
            // First, because a merged `show` document carries the flag and the
            // merged-document refusal points at --force, which cannot help here.
            reject_runtime_terms_flag(&body, "user-settings show")?;
            if !args.force {
                reject_unknown_user_settings(&body)?;
            }
            warn_each(user_settings_write_warnings(&body));
            client
                .request(Method::POST, "/v1/user-settings", Some(body))
                .await
        }
        UserSettingsCommand::Reset => {
            client
                .request(Method::DELETE, "/v1/user-settings", None)
                .await
        }
    };
    response.map(without_password_hash)
}

/// The appliance settings route blanks the bcrypt Prometheus password hash
/// before answering, but every per-user response merges it in from the
/// appliance document unblanked. Drop it rather than print a password hash to a
/// terminal or a CI log.
fn without_password_hash(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("prometheus_auth_password_hash");
    }
    value
}

/// Refuses a per-user update carrying fields the route cannot store. Such a
/// document came from `user-settings show` without `--overrides`, which merges
/// in appliance defaults, so sending it persists each of those defaults as a
/// personal override that only `reset` can clear.
fn reject_unknown_user_settings(body: &Value) -> Result<()> {
    let unknown = unknown_user_settings_fields(body);
    if unknown.is_empty() {
        return Ok(());
    }
    bail!(
        "this document carries {} field(s) a per-user update cannot store: {}. It came from `fabric agent-gateway user-settings show` without --overrides, which merges in appliance defaults, so sending it would persist those defaults as personal overrides. Start from `fabric agent-gateway user-settings show --overrides`, or re-run with --force",
        unknown.len(),
        unknown.join(", ")
    )
}

fn unknown_user_settings_fields(body: &Value) -> Vec<&str> {
    body.as_object()
        .map(|object| {
            object
                .keys()
                .map(String::as_str)
                .filter(|key| !USER_SETTINGS_FIELDS.contains(key))
                .collect()
        })
        .unwrap_or_default()
}

/// Every field a per-user settings update stores. Anything else in a request
/// body means the document came from `user-settings show` without
/// `--overrides`, which merges appliance defaults into the response.
const USER_SETTINGS_FIELDS: &[&str] = &[
    "refresh_interval_seconds",
    "log_timestamp_format",
    "bucket_seconds",
    "badge_threshold_minutes",
    "payments_min_display",
    "feature_flags",
];

fn user_settings_write_warnings(body: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    if !body.is_object() {
        return warnings;
    }
    let ignored = unknown_user_settings_fields(body);
    if !ignored.is_empty() {
        warnings.push(format!(
            "ignored by the gateway: {}. A document carrying these came from `user-settings show` without --overrides, which merges in appliance defaults — every remaining field becomes a personal override",
            ignored.join(", ")
        ));
    }
    if carries_value(body, "/feature_flags") {
        warnings.push(
            "'feature_flags' replaces this user's stored flags; any flag missing from this document is removed"
                .to_owned(),
        );
    }
    warnings
}

fn warn_each(warnings: Vec<String>) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

async fn run_terms(
    client: &GatewayClient,
    command: TermsCommand,
    output: Output,
) -> Result<Option<Value>> {
    match command {
        TermsCommand::Show => client
            .request(Method::GET, "/v1/terms", None)
            .await
            .map(Some),
        TermsCommand::Applicable => client
            .request(Method::GET, "/v1/terms/applicable", None)
            .await
            .map(Some),
        TermsCommand::Status => client
            .request(Method::GET, "/v1/terms/status", None)
            .await
            .map(Some),
        TermsCommand::ProviderHealth => client
            .request(Method::GET, "/v1/terms/provider-health", None)
            .await
            .map(Some),
        TermsCommand::Draft(args) => client
            .request(Method::PUT, "/v1/terms/customer/draft", Some(read_json(&args.file)?))
            .await
            .map(Some),
        TermsCommand::Publish => client
            .request(Method::POST, "/v1/terms/customer/publish", None)
            .await
            .map(Some),
        TermsCommand::Deactivate => client
            .request(Method::POST, "/v1/terms/customer/deactivate", None)
            .await
            .map(|value| confirm_empty(value, "Customer Terms of Use deactivated.", output)),
    }
}

/// Terms failures carry a machine `code` and no message, so the raw body
/// reaches the user unexplained. Say what each code means. The whole chain is
/// searched, because a command may have added context above the gateway's
/// answer.
fn add_terms_hint(error: anyhow::Error) -> anyhow::Error {
    let text = format!("{error:#}");
    let hint = if text.contains("TERMS_ACCEPTANCE_REQUIRED") {
        "this user has not accepted the gateway's Terms and Conditions yet, so the gateway refuses every call except the Terms of Use status routes: accept them in the Agent Gateway dashboard, or with `fabric agent-gateway api post /v1/terms/acceptances --file <json>` (see `fabric agent-gateway terms --help`), then retry; `fabric agent-gateway terms status` lists what is required"
    } else if text.contains("TERMS_DISABLED") {
        "this 404 means the Terms of Use feature is switched off on this gateway, not that the route is missing"
    } else if text.contains("TERMS_VERSION_STALE") {
        "the published terms changed while this request was in flight; re-read `fabric agent-gateway terms show` and retry"
    } else if text.contains("TERMS_DRAFT_REQUIRED") {
        "there is no saved draft to publish; save one with `fabric agent-gateway terms draft --file <json>` first"
    } else if text.contains("TERMS_OPERATIONAL_FAILURE") {
        "the upstream terms provider is unavailable; check `fabric agent-gateway terms provider-health`"
    } else {
        return error;
    };
    error.context(hint)
}

async fn run_notifications(
    client: &GatewayClient,
    command: NotificationCommand,
    output: Output,
) -> Result<Option<Value>> {
    match command {
        NotificationCommand::WelcomeTemplate {
            command: WelcomeTemplateCommand::Show,
        } => client
            .request(Method::GET, "/v1/notifications/user-welcome-template", None)
            .await
            .map(Some),
        NotificationCommand::WelcomeTemplate {
            command: WelcomeTemplateCommand::Set(args),
        } => client
            .request(Method::PUT, "/v1/notifications/user-welcome-template", Some(read_json(&args.file)?))
            .await
            .map(|value| confirm_empty(value, "Welcome notification template updated.", output)),
        NotificationCommand::SendWelcome(args) => {
            warn_each(unverified_recipient_warning(client, &args.user_id).await?);
            let body = json!({"user_id": args.user_id, "title": args.title, "message": args.message});
            client
                .request(Method::POST, "/v1/notifications/send-welcome", Some(body))
                .await
                .map(|value| confirm_empty(value, "Welcome notification sent.", output))
        }
    }
}

/// Looks the recipient up before sending. The gateway files a welcome
/// notification under any `user_id` without checking that the user exists, so
/// a mistyped id succeeds and the notification reaches nobody. Reading another
/// user needs `users.view`, which sending does not, so a lookup refused with
/// 403 yields a warning to print instead of an error; any other failed lookup
/// stops the send.
async fn unverified_recipient_warning(
    client: &GatewayClient,
    user_id: &str,
) -> Result<Vec<String>> {
    let Err(error) = client
        .request(Method::GET, &entity_path("/v1/users", user_id), None)
        .await
    else {
        return Ok(Vec::new());
    };
    match response_status(&error) {
        Some(StatusCode::NOT_FOUND) => bail!(
            "user '{user_id}' not found: no gateway user has that id, so the notification would reach nobody. Nothing was sent; `fabric agent-gateway api get /v1/users` lists user ids"
        ),
        // The Terms gate refuses the send as well, so warning and sending
        // would only add a misleading permission warning to the same refusal.
        Some(StatusCode::FORBIDDEN)
            if error
                .to_string()
                .contains("TERMS_ACCEPTANCE_REQUIRED") =>
        {
            Err(error)
        }
        Some(StatusCode::FORBIDDEN) => Ok(vec![format!(
            "could not verify that user '{user_id}' exists ({error}); reading another user needs the 'users.view' permission, which sending does not. Sending anyway: if the id is wrong, the notification reaches nobody"
        )]),
        _ => Err(error.context(format!("could not look up user '{user_id}' before sending; nothing was sent"))),
    }
}

/// Serialises tests that read or change process-wide environment variables:
/// the Prometheus credentials clap reads at parse time, and the home and
/// config directories the saved connections are found through.
#[cfg(test)]
static PROCESS_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod gateway_config_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Starts a one-shot HTTP server that replies with the given status line
    /// and body to the first request it receives. Returns its base URL and a
    /// receiver carrying that request's start line, so a test can assert the
    /// method and path actually put on the wire. Adapted from the `tests`
    /// module, which is a private sibling.
    async fn one_shot_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let request_line = String::from_utf8_lossy(&buf[..read])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let _ = sender.send(request_line);
                let response =
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), receiver)
    }

    /// Awaits the request start line the one-shot server captured.
    async fn request_line(receiver: tokio::sync::oneshot::Receiver<String>) -> String {
        let captured = receiver.await;
        captured.expect("the server should have received a request")
    }

    /// Answer to a request beyond a scripted server's script: a status no
    /// command treats specially, so the command fails on it rather than taking
    /// a branch the test did not set up.
    const UNSCRIPTED: (&str, &str) = ("HTTP/1.1 418 I'm a teapot", "unscripted request");

    /// Starts a server that answers successive requests with `responses`, one
    /// `(status line, body)` per connection. Returns its base URL and a
    /// receiver carrying each whole request. A request beyond the script
    /// is recorded too, and answered with [`UNSCRIPTED`], so a test asserting
    /// the recorded sequence catches any request it did not expect.
    async fn scripted_server(
        responses: Vec<(&'static str, &'static str)>
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut script = responses.into_iter();
            while let Ok((mut socket, _)) = listener.accept().await {
                let (status_line, body) = script
                    .next()
                    .unwrap_or(UNSCRIPTED);
                let _ = sender.send(read_request(&mut socket).await);
                let response =
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), receiver)
    }

    /// Reads one whole request, headers and body, so closing the connection
    /// never discards bytes the client is still sending.
    async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let read = socket
                .read(&mut buf)
                .await
                .unwrap_or(0);
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            let text = String::from_utf8_lossy(&request);
            if let Some(end) = text.find("\r\n\r\n") {
                let content_length = text[..end]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| {
                                value
                                    .trim()
                                    .parse::<usize>()
                                    .unwrap_or(0)
                            })
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + content_length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    /// Every whole request the scripted server has received. Complete once the
    /// command has returned: the server records each request before it
    /// answers, and the client waits for each answer.
    fn full_requests(mut receiver: tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
        let mut requests = Vec::new();
        while let Ok(request) = receiver.try_recv() {
            requests.push(request);
        }
        requests
    }

    fn start_lines(requests: &[String]) -> Vec<String> {
        requests
            .iter()
            .map(|request| {
                request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    fn request_lines(receiver: tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
        start_lines(&full_requests(receiver))
    }

    /// Asserts the one-shot server never saw a request, which is what makes a
    /// guard a pre-flight one. Without this a guard moved below
    /// `client.request` would still return an error and still satisfy an
    /// `expect_err`, with the write already persisted. The server sends the
    /// start line before it writes the response and the client cannot return
    /// before it reads that response, so an empty channel once the command has
    /// returned means nothing was put on the wire. Not awaited: the server task
    /// parks on `accept` forever when no request arrives.
    fn assert_no_request(
        mut receiver: tokio::sync::oneshot::Receiver<String>,
        guard: &str,
    ) {
        match receiver.try_recv() {
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            Ok(line) => panic!("{guard} let a request reach the gateway: {line}"),
            Err(error) => panic!("{guard}: unexpected one-shot server state: {error}"),
        }
    }

    /// Writes `contents` to a temporary JSON file kept alive by the returned
    /// handle.
    fn json_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), contents).expect("write JSON file");
        file
    }

    fn command_of(args: &[&str]) -> Command {
        Cli::try_parse_from(args)
            .expect("arguments should parse")
            .into_agent_gateway()
            .command
    }

    #[test]
    fn runtime_show_selects_the_matching_config_view() {
        for (argument, path) in [
            ("surface-routing", "/v1/config/surface-routing"),
            ("x402", "/v1/config/x402"),
            ("networking", "/v1/config/networking"),
        ] {
            let Command::Runtime {
                command: RuntimeCommand::Show { view },
            } = command_of(&["fabric", "agent-gateway", "runtime", "show", argument])
            else {
                panic!("expected `runtime show {argument}`");
            };
            assert_eq!(view.path(), path);
        }
    }

    #[test]
    fn runtime_show_rejects_a_view_the_gateway_does_not_serve() {
        Cli::try_parse_from(["fabric", "agent-gateway", "runtime", "show", "settings"])
            .expect_err("only the three gateway config views should be accepted");
    }

    #[test]
    fn runtime_reload_targets_one_surface_or_all_of_them() {
        let Command::Runtime {
            command: RuntimeCommand::Reload { surface },
        } = command_of(&["fabric", "agent-gateway", "runtime", "reload"])
        else {
            panic!("expected `runtime reload`");
        };
        assert_eq!(surface, None);

        let Command::Runtime {
            command: RuntimeCommand::Reload { surface },
        } = command_of(&["fabric", "agent-gateway", "runtime", "reload", "--surface", "surface-1"])
        else {
            panic!("expected `runtime reload --surface`");
        };
        assert_eq!(surface.as_deref(), Some("surface-1"));
    }

    #[test]
    fn local_profile_commands_stay_under_config() {
        assert!(
            matches!(
                command_of(&["fabric", "agent-gateway", "config", "list"]),
                Command::Config { command: ConfigCommand::List }
            ),
            "`fabric agent-gateway config list` must remain the local profile listing"
        );
    }

    #[test]
    fn settings_and_user_settings_are_singletons_without_ids() {
        assert!(matches!(
            command_of(&["fabric", "agent-gateway", "settings", "show"]),
            Command::Settings { command: SettingsCommand::Show }
        ));
        assert!(matches!(
            command_of(&["fabric", "agent-gateway", "settings", "reset"]),
            Command::Settings {
                command: SettingsCommand::Reset { force: false }
            }
        ));
        assert!(matches!(
            command_of(&["fabric", "agent-gateway", "settings", "reset", "--force"]),
            Command::Settings {
                command: SettingsCommand::Reset { force: true }
            }
        ));
        Cli::try_parse_from(["fabric", "agent-gateway", "settings", "show", "some-id"])
            .expect_err("settings take no id");
        Cli::try_parse_from(["fabric", "agent-gateway", "settings", "set"])
            .expect_err("`settings set` requires --file");
    }

    #[test]
    fn user_settings_show_exposes_the_overrides_only_view() {
        let Command::UserSettings {
            command: UserSettingsCommand::Show { overrides },
        } = command_of(&["fabric", "agent-gateway", "user-settings", "show"])
        else {
            panic!("expected `user-settings show`");
        };
        assert!(!overrides);

        let Command::UserSettings {
            command: UserSettingsCommand::Show { overrides },
        } = command_of(&["fabric", "agent-gateway", "user-settings", "show", "--overrides"])
        else {
            panic!("expected `user-settings show --overrides`");
        };
        assert!(overrides);
    }

    #[test]
    fn terms_offers_the_lifecycle_verbs_but_never_accept() {
        for verb in ["show", "applicable", "status", "provider-health", "publish", "deactivate"] {
            Cli::try_parse_from(["fabric", "agent-gateway", "terms", verb])
                .unwrap_or_else(|_| panic!("`terms {verb}` should parse"));
        }
        Cli::try_parse_from(["fabric", "agent-gateway", "terms", "draft", "--file", "draft.json"])
            .expect("`terms draft` should parse");
        // A personal access token is refused every route until terms are
        // accepted, including this one, so acceptance is browser-only. A
        // session token is exempt on that route and can use `fabric agent-gateway api`.
        Cli::try_parse_from(["fabric", "agent-gateway", "terms", "accept"])
            .expect_err("`terms accept` could only ever fail for a PAT");
    }

    #[test]
    fn notifications_expose_only_the_verbs_a_personal_access_token_can_use() {
        Cli::try_parse_from(["fabric", "agent-gateway", "notifications", "welcome-template", "show"])
            .expect("`welcome-template show` should parse");
        Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "notifications",
            "welcome-template",
            "set",
            "--file",
            "t.json",
        ])
        .expect("`welcome-template set` should parse");

        // The user-scoped handlers validate against session storage only, so
        // with a personal access token these would report an empty set or 401.
        // A session token reaches them through `fabric agent-gateway api`.
        for verb in ["list", "get", "create", "update", "delete", "unread-count"] {
            assert!(
                Cli::try_parse_from(["fabric", "agent-gateway", "notifications", verb]).is_err(),
                "`notifications {verb}` must not be offered"
            );
        }
    }

    #[test]
    fn send_welcome_requires_a_recipient_a_title_and_a_message() {
        let Command::Notifications {
            command: NotificationCommand::SendWelcome(args),
        } = command_of(&[
            "fabric",
            "agent-gateway",
            "notifications",
            "send-welcome",
            "--user-id",
            "user-1",
            "--title",
            "Welcome",
            "--message",
            "Hello",
        ])
        else {
            panic!("expected `notifications send-welcome`");
        };
        assert_eq!(args.user_id, "user-1");
        assert_eq!(args.title, "Welcome");
        assert_eq!(args.message, "Hello");

        Cli::try_parse_from(["fabric", "agent-gateway", "notifications", "send-welcome", "--user-id", "user-1"])
            .expect_err("send-welcome without --title and --message should be rejected");
    }

    #[test]
    fn settings_warnings_name_every_field_the_gateway_drops_or_replaces() {
        let warnings = settings_write_warnings(&json!({
            "payments_min_display": 10,
            "prometheus_auth_password_hash": "",
            "feature_flags": {"ap2_experimental": false}
        }));
        assert_eq!(warnings.len(), 3);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("payments_min_display"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("prometheus_auth_password_hash"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("replaces the stored map"))
        );

        assert!(settings_write_warnings(&json!({"refresh_interval_seconds": 30})).is_empty());

        // An explicit null deserialises to None on every settings field, so the
        // gateway leaves the stored value alone and there is nothing to warn
        // about.
        assert!(
            settings_write_warnings(&json!({
                "feature_flags": null,
                "payments_min_display": null,
                "prometheus_auth_password_hash": null
            }))
            .is_empty()
        );
    }

    #[test]
    fn user_settings_warnings_detect_a_merged_document() {
        let warnings = user_settings_write_warnings(&json!({
            "refresh_interval_seconds": 30,
            "metrics_retention_minutes": 60,
            "audit_enabled": true
        }));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("metrics_retention_minutes"));
        assert!(warnings[0].contains("audit_enabled"));
        assert!(!warnings[0].contains("refresh_interval_seconds"));

        assert!(user_settings_write_warnings(&json!({"bucket_seconds": 5})).is_empty());
    }

    #[tokio::test]
    async fn a_merged_show_document_is_refused_for_its_terms_flag_first() {
        // A merged `show` document always carries the flag. Refusing it for its
        // extra fields first would point at --force, which the terms refusal
        // ignores, so following that advice could never succeed.
        let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let file = json_file(r#"{"refresh_interval_seconds":30,"audit_enabled":true,"feature_flags":{"terms":false}}"#);

        let error = run_user_settings(
            &client,
            UserSettingsCommand::Set(GuardedJsonFileArgs {
                file: file.path().to_path_buf(),
                force: false,
            }),
        )
        .await
        .expect_err("a merged show document should be refused");

        let text = error.to_string();
        assert!(text.contains("feature_flags.terms"), "got: {text}");
        assert!(!text.contains("--force"), "the first refusal must not point at --force, got: {text}");
        assert_no_request(request, "`user-settings set` with a merged show document");
    }

    #[tokio::test]
    async fn user_settings_set_refuses_a_document_from_a_merged_show() {
        let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let merged = r#"{"refresh_interval_seconds":30,"metrics_retention_minutes":60,"audit_enabled":true}"#;

        let error = run_user_settings(
            &client,
            UserSettingsCommand::Set(GuardedJsonFileArgs {
                file: json_file(merged)
                    .path()
                    .to_path_buf(),
                force: false,
            }),
        )
        .await
        .expect_err("a merged document must not silently persist appliance defaults");

        let text = error.to_string();
        assert!(text.contains("metrics_retention_minutes"), "got: {text}");
        assert!(text.contains("--overrides"), "the error should point at the honest read");
        // The point of the guard is that the appliance defaults are never
        // persisted, so the refusal has to happen before the request.
        assert_no_request(request, "`user-settings set`");

        reject_unknown_user_settings(&json!({"bucket_seconds": 5})).expect("a genuine override document is accepted");
    }

    #[tokio::test]
    async fn settings_reset_refuses_to_clear_the_appliance_document_without_force() {
        let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_settings(&client, SettingsCommand::Reset { force: false })
            .await
            .expect_err("an unforced reset must not clear the appliance settings");

        let text = error.to_string();
        for cleared in ["prometheus_auth_enabled", "audit_enabled", "feature_flags"] {
            assert!(text.contains(cleared), "the refusal should name {cleared}, got: {text}");
        }
        assert!(text.contains("--force"), "the refusal should say how to proceed, got: {text}");
        // Prometheus authentication and audit logging go off the moment the
        // gateway answers, so the refusal is worth nothing unless it is
        // pre-flight.
        assert_no_request(request, "`settings reset`");
    }

    #[tokio::test]
    async fn settings_reset_clears_the_appliance_document_with_force() {
        // The reset answers with the stored defaults, which lack the
        // `feature_flags.terms` every read adds, so the CLI prints a re-read.
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 200 OK", r#"{"badge_threshold_minutes":5,"feature_flags":{}}"#),
            ("HTTP/1.1 200 OK", r#"{"badge_threshold_minutes":5,"feature_flags":{"terms":false}}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_settings(&client, SettingsCommand::Reset { force: true })
            .await
            .expect("a forced reset should reach the gateway");

        assert_eq!(request_lines(requests), ["DELETE /api/v1/settings HTTP/1.1", "GET /api/v1/settings HTTP/1.1"]);
        assert_eq!(value, json!({"badge_threshold_minutes": 5, "feature_flags": {"terms": false}}));
    }

    #[tokio::test]
    async fn settings_set_prints_the_settings_read_back_rather_than_the_write_response() {
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 200 OK", r#"{"badge_threshold_minutes":15,"feature_flags":{}}"#),
            ("HTTP/1.1 200 OK", r#"{"badge_threshold_minutes":15,"feature_flags":{"terms":false}}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let file = json_file(r#"{"badge_threshold_minutes":15}"#);

        let value = run_settings(
            &client,
            SettingsCommand::Set(JsonFileArgs {
                file: file.path().to_path_buf(),
            }),
        )
        .await
        .expect("set should succeed");

        assert_eq!(request_lines(requests), ["POST /api/v1/settings HTTP/1.1", "GET /api/v1/settings HTTP/1.1"]);
        assert_eq!(value, json!({"badge_threshold_minutes": 15, "feature_flags": {"terms": false}}));
    }

    #[tokio::test]
    async fn a_failed_settings_read_back_says_the_write_already_happened() {
        let file = json_file(r#"{"badge_threshold_minutes":15}"#);
        for (command, done) in [
            (
                SettingsCommand::Set(JsonFileArgs {
                    file: file.path().to_path_buf(),
                }),
                "saved",
            ),
            (SettingsCommand::Reset { force: true }, "reset to the built-in defaults"),
        ] {
            let (host, requests) = scripted_server(vec![
                ("HTTP/1.1 200 OK", r#"{"badge_threshold_minutes":15,"feature_flags":{}}"#),
                ("HTTP/1.1 503 Service Unavailable", r#"{"error":"settings store unavailable"}"#),
            ])
            .await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");

            let error = run_settings(&client, command)
                .await
                .expect_err("a failed read-back must not pass off the write response as the state");

            let text = format!("{error:#}");
            assert!(
                text.starts_with(&format!("the appliance settings were {done}, but reading them back failed")),
                "got: {text}"
            );
            assert!(text.contains("settings store unavailable"), "the cause should follow, got: {text}");
            assert_eq!(request_lines(requests).len(), 2);
        }
    }

    #[tokio::test]
    async fn settings_set_refuses_the_runtime_terms_flag_before_sending() {
        // A `settings show` document always carries the flag, whatever its value.
        for document in [
            r#"{"feature_flags":{"terms":true}}"#,
            r#"{"feature_flags":{"terms":false,"ap2":true}}"#,
            r#"{"feature_flags":{"terms":null}}"#,
        ] {
            let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let file = json_file(document);

            let error = run_settings(
                &client,
                SettingsCommand::Set(JsonFileArgs {
                    file: file.path().to_path_buf(),
                }),
            )
            .await
            .expect_err("a write that can never take effect should be refused");

            let text = error.to_string();
            for expected in ["feature_flags.terms", "network.terms", "`fabric agent-gateway settings show`", "re-run"] {
                assert!(text.contains(expected), "the refusal should mention {expected}, got: {text}");
            }
            assert_no_request(request, "`settings set` with feature_flags.terms");
        }
    }

    #[test]
    fn a_terms_key_is_refused_whatever_its_value() {
        // A flag is a plain boolean, so the gateway answers a null one with 422
        // rather than treating it as absent.
        reject_runtime_terms_flag(&json!({"feature_flags": {"terms": null}}), "settings show")
            .expect_err("a null terms flag is still refused");
        // The flag map itself is optional, so a null map leaves it alone.
        reject_runtime_terms_flag(&json!({"feature_flags": null}), "settings show")
            .expect("a null flag map writes nothing");
        reject_runtime_terms_flag(&json!({"feature_flags": {"ap2_experimental": true}}), "settings show")
            .expect("other flags are writable");
    }

    #[tokio::test]
    async fn user_settings_set_refuses_the_runtime_terms_flag_even_with_force() {
        for force in [false, true] {
            let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let file = json_file(r#"{"feature_flags":{"terms":true}}"#);

            let error = run_user_settings(
                &client,
                UserSettingsCommand::Set(GuardedJsonFileArgs {
                    file: file.path().to_path_buf(),
                    force,
                }),
            )
            .await
            .expect_err("--force must not send a write that can never take effect");

            let text = error.to_string();
            for expected in ["feature_flags.terms", "network.terms", "`fabric agent-gateway user-settings show`"] {
                assert!(text.contains(expected), "the refusal should mention {expected}, got: {text}");
            }
            assert_no_request(request, "`user-settings set` with feature_flags.terms");
        }
    }

    #[tokio::test]
    async fn user_settings_never_print_the_prometheus_password_hash() {
        // The appliance route blanks this; the per-user routes merge it in
        // unblanked, so the CLI drops it.
        let (host, _request) = one_shot_server(
            "HTTP/1.1 200 OK",
            r#"{"refresh_interval_seconds":30,"prometheus_auth_password_hash":"$2b$12$secrethash"}"#,
        )
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_user_settings(&client, UserSettingsCommand::Show { overrides: false })
            .await
            .expect("show should succeed");

        let hash = value.get("prometheus_auth_password_hash");
        assert!(hash.is_none(), "the password hash must not reach output");
        assert_eq!(value["refresh_interval_seconds"], json!(30));
    }

    #[test]
    fn user_settings_warnings_name_a_replaced_flag_map() {
        assert_eq!(user_settings_write_warnings(&json!({"feature_flags": {"ap2_experimental": true}})).len(), 1);
        // `feature_flags` is Option-typed here too, so a null leaves the stored
        // map alone and must not claim it was replaced.
        assert!(user_settings_write_warnings(&json!({"feature_flags": null})).is_empty());
    }

    #[tokio::test]
    async fn runtime_reload_addresses_a_single_surface_by_config_id() {
        let (host, request) =
            one_shot_server("HTTP/1.1 200 OK", r#"{"channel_name":"Sales Agent","is_fallback":false}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_runtime(
            &client,
            RuntimeCommand::Reload {
                surface: Some("surface-1".to_owned()),
            },
        )
        .await
        .expect("reload should succeed");

        assert_eq!(request_line(request).await, "POST /api/v1/config/reload/surface-1 HTTP/1.1");
        assert_eq!(value, json!({"channel_name": "Sales Agent", "is_fallback": false}));
    }

    fn surface_update(
        set: &[&str],
        add: &[&str],
        remove: &[&str],
    ) -> SurfaceCommand {
        surface_edit(set, &[], add, remove, false)
    }

    fn surface_edit(
        set: &[&str],
        unset: &[&str],
        add: &[&str],
        remove: &[&str],
        dry_run: bool,
    ) -> SurfaceCommand {
        let strings = |values: &[&str]| -> Vec<String> {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        };
        SurfaceCommand::Update {
            surface_id: "s-1".to_owned(),
            file: None,
            set: strings(set),
            unset: strings(unset),
            add: strings(add),
            remove: strings(remove),
            dry_run,
        }
    }

    /// A surface holding every field the local check requires.
    const STORED_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"tags":["prod"]}"#;

    /// The status line of a surface read from a gateway that honours
    /// `?dry_run=true`, carrying the header that says so.
    const DRY_RUN_GATEWAY_OK: &str = "HTTP/1.1 200 OK\r\nx-surface-dry-run: supported";

    #[tokio::test]
    async fn surface_update_with_only_set_reads_the_surface_before_patching() {
        let (host, requests) =
            scripted_server(vec![("HTTP/1.1 200 OK", STORED_SURFACE), ("HTTP/1.1 200 OK", r#"{"name":"Sales"}"#)])
                .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        run_surfaces(&client, surface_update(&["name=Sales"], &[], &[]), Output::Json)
            .await
            .expect("the update should succeed");

        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn surface_update_with_add_reads_the_surface_before_patching() {
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 200 OK", STORED_SURFACE),
            ("HTTP/1.1 200 OK", r#"{"tags":["prod","beta"]}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_surfaces(&client, surface_update(&[], &["tags=beta"], &[]), Output::Json)
            .await
            .expect("the update should succeed");

        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
        assert_eq!(value, Some(json!({"tags": ["prod", "beta"]})));
    }

    #[tokio::test]
    async fn surface_update_with_only_remove_reads_the_surface_before_patching() {
        let (host, requests) =
            scripted_server(vec![("HTTP/1.1 200 OK", STORED_SURFACE), ("HTTP/1.1 200 OK", r#"{"tags":[]}"#)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        run_surfaces(&client, surface_update(&[], &[], &["tags=prod"]), Output::Json)
            .await
            .expect("the update should succeed");

        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn surface_update_sends_nothing_when_the_surface_cannot_be_read() {
        let (host, requests) = scripted_server(vec![(
            "HTTP/1.1 403 Forbidden",
            r#"{"error": "access token scope does not include 'surfaces.view'", "required_permission": "surfaces.view"}"#,
        )])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_update(&[], &["tags=beta"], &[]), Output::Json)
            .await
            .expect_err("a failed read should stop the update");

        let text = format!("{error:#}");
        assert!(text.contains("read the surface before changing it"), "{text}");
        assert!(text.contains("surfaces.view"), "{text}");
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    /// The gateway's answer to a surface read from a token without surfaces.view.
    const SURFACES_VIEW_DENIED: &str =
        r#"{"error":"access token scope does not include 'surfaces.view'","required_permission":"surfaces.view"}"#;

    #[tokio::test]
    async fn surface_update_with_only_set_sends_the_patch_unchecked_when_the_read_is_refused() {
        for refusal in ["HTTP/1.1 403 Forbidden", "HTTP/1.1 401 Unauthorized"] {
            let (host, requests) =
                scripted_server(vec![(refusal, SURFACES_VIEW_DENIED), ("HTTP/1.1 200 OK", r#"{"name":"Billing"}"#)])
                    .await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");

            let value =
                run_surfaces(&client, surface_edit(&["name=Billing"], &["tags"], &[], &[], false), Output::Json)
                    .await
                    .expect("the edit should still be sent");

            assert_eq!(value, Some(json!({"name": "Billing"})));
            assert_eq!(
                request_lines(requests),
                ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"],
                "after {refusal}"
            );
        }
    }

    #[tokio::test]
    async fn surface_update_dry_run_sends_nothing_when_the_read_is_refused() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 403 Forbidden", SURFACES_VIEW_DENIED)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Json)
            .await
            .expect_err("a dry run needs the surface");

        assert!(format!("{error:#}").contains("surfaces.view"), "{error:#}");
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn surface_update_with_add_sends_nothing_when_the_read_is_refused() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 403 Forbidden", SURFACES_VIEW_DENIED)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_update(&[], &["tags=beta"], &[]), Output::Json)
            .await
            .expect_err("--add needs the surface");

        assert!(format!("{error:#}").contains("surfaces.view"), "{error:#}");
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn surface_update_sends_nothing_when_the_list_edit_is_refused() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", STORED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_update(&[], &["tags=prod"], &[]), Output::Json)
            .await
            .expect_err("a duplicate item should be refused");

        assert!(
            error
                .to_string()
                .contains("already has 'prod'"),
            "{error}"
        );
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn surface_update_sends_nothing_when_the_edit_leaves_a_required_field_empty() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", STORED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&[], &["access_point.route"], &[], &[], false), Output::Json)
            .await
            .expect_err("an edit that drops the route should be refused");

        assert_eq!(error.to_string(), "access_point.route is required");
        assert_eq!(exit_code(&error), 1);
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn surface_update_dry_run_only_sends_the_dry_run_patch() {
        let (host, requests) = scripted_server(vec![
            (DRY_RUN_GATEWAY_OK, STORED_SURFACE),
            ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Billing"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Json)
            .await
            .expect("the dry run should succeed");

        assert_eq!(value, None, "the report is printed by the dry run itself");
        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn surface_update_dry_run_sends_no_patch_to_a_gateway_without_dry_run() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", STORED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Table)
            .await
            .expect_err("only the checks on this machine ran");

        assert_eq!(exit_code(&error), INCOMPLETE_DRY_RUN_EXIT_CODE);
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn surface_update_dry_run_is_incomplete_when_the_gateway_fails_with_a_server_error() {
        let (host, _) =
            scripted_server(vec![(DRY_RUN_GATEWAY_OK, STORED_SURFACE), ("HTTP/1.1 503 Service Unavailable", "")]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Json)
            .await
            .expect_err("the gateway's checks did not run");

        assert_eq!(exit_code(&error), INCOMPLETE_DRY_RUN_EXIT_CODE);
    }

    #[test]
    fn incomplete_dry_run_exit_code_differs_from_clap_usage_error() {
        let error = Cli::try_parse_from(["fabric", "agent-gateway", "no-such-command"]).unwrap_err();
        assert_ne!(error.exit_code(), INCOMPLETE_DRY_RUN_EXIT_CODE);
    }

    #[tokio::test]
    async fn surface_update_dry_run_fails_when_a_gateway_announcing_dry_run_answers_404() {
        let (host, requests) = scripted_server(vec![
            (DRY_RUN_GATEWAY_OK, STORED_SURFACE),
            ("HTTP/1.1 404 Not Found", r#"{"error":"Not Found","details":"Surface 's-1' not found"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Table)
            .await
            .expect_err("the surface is gone, which is a refused edit");

        assert_eq!(exit_code(&error), 1, "not reported as a dry run checked on this machine only");
        assert!(
            error
                .downcast_ref::<IncompleteDryRun>()
                .is_none(),
            "{error:#}"
        );
        assert!(format!("{error:#}").contains("Surface 's-1' not found"), "{error:#}");
        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn surface_update_dry_run_fails_when_a_gateway_announcing_dry_run_answers_405() {
        let (host, _) =
            scripted_server(vec![(DRY_RUN_GATEWAY_OK, STORED_SURFACE), ("HTTP/1.1 405 Method Not Allowed", "")]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(&client, surface_edit(&["name=Billing"], &[], &[], &[], true), Output::Json)
            .await
            .expect_err("the gateway refused the dry run");

        assert_eq!(exit_code(&error), 1);
    }

    #[tokio::test]
    async fn surface_update_dry_run_refused_by_the_local_check_sends_nothing() {
        for output in [Output::Table, Output::Json] {
            let (host, requests) = scripted_server(vec![(DRY_RUN_GATEWAY_OK, STORED_SURFACE)]).await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");

            let error = run_surfaces(&client, surface_edit(&[], &["target.endpoint"], &[], &[], true), output)
                .await
                .expect_err("an edit that drops the endpoint should be refused");

            assert_eq!(error.to_string(), "target.endpoint is required");
            assert_eq!(exit_code(&error), 1);
            assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
        }
    }

    #[tokio::test]
    async fn surface_update_file_missing_the_endpoint_is_refused_before_the_put() {
        let (host, requests) = scripted_server(vec![]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let file = json_file(
            r#"{"name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{}}"#,
        );

        let error = run_surfaces(
            &client,
            SurfaceCommand::Update {
                surface_id: "s-1".to_owned(),
                file: Some(file.path().to_path_buf()),
                set: Vec::new(),
                unset: Vec::new(),
                add: Vec::new(),
                remove: Vec::new(),
                dry_run: false,
            },
            Output::Json,
        )
        .await
        .expect_err("a file without target.endpoint should be refused");

        assert_eq!(error.to_string(), "target.endpoint is required");
        assert!(request_lines(requests).is_empty(), "nothing should reach the gateway");
    }

    fn surface_command(args: &[&str]) -> SurfaceCommand {
        let Command::Surfaces { command } = command_of(args) else {
            panic!("expected a surfaces command");
        };
        command
    }

    #[tokio::test]
    async fn add_feature_dry_run_only_sends_the_dry_run_patch() {
        let (host, requests) = scripted_server(vec![
            (DRY_RUN_GATEWAY_OK, STORED_SURFACE),
            ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","access_point":{"rate_limit":{"requests":100}}}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = surface_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "add-feature",
            "s-1",
            "rate-limit",
            "--json",
            r#"{"requests":100}"#,
            "--dry-run",
        ]);

        let value = run_surfaces(&client, command, Output::Json)
            .await
            .expect("the dry run should succeed");

        assert_eq!(value, None, "the report is printed by the dry run itself");
        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"]
        );
    }

    const TRANSIT_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"alias":"gh"}]}}"#;

    const GATED_TRANSIT_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000","mcp_tool_gating":{"default_effect":"deny","gates":[]}},"transit":{"points":[{"alias":"gh","mcp_tool_gating":{"default_effect":"deny","gates":[]}}]}}"#;

    const RATE_LIMITED_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","rate_limit":{"requests":100,"window_secs":60}},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;

    const NO_GATES: &str = r#"{"default_effect":"deny","gates":[]}"#;

    /// Runs a feature command as a dry run against a server that records each
    /// whole request, and returns the two requests it made: the read of the
    /// surface, then the dry-run patch.
    async fn feature_dry_run(
        args: &[&str],
        stored: &'static str,
    ) -> Result<Vec<String>> {
        let (host, requests) =
            scripted_server(vec![(DRY_RUN_GATEWAY_OK, stored), ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let mut argv = vec!["fabric", "agent-gateway", "surfaces"];
        argv.extend_from_slice(args);
        argv.push("--dry-run");
        run_surfaces(&client, surface_command(&argv), Output::Json).await?;
        Ok(full_requests(requests))
    }

    fn patch_body(requests: &[String]) -> Value {
        let body = requests[1]
            .split_once("\r\n\r\n")
            .expect("request body")
            .1;
        serde_json::from_str(body).expect("patch body is JSON")
    }

    const READ_AND_DRY_RUN: [&str; 2] =
        ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"];

    #[tokio::test]
    async fn add_feature_finds_the_surface_wide_place_for_tool_gating_with_no_flags() {
        let requests = feature_dry_run(&["add-feature", "s-1", "tool-gating", "--json", NO_GATES], TRANSIT_SURFACE)
            .await
            .expect("tool gating needs no edge flags");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(
            patch_body(&requests),
            json!({"target": {"mcp_tool_gating": {"default_effect": "deny", "gates": []}}})
        );
    }

    #[tokio::test]
    async fn add_feature_finds_the_transit_point_place_when_a_transit_point_is_given() {
        let requests = feature_dry_run(
            &["add-feature", "s-1", "tool-gating", "--transit-point", "gh", "--json", NO_GATES],
            TRANSIT_SURFACE,
        )
        .await
        .expect("a transit point picks the per-transit-point place");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [{"alias": "gh", "mcp_tool_gating": {"default_effect": "deny", "gates": []}}]}})
        );
    }

    #[tokio::test]
    async fn add_feature_uses_the_one_networking_place_with_no_flags() {
        let requests =
            feature_dry_run(&["add-feature", "s-1", "timeout", "--json", r#"{"timeout_secs":5}"#], TRANSIT_SURFACE)
                .await
                .expect("both edges write the same networking spot");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(patch_body(&requests).pointer("/target/networking/timeout_secs"), Some(&json!(5)));
    }

    #[tokio::test]
    async fn remove_feature_finds_the_place_with_no_flags() {
        let requests = feature_dry_run(&["remove-feature", "s-1", "rate-limit"], RATE_LIMITED_SURFACE)
            .await
            .expect("rate limit needs no edge flags");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(patch_body(&requests), json!({"access_point": {"rate_limit": null}}));
    }

    #[tokio::test]
    async fn remove_feature_takes_tool_gating_off_the_surface_with_no_flags() {
        let requests = feature_dry_run(&["remove-feature", "s-1", "tool-gating"], GATED_TRANSIT_SURFACE)
            .await
            .expect("tool gating needs no edge flags");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(patch_body(&requests), json!({"target": {"mcp_tool_gating": null}}));
    }

    #[tokio::test]
    async fn remove_feature_takes_tool_gating_off_one_transit_point() {
        let requests =
            feature_dry_run(&["remove-feature", "s-1", "tool-gating", "--transit-point", "gh"], GATED_TRANSIT_SURFACE)
                .await
                .expect("a transit point picks the per-transit-point place");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(patch_body(&requests), json!({"transit": {"points": [{"alias": "gh"}]}}));
    }

    #[tokio::test]
    async fn add_feature_treats_policy_with_no_flags_as_the_request_policy() {
        let requests = feature_dry_run(&["add-feature", "s-1", "policy", "--policy-id", "p1"], STORED_SURFACE)
            .await
            .expect("policy needs no edge flags");
        assert_eq!(
            patch_body(&requests),
            json!({"target": {"policy": {"policy_definition_id": "p1", "require_agent_context": false}}})
        );
    }

    #[tokio::test]
    async fn add_feature_takes_response_and_transit_point_without_an_edge() {
        let requests =
            feature_dry_run(&["add-feature", "s-1", "policy", "--response", "--policy-id", "p1"], STORED_SURFACE)
                .await
                .expect("--response alone picks the response policy");
        assert!(
            patch_body(&requests)
                .pointer("/target/response_policy")
                .is_some()
        );
        let requests = feature_dry_run(
            &["add-feature", "s-1", "policy", "--transit-point", "gh", "--policy-id", "p1"],
            TRANSIT_SURFACE,
        )
        .await
        .expect("a transit point alone picks its request policy");
        assert!(
            patch_body(&requests)
                .pointer("/transit/points/0/policy")
                .is_some()
        );
    }

    #[tokio::test]
    async fn add_and_remove_feature_ask_for_the_edge_when_identity_response_has_two_places() {
        for args in [
            &["add-feature", "s-1", "identity", "--response", "--json", "{}"][..],
            &["remove-feature", "s-1", "identity", "--response"][..],
        ] {
            let error = feature_dry_run(args, STORED_SURFACE)
                .await
                .expect_err("identity has two response places")
                .to_string();
            assert!(error.contains("can go in more than one place"), "{error}");
            assert!(error.contains("--edge ap-ma  (response"), "{error}");
            assert!(error.contains("--edge ma-external  (response"), "{error}");
        }
    }

    #[tokio::test]
    async fn add_feature_still_accepts_an_explicit_edge_and_response() {
        let requests = feature_dry_run(
            &["add-feature", "s-1", "policy", "--edge", "ap-ma", "--response", "--policy-id", "p1"],
            STORED_SURFACE,
        )
        .await
        .expect("explicit flags pick the place");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(
            patch_body(&requests),
            json!({"target": {"response_policy": {"policy_definition_id": "p1", "require_agent_context": false}}})
        );
    }

    #[tokio::test]
    async fn add_feature_takes_a_response_only_edge_without_response() {
        let requests = feature_dry_run(
            &["add-feature", "s-1", "identity", "--edge", "ma-external", "--json", r#"{"strategy":"from_mtls"}"#],
            STORED_SURFACE,
        )
        .await
        .expect("ma-external only has a response place for identity");
        assert_eq!(patch_body(&requests), json!({"identity_slots": {"external": {"strategy": "from_mtls"}}}));
    }

    #[tokio::test]
    async fn add_feature_refuses_response_on_a_transit_point_for_a_request_only_feature() {
        let error = feature_dry_run(
            &["add-feature", "s-1", "networking", "--transit-point", "gh", "--response", "--json", "{}"],
            TRANSIT_SURFACE,
        )
        .await
        .expect_err("networking has no response place on a transit point")
        .to_string();
        assert_eq!(
            error,
            "feature 'networking' cannot use --transit-point <alias> --response; use one of: --edge ap-ma, --edge ma-external, --transit-point <alias>"
        );
    }

    const TRUST_CHECKED_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","trust_check_list":[{"id":"a","trust_registry_id":"tr-1","query_type":"recognition","query":{}}]},"target":{"endpoint":"http://127.0.0.1:3000","trust_check_list":[{"id":"b","trust_registry_id":"tr-1","query_type":"recognition","query":{}}]}}"#;

    #[tokio::test]
    async fn add_feature_puts_trust_check_on_the_caller_or_target_leg() {
        let element = r#"{"id":"c","trust_registry_id":"tr-1","query_type":"recognition","query":{}}"#;
        let requests = feature_dry_run(&["add-feature", "s-1", "trust-check", "--json", element], STORED_SURFACE)
            .await
            .expect("no flags means the caller leg");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(
            patch_body(&requests),
            json!({"access_point": {"trust_check_list": [serde_json::from_str::<Value>(element).unwrap()]}})
        );
        let requests = feature_dry_run(
            &["add-feature", "s-1", "trust-check", "--edge", "ma-tp", "--json", element],
            STORED_SURFACE,
        )
        .await
        .expect("--edge ma-tp means the target leg");
        assert_eq!(
            patch_body(&requests),
            json!({"target": {"trust_check_list": [serde_json::from_str::<Value>(element).unwrap()]}})
        );
    }

    #[tokio::test]
    async fn remove_feature_takes_trust_check_off_the_caller_or_target_leg() {
        let requests = feature_dry_run(&["remove-feature", "s-1", "trust-check"], TRUST_CHECKED_SURFACE)
            .await
            .expect("no flags means the caller leg");
        assert_eq!(patch_body(&requests), json!({"access_point": {"trust_check_list": null}}));
        let requests =
            feature_dry_run(&["remove-feature", "s-1", "trust-check", "--edge", "ma-tp"], TRUST_CHECKED_SURFACE)
                .await
                .expect("--edge ma-tp means the target leg");
        assert_eq!(patch_body(&requests), json!({"target": {"trust_check_list": null}}));
    }

    #[tokio::test]
    async fn add_and_remove_feature_refuse_edge_ma_tp_where_an_alias_is_needed() {
        for (args, feature) in [
            (&["add-feature", "s-1", "policy", "--edge", "ma-tp", "--policy-id", "p1"][..], "policy"),
            (&["remove-feature", "s-1", "policy", "--edge", "ma-tp"][..], "policy"),
            (&["add-feature", "s-1", "tool-gating", "--edge", "ma-tp", "--json", "{}"][..], "mcp-tool-gating"),
            (&["remove-feature", "s-1", "tool-gating", "--edge", "ma-tp"][..], "mcp-tool-gating"),
        ] {
            let error = feature_dry_run(args, TRANSIT_SURFACE)
                .await
                .expect_err("these features need an alias for ma-tp")
                .to_string();
            assert_eq!(
                error,
                format!(
                    "feature '{feature}' goes on one transit point, so use --transit-point <alias> instead of --edge ma-tp"
                )
            );
        }
    }

    #[tokio::test]
    async fn add_and_remove_feature_reject_a_transit_point_for_a_feature_without_one() {
        for args in [
            &["add-feature", "s-1", "rate-limit", "--transit-point", "gh", "--json", "{}"][..],
            &["remove-feature", "s-1", "rate-limit", "--transit-point", "gh"][..],
            &["add-feature", "s-1", "trust-check", "--transit-point", "gh", "--json", "{}"][..],
            &["remove-feature", "s-1", "trust-check", "--transit-point", "gh"][..],
        ] {
            let error = feature_dry_run(args, RATE_LIMITED_SURFACE)
                .await
                .expect_err("these features have no transit point place")
                .to_string();
            let expected = match args[2] {
                "trust-check" => {
                    "feature 'trust-check' has no place per transit point alias, so leave out --transit-point (--edge ma-tp is the target leg); use one of: --edge ap-ma, --edge ma-tp"
                }
                _ => {
                    "feature 'rate-limit' cannot go on a transit point, so leave out --transit-point; use one of: --edge ap-ma"
                }
            };
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn edge_and_transit_point_cannot_be_given_together() {
        for command in ["add-feature", "remove-feature"] {
            let error = Cli::try_parse_from([
                "fabric",
                "agent-gateway",
                "surfaces",
                command,
                "s-1",
                "tool-gating",
                "--edge",
                "ma-external",
                "--transit-point",
                "gh",
            ])
            .expect_err("--edge and --transit-point pick different places");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }

    const SURFACE_LIST: &str = r#"[{"surface_id":"s-1","name":"Sales"},{"surface_id":"s-2","name":"Billing"},{"surface_id":"s-3","name":"Billing"}]"#;

    const LIST_REQUEST: &str = "GET /api/v1/surfaces HTTP/1.1";

    const LIST_OK: (&str, &str) = ("HTTP/1.1 200 OK", SURFACE_LIST);

    async fn resolved_id(
        reference: &str,
        responses: Vec<(&'static str, &'static str)>,
    ) -> (Result<String>, Vec<String>) {
        let (host, requests) = scripted_server(responses).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let resolved = resolve_surface_id(&client, reference).await;
        (resolved, request_lines(requests))
    }

    async fn resolved_name(reference: &str) -> (Result<String>, Vec<String>) {
        resolved_id(reference, vec![LIST_OK]).await
    }

    async fn resolved_in(
        reference: &str,
        list: &'static str,
    ) -> Result<String> {
        resolved_id(reference, vec![("HTTP/1.1 200 OK", list)])
            .await
            .0
    }

    #[tokio::test]
    async fn a_surface_id_resolves_to_itself_with_only_the_list_asked_for() {
        let (resolved, requests) = resolved_name("s-2").await;

        assert_eq!(resolved.expect("an ID should resolve"), "s-2");
        assert_eq!(requests, [LIST_REQUEST]);
    }

    #[tokio::test]
    async fn a_name_only_one_surface_has_resolves_to_its_id() {
        let (resolved, requests) = resolved_name("Sales").await;

        assert_eq!(resolved.expect("a unique name should resolve"), "s-1");
        assert_eq!(requests, [LIST_REQUEST]);
    }

    #[tokio::test]
    async fn a_name_more_than_one_surface_has_lists_the_matches() {
        let (resolved, _) = resolved_name("Billing").await;

        let error = resolved.expect_err("a shared name should not be guessed");
        assert_eq!(
            error.to_string(),
            "'Billing' matches more than one surface; pass one of these ids instead:\n  s-2  (name: Billing)\n  s-3  (name: Billing)"
        );
        assert_eq!(exit_code(&error), 1);
    }

    #[tokio::test]
    async fn a_reference_no_surface_has_points_to_the_list() {
        let (resolved, _) = resolved_name("Support").await;

        let error = resolved.expect_err("an unknown reference should be refused");
        assert_eq!(
            error.to_string(),
            "surface not found: no surface has the ID or name 'Support'; run `fabric agent-gateway surfaces list` to see them"
        );
    }

    #[tokio::test]
    async fn a_reference_with_spaces_around_it_that_matches_nothing_says_so() {
        let error = resolved_name(" Sales")
            .await
            .0
            .expect_err("a padded name matches nothing");

        assert!(
            error
                .to_string()
                .contains("starts or ends with a space"),
            "{error}"
        );
        let plain = resolved_name("Support")
            .await
            .0
            .expect_err("an unknown name matches nothing");
        assert!(
            !plain
                .to_string()
                .contains("space"),
            "{plain}"
        );
    }

    #[tokio::test]
    async fn a_surface_id_wins_over_another_surface_with_that_name() {
        let list = r#"[{"surface_id":"s-1","name":"s-2"},{"surface_id":"s-2","name":"Billing"}]"#;

        let resolved = resolved_in("s-2", list)
            .await
            .expect("the ID should win");
        assert_eq!(resolved, "s-2");
        assert_eq!(name_resolved_note(&resolved, "s-2"), None, "an ID prints no note");
        assert_eq!(
            resolved_in("s-1", list)
                .await
                .expect("the ID should win"),
            "s-1"
        );
    }

    #[tokio::test]
    async fn a_surface_listed_twice_with_the_same_id_is_one_match() {
        let list = r#"[{"surface_id":"s-1","name":"Sales"},{"surface_id":"s-1","name":"Sales"}]"#;

        assert_eq!(
            resolved_in("Sales", list)
                .await
                .expect("one surface should resolve"),
            "s-1"
        );
    }

    #[tokio::test]
    async fn a_matching_surface_listed_without_an_id_is_never_skipped_for_another_of_that_name() {
        let message = "the gateway listed a surface named 'Sales' without its surface_id, so the CLI can't tell which one you mean; pass the surface's id instead";
        let alone = r#"[{"name":"Sales"},{"surface_id":"s-2","name":"Billing"}]"#;
        let with_twin =
            r#"[{"name":"Billing"},{"surface_id":"s-2","name":"Billing"},{"surface_id":"s-3","name":"Billing"}]"#;

        let error = resolved_in("Sales", alone)
            .await
            .expect_err("a surface with no ID cannot be used");
        assert_eq!(error.to_string(), message);
        let error = resolved_in("Billing", with_twin)
            .await
            .expect_err("a name that may be a surface with no ID is not safe to act on");
        assert!(
            error
                .to_string()
                .contains("without its surface_id"),
            "{error}"
        );
        assert_eq!(
            resolved_in("Billing", alone)
                .await
                .expect("other rows still resolve"),
            "s-2"
        );
    }

    #[tokio::test]
    async fn a_name_with_two_dots_or_only_dots_resolves_through_the_list() {
        let list = r#"[{"surface_id":"s-7","name":"Q1..Q2"},{"surface_id":"s-4","name":"."},{"surface_id":"s-5","name":".."}]"#;

        for (reference, expected) in [("Q1..Q2", "s-7"), (".", "s-4"), ("..", "s-5")] {
            let (resolved, requests) = resolved_id(reference, vec![("HTTP/1.1 200 OK", list)]).await;

            assert_eq!(resolved.expect("the name should resolve"), expected);
            assert_eq!(requests, [LIST_REQUEST], "{reference}");
        }
    }

    #[tokio::test]
    async fn an_empty_reference_is_refused_before_any_request() {
        for reference in ["", "  \t"] {
            let (resolved, requests) = resolved_id(reference, vec![]).await;

            let error = resolved.expect_err("an empty reference names nothing");
            assert_eq!(
                error.to_string(),
                "give a surface ID or name; run `fabric agent-gateway surfaces list` to see them"
            );
            assert!(requests.is_empty(), "nothing should reach the gateway");
        }
    }

    #[tokio::test]
    async fn names_with_a_space_or_a_slash_resolve_through_the_list() {
        let list = r#"[{"surface_id":"s-6","name":"Sales Agent"},{"surface_id":"s-7","name":"a/b"}]"#;
        for (reference, expected) in [("Sales Agent", "s-6"), ("a/b", "s-7")] {
            let (resolved, requests) = resolved_id(reference, vec![("HTTP/1.1 200 OK", list)]).await;

            assert_eq!(resolved.expect("the name should resolve"), expected);
            assert_eq!(requests, [LIST_REQUEST]);
        }
    }

    #[tokio::test]
    async fn a_forbidden_list_keeps_a_uuid_as_the_id() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";

        let (resolved, requests) = resolved_id(uuid, vec![("HTTP/1.1 403 Forbidden", "")]).await;

        assert_eq!(resolved.expect("a UUID needs no list"), uuid);
        assert_eq!(requests, [LIST_REQUEST]);
    }

    #[tokio::test]
    async fn a_forbidden_list_refuses_a_name_and_explains_why() {
        let (resolved, _) = resolved_id("Sales", vec![("HTTP/1.1 403 Forbidden", "")]).await;

        let error = resolved.expect_err("a name cannot be looked up without the list");
        let message = format!("{error:#}");
        assert!(message.contains("surfaces.view") && message.contains("pass the surface's id"), "{message}");
    }

    #[tokio::test]
    async fn an_unauthorized_list_is_an_error() {
        let (resolved, requests) = resolved_id("s-9", vec![("HTTP/1.1 401 Unauthorized", "")]).await;

        let error = resolved.expect_err("a rejected token should stop the command");
        assert!(
            error
                .to_string()
                .contains("list surfaces to find 's-9'"),
            "{error}"
        );
        assert_eq!(requests, [LIST_REQUEST]);
    }

    #[tokio::test]
    async fn a_failed_surface_list_names_the_lookup() {
        let (resolved, _) = resolved_id("Sales", vec![("HTTP/1.1 500 Internal Server Error", "")]).await;

        let error = resolved.expect_err("a failed list should stop the command");
        assert!(
            error
                .to_string()
                .contains("list surfaces to find 'Sales'"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_surface_list_that_is_not_a_list_is_refused() {
        let error = resolved_in("Sales", r#"{"surfaces":[]}"#)
            .await
            .expect_err("an odd answer should be refused");

        assert!(
            error
                .to_string()
                .contains("not a JSON array"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn control_characters_in_a_reference_are_stripped_from_the_errors() {
        let list = r#"[{"surface_id":"s-1","name":"a\nb\tc"},{"surface_id":"s-2","name":"a\nb\tc"}]"#;

        let ambiguous = resolved_in("a\nb\tc", list)
            .await
            .expect_err("two surfaces share the name");
        let missing = resolved_name("x\ny\tz\u{1b}[2J")
            .await
            .0
            .expect_err("no surface has the name");

        assert_eq!(
            ambiguous.to_string(),
            "'a b c' matches more than one surface; pass one of these ids instead:\n  s-1  (name: a b c)\n  s-2  (name: a b c)"
        );
        let missing = missing.to_string();
        assert!(missing.contains("'x y z[2J'"), "{missing}");
        assert!(!missing.contains('\u{1b}'), "{missing:?}");
    }

    #[test]
    fn a_name_prints_the_using_surface_note_and_an_id_prints_nothing() {
        assert_eq!(name_resolved_note("s-1", "Sales").as_deref(), Some("using surface s-1 (Sales)"));
        assert_eq!(name_resolved_note("s-1", "s-1"), None);
    }

    #[test]
    fn the_using_surface_note_names_the_id_and_the_name_on_one_line() {
        assert_eq!(using_surface_note("s-1", "Sales"), "using surface s-1 (Sales)");
        let note = using_surface_note("s-1", "Sa\nles\u{1b}[2J");
        assert_eq!(note, "using surface s-1 (Sa les[2J)");
    }

    async fn resolved_command(args: &[&str]) -> SurfaceCommand {
        let (host, _) = scripted_server(vec![LIST_OK]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        resolve_surface_command(&client, surface_command(args))
            .await
            .expect("the surface should resolve")
    }

    #[tokio::test]
    async fn get_takes_a_surface_name() {
        let command = resolved_command(&["fabric", "agent-gateway", "surfaces", "get", "Sales"]).await;

        assert!(matches!(command, SurfaceCommand::Get { surface_id } if surface_id == "s-1"));
    }

    #[tokio::test]
    async fn update_takes_a_surface_name_and_keeps_its_other_arguments() {
        let command = resolved_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "update",
            "Sales",
            "--set",
            "name=Retail",
            "--dry-run",
        ])
        .await;

        let SurfaceCommand::Update { surface_id, set, dry_run, .. } = command else {
            panic!("expected `surfaces update`");
        };
        assert_eq!(surface_id, "s-1");
        assert_eq!(set, ["name=Retail"]);
        assert!(dry_run);
    }

    /// Runs `args` through the command dispatch against a gateway that answers
    /// with `responses`, and returns the requests it received.
    async fn dispatched_requests(
        args: &[&str],
        responses: Vec<(&'static str, &'static str)>,
    ) -> Vec<String> {
        let (host, requests) = scripted_server(responses).await;
        let config = crate::config::Config {
            current: Some("default".to_owned()),
            connections: [("default".to_owned(), crate::config::Connection::new(host))].into(),
        };
        let cli = Cli::try_parse_from(args).expect("arguments parse");
        dispatch_with(cli.into_agent_gateway(), config, &NoCredentials)
            .await
            .expect("the command should succeed");
        request_lines(requests)
    }

    const FEATURES_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"rate_limit":{"requests":100}},"target":{"mcp_tool_gating":{"allow":["a"]}},"transit":{"points":[{"alias":"gh","mcp_tool_gating":{"allow":["b"]}}]}}"#;

    #[tokio::test]
    async fn features_with_no_surface_looks_nothing_up() {
        let (host, requests) = scripted_server(vec![]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command =
            resolve_surface_command(&client, surface_command(&["fabric", "agent-gateway", "surfaces", "features"]))
                .await
                .expect("nothing to look up");

        assert!(matches!(command, SurfaceCommand::Features { surface_id: None }));
        assert!(request_lines(requests).is_empty());
    }

    #[tokio::test]
    async fn features_takes_a_surface_name() {
        let command = resolved_command(&["fabric", "agent-gateway", "surfaces", "features", "Sales"]).await;

        assert!(matches!(command, SurfaceCommand::Features { surface_id: Some(id) } if id == "s-1"));
    }

    /// Runs `surfaces features <reference>` the way dispatch does, against a
    /// gateway that answers with the surface list and then `FEATURES_SURFACE`,
    /// and returns the requests it received and what was printed.
    async fn shown_features(
        reference: &str,
        output: Output,
    ) -> (Vec<String>, String) {
        let (host, requests) = scripted_server(vec![LIST_OK, ("HTTP/1.1 200 OK", FEATURES_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = resolve_surface_command(
            &client,
            surface_command(&["fabric", "agent-gateway", "surfaces", "features", reference]),
        )
        .await
        .expect("the surface should resolve");
        let SurfaceCommand::Features { surface_id: Some(surface_id) } = command else {
            panic!("expected `surfaces features` with a surface");
        };
        let mut printed = Vec::new();
        show_surface_features(&client, &surface_id, output, &mut printed)
            .await
            .expect("the features should print");
        (request_lines(requests), String::from_utf8(printed).expect("utf-8 output"))
    }

    #[tokio::test]
    async fn features_through_dispatch_reads_the_surface_by_id_and_by_name() {
        for reference in ["s-1", "Sales"] {
            let requests = dispatched_requests(
                &["fabric", "agent-gateway", "--token", "agpat_valid", "surfaces", "features", reference],
                vec![LIST_OK, ("HTTP/1.1 200 OK", FEATURES_SURFACE)],
            )
            .await;

            assert_eq!(requests, [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1"]);
        }
    }

    #[tokio::test]
    async fn features_with_no_surface_through_dispatch_calls_no_gateway() {
        let requests =
            dispatched_requests(&["fabric", "agent-gateway", "--token", "agpat_valid", "surfaces", "features"], vec![])
                .await;

        assert!(requests.is_empty());
    }

    #[test]
    fn the_catalogue_lists_every_feature_with_its_places() {
        let mut table = Vec::new();
        write_features(Output::Table, &mut table).expect("table prints");
        let table = String::from_utf8(table).expect("utf-8 output");
        assert!(table.starts_with("policy  (aliases: opa)\n    OPA policy reference"), "{table}");
        assert!(table.contains("    ap-ma/request -> /access_point/rate_limit [object]\n"), "{table}");

        let mut json = Vec::new();
        write_features(Output::Json, &mut json).expect("json prints");
        let rows: Value = serde_json::from_slice(&json).expect("json output");
        assert_eq!(rows.as_array().map(Vec::len), Some(features::FEATURES.len()));
    }

    #[tokio::test]
    async fn features_prints_the_table_for_a_surface_id() {
        let (requests, printed) = shown_features("s-1", Output::Table).await;

        assert_eq!(requests, [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1"]);
        assert!(printed.starts_with("FEATURE  "), "{printed}");
        assert!(
            printed.contains("rate-limit             on   access point: rate_limit (remove with no flags)\n"),
            "{printed}"
        );
    }

    #[tokio::test]
    async fn features_prints_the_feature_list_as_json_for_a_surface_name() {
        let (requests, printed) = shown_features("Sales", Output::Json).await;

        assert_eq!(requests, [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1"]);
        let rows: Value = serde_json::from_str(&printed).expect("json output");
        let rows = rows
            .as_array()
            .expect("a list of features");
        assert_eq!(rows.len(), features::FEATURES.len());
        let gating = rows
            .iter()
            .find(|row| row["feature"] == "mcp-tool-gating")
            .expect("tool gating row");
        assert_eq!(gating["on"], true);
        assert_eq!(gating["placements"][1]["pointer"], "/transit/points/0/mcp_tool_gating");
        assert_eq!(gating["placements"][1]["remove_flags"], "--transit-point gh");
        assert_eq!(
            rows.iter()
                .filter(|row| row["on"] == true)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn features_says_when_several_surfaces_or_none_have_the_name() {
        let (host, _) = scripted_server(vec![LIST_OK, LIST_OK]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        for (name, expected) in [
            ("Billing", "'Billing' matches more than one surface; pass one of these ids instead:"),
            ("Support", "surface not found: no surface has the ID or name 'Support'"),
        ] {
            let error = resolve_surface_command(
                &client,
                surface_command(&["fabric", "agent-gateway", "surfaces", "features", name]),
            )
            .await
            .expect_err("the name should not resolve");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }

    #[test]
    fn the_features_table_shows_each_feature_on_or_off_and_where() {
        let surface: Value = serde_json::from_str(FEATURES_SURFACE).unwrap();
        let table = surface_features_table(&surface);
        let lines: Vec<&str> = table.lines().collect();

        assert_eq!(lines.len(), features::FEATURES.len() + 1);
        assert_eq!(lines[0], "FEATURE                ON   WHERE");
        assert!(
            lines.contains(&"rate-limit             on   access point: rate_limit (remove with no flags)"),
            "{table}"
        );
        assert!(
            lines.contains(&"mcp-tool-gating        on   target: mcp_tool_gating (remove with no flags); transit point gh: mcp_tool_gating (remove with --transit-point gh)"),
            "{table}"
        );
        assert!(lines.contains(&"payment                off  -"), "{table}");
    }

    #[test]
    fn the_remove_flags_in_the_table_parse_and_pick_the_place_shown() {
        let surface = json!({
            "access_point": {
                "trust_check_list": [{"id": "a"}],
                "rate_limit": {"requests": 1},
                "trust_recorder": {"x": 1},
            },
            "target": {
                "response_custom_metadata": {"a": 1},
                "policy": {"policy_definition_id": "p"},
                "response_policy": {"policy_definition_id": "r"},
                "trust_check_list": [{"id": "t"}],
                "networking": {"timeout_secs": 5},
                "mcp_tool_gating": {"allow": ["a"]},
            },
            "identity_slots": {"inbound": {"a": 1}, "protected": {"a": 1}, "external": {"a": 1}},
            "transit": {"points": [{
                "alias": "gh",
                "policy": {"policy_definition_id": "p"},
                "response_policy": {"policy_definition_id": "r"},
                "networking": {"timeout_secs": 1},
                "mcp_tool_gating": {"allow": ["b"]},
            }, {
                "alias": "my gh",
                "policy": {"policy_definition_id": "p"},
                "response_policy": {"policy_definition_id": "r"},
            }]},
        });
        let mut checked = 0;
        for state in features::on_surface(&surface) {
            for place in state.places {
                let features::RemoveBy::Flags(flags) = place.remove else {
                    panic!("every place here can be picked");
                };
                let words = shell_words::split(&flags).expect("the flags should split like a shell would");
                let mut args = vec!["fabric", "agent-gateway", "surfaces", "remove-feature", "s-1", state.feature.key];
                args.extend(
                    words
                        .iter()
                        .map(String::as_str),
                );
                let Command::Surfaces {
                    command: SurfaceCommand::RemoveFeature(parsed),
                } = command_of(&args)
                else {
                    panic!("expected `surfaces remove-feature`");
                };
                let chosen = state
                    .feature
                    .select_placement(
                        parsed
                            .placement
                            .edge
                            .map(Into::into),
                        parsed
                            .placement
                            .transit_point
                            .is_some(),
                        parsed.placement.response,
                    )
                    .expect("the flags should pick a place");
                assert_eq!(chosen.pointer, place.placement.pointer, "{} {flags}", state.feature.key);
                checked += 1;
            }
        }
        assert_eq!(checked, 18);
    }

    #[test]
    fn the_features_table_says_when_remove_feature_cannot_pick_a_transit_point() {
        let policy = json!({"policy_definition_id": "p"});
        let surface = json!({"transit": {"points": [
            {"alias": "gh", "policy": policy},
            {"policy": policy},
            {"alias": "gh", "policy": policy},
        ]}});
        let table = surface_features_table(&surface);

        assert!(
            table.contains(
                "transit point gh: policy (remove with --transit-point gh); \
                 transit point 1 (no alias): policy (remove-feature can't pick it, it has no alias); \
                 transit point gh: policy (remove-feature can't pick it, an earlier transit point has the same alias)"
            ),
            "{table}"
        );
    }

    #[test]
    fn the_features_table_for_a_bare_surface_has_every_feature_off() {
        let table = surface_features_table(&json!({"surface_id": "s-1"}));

        assert!(
            table
                .lines()
                .skip(1)
                .all(|line| line.contains("  off  -")),
            "{table}"
        );
    }

    #[test]
    fn the_features_table_names_features_the_way_remove_feature_takes_them() {
        let table = surface_features_table(&json!({}));
        let names: Vec<&str> = table
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .collect();

        assert_eq!(names.len(), features::FEATURES.len());
        for name in names {
            assert_eq!(features::find(name).map(|feature| feature.key), Some(name));
        }
    }

    #[tokio::test]
    async fn delete_takes_a_surface_name() {
        let requests = dispatched_requests(
            &["fabric", "agent-gateway", "--token", "agpat_valid", "surfaces", "delete", "Sales"],
            vec![LIST_OK, ("HTTP/1.1 204 No Content", "")],
        )
        .await;

        assert_eq!(requests, [LIST_REQUEST, "DELETE /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn add_feature_takes_a_surface_name() {
        let requests = dispatched_requests(
            &[
                "fabric",
                "agent-gateway",
                "--token",
                "agpat_valid",
                "surfaces",
                "add-feature",
                "Sales",
                "rate-limit",
                "--json",
                r#"{"requests":100}"#,
            ],
            vec![
                LIST_OK,
                ("HTTP/1.1 200 OK", STORED_SURFACE),
                ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Sales"}"#),
            ],
        )
        .await;

        assert_eq!(
            requests,
            [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn remove_feature_takes_a_surface_name() {
        let requests = dispatched_requests(
            &["fabric", "agent-gateway", "--token", "agpat_valid", "surfaces", "remove-feature", "Sales", "rate-limit"],
            vec![
                LIST_OK,
                (
                    "HTTP/1.1 200 OK",
                    r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","rate_limit":{"requests":100}},"target":{"endpoint":"http://127.0.0.1:3000"}}"#,
                ),
                ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Sales"}"#),
            ],
        )
        .await;

        assert_eq!(
            requests,
            [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn tool_gate_preview_takes_a_surface_name() {
        let command = resolved_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "Sales",
            "--tool",
            "get_user",
        ])
        .await;

        let SurfaceCommand::ToolGatePreview(args) = command else {
            panic!("expected `surfaces tool-gate-preview`");
        };
        assert_eq!(args.surface_id.as_deref(), Some("s-1"));
    }

    #[tokio::test]
    async fn tool_gate_preview_from_a_file_looks_up_no_surface() {
        let (host, requests) = scripted_server(vec![]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = surface_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "--gates-file",
            "gates.json",
            "--tool",
            "get_user",
        ]);

        let command = resolve_surface_command(&client, command)
            .await
            .expect("no surface to look up");

        let SurfaceCommand::ToolGatePreview(args) = command else {
            panic!("expected `surfaces tool-gate-preview`");
        };
        assert_eq!(args.surface_id, None);
        assert!(request_lines(requests).is_empty(), "nothing should reach the gateway");
    }

    #[tokio::test]
    async fn commands_that_name_no_saved_surface_look_up_nothing() {
        let (host, requests) = scripted_server(vec![]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        for args in
            [["fabric", "agent-gateway", "surfaces", "list"], ["fabric", "agent-gateway", "surfaces", "features"]]
        {
            resolve_surface_command(&client, surface_command(&args))
                .await
                .expect("nothing to look up");
        }

        assert!(request_lines(requests).is_empty(), "nothing should reach the gateway");
    }

    #[tokio::test]
    async fn update_by_name_dry_run_sends_the_patch_to_the_resolved_surface() {
        let (host, requests) = scripted_server(vec![
            LIST_OK,
            (DRY_RUN_GATEWAY_OK, STORED_SURFACE),
            ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Retail"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = resolve_surface_command(
            &client,
            surface_command(&[
                "fabric",
                "agent-gateway",
                "surfaces",
                "update",
                "Sales",
                "--set",
                "name=Retail",
                "--dry-run",
            ]),
        )
        .await
        .expect("the surface should resolve");

        run_surfaces(&client, command, Output::Json)
            .await
            .expect("the dry run should succeed");

        assert_eq!(
            request_lines(requests),
            [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn get_by_name_reads_the_resolved_surface() {
        let (host, requests) = scripted_server(vec![LIST_OK, ("HTTP/1.1 200 OK", STORED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command =
            resolve_surface_command(&client, surface_command(&["fabric", "agent-gateway", "surfaces", "get", "Sales"]))
                .await
                .expect("the surface should resolve");

        let value = run_surfaces(&client, command, Output::Json)
            .await
            .expect("the read should succeed");

        assert!(value.is_some());
        assert_eq!(request_lines(requests), [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    const S1_REQUEST: &str = "GET /api/v1/surfaces/s-1 HTTP/1.1";

    const OK: (&str, &str) = ("HTTP/1.1 200 OK", STORED_SURFACE);

    fn agent_gateway_args<'a>(rest: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec!["fabric", "agent-gateway", "--token", "agpat_valid", "surfaces"];
        args.extend_from_slice(rest);
        args
    }

    #[tokio::test]
    async fn delete_by_id_looks_in_the_list_and_deletes_it() {
        let requests = dispatched_requests(
            &agent_gateway_args(&["delete", "s-1"]),
            vec![LIST_OK, ("HTTP/1.1 204 No Content", "")],
        )
        .await;

        assert_eq!(requests, [LIST_REQUEST, "DELETE /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn get_by_id_looks_in_the_list_and_reads_it() {
        let requests = dispatched_requests(&agent_gateway_args(&["get", "s-1"]), vec![LIST_OK, OK]).await;

        assert_eq!(requests, [LIST_REQUEST, S1_REQUEST]);
    }

    #[tokio::test]
    async fn get_by_name_reads_the_resolved_surface_through_the_dispatch() {
        let requests = dispatched_requests(&agent_gateway_args(&["get", "Sales"]), vec![LIST_OK, OK]).await;

        assert_eq!(requests, [LIST_REQUEST, S1_REQUEST]);
    }

    #[tokio::test]
    async fn update_by_id_and_by_name_patch_the_same_surface() {
        let by_id =
            dispatched_requests(&agent_gateway_args(&["update", "s-1", "--set", "name=Retail"]), vec![LIST_OK, OK, OK])
                .await;
        let by_name = dispatched_requests(
            &agent_gateway_args(&["update", "Sales", "--set", "name=Retail"]),
            vec![LIST_OK, OK, OK],
        )
        .await;

        assert_eq!(by_id, [LIST_REQUEST, S1_REQUEST, "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]);
        assert_eq!(by_name, by_id);
    }

    #[tokio::test]
    async fn feature_edits_by_id_look_in_the_list_then_read_and_patch_it() {
        let expected = [LIST_REQUEST, S1_REQUEST, "PATCH /api/v1/surfaces/s-1 HTTP/1.1"];
        let added = dispatched_requests(
            &agent_gateway_args(&["add-feature", "s-1", "rate-limit", "--json", r#"{"requests":100}"#]),
            vec![LIST_OK, OK, OK],
        )
        .await;
        let removed = dispatched_requests(
            &agent_gateway_args(&["remove-feature", "s-1", "rate-limit"]),
            vec![LIST_OK, ("HTTP/1.1 200 OK", RATE_LIMITED_SURFACE), OK],
        )
        .await;

        assert_eq!(added, expected);
        assert_eq!(removed, expected);
    }

    #[tokio::test]
    async fn tool_gate_preview_by_id_looks_in_the_list_and_reads_it() {
        let requests = dispatched_requests(
            &agent_gateway_args(&["tool-gate-preview", "s-1", "--tool", "get_user"]),
            vec![LIST_OK, ("HTTP/1.1 200 OK", GATED_SURFACE)],
        )
        .await;

        assert_eq!(requests, [LIST_REQUEST, S1_REQUEST]);
    }

    const DELETE_GATE_FILE: &str = r#"{"default_effect":"allow","gates":[{"id":"g1","condition_policy_definition_id":"non-admins","action":{"effect":"deny","patterns":["^delete_"]}}]}"#;

    const GATED_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","target":{"endpoint":"http://127.0.0.1:3000","mcp_tool_gating":{"default_effect":"deny","gates":[{"name":"Reads","action":{"effect":"allow","patterns":["^get_"]}}]}}}"#;

    const ADMINS_AND_CONTRACTORS_FILE: &str = r#"{"default_effect":"deny","gates":[{"condition_policy_definition_id":"admins","action":{"effect":"allow","patterns":["^delete_"]}},{"condition_policy_definition_id":"contractors","action":{"effect":"deny","patterns":["^delete_"]}}]}"#;

    fn preview_of(
        gating_json: &str,
        tools: &[&str],
        conditions: &[&str],
    ) -> (Gating, Preview, Vec<String>) {
        let gating = tool_gate_preview::read_gating_config(
            &serde_json::from_str(gating_json).expect("gating JSON"),
            "mcp_tool_gating",
        )
        .expect("gating reads");
        let names: Vec<String> = tools
            .iter()
            .map(|tool| (*tool).to_owned())
            .collect();
        let pinned = tool_gate_preview::parse_pins(
            &conditions
                .iter()
                .map(|condition| (*condition).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("conditions parse");
        let previewed = tool_gate_preview::preview(&gating, &names, &pinned).expect("preview works");
        let warnings = tool_gate_preview::warnings(&gating, &names);
        (gating, previewed, warnings)
    }

    #[test]
    fn tool_gate_preview_takes_a_surface_or_a_gates_file_and_at_least_one_tool() {
        let Command::Surfaces {
            command: SurfaceCommand::ToolGatePreview(args),
        } = command_of(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "s-1",
            "--tool",
            "a,b",
            "--tool",
            "c",
        ])
        else {
            panic!("expected tool-gate-preview");
        };
        assert_eq!(args.surface_id.as_deref(), Some("s-1"));
        assert_eq!(args.tools, ["a", "b", "c"]);
        assert!(args.conditions.is_empty());

        let Command::Surfaces {
            command: SurfaceCommand::ToolGatePreview(args),
        } = command_of(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "--gates-file",
            "-",
            "--tool",
            "a",
        ])
        else {
            panic!("expected tool-gate-preview");
        };
        assert_eq!(args.gates_file, Some(PathBuf::from("-")));

        for invalid in [
            &["fabric", "agent-gateway", "surfaces", "tool-gate-preview", "--tool", "a"][..],
            &["fabric", "agent-gateway", "surfaces", "tool-gate-preview", "s-1"][..],
            &[
                "fabric",
                "agent-gateway",
                "surfaces",
                "tool-gate-preview",
                "s-1",
                "--gates-file",
                "g.json",
                "--tool",
                "a",
            ][..],
        ] {
            assert!(Cli::try_parse_from(invalid).is_err(), "{invalid:?} should not parse");
        }
    }

    #[test]
    fn tool_gate_preview_table_shows_each_combination_of_conditions() {
        let (gating, previewed, warnings) = preview_of(ADMINS_AND_CONTRACTORS_FILE, &["delete_user", "get_user"], &[]);

        let table = tool_gate_preview_table(&gating, &previewed, &warnings);

        assert_eq!(
            table,
            "TOOL         CONDITION                            RESULT  DECIDED BY\n\
             delete_user  admins met, contractors met          DENY    Tool Gate 2\n\
             delete_user  admins met, contractors not met      ALLOW   Tool Gate 1\n\
             delete_user  admins not met, contractors met      DENY    Tool Gate 2\n\
             delete_user  admins not met, contractors not met  DENY    default (deny)\n\
             get_user     either way                           DENY    default (deny)\n"
        );
    }

    #[test]
    fn tool_gate_preview_table_lists_what_was_pinned_above_the_table() {
        let (gating, previewed, warnings) = preview_of(ADMINS_AND_CONTRACTORS_FILE, &["delete_user"], &["admins=met"]);

        let table = tool_gate_preview_table(&gating, &previewed, &warnings);

        assert_eq!(
            table,
            "Assuming: admins met\n\
             \n\
             TOOL         CONDITION            RESULT  DECIDED BY\n\
             delete_user  contractors met      DENY    Tool Gate 2\n\
             delete_user  contractors not met  ALLOW   Tool Gate 1\n"
        );
    }

    #[test]
    fn tool_gate_preview_table_leaves_out_the_condition_column_when_it_makes_no_difference() {
        let (gating, previewed, warnings) = preview_of(
            r#"{"default_effect":"deny","gates":[{"name":"Reads","action":{"effect":"allow","patterns":["^get_"]}}]}"#,
            &["get_user", "delete_user"],
            &[],
        );

        let table = tool_gate_preview_table(&gating, &previewed, &warnings);

        assert_eq!(
            table,
            "TOOL         RESULT  DECIDED BY\n\
             get_user     ALLOW   Reads\n\
             delete_user  DENY    default (deny)\n"
        );
    }

    #[test]
    fn tool_gate_preview_table_lists_warnings_under_a_heading() {
        let (gating, previewed, warnings) = preview_of(
            r#"{"gates":[{"name":"Blocker","action":{"effect":"deny","patterns":["delete_(", "delete_"]}}]}"#,
            &["undelete_draft"],
            &[],
        );

        let table = tool_gate_preview_table(&gating, &previewed, &warnings);

        assert!(
            table.contains("\nWarnings\n  - 'Blocker' has a pattern that is not valid regex ('delete_(')."),
            "{table}"
        );
        assert!(table.contains("so it also catches 'undelete_draft'"), "{table}");
        assert!(table.contains("undelete_draft  DENY    Blocker"), "{table}");
    }

    #[test]
    fn tool_gate_preview_json_carries_conditions_assumptions_and_warnings() {
        let (gating, previewed, warnings) =
            preview_of(ADMINS_AND_CONTRACTORS_FILE, &["delete_user", "get_user"], &["admins=met"]);

        let value = tool_gate_preview_json(&gating, &previewed, &warnings);

        assert_eq!(
            value,
            json!({
                "default_effect": "deny",
                "assumed": {"admins": "met"},
                "tools": [
                    {"tool": "delete_user", "results": [
                        {"conditions": {"contractors": "met"}, "result": "deny", "decided_by": "Tool Gate 2"},
                        {"conditions": {"contractors": "unmet"}, "result": "allow", "decided_by": "Tool Gate 1"}
                    ]},
                    {"tool": "get_user", "results": [
                        {"conditions": {}, "result": "deny", "decided_by": null}
                    ]}
                ],
                "warnings": []
            })
        );
    }

    #[test]
    fn tool_gate_preview_help_ends_with_examples() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        let help = cli
            .find_subcommand_mut("agent-gateway")
            .and_then(|command| command.find_subcommand_mut("surfaces"))
            .and_then(|command| command.find_subcommand_mut("tool-gate-preview"))
            .expect("tool-gate-preview exists")
            .render_long_help()
            .to_string();

        assert!(help.contains("Examples:\n  Check the gates a surface has saved, named by its name or ID:"), "{help}");
        assert!(help.contains("--condition admins=met --condition contractors=unmet"), "{help}");
        assert!(
            help.trim_end()
                .ends_with("a single row and the CONDITION column is left out."),
            "{help}"
        );
    }

    #[test]
    fn tool_gate_preview_takes_repeatable_conditions() {
        let Command::Surfaces {
            command: SurfaceCommand::ToolGatePreview(args),
        } = command_of(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "s-1",
            "--tool",
            "a",
            "--condition",
            "admins=met",
            "--condition",
            "contractors=unmet",
        ])
        else {
            panic!("expected tool-gate-preview");
        };

        assert_eq!(args.conditions, ["admins=met", "contractors=unmet"]);
    }

    #[test]
    fn tool_gate_preview_refuses_bad_conditions_and_more_than_three_unpinned() {
        let gating = tool_gate_preview::read_gating_config(
            &serde_json::from_str(ADMINS_AND_CONTRACTORS_FILE).expect("gating JSON"),
            "mcp_tool_gating",
        )
        .expect("gating reads");
        let gates: Vec<Value> = ["a", "b", "c", "d"]
            .iter()
            .map(|policy| {
                json!({
                    "condition_policy_definition_id": policy,
                    "action": {"effect": "deny", "patterns": ["^x"]}
                })
            })
            .collect();
        let four_policies =
            tool_gate_preview::read_gating_config(&json!({ "gates": gates }), "mcp_tool_gating").expect("gating reads");
        let tools = ["delete_user".to_owned()];
        let render = |gating: &Gating, conditions: &[&str]| {
            let conditions: Vec<String> = conditions
                .iter()
                .map(|condition| (*condition).to_owned())
                .collect();
            render_tool_gate_preview(gating, &tools, &conditions, Vec::new(), Output::Table)
                .expect_err("the preview is refused")
                .to_string()
        };

        assert!(render(&gating, &["admin=met"]).starts_with("--condition names 'admin'"));
        assert!(render(&gating, &["admins"]).starts_with("--condition 'admins' should be"));
        assert!(render(&four_policies, &[]).starts_with("4 condition policies are not pinned (a, b, c, d)"));
    }

    #[test]
    fn a_gates_file_that_is_not_valid_is_refused_with_the_field() {
        let file = json_file(r#"{"gates":[{"action":{"effect":"block"}}]}"#);

        let error = read_gates_file(file.path())
            .expect_err("block is not an effect")
            .to_string();

        assert_eq!(error, "mcp_tool_gating.gates.0.action.effect should be 'allow' or 'deny', found 'block'");
    }

    #[test]
    fn a_preview_with_only_blank_tool_names_is_refused() {
        let error = render_tool_gate_preview(
            &Gating {
                denies_by_default: false,
                gates: Vec::new(),
            },
            &[" ".to_owned(), String::new()],
            &[],
            Vec::new(),
            Output::Table,
        )
        .expect_err("a preview needs a tool")
        .to_string();

        assert_eq!(error, "--tool needs at least one tool name");
    }

    #[tokio::test]
    async fn tool_gate_preview_with_a_gates_file_runs_offline_through_the_real_entry_point() {
        let (host, requests) = scripted_server(vec![]).await;
        let file = json_file(DELETE_GATE_FILE);
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "--gates-file",
            file.path()
                .to_str()
                .expect("path"),
            "--tool",
            "delete_user,get_user",
            "--condition",
            "non-admins=met",
            "--host",
            host.as_str(),
            "--token",
            "agpat_valid",
            "-o",
            "json",
        ])
        .expect("arguments should parse");

        run(cli)
            .await
            .expect("the preview should succeed with no saved connection");

        assert!(request_lines(requests).is_empty(), "a gates file never contacts a gateway");
    }

    #[test]
    fn only_a_gates_file_preview_is_run_offline() {
        let file = json_file(DELETE_GATE_FILE);
        let path = file
            .path()
            .to_str()
            .expect("path");
        let parse = |args: &[&str]| {
            let mut all = vec!["fabric", "agent-gateway"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all)
                .expect("arguments should parse")
                .into_agent_gateway()
        };

        assert!(run_offline(&parse(&["surfaces", "tool-gate-preview", "--gates-file", path, "--tool", "a"])).is_some());
        assert!(run_offline(&parse(&["surfaces", "tool-gate-preview", "s-1", "--tool", "a"])).is_none());
        assert!(run_offline(&parse(&["surfaces", "list"])).is_none());
    }

    #[tokio::test]
    async fn tool_gate_preview_with_a_surface_reads_it_and_changes_nothing() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", GATED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        preview_saved_surface(&client, "s-1", &["get_user".to_owned()], &[], Output::Table)
            .await
            .expect("the preview should succeed");

        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn tool_gate_preview_of_a_missing_surface_fails() {
        let (host, _) = scripted_server(vec![("HTTP/1.1 404 Not Found", r#"{"error":"not found"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        preview_saved_surface(&client, "s-9", &["a".to_owned()], &[], Output::Table)
            .await
            .expect_err("a surface that does not exist has no gates to preview");
    }

    const GATING_OVERRIDE: &str = r#"{"default_effect":"deny","gates":[]}"#;

    fn surface_with_variants(
        variants: &str,
        default_variant_id: Option<&str>,
    ) -> Value {
        let mut surface = json!({
            "surface_id": "s-1",
            "variants": serde_json::from_str::<Value>(variants).expect("variants JSON"),
            "target": {"mcp_tool_gating": {"gates": [{"action": {"effect": "deny", "patterns": ["^delete_"]}}]}}
        });
        if let Some(id) = default_variant_id {
            surface["default_variant_id"] = json!(id);
        }
        surface
    }

    fn surface_preview_text(surface: &Value) -> String {
        render_surface_tool_gate_preview(surface, &["delete_user".to_owned()], &[], Output::Table).expect("renders")
    }

    #[test]
    fn a_default_variant_that_sets_its_own_gating_says_the_preview_does_not_match_the_gateway() {
        let variants = format!(
            r#"[{{"id":"v1","alias":"blue","overrides":{{"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}}]"#
        );

        let table = surface_preview_text(&surface_with_variants(&variants, Some("v1")));

        let note = "The default variant 'blue' sets its own tool gating, and the gateway builds the surface's gating from the default variant, so this preview does not match what the gateway serves.";
        assert!(table.contains(&format!("\nWarnings\n  - {note}\n")), "{table}");
    }

    #[test]
    fn a_complete_default_variant_with_no_gating_says_the_gateway_serves_no_gates() {
        let variants = r#"[{"id":"v1","alias":"blue","overrides":{"complete":true,"target":{"endpoint":"http://x"}}}]"#;

        let table = surface_preview_text(&surface_with_variants(variants, Some("v1")));

        assert!(
            table.contains(
                "The default variant 'blue' is complete and has no tool gating, and the gateway builds the surface's gating from the default variant, so the gateway serves no gates and this preview does not match."
            ),
            "{table}"
        );
    }

    #[test]
    fn a_complete_default_variant_with_no_target_keeps_the_saved_gating_and_gives_no_note() {
        let variants = r#"[{"id":"v1","alias":"blue","overrides":{"complete":true}},{"id":"v2","alias":"green","overrides":{"complete":true,"target":null}}]"#;

        let table = surface_preview_text(&surface_with_variants(variants, Some("v1")));

        assert!(!table.contains("variant"), "{table}");
    }

    #[test]
    fn a_disabled_variant_gives_no_note_because_the_gateway_skips_it() {
        let variants = format!(
            r#"[{{"id":"v1","alias":"blue","enabled":false,"overrides":{{"complete":true,"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}},{{"id":"v2","alias":"green","enabled":false,"overrides":{{"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}},{{"id":"v3","alias":"plain","enabled":false,"overrides":{{"complete":true,"target":{{"endpoint":"http://x"}}}}}}]"#
        );

        let table = surface_preview_text(&surface_with_variants(&variants, Some("v1")));

        assert!(!table.contains("variant"), "{table}");
    }

    #[test]
    fn a_complete_variant_that_is_not_the_default_and_has_no_gating_is_named() {
        let variants = r#"[{"id":"v1","alias":"blue"},{"id":"v2","alias":"green","overrides":{"complete":true,"target":{"endpoint":"http://x"}}},{"id":"v3","alias":"plain","overrides":{"complete":true}}]"#;

        let table = surface_preview_text(&surface_with_variants(variants, Some("v1")));

        assert!(
            table.contains(
                "The variant 'green' is complete and has no tool gating, so the gateway serves it with no gates and this preview does not match."
            ),
            "{table}"
        );
        assert!(!table.contains("'plain'"), "{table}");
        assert!(!table.contains("default variant"), "{table}");
    }

    #[test]
    fn a_variant_that_is_not_the_default_and_sets_gating_is_named() {
        let variants = format!(
            r#"[{{"id":"v1","alias":"blue","overrides":{{"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}},{{"id":"v2","alias":"green","overrides":{{"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}},{{"id":"v3","alias":"plain"}}]"#
        );

        let table = surface_preview_text(&surface_with_variants(&variants, Some("v3")));

        assert!(
            table.contains(
                "The variants 'blue', 'green' set their own tool gating, and this preview reads only the surface's gating."
            ),
            "{table}"
        );
        assert!(!table.contains("default variant"), "{table}");
    }

    #[test]
    fn variants_that_leave_gating_alone_give_no_note() {
        let variants = r#"[{"id":"v1","alias":"blue","overrides":{"target":{"endpoint":"http://x"}}},{"id":"v2","alias":"green","overrides":{"access_point":{"publish_to_did_document":true}}},{"id":"v3","alias":"empty","overrides":{"target":{"mcp_tool_gating":null}}}]"#;

        let table = surface_preview_text(&surface_with_variants(variants, Some("v1")));
        let none = surface_preview_text(&surface_with_variants("[]", None));

        assert!(!table.contains("variant"), "{table}");
        assert!(!none.contains("variant"), "{none}");
    }

    #[test]
    fn a_variant_note_reaches_the_json_output() {
        let variants = format!(
            r#"[{{"id":"v1","alias":"blue","overrides":{{"target":{{"mcp_tool_gating":{GATING_OVERRIDE}}}}}}}]"#
        );
        let surface = surface_with_variants(&variants, None);

        let text = render_surface_tool_gate_preview(&surface, &["delete_user".to_owned()], &[], Output::Json)
            .expect("renders");

        let value: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(
            value["warnings"][0],
            "The variant 'blue' sets its own tool gating, and this preview reads only the surface's gating."
        );
    }

    #[test]
    fn padded_and_repeated_tool_names_give_one_row() {
        let gating = tool_gate_preview::read_gating_config(
            &serde_json::from_str::<Value>(DELETE_GATE_FILE).expect("gating JSON"),
            "mcp_tool_gating",
        )
        .expect("gating reads");
        let Command::Surfaces {
            command: SurfaceCommand::ToolGatePreview(args),
        } = command_of(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "tool-gate-preview",
            "--gates-file",
            "g.json",
            "--tool",
            "delete_user, delete_user",
            "--tool",
            " delete_user ",
        ])
        else {
            panic!("expected tool-gate-preview");
        };

        let table =
            render_tool_gate_preview(&gating, &args.tools, &["non-admins=met".to_owned()], Vec::new(), Output::Table)
                .expect("renders");

        assert_eq!(args.tools.len(), 3);
        assert_eq!(
            table
                .matches("delete_user")
                .count(),
            1,
            "{table}"
        );
    }

    #[test]
    fn the_json_output_is_one_document_with_a_trailing_newline() {
        let gating = tool_gate_preview::read_gating_config(
            &serde_json::from_str::<Value>(DELETE_GATE_FILE).expect("gating JSON"),
            "mcp_tool_gating",
        )
        .expect("gating reads");
        let tools = ["delete_user".to_owned(), "get_user".to_owned()];

        let text = render_tool_gate_preview(&gating, &tools, &["non-admins=met".to_owned()], Vec::new(), Output::Json)
            .expect("renders");

        assert!(text.ends_with("}\n"), "{text}");
        let value: Value = serde_json::from_str(&text).expect("one JSON document");
        assert_eq!(value["default_effect"], "allow");
        assert_eq!(value["assumed"], json!({"non-admins": "met"}));
        assert_eq!(value["tools"][0]["tool"], "delete_user");
        assert_eq!(value["tools"][0]["results"][0]["result"], "deny");
        assert_eq!(value["tools"][0]["results"][0]["decided_by"], "Tool Gate 1");
        assert_eq!(value["tools"][1]["results"][0]["result"], "allow");
        assert_eq!(value["warnings"], json!([]));
    }

    struct NoCredentials;

    impl CredentialStore for NoCredentials {
        fn get_token(
            &self,
            _connection: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        fn set_token(
            &self,
            _connection: &str,
            _token: &str,
        ) -> Result<()> {
            bail!("the test credential store is read only")
        }

        fn delete_token(
            &self,
            _connection: &str,
        ) -> Result<()> {
            bail!("the test credential store is read only")
        }
    }

    #[tokio::test]
    async fn tool_gate_preview_with_a_surface_name_reads_it_through_the_command_dispatch() {
        let (host, requests) = scripted_server(vec![LIST_OK, ("HTTP/1.1 200 OK", GATED_SURFACE)]).await;
        let config = crate::config::Config {
            current: Some("default".to_owned()),
            connections: [("default".to_owned(), crate::config::Connection::new(host))].into(),
        };
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "--token",
            "agpat_valid",
            "surfaces",
            "tool-gate-preview",
            "Sales",
            "--tool",
            "get_user, delete_user",
        ])
        .expect("arguments parse");

        dispatch_with(cli.into_agent_gateway(), config, &NoCredentials)
            .await
            .expect("the preview should succeed");

        assert_eq!(request_lines(requests), [LIST_REQUEST, "GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn remove_feature_dry_run_only_sends_the_dry_run_patch() {
        let (host, requests) = scripted_server(vec![
            (
                DRY_RUN_GATEWAY_OK,
                r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","rate_limit":{"requests":100}},"target":{"endpoint":"http://127.0.0.1:3000"}}"#,
            ),
            ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1","name":"Sales"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = surface_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "remove-feature",
            "s-1",
            "rate-limit",
            "--dry-run",
        ]);

        let value = run_surfaces(&client, command, Output::Table)
            .await
            .expect("the dry run should succeed");

        assert_eq!(value, None, "the report is printed by the dry run itself");
        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1?dry_run=true HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn surface_update_dry_run_reports_a_refused_edit_like_a_real_one() {
        let (host, _) = scripted_server(vec![
            (DRY_RUN_GATEWAY_OK, STORED_SURFACE),
            (
                "HTTP/1.1 400 Bad Request",
                r#"{"error":"Bad Request","details":"Policy definition reference is not accessible"}"#,
            ),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_surfaces(
            &client,
            surface_edit(&["target.policy.policy_definition_id=missing"], &[], &[], &[], true),
            Output::Json,
        )
        .await
        .expect_err("the gateway refuses the edit");

        assert_eq!(exit_code(&error), 1);
        assert!(format!("{error:#}").contains("Policy definition reference is not accessible"), "{error:#}");
    }

    #[test]
    fn dry_run_json_holds_the_patch_and_both_surfaces() {
        let patch = json!({"name": "Billing"});
        let before = json!({"name": "Sales"});
        let after = json!({"name": "Billing", "status": "enabled"});

        assert_eq!(
            dry_run_json(&patch, &before, &DryRunResult::Gateway(after.clone())),
            json!({"dry_run": true, "checked": "gateway", "patch": patch, "before": before, "after": after})
        );
        let local = dry_run_json(
            &patch,
            &before,
            &DryRunResult::Local {
                after: after.clone(),
                reason: "no answer".to_owned(),
            },
        );
        assert_eq!(local["checked"], "local");
        assert!(
            local["warning"]
                .as_str()
                .is_some_and(|warning| warning.contains("no answer")),
            "{local}"
        );
        assert_eq!(local["after"], after);
    }

    #[test]
    fn dry_run_refused_by_the_local_check_reports_the_patch_and_the_error() {
        let patch = json!({"target": {"endpoint": null}});
        let before = json!({"name": "Sales", "target": {"endpoint": "http://127.0.0.1:3000"}});
        let result = DryRunResult::Refused {
            after: json!({"name": "Sales", "target": {}}),
            error: "target.endpoint is required".to_owned(),
        };

        assert_eq!(
            dry_run_json(&patch, &before, &result),
            json!({
                "dry_run": true,
                "checked": "local",
                "error": "target.endpoint is required",
                "patch": patch,
                "before": before,
                "after": {"name": "Sales", "target": {}},
            })
        );
        assert_eq!(
            dry_run_table(&patch, &before, &result).expect("table"),
            "Patch:\n{\n  \"target\": {\n    \"endpoint\": null\n  }\n}\n\n\
             Changes (checked on this machine only):\n  target.endpoint: \"http://127.0.0.1:3000\" -> (absent)\n\n\
             Dry run: nothing was saved.\n"
        );
    }

    #[test]
    fn dry_run_table_lists_only_the_changed_paths() {
        let patch = json!({"access_point": {"route": "billing"}});
        let before = json!({"name": "Sales", "access_point": {"route": "/sales", "listen_address": "0.0.0.0:8080"}});
        let after = json!({"name": "Sales", "access_point": {"route": "/billing", "listen_address": "0.0.0.0:8080"}});

        let table = dry_run_table(&patch, &before, &DryRunResult::Gateway(after)).expect("table");

        assert_eq!(
            table,
            "Patch:\n{\n  \"access_point\": {\n    \"route\": \"billing\"\n  }\n}\n\n\
             Changes (checked by the gateway):\n  access_point.route: \"/sales\" -> \"/billing\"\n\n\
             Dry run: nothing was saved.\n"
        );
    }

    #[tokio::test]
    async fn runtime_reload_names_a_surface_id_nothing_is_stored_under() {
        let (host, requests) = scripted_server(vec![
            (
                "HTTP/1.1 500 Internal Server Error",
                r#"{"error":"Internal Server Error","details":"Failed to reload channel 'missing': Surface with config_id 'missing' not found in local storage"}"#,
            ),
            ("HTTP/1.1 404 Not Found", r#"{"error":"Not Found","details":"Surface 'missing' not found"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_runtime(
            &client,
            RuntimeCommand::Reload {
                surface: Some("missing".to_owned()),
            },
        )
        .await
        .expect_err("reloading an unknown surface should fail");

        let text = error.to_string();
        assert!(text.contains("'missing' not found"), "got: {text}");
        assert!(
            text.contains("fabric agent-gateway surfaces list"),
            "the error should say where the ids are, got: {text}"
        );
        // The lookup can disagree with the reload's configuration source, so
        // the gateway's own error stays underneath as the cause.
        assert_eq!(error.chain().count(), 2, "got: {error:#}");
        assert_eq!(response_status(&error), Some(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(
            request_lines(requests),
            ["POST /api/v1/config/reload/missing HTTP/1.1", "GET /api/v1/surfaces/missing HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn runtime_reload_keeps_the_gateway_error_unless_the_surface_is_missing() {
        // The surface exists, or the lookup is itself refused: the reload
        // failed for a reason the lookup cannot explain.
        for lookup in [("HTTP/1.1 200 OK", r#"{"surface_id":"surface-1"}"#), ("HTTP/1.1 403 Forbidden", "")] {
            let (host, requests) = scripted_server(vec![
                (
                    "HTTP/1.1 500 Internal Server Error",
                    r#"{"error":"Internal Server Error","details":"Failed to reload channel 'surface-1': Could not map channel listen_address to internal port: 0.0.0.0:8080"}"#,
                ),
                lookup,
            ])
            .await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");

            let error = run_runtime(
                &client,
                RuntimeCommand::Reload {
                    surface: Some("surface-1".to_owned()),
                },
            )
            .await
            .expect_err("the reload failure should surface");

            // The gateway's own error, untouched: no diagnosis added above it.
            assert_eq!(response_status(&error), Some(StatusCode::INTERNAL_SERVER_ERROR));
            assert_eq!(error.chain().count(), 1, "got: {error:#}");
            assert!(
                !error
                    .to_string()
                    .contains("not found"),
                "got: {error:#}"
            );
            assert_eq!(
                request_lines(requests),
                ["POST /api/v1/config/reload/surface-1 HTTP/1.1", "GET /api/v1/surfaces/surface-1 HTTP/1.1"]
            );
        }
    }

    #[tokio::test]
    async fn runtime_reload_looks_nothing_up_after_a_refusal() {
        // A resource-scoped token is refused the reload with 403 and answered
        // 404 for a surface outside its scope, so a lookup would misreport an
        // existing surface as missing.
        let (host, requests) = scripted_server(vec![(
            "HTTP/1.1 403 Forbidden",
            r#"{"error":"missing permission 'config.reload'","required_permission":"config.reload"}"#,
        )])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_runtime(
            &client,
            RuntimeCommand::Reload {
                surface: Some("surface-1".to_owned()),
            },
        )
        .await
        .expect_err("a refused reload should fail");

        assert_eq!(error.to_string(), "missing permission 'config.reload'");
        assert_eq!(request_lines(requests), ["POST /api/v1/config/reload/surface-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn user_settings_overrides_reads_the_overrides_route() {
        let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        run_user_settings(&client, UserSettingsCommand::Show { overrides: true })
            .await
            .expect("overrides read should succeed");

        assert_eq!(request_line(request).await, "GET /api/v1/user-settings/overrides HTTP/1.1");
    }

    #[tokio::test]
    async fn saving_a_terms_draft_uses_put_not_post() {
        let (host, request) = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let file = json_file(r#"{"version":"2026-09","title":"Customer terms","url":"https://example.com/terms.pdf"}"#);

        run_terms(
            &client,
            TermsCommand::Draft(JsonFileArgs {
                file: file.path().to_path_buf(),
            }),
            Output::Table,
        )
        .await
        .expect("draft save should succeed");

        assert_eq!(request_line(request).await, "PUT /api/v1/terms/customer/draft HTTP/1.1");
    }

    #[tokio::test]
    async fn setting_the_welcome_template_uses_put_not_post() {
        let (host, request) = one_shot_server("HTTP/1.1 204 No Content", "").await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let file = json_file(r#"{"title":"Welcome","message":"Hello"}"#);

        run_notifications(
            &client,
            NotificationCommand::WelcomeTemplate {
                command: WelcomeTemplateCommand::Set(JsonFileArgs {
                    file: file.path().to_path_buf(),
                }),
            },
            Output::Table,
        )
        .await
        .expect("template update should succeed");

        assert_eq!(request_line(request).await, "PUT /api/v1/notifications/user-welcome-template HTTP/1.1");
    }

    fn send_welcome_to(user_id: &str) -> NotificationCommand {
        NotificationCommand::SendWelcome(SendWelcomeArgs {
            user_id: user_id.to_owned(),
            title: "Welcome".to_owned(),
            message: "Hello".to_owned(),
        })
    }

    #[tokio::test]
    async fn send_welcome_refuses_a_recipient_the_gateway_does_not_know() {
        // The gateway's own 404 here is a bare plain-text body.
        let (host, requests) = scripted_server(vec![("HTTP/1.1 404 Not Found", "User not found")]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_notifications(&client, send_welcome_to("nobody"), Output::Table)
            .await
            .expect_err("a notification for no user should not be sent");

        let text = error.to_string();
        assert!(text.contains("'nobody' not found"), "got: {text}");
        assert!(text.contains("Nothing was sent"), "got: {text}");
        assert_eq!(request_lines(requests), ["GET /api/v1/users/nobody HTTP/1.1"]);
    }

    #[tokio::test]
    async fn send_welcome_sends_to_a_recipient_the_gateway_knows() {
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 200 OK", r#"{"user_id":"user-1","username":"someone"}"#),
            ("HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let value = run_notifications(&client, send_welcome_to("user-1"), Output::Table)
            .await
            .expect("send-welcome should succeed");

        assert_eq!(value, None);
        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/users/user-1 HTTP/1.1", "POST /api/v1/notifications/send-welcome HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn send_welcome_warns_and_sends_when_the_caller_cannot_read_users() {
        // Sending needs no permission, reading another user needs `users.view`,
        // so a caller allowed to send can be refused the lookup.
        let (host, requests) = scripted_server(vec![
            ("HTTP/1.1 403 Forbidden", "Insufficient permissions"),
            ("HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        run_notifications(&client, send_welcome_to("user-1"), Output::Table)
            .await
            .expect("an unverifiable recipient should still be sent to");

        assert_eq!(
            request_lines(requests),
            ["GET /api/v1/users/user-1 HTTP/1.1", "POST /api/v1/notifications/send-welcome HTTP/1.1"]
        );

        let (host, _requests) = scripted_server(vec![("HTTP/1.1 403 Forbidden", "Insufficient permissions")]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let warnings = unverified_recipient_warning(&client, "user-1")
            .await
            .expect("a refused lookup is a warning, not an error");
        assert_eq!(warnings.len(), 1);
        for expected in ["could not verify that user 'user-1' exists", "users.view", "Insufficient permissions"] {
            assert!(warnings[0].contains(expected), "the warning should mention {expected}, got: {}", warnings[0]);
        }
    }

    #[tokio::test]
    async fn send_welcome_sends_nothing_when_the_lookup_fails_otherwise() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 500 Internal Server Error", "")]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_notifications(&client, send_welcome_to("user-1"), Output::Table)
            .await
            .expect_err("an unexplained lookup failure should stop the send");

        let text = format!("{error:#}");
        assert!(text.contains("could not look up user 'user-1' before sending; nothing was sent"), "got: {text}");
        assert!(text.contains("500"), "the cause should follow, got: {text}");
        assert_eq!(request_lines(requests), ["GET /api/v1/users/user-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn an_empty_success_body_is_suppressed_in_table_mode_only() {
        // Table mode prints the confirmation and returns nothing to print;
        // JSON mode returns the empty document the gateway actually sent.
        for (output, expected) in [(Output::Table, None), (Output::Json, Some(Value::Null))] {
            let (host, request) = one_shot_server("HTTP/1.1 204 No Content", "").await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");

            let value = run_terms(&client, TermsCommand::Deactivate, output)
                .await
                .expect("deactivate should succeed");

            assert_eq!(request_line(request).await, "POST /api/v1/terms/customer/deactivate HTTP/1.1");
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn confirm_empty_never_rewrites_a_document_the_gateway_sent() {
        // A real body is passed through untouched, so the 204 assumption is
        // never hard-coded into a command that might answer with content.
        let sent = json!({"title": "Welcome", "message": "Hello"});
        assert_eq!(confirm_empty(sent.clone(), "ignored", Output::Table), Some(sent.clone()));
        assert_eq!(confirm_empty(sent.clone(), "ignored", Output::Json), Some(sent));
        // JSON mode keeps the empty document, matching every other command.
        assert_eq!(confirm_empty(Value::Null, "ignored", Output::Json), Some(Value::Null));
        // Table mode prints the confirmation itself and suppresses the output,
        // so `null` never reaches standard output.
        assert_eq!(confirm_empty(Value::Null, "confirmed", Output::Table), None);
    }

    #[tokio::test]
    async fn a_terms_command_error_gets_exactly_one_hint_from_the_top_level_mapping() {
        let (host, _request) = one_shot_server("HTTP/1.1 404 Not Found", r#"{"code":"TERMS_DISABLED"}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");

        let error = run_terms(&client, TermsCommand::Show, Output::Table)
            .await
            .expect_err("a disabled terms feature should surface as an error");
        // `run` applies the hint to every command, so the terms commands must
        // not add their own and print it twice.
        assert_eq!(error.to_string(), r#"{"code":"TERMS_DISABLED"}"#);

        let printed = format!("{:#}", add_terms_hint(error));
        assert_eq!(
            printed
                .matches("switched off")
                .count(),
            1,
            "got: {printed}"
        );
        assert!(printed.ends_with(r#"{"code":"TERMS_DISABLED"}"#), "the gateway's answer should follow: {printed}");
    }

    #[tokio::test]
    async fn an_unaccepted_terms_refusal_is_explained_on_any_command() {
        // A session whose user has not accepted the Terms is refused every
        // route outside the gateway's consent list with this code-only body.
        let (host, _request) =
            one_shot_server("HTTP/1.1 403 Forbidden", r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#).await;
        let client = GatewayClient::new(host, "session-token").expect("client");

        let error = run_settings(&client, SettingsCommand::Show)
            .await
            .expect_err("the Terms gate should refuse the call");

        let printed = format!("{:#}", add_terms_hint(error));
        for expected in [
            "has not accepted the gateway's Terms and Conditions",
            "dashboard",
            "`fabric agent-gateway api post /v1/terms/acceptances --file <json>`",
            "`fabric agent-gateway terms status`",
        ] {
            assert!(printed.contains(expected), "the hint should mention {expected}, got: {printed}");
        }
        assert_eq!(
            printed
                .matches("has not accepted")
                .count(),
            1,
            "got: {printed}"
        );
    }

    #[test]
    fn every_terms_code_gets_its_own_hint() {
        for (code, expected) in [
            ("TERMS_ACCEPTANCE_REQUIRED", "has not accepted the gateway's Terms and Conditions"),
            ("TERMS_DISABLED", "switched off"),
            ("TERMS_VERSION_STALE", "re-read `fabric agent-gateway terms show`"),
            ("TERMS_DRAFT_REQUIRED", "no saved draft to publish"),
            ("TERMS_OPERATIONAL_FAILURE", "`fabric agent-gateway terms provider-health`"),
        ] {
            let body = format!(r#"{{"code":"{code}"}}"#);
            let hinted = format!("{:#}", add_terms_hint(anyhow::anyhow!("{body}")));
            assert!(hinted.contains(expected), "{code} should be explained with {expected}, got: {hinted}");
            assert!(hinted.ends_with(&body), "{code}: the gateway's answer should follow the hint, got: {hinted}");
        }
    }

    #[test]
    fn a_terms_code_under_added_context_still_gets_its_hint() {
        let error = anyhow::Error::msg(r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#)
            .context("the appliance settings were saved, but reading them back failed");
        let hinted = format!("{:#}", add_terms_hint(error));
        assert!(hinted.starts_with("this user has not accepted"), "got: {hinted}");
    }

    #[test]
    fn an_unrelated_error_is_left_unchanged() {
        let hinted = add_terms_hint(anyhow::anyhow!("gateway returned 500 Internal Server Error: boom"));
        assert_eq!(format!("{hinted:#}"), "gateway returned 500 Internal Server Error: boom");
        assert_eq!(hinted.chain().count(), 1);
    }

    #[tokio::test]
    async fn send_welcome_stops_at_an_unaccepted_terms_refusal_instead_of_warning() {
        // The send would be refused the same way, so a users.view warning
        // would only mislead.
        let (host, requests) =
            scripted_server(vec![("HTTP/1.1 403 Forbidden", r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#)]).await;
        let client = GatewayClient::new(host, "session-token").expect("client");

        let error = run_notifications(&client, send_welcome_to("user-1"), Output::Table)
            .await
            .expect_err("the Terms gate should stop the send");

        assert_eq!(error.to_string(), r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#);
        assert_eq!(request_lines(requests), ["GET /api/v1/users/user-1 HTTP/1.1"]);
    }
}

async fn run_crud(
    client: &GatewayClient,
    base: &str,
    command: CrudCommand,
) -> Result<Value> {
    match command {
        CrudCommand::List => {
            client
                .request(Method::GET, base, None)
                .await
        }
        CrudCommand::Get { id } => {
            client
                .request(Method::GET, &entity_path(base, &id), None)
                .await
        }
        CrudCommand::Create(args) => {
            client
                .request(Method::POST, base, Some(read_json(&args.file)?))
                .await
        }
        CrudCommand::Update { id, file } => {
            client
                .request(Method::PUT, &entity_path(base, &id), Some(read_json(&file)?))
                .await
        }
        CrudCommand::Delete { id } => {
            client
                .request(Method::DELETE, &entity_path(base, &id), None)
                .await
        }
    }
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// List secrets. List responses never carry secret values.
    List {
        /// Only list secrets carrying this tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// Get a secret by its id, secret_id or name, including its value.
    Get {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
    /// Create a secret using flags or a complete JSON document.
    Create(SecretCreateArgs),
    /// Update a secret from a JSON document.
    Update {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a secret by its id, secret_id or name.
    Delete {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
}

#[derive(Debug, Args)]
struct SecretCreateArgs {
    /// Human-readable name.
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    /// Machine-readable identifier used by $SECRET:<secret-id> references.
    #[arg(long, required_unless_present = "file")]
    secret_id: Option<String>,
    /// Secret value, stored exactly as given including any whitespace.
    #[arg(long, conflicts_with = "value_stdin")]
    value: Option<String>,
    /// Read the secret value from standard input.
    #[arg(long)]
    value_stdin: bool,
    /// What the secret is for.
    #[arg(long)]
    description: Option<String>,
    /// Secret type, as configured on the gateway. Omit for the gateway
    /// default.
    #[arg(long = "type")]
    secret_type: Option<String>,
    /// Tag to attach. Repeat for multiple tags.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Complete CreateSecretRequest JSON. Use '-' to read from standard
    /// input. Other creation flags are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum DelegationVaultCommand {
    /// List delegated credential grants.
    List,
    /// Get a grant by ID.
    Get { id: String },
    /// Revoke a single grant by ID.
    Revoke { id: String },
    /// Revoke every grant held for one user identity hash (sha256:...).
    #[command(name = "revoke-user")]
    RevokeUser { user_hash: String },
}

const CERTIFICATES_PATH: &str = "/v1/certificates";
const SECRETS_PATH: &str = "/v1/secrets";
const SURFACES_PATH: &str = "/v1/surfaces";
const DELEGATION_VAULT_PATH: &str = "/v1/delegation-vault";

/// Stand-in printed in place of a credential the caller did not ask to see.
const MASKED_VALUE: &str = "<hidden; pass --reveal to show>";

/// Where the CLI looks up an entity the caller named by its `id` (the field
/// called `id_field`) or by any of `names`, for a collection whose entity
/// routes accept only the ID. `view` is the permission the list needs and
/// `list_command` is what to run to see the entities.
struct Lookup {
    base: &'static str,
    noun: &'static str,
    id_field: &'static str,
    list_command: &'static str,
    names: &'static [&'static str],
    view: &'static str,
}

const SECRET_LOOKUP: Lookup = Lookup {
    base: SECRETS_PATH,
    noun: "secret",
    id_field: "id",
    list_command: "fabric agent-gateway secrets list",
    names: &["secret_id", "name"],
    view: "secrets.view",
};

/// `certificate_id` is deliberately absent: it is a second UUID the gateway
/// never uses as a lookup key.
const CERTIFICATE_LOOKUP: Lookup = Lookup {
    base: CERTIFICATES_PATH,
    noun: "certificate",
    id_field: "id",
    list_command: "fabric agent-gateway certificates list",
    names: &["name"],
    view: "certificates.view",
};

const SURFACE_LOOKUP: Lookup = Lookup {
    base: SURFACES_PATH,
    noun: "surface",
    id_field: "surface_id",
    list_command: "fabric agent-gateway surfaces list",
    names: &["name"],
    view: "surfaces.view",
};

/// `CrudCommand` is shared with resources whose routes take only the raw ID,
/// so the certificates command rewrites the help of the subcommands that
/// resolve a name instead of changing the shared definitions.
fn certificate_reference_help(about: &'static str) -> impl FnOnce(clap::Command) -> clap::Command {
    move |subcommand| {
        subcommand
            .about(about)
            .mut_arg("id", |id| {
                id.value_name("CERTIFICATE")
                    .help("The certificate's id or name. A name shared by several certificates is refused; pass the id instead")
            })
    }
}

/// Runs the certificates commands through the shared CRUD flow, except
/// `update`, which sends its own `PUT` so its document is checked before the
/// lookup. It then hides the stored private key, which `GET {id}`, `POST` and
/// `PUT` all return in full. `get`, `update` and `delete` first resolve the
/// caller's id or name to the `id` the entity routes take. `None` means the
/// outcome has already been reported and there is nothing left for the shared
/// printer.
async fn run_certificates(
    client: &GatewayClient,
    command: CrudCommand,
    reveal: bool,
    output: Output,
) -> Result<Option<Value>> {
    let command = match command {
        CrudCommand::Get { id } => CrudCommand::Get {
            id: resolve_id(client, &CERTIFICATE_LOOKUP, &id).await?,
        },
        CrudCommand::Delete { id } => CrudCommand::Delete {
            id: resolve_id(client, &CERTIFICATE_LOOKUP, &id).await?,
        },
        command => command,
    };
    let deleted = match &command {
        CrudCommand::Delete { id } => Some(id.clone()),
        _ => None,
    };
    let mut value = match command {
        // The document is read and checked before the lookup, as for secrets,
        // so a bad file fails without a request and `--file -` is read once.
        CrudCommand::Update { id, file } => {
            let body = read_json(&file)?;
            let id = resolve_id(client, &CERTIFICATE_LOOKUP, &id).await?;
            client
                .request(Method::PUT, &entity_path(CERTIFICATES_PATH, &id), Some(body))
                .await?
        }
        command => run_crud(client, CERTIFICATES_PATH, command).await?,
    };
    if let Some(id) = deleted {
        return Ok(report_removal(value, "Deleted certificate", &id, output));
    }
    if !reveal {
        mask_keys(&mut value, &["private_key_pem"]);
    }
    Ok(Some(value))
}

/// Creation posts to `/v1/secrets/new` rather than the collection, and the
/// tag search sits under `/v1/secrets/tag/{tag}`, so the shared CRUD runner
/// does not fit this resource. `None` means the outcome has already been
/// reported and there is nothing left for the shared printer.
async fn run_secrets(
    client: &GatewayClient,
    command: SecretCommand,
    reveal: bool,
    output: Output,
) -> Result<Option<Value>> {
    let mut value = match command {
        SecretCommand::List { tag: None } => {
            client
                .request(Method::GET, SECRETS_PATH, None)
                .await?
        }
        SecretCommand::List { tag: Some(tag) } => {
            let path = encoded_path(&format!("{SECRETS_PATH}/tag"), &tag);
            client
                .request(Method::GET, &path, None)
                .await?
        }
        SecretCommand::Get { secret } => {
            let id = resolve_id(client, &SECRET_LOOKUP, &secret).await?;
            client
                .request(Method::GET, &encoded_path(SECRETS_PATH, &id), None)
                .await?
        }
        SecretCommand::Create(args) => {
            let body = if let Some(file) = args.file {
                read_json(&file)?
            } else {
                secret_create_body(args)?
            };
            client
                .request(Method::POST, &format!("{SECRETS_PATH}/new"), Some(body))
                .await?
        }
        SecretCommand::Update { secret, file } => {
            let body = read_json(&file)?;
            check_secret_update(&body)?;
            let id = resolve_id(client, &SECRET_LOOKUP, &secret).await?;
            client
                .request(Method::PUT, &encoded_path(SECRETS_PATH, &id), Some(body))
                .await?
        }
        SecretCommand::Delete { secret } => {
            let id = resolve_id(client, &SECRET_LOOKUP, &secret).await?;
            let value = client
                .request(Method::DELETE, &encoded_path(SECRETS_PATH, &id), None)
                .await?;
            return Ok(report_removal(value, "Deleted secret", &id, output));
        }
    };
    if !reveal {
        mask_keys(&mut value, &["value"]);
    }
    Ok(Some(value))
}

/// Grants are minted only by a user completing the provider's OAuth flow in a
/// browser, so this resource has no create and no update: the gateway offers
/// reads and the two revoke routes only. `None` means the outcome has already
/// been reported and there is nothing left for the shared printer.
async fn run_delegation_vault(
    client: &GatewayClient,
    command: DelegationVaultCommand,
    output: Output,
) -> Result<Option<Value>> {
    match command {
        DelegationVaultCommand::List => client
            .request(Method::GET, DELEGATION_VAULT_PATH, None)
            .await
            .map(Some),
        DelegationVaultCommand::Get { id } => client
            .request(Method::GET, &encoded_path(DELEGATION_VAULT_PATH, &id), None)
            .await
            .map(Some),
        DelegationVaultCommand::Revoke { id } => {
            let value = client
                .request(Method::DELETE, &encoded_path(DELEGATION_VAULT_PATH, &id), None)
                .await?;
            Ok(report_removal(value, "Revoked grant", &id, output))
        }
        // A mass revoke answers with a real 200 body reporting how many
        // grants went, so it never takes the empty-body path.
        DelegationVaultCommand::RevokeUser { user_hash } => {
            let path = encoded_path(&format!("{DELEGATION_VAULT_PATH}/by-user"), &user_hash);
            client
                .request(Method::DELETE, &path, None)
                .await
                .map(Some)
        }
    }
}

fn secret_create_body(args: SecretCreateArgs) -> Result<Value> {
    let name = args
        .name
        .context("--name is required without --file")?;
    let secret_id = args
        .secret_id
        .context("--secret-id is required without --file")?;
    let value = match (args.value, args.value_stdin) {
        (Some(value), _) => value,
        (None, true) => read_stdin_secret()?,
        (None, false) => bail!("--value or --value-stdin is required without --file"),
    };
    let mut body = json!({
        "name": name,
        "secret_id": secret_id,
        "value": value,
        "tags": args.tags,
    });
    if let Some(description) = args.description {
        body["description"] = json!(description);
    }
    if let Some(secret_type) = args.secret_type {
        body["secret_type"] = json!(secret_type);
    }
    reject_masked_values(&body)?;
    Ok(body)
}

/// The gateway ignores an update's `value` unless `update_value` is true, so
/// a document that sets one without the other reports success while leaving
/// the stored secret untouched. Supplying the flag automatically would turn
/// that safe no-op into a write the caller never asked for, so an ambiguous
/// document is rejected instead.
fn check_secret_update(body: &Value) -> Result<()> {
    if let Some(object) = body.as_object()
        && object.contains_key("value")
        && !object.contains_key("update_value")
    {
        bail!(
            "the document sets \"value\" without \"update_value\": true, and the gateway would keep the stored secret; add \"update_value\": true to replace it, or drop \"value\" to leave it alone"
        );
    }
    Ok(())
}

/// Refuses a request body carrying [`MASKED_VALUE`]. A document captured from
/// `get` and replayed through `create` or `update` would otherwise store the
/// placeholder as the credential itself, and the masked response would look
/// exactly as it did before.
fn reject_masked_values(value: &Value) -> Result<()> {
    if contains_masked_value(value) {
        bail!(
            "the request body still carries the masked placeholder {MASKED_VALUE}; re-read the entity with --reveal, or remove the masked field to leave the stored credential untouched"
        );
    }
    Ok(())
}

fn contains_masked_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text == MASKED_VALUE,
        Value::Object(object) => object
            .values()
            .any(contains_masked_value),
        Value::Array(items) => items
            .iter()
            .any(contains_masked_value),
        _ => false,
    }
}

/// Reads a secret value from standard input. Unlike a bearer token the value
/// is kept verbatim — trailing spaces and interior newlines are significant
/// in PEM blocks and signing keys — apart from the single line ending a
/// shell pipeline appends.
fn read_stdin_secret() -> Result<String> {
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .context("read secret value from standard input")?;
    Ok(strip_one_line_ending(value))
}

fn strip_one_line_ending(value: String) -> String {
    match value.strip_suffix('\n') {
        Some(stripped) => stripped
            .strip_suffix('\r')
            .unwrap_or(stripped)
            .to_owned(),
        None => value,
    }
}

/// Joins a single path segment onto a base path. `urlencoding` follows the
/// form-encoding rules, where a space becomes `+` and a URL path reads that
/// back as a literal plus, so spaces are re-encoded as `%20` here.
fn encoded_path(
    base: &str,
    segment: &str,
) -> String {
    format!("{}/{}", base.trim_end_matches('/'), urlencoding(segment).replace('+', "%20"))
}

/// Finds the one `id` the entity routes accept for a reference the caller may
/// have given as the `id` or as any of the lookup's `names`. An exact `id`
/// match wins outright: ids are unique and are what the ambiguity refusal asks
/// for, so an entity stays reachable by its `id` even when another carries the
/// same string as a name or `secret_id`. Otherwise every name field of every
/// listed entity is compared at once rather than field by field, so a name
/// that equals another entity's `secret_id` is refused as ambiguous instead of
/// resolving to whichever field happened to be checked first.
///
/// A caller refused the list can still pass a UUID: the entity routes check
/// their own permission, which a token scoped to edit or delete may hold
/// without the view one, and report a UUID that is no entity's id as not found.
async fn resolve_id(
    client: &GatewayClient,
    lookup: &Lookup,
    reference: &str,
) -> Result<String> {
    let Lookup {
        base,
        noun,
        id_field,
        list_command,
        names,
        view,
    } = lookup;
    let shown = one_line(reference);
    let response = client
        .request(Method::GET, base, None)
        .await;
    let listed = match response {
        Ok(listed) => listed,
        Err(error) => {
            let forbidden = response_status(&error) == Some(StatusCode::FORBIDDEN);
            if forbidden && is_uuid(reference) {
                return Ok(reference.to_owned());
            }
            let error = error.context(format!("list {noun}s to find '{shown}'"));
            // The gateway also answers a bare 403 for a resource-scope or tenant
            // rejection, so the missing view permission is only the likely cause.
            if forbidden {
                bail!(
                    "{error:#}; if the token lacks {view}, the CLI can't look names up; pass the {noun}'s id (a UUID) instead"
                );
            }
            return Err(error);
        }
    };
    let entities = listed
        .as_array()
        .with_context(|| format!("the gateway's {noun} list is not a JSON array"))?;
    if entities
        .iter()
        .any(|entity| string_field(entity, id_field) == Some(reference))
    {
        return Ok(reference.to_owned());
    }
    let mut matches: Vec<(&str, &Value)> = Vec::new();
    let mut without_id = 0;
    for entity in entities {
        let matched = names
            .iter()
            .any(|name| string_field(entity, name) == Some(reference));
        if !matched {
            continue;
        }
        let Some(id) = string_field(entity, id_field) else {
            without_id += 1;
            continue;
        };
        if !matches
            .iter()
            .any(|(seen, _)| *seen == id)
        {
            matches.push((id, entity));
        }
    }
    // A row with no id could be the one meant, so it is never left out of the
    // match: using another row of the same name could act on the wrong entity.
    if without_id > 0 {
        bail!(
            "the gateway listed a {noun} named '{shown}' without its {id_field}, so the CLI can't tell which one you mean; pass the {noun}'s id instead"
        );
    }
    match matches.as_slice() {
        [] => {
            let fields = [&["ID"][..], *names].concat();
            let described = match fields.split_last() {
                Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
                _ => fields.join(", "),
            };
            let hint = if reference.trim() != reference {
                "; the reference starts or ends with a space, which may not be meant"
            } else {
                ""
            };
            bail!("{noun} not found: no {noun} has the {described} '{shown}'{hint}; run `{list_command}` to see them")
        }
        [(id, _)] => Ok((*id).to_owned()),
        _ => {
            let candidates = matches
                .iter()
                .map(|(id, entity)| {
                    let details = names
                        .iter()
                        .map(|name| format!("{name}: {}", one_line(string_field(entity, name).unwrap_or("-"))))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("  {}  ({details})", one_line(id))
                })
                .collect::<Vec<_>>()
                .join("\n");
            bail!("'{shown}' matches more than one {noun}; pass one of these ids instead:\n{candidates}")
        }
    }
}

/// `value` on one line with control characters removed, for text that goes to
/// the terminal inside a message. A newline or tab becomes a space, where
/// `sanitize_for_terminal` would keep it.
fn one_line(value: &str) -> String {
    sanitize_for_terminal(&value.replace(['\n', '\t', '\r'], " "))
}

fn string_field<'a>(
    entity: &'a Value,
    key: &str,
) -> Option<&'a str> {
    entity
        .get(key)
        .and_then(Value::as_str)
}

/// Whether `value` has the 8-4-4-4-12 hex shape of the ids the gateway assigns.
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
}

/// Reports the empty body a 204 carries. Table output gets a human line and
/// nothing to print afterwards; JSON output keeps the `null` that body parses
/// to, so it matches every other delete command. A response that does carry a
/// document is passed through untouched.
fn report_removal(
    value: Value,
    action: &str,
    id: &str,
    output: Output,
) -> Option<Value> {
    if value.is_null() && matches!(output, Output::Table) {
        println!("{action} {id}");
        return None;
    }
    Some(value)
}

/// Replaces every string stored under one of `keys` with [`MASKED_VALUE`].
/// Absent and null entries are left alone so the output still distinguishes
/// a certificate with no stored private key from one that is hidden.
fn mask_keys(
    value: &mut Value,
    keys: &[&str],
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if keys.contains(&key.as_str()) && child.is_string() {
                    *child = json!(MASKED_VALUE);
                } else {
                    mask_keys(child, keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                mask_keys(item, keys);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod secrets_certs_tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use clap::CommandFactory;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Starts a one-shot HTTP server that records the first request it
    /// receives and answers it with `status_line` and `body`, returning its
    /// base URL alongside the recording.
    async fn recording_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let request = Arc::new(Mutex::new(String::new()));
        let recorder = Arc::clone(&request);
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                if let Ok(read) = socket.read(&mut buf).await {
                    *recorder
                        .lock()
                        .expect("record request") = String::from_utf8_lossy(&buf[..read]).into_owned();
                }
                let response =
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), request)
    }

    fn request_line(request: &Arc<Mutex<String>>) -> String {
        request
            .lock()
            .expect("read request")
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    /// Answer to a request the test did not script.
    const UNSCRIPTED: (&str, &str) = ("HTTP/1.1 418 I'm a teapot", "unscripted request");

    /// Starts an HTTP server that answers the requests it receives with the
    /// entries of `responses`, in order, and records every request line. A
    /// request past the end of the script is recorded too and answered with
    /// [`UNSCRIPTED`], so a call that should never have been made shows up in
    /// the recording instead of failing to connect unseen. `connection: close`
    /// makes the client open a new connection per request, so a name lookup's
    /// list and the call that follows it arrive as two accepts.
    async fn scripted_server(responses: &[(&'static str, &'static str)]) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&requests);
        let responses = responses.to_vec();
        tokio::spawn(async move {
            let mut script = responses.into_iter();
            while let Ok((mut socket, _)) = listener.accept().await {
                let (status_line, body) = script
                    .next()
                    .unwrap_or(UNSCRIPTED);
                let mut buf = [0u8; 4096];
                if let Ok(read) = socket.read(&mut buf).await {
                    let request = String::from_utf8_lossy(&buf[..read]);
                    recorder
                        .lock()
                        .expect("record request")
                        .push(
                            request
                                .lines()
                                .next()
                                .unwrap_or_default()
                                .to_owned(),
                        );
                }
                let response =
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), requests)
    }

    fn request_lines(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        requests
            .lock()
            .expect("read requests")
            .clone()
    }

    fn json_file(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes())
            .expect("write");
        file
    }

    const OK: &str = "HTTP/1.1 200 OK";
    const NO_CONTENT: &str = "HTTP/1.1 204 No Content";
    const SECRET_LIST: &str =
        r#"[{"id":"s-1","secret_id":"stripe","name":"Stripe"},{"id":"s-2","secret_id":"github","name":"GitHub"}]"#;
    const CERTIFICATE_LIST: &str = r#"[{"id":"cert-1","certificate_id":"serial-1","name":"Edge"},{"id":"cert-2","certificate_id":"serial-2","name":"Anchor"}]"#;

    fn stripe_args() -> SecretCreateArgs {
        SecretCreateArgs {
            name: Some("Stripe".to_owned()),
            secret_id: Some("stripe".to_owned()),
            value: Some("sk_live_1".to_owned()),
            value_stdin: false,
            description: None,
            secret_type: None,
            tags: Vec::new(),
            file: None,
        }
    }

    fn certificate_command(cli: Cli) -> (CrudCommand, bool) {
        match cli
            .into_agent_gateway()
            .command
        {
            Command::Certificates { command, reveal } => (command, reveal),
            other => panic!("expected a certificates command, got {other:?}"),
        }
    }

    #[test]
    fn reveal_is_accepted_after_the_subcommand() {
        let (command, reveal) = certificate_command(
            Cli::try_parse_from(["fabric", "agent-gateway", "certificates", "get", "cert-1", "--reveal"])
                .expect("parse"),
        );

        assert!(reveal);
        assert!(matches!(command, CrudCommand::Get { .. }));
    }

    #[test]
    fn reveal_defaults_to_off() {
        let (_, reveal) = certificate_command(
            Cli::try_parse_from(["fabric", "agent-gateway", "certificates", "get", "cert-1"]).expect("parse"),
        );

        assert!(!reveal);
    }

    #[test]
    fn masking_hides_stored_keys_but_keeps_absent_ones() {
        let mut value = json!([
            {"id": "cert-1", "name": "Edge", "private_key_pem": "test-pem"},
            {"id": "cert-2", "name": "Anchor", "private_key_pem": null},
            {"id": "cert-3", "name": "Listed"}
        ]);

        mask_keys(&mut value, &["private_key_pem"]);

        assert_eq!(value[0]["private_key_pem"], json!(MASKED_VALUE));
        assert_eq!(value[0]["name"], json!("Edge"));
        assert_eq!(value[1]["private_key_pem"], Value::Null);
        assert_eq!(value[2].get("private_key_pem"), None);
    }

    #[test]
    fn masking_hides_secret_values() {
        let mut value = json!({"id": "s-1", "secret_id": "stripe", "value": "sk_live_1"});

        mask_keys(&mut value, &["value"]);

        assert_eq!(value["value"], json!(MASKED_VALUE));
        assert_eq!(value["secret_id"], json!("stripe"));
    }

    #[tokio::test]
    async fn certificate_get_masks_the_private_key_unless_revealed() {
        let body = r#"{"id":"cert-1","private_key_pem":"test-pem"}"#;
        let (host, _) = scripted_server(&[(OK, CERTIFICATE_LIST), (OK, body)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let masked = run_certificates(&client, CrudCommand::Get { id: "cert-1".to_owned() }, false, Output::Table)
            .await
            .expect("get")
            .expect("a document to print");

        assert_eq!(masked["private_key_pem"], json!(MASKED_VALUE));

        let (host, _) = scripted_server(&[(OK, CERTIFICATE_LIST), (OK, body)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let revealed = run_certificates(&client, CrudCommand::Get { id: "cert-1".to_owned() }, true, Output::Table)
            .await
            .expect("get")
            .expect("a document to print");

        assert_eq!(revealed["private_key_pem"], json!("test-pem"));
    }

    #[tokio::test]
    async fn certificate_delete_reports_the_empty_body_per_output_mode() {
        let (host, _) = scripted_server(&[(OK, CERTIFICATE_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let table = run_certificates(&client, CrudCommand::Delete { id: "cert-1".to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(table, None);

        let (host, _) = scripted_server(&[(OK, CERTIFICATE_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let json = run_certificates(&client, CrudCommand::Delete { id: "cert-1".to_owned() }, false, Output::Json)
            .await
            .expect("delete");

        assert_eq!(json, Some(Value::Null));
    }

    #[tokio::test]
    async fn a_certificate_is_found_by_its_id_or_name() {
        for reference in ["cert-2", "Anchor"] {
            let (host, requests) = scripted_server(&[(OK, CERTIFICATE_LIST), (OK, r#"{"id":"cert-2"}"#)]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            run_certificates(&client, CrudCommand::Get { id: reference.to_owned() }, false, Output::Table)
                .await
                .expect("get");

            assert_eq!(
                request_lines(&requests),
                ["GET /api/v1/certificates HTTP/1.1", "GET /api/v1/certificates/cert-2 HTTP/1.1"],
                "looking up {reference}"
            );
        }
    }

    #[tokio::test]
    async fn certificate_delete_and_update_send_the_resolved_id() {
        let (host, requests) = scripted_server(&[(OK, CERTIFICATE_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_certificates(&client, CrudCommand::Delete { id: "Edge".to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(request_lines(&requests)[1], "DELETE /api/v1/certificates/cert-1 HTTP/1.1");

        let document = json_file(r#"{"description":"Rotated"}"#);
        let (host, requests) = scripted_server(&[(OK, CERTIFICATE_LIST), (OK, r#"{"id":"cert-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_certificates(
            &client,
            CrudCommand::Update {
                id: "Edge".to_owned(),
                file: document.path().to_owned(),
            },
            false,
            Output::Table,
        )
        .await
        .expect("update");

        assert_eq!(request_lines(&requests)[1], "PUT /api/v1/certificates/cert-1 HTTP/1.1");
    }

    /// As for secrets, the document is checked before the lookup: a bad file
    /// costs no request, and its error is not hidden behind a refused list.
    #[tokio::test]
    async fn certificate_update_checks_the_document_before_the_lookup() {
        for (contents, expected) in [
            (format!(r#"{{"name":"Edge","private_key_pem":"{MASKED_VALUE}"}}"#), "--reveal"),
            ("{not json".to_owned(), "as JSON"),
        ] {
            let document = json_file(&contents);
            let (host, requests) = scripted_server(&[(FORBIDDEN, CERTIFICATES_VIEW_DENIED)]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            let error = run_certificates(
                &client,
                CrudCommand::Update {
                    id: "Edge".to_owned(),
                    file: document.path().to_owned(),
                },
                false,
                Output::Table,
            )
            .await
            .expect_err("the document must be refused");

            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert!(request_lines(&requests).is_empty(), "{contents} reached the gateway");
        }
    }

    /// `certificate_id` is a second UUID the gateway never looks anything up
    /// by, so accepting it would resolve a reference no route understands.
    #[tokio::test]
    async fn a_certificate_id_is_not_a_lookup_key() {
        let (host, requests) = scripted_server(&[(OK, CERTIFICATE_LIST)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_certificates(&client, CrudCommand::Get { id: "serial-1".to_owned() }, false, Output::Table)
            .await
            .expect_err("certificate_id must not match");

        assert_eq!(
            error.to_string(),
            "certificate not found: no certificate has the ID or name 'serial-1'; run `fabric agent-gateway certificates list` to see them"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/certificates HTTP/1.1"]);
    }

    #[tokio::test]
    async fn an_exact_id_wins_over_another_certificates_name() {
        let list = r#"[{"id":"cert-1","name":"Edge"},{"id":"cert-2","name":"cert-1"}]"#;
        for id in ["cert-1", "cert-2"] {
            let (host, requests) = scripted_server(&[(OK, list), (OK, r#"{"id":"cert-1"}"#)]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            run_certificates(&client, CrudCommand::Get { id: id.to_owned() }, false, Output::Table)
                .await
                .expect("an exact id is never ambiguous");

            assert_eq!(
                request_lines(&requests),
                ["GET /api/v1/certificates HTTP/1.1".to_owned(), format!("GET /api/v1/certificates/{id} HTTP/1.1")]
            );
        }
    }

    #[tokio::test]
    async fn a_name_shared_by_two_certificates_is_refused() {
        let list = r#"[{"id":"cert-1","name":"Edge"},{"id":"cert-2","name":"Edge"}]"#;
        let (host, requests) = scripted_server(&[(OK, list)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_certificates(&client, CrudCommand::Delete { id: "Edge".to_owned() }, false, Output::Table)
            .await
            .expect_err("an ambiguous name must be refused");

        assert_eq!(
            error.to_string(),
            "'Edge' matches more than one certificate; pass one of these ids instead:\n  cert-1  (name: Edge)\n  cert-2  (name: Edge)"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/certificates HTTP/1.1"], "nothing may be deleted");
    }

    /// `CrudCommand` is shared, so the certificates-only help must not leak
    /// into resources whose routes still take the raw ID.
    #[test]
    fn only_certificates_describe_a_name_lookup_in_their_help() {
        let cli = Cli::command();
        cli.clone().debug_assert();
        let reference_help = |resource: &str, action: &str| {
            cli.find_subcommand("agent-gateway")
                .and_then(|command| command.find_subcommand(resource))
                .and_then(|command| command.find_subcommand(action))
                .and_then(|command| {
                    command
                        .get_arguments()
                        .find(|argument| argument.get_id() == "id")
                        .and_then(|argument| argument.get_help())
                        .map(ToString::to_string)
                })
        };

        for action in ["get", "update", "delete"] {
            let help = reference_help("certificates", action).expect("certificate reference help");
            assert!(help.contains("id or name"), "certificates {action}: {help}");
            assert!(help.contains("refused"), "certificates {action}: {help}");
            assert_eq!(reference_help("connections", action), None, "connections {action}");
        }
    }

    #[tokio::test]
    async fn secret_create_masks_the_stored_value_unless_revealed() {
        let body = r#"{"id":"s-1","secret_id":"stripe","value":"sk_live_1"}"#;
        let (host, _) = recording_server("HTTP/1.1 201 Created", body).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let masked = run_secrets(&client, SecretCommand::Create(stripe_args()), false, Output::Table)
            .await
            .expect("create")
            .expect("a document to print");

        assert_eq!(masked["value"], json!(MASKED_VALUE));
        assert_eq!(masked["secret_id"], json!("stripe"));

        let (host, _) = recording_server("HTTP/1.1 201 Created", body).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let revealed = run_secrets(&client, SecretCommand::Create(stripe_args()), true, Output::Table)
            .await
            .expect("create")
            .expect("a document to print");

        assert_eq!(revealed["value"], json!("sk_live_1"));
    }

    #[tokio::test]
    async fn secret_get_masks_the_stored_value_unless_revealed() {
        let body = r#"{"id":"s-1","secret_id":"stripe","value":"sk_live_1"}"#;
        let (host, _) = scripted_server(&[(OK, SECRET_LIST), (OK, body)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let masked = run_secrets(&client, SecretCommand::Get { secret: "s-1".to_owned() }, false, Output::Table)
            .await
            .expect("get")
            .expect("a document to print");

        assert_eq!(masked["value"], json!(MASKED_VALUE));
    }

    #[tokio::test]
    async fn a_secret_is_found_by_its_id_secret_id_or_name() {
        for reference in ["s-2", "github", "GitHub"] {
            let (host, requests) = scripted_server(&[(OK, SECRET_LIST), (OK, r#"{"id":"s-2"}"#)]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            run_secrets(&client, SecretCommand::Get { secret: reference.to_owned() }, false, Output::Table)
                .await
                .expect("get");

            assert_eq!(
                request_lines(&requests),
                ["GET /api/v1/secrets HTTP/1.1", "GET /api/v1/secrets/s-2 HTTP/1.1"],
                "looking up {reference}"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_secret_is_not_found() {
        let (host, requests) = scripted_server(&[(OK, SECRET_LIST)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Get { secret: "missing".to_owned() }, false, Output::Table)
            .await
            .expect_err("an unknown reference must fail");

        assert_eq!(
            error.to_string(),
            "secret not found: no secret has the ID, secret_id or name 'missing'; run `fabric agent-gateway secrets list` to see them"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_name_shared_by_two_secrets_is_refused() {
        let list = r#"[{"id":"s-1","secret_id":"stripe-live","name":"Stripe"},{"id":"s-2","secret_id":"stripe-test","name":"Stripe"}]"#;
        let (host, requests) = scripted_server(&[(OK, list)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Get { secret: "Stripe".to_owned() }, false, Output::Table)
            .await
            .expect_err("an ambiguous name must be refused");

        assert_eq!(
            error.to_string(),
            "'Stripe' matches more than one secret; pass one of these ids instead:\n  s-1  (secret_id: stripe-live, name: Stripe)\n  s-2  (secret_id: stripe-test, name: Stripe)"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"]);
    }

    /// Checking the keys in turn would pick `s-1` for its `secret_id` and
    /// never notice that `s-2` carries the same string as its name.
    #[tokio::test]
    async fn a_name_equal_to_another_secrets_secret_id_is_refused() {
        let list = r#"[{"id":"s-1","secret_id":"billing","name":"Stripe"},{"id":"s-2","secret_id":"stripe-test","name":"billing"}]"#;
        let (host, requests) = scripted_server(&[(OK, list)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Delete { secret: "billing".to_owned() }, false, Output::Table)
            .await
            .expect_err("a reference matching two secrets must be refused");

        let message = error.to_string();
        assert!(message.contains("more than one secret"), "{message}");
        assert!(message.contains("  s-1  (secret_id: billing, name: Stripe)"), "{message}");
        assert!(message.contains("  s-2  (secret_id: stripe-test, name: billing)"), "{message}");
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"], "nothing may be deleted");
    }

    #[tokio::test]
    async fn a_secret_matching_on_several_keys_counts_once() {
        let list = r#"[{"id":"s-1","secret_id":"stripe","name":"stripe"}]"#;
        let (host, requests) = scripted_server(&[(OK, list), (OK, r#"{"id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Get { secret: "stripe".to_owned() }, false, Output::Table)
            .await
            .expect("one secret matching on both name fields is not ambiguous");

        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1", "GET /api/v1/secrets/s-1 HTTP/1.1"]);
    }

    /// `secret_id` is caller-chosen, so it can equal another secret's `id`.
    /// Refusing that as ambiguous would leave the secret unreachable, since
    /// the refusal's own advice is to pass the `id`.
    #[tokio::test]
    async fn an_exact_id_wins_over_another_secrets_name_or_secret_id() {
        let name_clash =
            r#"[{"id":"s-1","secret_id":"stripe","name":"Stripe"},{"id":"s-2","secret_id":"github","name":"s-1"}]"#;
        let secret_id_clash =
            r#"[{"id":"s-1","secret_id":"stripe","name":"Stripe"},{"id":"s-2","secret_id":"s-1","name":"GitHub"}]"#;
        for list in [name_clash, secret_id_clash] {
            for id in ["s-1", "s-2"] {
                let (host, requests) = scripted_server(&[(OK, list), (OK, r#"{"id":"s-1"}"#)]).await;
                let client = GatewayClient::new(host, "agpat_test").expect("client");

                run_secrets(&client, SecretCommand::Delete { secret: id.to_owned() }, false, Output::Json)
                    .await
                    .expect("an exact id is never ambiguous");

                assert_eq!(
                    request_lines(&requests),
                    ["GET /api/v1/secrets HTTP/1.1".to_owned(), format!("DELETE /api/v1/secrets/{id} HTTP/1.1")],
                    "{id} in {list}"
                );
            }
        }
    }

    #[tokio::test]
    async fn secret_update_by_name_puts_to_the_resolved_id() {
        let document = json_file(r#"{"value":"sk_live_2","update_value":true}"#);
        let (host, requests) = scripted_server(&[(OK, SECRET_LIST), (OK, r#"{"id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(
            &client,
            SecretCommand::Update {
                secret: "Stripe".to_owned(),
                file: document.path().to_owned(),
            },
            false,
            Output::Table,
        )
        .await
        .expect("update");

        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1", "PUT /api/v1/secrets/s-1 HTTP/1.1"]);
    }

    /// Both document guards run before the lookup, so a refused document never
    /// reaches the gateway at all, not even as a list request.
    #[tokio::test]
    async fn secret_update_by_name_keeps_the_document_guards() {
        for (contents, expected) in [
            (r#"{"value":"sk_live_2"}"#.to_owned(), "\"update_value\": true"),
            (format!(r#"{{"value":"{MASKED_VALUE}","update_value":true}}"#), "--reveal"),
        ] {
            let document = json_file(&contents);
            let (host, requests) = scripted_server(&[(OK, SECRET_LIST), (OK, r#"{"id":"s-1"}"#)]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            let error = run_secrets(
                &client,
                SecretCommand::Update {
                    secret: "Stripe".to_owned(),
                    file: document.path().to_owned(),
                },
                false,
                Output::Table,
            )
            .await
            .expect_err("the document must be refused");

            assert!(
                error
                    .to_string()
                    .contains(expected),
                "{error}"
            );
            assert!(request_lines(&requests).is_empty(), "{contents} reached the gateway");
        }
    }

    const FORBIDDEN: &str = "HTTP/1.1 403 Forbidden";
    const SECRETS_VIEW_DENIED: &str =
        r#"{"error":"access token scope does not include 'secrets.view'","required_permission":"secrets.view"}"#;
    const CERTIFICATES_VIEW_DENIED: &str = r#"{"error":"access token scope does not include 'certificates.view'","required_permission":"certificates.view"}"#;
    const UUID: &str = "5f0c2a4e-8b1d-4c3a-9e7f-1a2b3c4d5e6f";

    /// A token scoped to edit or delete but not view cannot list, so the id is
    /// the only reference it can use; the entity route checks its own scope.
    #[tokio::test]
    async fn a_refused_list_lets_a_secret_uuid_through_to_the_entity_route() {
        let (host, requests) = scripted_server(&[(FORBIDDEN, SECRETS_VIEW_DENIED), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Delete { secret: UUID.to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(request_lines(&requests)[1], format!("DELETE /api/v1/secrets/{UUID} HTTP/1.1"));

        let document = json_file(r#"{"value":"sk_live_2","update_value":true}"#);
        let (host, requests) = scripted_server(&[(FORBIDDEN, SECRETS_VIEW_DENIED), (OK, r#"{"id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(
            &client,
            SecretCommand::Update {
                secret: UUID.to_owned(),
                file: document.path().to_owned(),
            },
            false,
            Output::Table,
        )
        .await
        .expect("update");

        assert_eq!(request_lines(&requests)[1], format!("PUT /api/v1/secrets/{UUID} HTTP/1.1"));
    }

    #[tokio::test]
    async fn a_refused_list_lets_a_certificate_uuid_through_to_the_entity_route() {
        let (host, requests) = scripted_server(&[(FORBIDDEN, CERTIFICATES_VIEW_DENIED), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_certificates(&client, CrudCommand::Delete { id: UUID.to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(request_lines(&requests)[1], format!("DELETE /api/v1/certificates/{UUID} HTTP/1.1"));

        let document = json_file(r#"{"description":"Rotated"}"#);
        let (host, requests) =
            scripted_server(&[(FORBIDDEN, CERTIFICATES_VIEW_DENIED), (OK, r#"{"id":"cert-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_certificates(
            &client,
            CrudCommand::Update {
                id: UUID.to_owned(),
                file: document.path().to_owned(),
            },
            false,
            Output::Table,
        )
        .await
        .expect("update");

        assert_eq!(request_lines(&requests)[1], format!("PUT /api/v1/certificates/{UUID} HTTP/1.1"));
    }

    #[tokio::test]
    async fn a_refused_list_refuses_a_name_and_points_at_the_uuid() {
        let (host, requests) = scripted_server(&[(FORBIDDEN, SECRETS_VIEW_DENIED)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Delete { secret: "Stripe".to_owned() }, false, Output::Table)
            .await
            .expect_err("a name cannot be resolved without the list");

        assert_eq!(
            format!("{error:#}"),
            "list secrets to find 'Stripe': access token scope does not include 'secrets.view'; if the token lacks secrets.view, the CLI can't look names up; pass the secret's id (a UUID) instead"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"], "nothing may be deleted");

        let (host, requests) = scripted_server(&[(FORBIDDEN, CERTIFICATES_VIEW_DENIED)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_certificates(&client, CrudCommand::Delete { id: "Edge".to_owned() }, false, Output::Table)
            .await
            .expect_err("a name cannot be resolved without the list");

        let message = format!("{error:#}");
        assert!(message.contains("access token scope does not include 'certificates.view'"), "{message}");
        assert!(message.contains("if the token lacks certificates.view"), "{message}");
        assert!(message.contains("the certificate's id (a UUID)"), "{message}");
        assert_eq!(request_lines(&requests), ["GET /api/v1/certificates HTTP/1.1"], "nothing may be deleted");
    }

    /// A 403 with no body says nothing about why, so the hint must not claim the
    /// view permission as the cause; the status alone still lets a UUID through.
    #[tokio::test]
    async fn a_bare_403_on_the_list_is_treated_as_a_refused_list() {
        let (host, requests) = scripted_server(&[(FORBIDDEN, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Delete { secret: "Stripe".to_owned() }, false, Output::Table)
            .await
            .expect_err("a name cannot be resolved without the list");

        assert_eq!(
            format!("{error:#}"),
            "list secrets to find 'Stripe': gateway returned 403 Forbidden: no additional detail from server; if the token lacks secrets.view, the CLI can't look names up; pass the secret's id (a UUID) instead"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"], "nothing may be deleted");

        let (host, requests) = scripted_server(&[(FORBIDDEN, ""), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Delete { secret: UUID.to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(request_lines(&requests)[1], format!("DELETE /api/v1/secrets/{UUID} HTTP/1.1"));
    }

    /// Only a 403 says the caller may lack just the view permission. Any other
    /// failed list leaves nothing to go on, so even a UUID stops there.
    #[tokio::test]
    async fn any_other_failed_list_stops_a_uuid_too() {
        for (status_line, body) in [
            ("HTTP/1.1 500 Internal Server Error", "storage unavailable"),
            ("HTTP/1.1 401 Unauthorized", ""),
            (OK, r#"{"secrets":[]}"#),
        ] {
            let (host, requests) = scripted_server(&[(status_line, body), (NO_CONTENT, "")]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");

            run_secrets(&client, SecretCommand::Delete { secret: UUID.to_owned() }, false, Output::Table)
                .await
                .expect_err("the lookup must fail");

            assert_eq!(
                request_lines(&requests),
                ["GET /api/v1/secrets HTTP/1.1"],
                "{status_line} let the delete through"
            );
        }
    }

    #[tokio::test]
    async fn a_list_that_never_answers_stops_a_uuid_too() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        drop(listener);
        let client = GatewayClient::new(format!("http://{addr}"), "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Delete { secret: UUID.to_owned() }, false, Output::Table)
            .await
            .expect_err("a refused connection must fail");

        assert!(format!("{error:#}").starts_with(&format!("list secrets to find '{UUID}'")), "{error:#}");
    }

    /// The UUID shortcut applies only when the list is refused. A readable list
    /// still decides, even when the UUID is merely another secret's name.
    #[tokio::test]
    async fn a_readable_list_still_resolves_a_uuid_shaped_name() {
        let list = r#"[{"id":"s-1","secret_id":"stripe","name":"5f0c2a4e-8b1d-4c3a-9e7f-1a2b3c4d5e6f"}]"#;
        let (host, requests) = scripted_server(&[(OK, list), (OK, r#"{"id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Get { secret: UUID.to_owned() }, false, Output::Table)
            .await
            .expect("get");

        assert_eq!(request_lines(&requests)[1], "GET /api/v1/secrets/s-1 HTTP/1.1");
    }

    /// The entity GET needs the same view permission as the list, so without it
    /// a UUID gets past the lookup and the route itself refuses the read.
    #[tokio::test]
    async fn the_entity_route_still_decides_after_the_uuid_fallback() {
        let (host, requests) =
            scripted_server(&[(FORBIDDEN, SECRETS_VIEW_DENIED), (FORBIDDEN, SECRETS_VIEW_DENIED)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Get { secret: UUID.to_owned() }, false, Output::Table)
            .await
            .expect_err("the entity route refuses the read");

        assert_eq!(format!("{error:#}"), "access token scope does not include 'secrets.view'");
        assert_eq!(
            request_lines(&requests),
            ["GET /api/v1/secrets HTTP/1.1".to_owned(), format!("GET /api/v1/secrets/{UUID} HTTP/1.1")]
        );
    }

    /// An entry without an `id` could be the one meant, so a name it shares
    /// with a secret that has an id is refused rather than resolved to that one.
    #[tokio::test]
    async fn a_listed_entry_without_an_id_is_never_skipped_for_another_of_that_name() {
        let list = r#"[{"secret_id":"stripe-old","name":"Stripe"},{"id":"s-2","secret_id":"stripe","name":"Stripe"}]"#;
        let (host, requests) = scripted_server(&[(OK, list)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_secrets(&client, SecretCommand::Get { secret: "Stripe".to_owned() }, false, Output::Table)
            .await
            .expect_err("a secret with no id may be the one meant");

        assert!(
            error
                .to_string()
                .contains("without its id"),
            "{error}"
        );
        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1"]);
    }

    #[test]
    fn only_the_canonical_uuid_shape_counts_as_an_id() {
        assert!(is_uuid(UUID));
        assert!(is_uuid("5F0C2A4E-8B1D-4C3A-9E7F-1A2B3C4D5E6F"));
        assert!(!is_uuid("5f0c2a4e8b1d4c3a9e7f1a2b3c4d5e6f"));
        assert!(!is_uuid("5f0c2a4e-8b1d-4c3a-9e7f-1a2b3c4d5e6"));
        assert!(!is_uuid("5f0c2a4e-8b1d-4c3a-9e7f-1a2b3c4d5e6g"));
        assert!(!is_uuid("5f0c2a4e-8b1d-4c3a9-e7f-1a2b3c4d5e6f"));
        assert!(!is_uuid("stripe-live"));
    }

    #[tokio::test]
    async fn secret_create_posts_to_the_new_subpath() {
        let (host, request) = recording_server("HTTP/1.1 201 Created", r#"{"id":"s-1"}"#).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Create(stripe_args()), false, Output::Table)
            .await
            .expect("create");

        assert_eq!(request_line(&request), "POST /api/v1/secrets/new HTTP/1.1");
    }

    #[tokio::test]
    async fn secret_tag_search_uses_the_tag_subpath() {
        let (host, request) = recording_server("HTTP/1.1 200 OK", "[]").await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(
            &client,
            SecretCommand::List {
                tag: Some("payment gateway".to_owned()),
            },
            false,
            Output::Table,
        )
        .await
        .expect("list");

        assert_eq!(request_line(&request), "GET /api/v1/secrets/tag/payment%20gateway HTTP/1.1");
    }

    #[tokio::test]
    async fn secret_delete_reports_the_empty_body_per_output_mode() {
        let (host, _) = scripted_server(&[(OK, SECRET_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let table = run_secrets(&client, SecretCommand::Delete { secret: "s-1".to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(table, None);

        let (host, _) = scripted_server(&[(OK, SECRET_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let json = run_secrets(&client, SecretCommand::Delete { secret: "s-1".to_owned() }, false, Output::Json)
            .await
            .expect("delete");

        assert_eq!(json, Some(Value::Null));
    }

    #[tokio::test]
    async fn secret_delete_by_name_sends_the_resolved_id() {
        let (host, requests) = scripted_server(&[(OK, SECRET_LIST), (NO_CONTENT, "")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_secrets(&client, SecretCommand::Delete { secret: "Stripe".to_owned() }, false, Output::Table)
            .await
            .expect("delete");

        assert_eq!(request_lines(&requests), ["GET /api/v1/secrets HTTP/1.1", "DELETE /api/v1/secrets/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn delegation_vault_revoke_user_targets_the_by_user_route() {
        let (host, request) = recording_server("HTTP/1.1 200 OK", r#"{"revoked":2}"#).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let value = run_delegation_vault(
            &client,
            DelegationVaultCommand::RevokeUser {
                user_hash: "sha256:abc".to_owned(),
            },
            Output::Table,
        )
        .await
        .expect("revoke user");

        assert_eq!(request_line(&request), "DELETE /api/v1/delegation-vault/by-user/sha256%3Aabc HTTP/1.1");
        assert_eq!(value, Some(json!({"revoked": 2})));
    }

    #[tokio::test]
    async fn delegation_vault_revoke_targets_the_entity_route() {
        let (host, request) = recording_server("HTTP/1.1 204 No Content", "").await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let table =
            run_delegation_vault(&client, DelegationVaultCommand::Revoke { id: "grant-1".to_owned() }, Output::Table)
                .await
                .expect("revoke");

        assert_eq!(request_line(&request), "DELETE /api/v1/delegation-vault/grant-1 HTTP/1.1");
        assert_eq!(table, None);

        let (host, _) = recording_server("HTTP/1.1 204 No Content", "").await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let json =
            run_delegation_vault(&client, DelegationVaultCommand::Revoke { id: "grant-1".to_owned() }, Output::Json)
                .await
                .expect("revoke");

        assert_eq!(json, Some(Value::Null));
    }

    #[test]
    fn secret_create_keeps_the_value_verbatim() {
        let args = SecretCreateArgs {
            name: Some("Signing key".to_owned()),
            secret_id: Some("signing-key".to_owned()),
            value: Some("-----BEGIN KEY-----\nbody\n-----END KEY-----\n".to_owned()),
            value_stdin: false,
            description: Some("Release signing".to_owned()),
            secret_type: Some("ApiKey".to_owned()),
            tags: vec!["release".to_owned()],
            file: None,
        };

        let body = secret_create_body(args).expect("body");

        assert_eq!(body["value"], json!("-----BEGIN KEY-----\nbody\n-----END KEY-----\n"));
        assert_eq!(body["secret_id"], json!("signing-key"));
        assert_eq!(body["secret_type"], json!("ApiKey"));
        assert_eq!(body["tags"], json!(["release"]));
        assert_eq!(body["description"], json!("Release signing"));
    }

    #[test]
    fn secret_create_requires_a_value() {
        let args = SecretCreateArgs {
            name: Some("Stripe".to_owned()),
            secret_id: Some("stripe".to_owned()),
            value: None,
            value_stdin: false,
            description: None,
            secret_type: None,
            tags: Vec::new(),
            file: None,
        };

        let error = secret_create_body(args).expect_err("a value is required");

        assert!(
            error
                .to_string()
                .contains("--value or --value-stdin")
        );
    }

    #[test]
    fn stdin_values_lose_one_line_ending_and_nothing_else() {
        assert_eq!(strip_one_line_ending("token".to_owned()), "token");
        assert_eq!(strip_one_line_ending("token\n".to_owned()), "token");
        assert_eq!(strip_one_line_ending("token\r\n".to_owned()), "token");
        assert_eq!(strip_one_line_ending("token\n\n".to_owned()), "token\n");
        assert_eq!(strip_one_line_ending("  padded  ".to_owned()), "  padded  ");
        assert_eq!(strip_one_line_ending("first\nsecond\n".to_owned()), "first\nsecond");
    }

    #[test]
    fn an_update_must_say_whether_it_replaces_the_value() {
        let error = check_secret_update(&json!({"value": "new"})).expect_err("an ambiguous value must be rejected");

        assert!(
            error
                .to_string()
                .contains("\"update_value\": true")
        );
        check_secret_update(&json!({"value": "new", "update_value": true})).expect("an explicit replacement");
        check_secret_update(&json!({"value": "new", "update_value": false})).expect("an explicit no-op");
        check_secret_update(&json!({"name": "Renamed"})).expect("an update that leaves the value alone");
    }

    #[test]
    fn a_masked_document_is_refused_before_it_reaches_the_gateway() {
        let round_tripped = json!({"id": "s-1", "name": "Stripe", "value": MASKED_VALUE});

        let error = reject_masked_values(&round_tripped).expect_err("a masked value must be refused");

        assert!(
            error
                .to_string()
                .contains("--reveal")
        );
        reject_masked_values(&json!({"id": "s-1", "value": "sk_live_1"})).expect("a real value");
        reject_masked_values(&json!({"id": "cert-1", "private_key_pem": null})).expect("no credential at all");
    }

    /// Certificate bodies never reach `reject_masked_values` directly: they
    /// are parsed by `read_json`, in the shared CRUD runner for a create and in
    /// `run_certificates` for an update, so the guard has to live there for a
    /// certificate round trip to be refused.
    #[test]
    fn a_masked_certificate_document_is_refused_when_read_from_a_file() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, r#"{{"name":"Edge","private_key_pem":"{MASKED_VALUE}"}}"#).expect("write");

        let error = read_json(file.path()).expect_err("a masked document must be refused");

        assert!(
            error
                .to_string()
                .contains("--reveal")
        );

        let mut clean = tempfile::NamedTempFile::new().expect("temp file");
        write!(clean, r#"{{"name":"Edge","private_key_pem":"test-pem"}}"#).expect("write");

        read_json(clean.path()).expect("a document with a real key");
    }

    /// `fabric agent-gateway api --data` is the one route that never reads a document, so a
    /// guard sitting on the file reader alone would let an inline masked body
    /// through and overwrite the stored credential with the placeholder.
    #[tokio::test]
    async fn a_masked_inline_body_is_refused_before_it_reaches_the_gateway() {
        let (host, request) = recording_server("HTTP/1.1 200 OK", r#"{"id":"s-1"}"#).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_api(
            &client,
            ApiArgs {
                method: ApiMethod::Put,
                path: "/v1/secrets/s-1".to_owned(),
                data: Some(format!(r#"{{"value":"{MASKED_VALUE}","update_value":true}}"#)),
                file: None,
            },
        )
        .await
        .expect_err("a masked inline body must be refused");

        assert!(
            error
                .to_string()
                .contains("--reveal")
        );
        assert_eq!(request_line(&request), "", "the refused body must not reach the gateway");

        let (host, request) = recording_server("HTTP/1.1 200 OK", r#"{"id":"s-1"}"#).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        run_api(
            &client,
            ApiArgs {
                method: ApiMethod::Put,
                path: "/v1/secrets/s-1".to_owned(),
                data: Some(r#"{"value":"sk_live_1","update_value":true}"#.to_owned()),
                file: None,
            },
        )
        .await
        .expect("a real value");

        assert_eq!(request_line(&request), "PUT /api/v1/secrets/s-1 HTTP/1.1");
    }

    #[test]
    fn masked_values_are_found_at_any_depth() {
        assert!(contains_masked_value(&json!([{"certificate": {"private_key_pem": MASKED_VALUE}}])));
        assert!(!contains_masked_value(&json!([{"certificate": {"private_key_pem": "-----BEGIN"}}])));
    }

    #[test]
    fn path_segments_encode_spaces_as_percent_twenty() {
        assert_eq!(encoded_path("/v1/secrets/tag", "my tag"), "/v1/secrets/tag/my%20tag");
        assert_eq!(
            encoded_path("/v1/delegation-vault/by-user", "sha256:a+b"),
            "/v1/delegation-vault/by-user/sha256%3Aa%2Bb"
        );
        assert_eq!(encoded_path("/v1/secrets/", "s-1"), "/v1/secrets/s-1");
    }

    #[test]
    fn only_the_create_subcommands_print_a_new_entity_id() {
        let create = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "secrets",
            "create",
            "--name",
            "S",
            "--secret-id",
            "s",
            "--value",
            "v",
        ])
        .expect("parse");
        let list = Cli::try_parse_from(["fabric", "agent-gateway", "delegation-vault", "list"]).expect("parse");

        assert!(is_create_command(
            &create
                .into_agent_gateway()
                .command
        ));
        assert!(!is_create_command(
            &list
                .into_agent_gateway()
                .command
        ));
    }
}

async fn run_surfaces(
    client: &GatewayClient,
    command: SurfaceCommand,
    output: Output,
) -> Result<Option<Value>> {
    match command {
        SurfaceCommand::List => client
            .request(Method::GET, "/v1/surfaces", None)
            .await
            .map(Some),
        SurfaceCommand::Get { surface_id } => client
            .request(Method::GET, &entity_path("/v1/surfaces", &surface_id), None)
            .await
            .map(Some),
        SurfaceCommand::Create(args) => {
            let body = if let Some(file) = args.file {
                read_json(&file)?
            } else {
                surface_body(args)?
            };
            client
                .request(Method::POST, "/v1/surfaces", Some(body))
                .await
                .map(Some)
        }
        SurfaceCommand::Update {
            surface_id,
            file,
            set,
            unset,
            add,
            remove,
            dry_run,
        } => {
            let path = entity_path("/v1/surfaces", &surface_id);
            match file {
                Some(file) => {
                    let surface = read_json(&file)?;
                    surface_validate::check_surface(&surface)?;
                    client
                        .request(Method::PUT, &path, Some(surface))
                        .await
                        .map(Some)
                }
                None => {
                    let checkable = dry_run || !add.is_empty() || !remove.is_empty();
                    let surface = match fetch_surface(client, &path).await {
                        Ok(surface) => surface,
                        // --set and --unset alone need only surfaces.edit, so a
                        // token without surfaces.view still sends them, just
                        // without the check on this machine.
                        Err(error)
                            if !checkable
                                && matches!(
                                    response_status(&error),
                                    Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
                                ) =>
                        {
                            eprintln!(
                                "warning: could not read the surface to check the edit first (needs surfaces.view), \
                                 sending it unchecked"
                            );
                            let patch = surface_patch::build_patch(&set, &unset, &[], &[], &Value::Null)?;
                            return client
                                .merge_patch(&path, patch)
                                .await
                                .map(Some);
                        }
                        Err(error) if !add.is_empty() || !remove.is_empty() => {
                            return Err(error.context("--add and --remove read the surface before changing it"));
                        }
                        Err(error) => return Err(error),
                    };
                    let patch = surface_patch::build_patch(&set, &unset, &add, &remove, &surface.value)?;
                    send_surface_patch(client, &path, &surface, patch, dry_run, output).await
                }
            }
        }
        SurfaceCommand::Delete { surface_id } => client
            .request(Method::DELETE, &entity_path("/v1/surfaces", &surface_id), None)
            .await
            .map(Some),
        SurfaceCommand::AddFeature(args) => add_feature(client, args, output).await,
        SurfaceCommand::RemoveFeature(args) => remove_feature(client, args, output).await,
        SurfaceCommand::Features { surface_id: Some(surface_id) } => {
            show_surface_features(client, &surface_id, output, &mut io::stdout()).await?;
            Ok(None)
        }
        SurfaceCommand::Features { surface_id: None } => {
            unreachable!("features listing is handled before client setup")
        }
        SurfaceCommand::ToolGatePreview(_) => {
            unreachable!("the tool gate preview is handled before the surfaces commands run")
        }
    }
}

/// Where a surface keeps its MCP tool gating.
const MCP_TOOL_GATING_PATH: &str = "target.mcp_tool_gating";

fn read_gates_file(file: &Path) -> Result<Gating> {
    tool_gate_preview::read_gating_config(&read_json(file)?, "mcp_tool_gating")
}

/// Print the outcome of `tools` under `gating` for a caller who meets the
/// `conditions` given as `POLICY_ID=met` or `POLICY_ID=unmet`.
fn print_tool_gate_preview(
    gating: &Gating,
    tools: &[String],
    conditions: &[String],
    output: Output,
) -> Result<()> {
    print!("{}", render_tool_gate_preview(gating, tools, conditions, Vec::new(), output)?);
    Ok(())
}

/// Read the saved surface `surface_id` and print the preview of its gates.
async fn preview_saved_surface(
    client: &GatewayClient,
    surface_id: &str,
    tools: &[String],
    conditions: &[String],
    output: Output,
) -> Result<()> {
    let surface = fetch_surface(client, &entity_path("/v1/surfaces", surface_id)).await?;
    print!("{}", render_surface_tool_gate_preview(&surface.value, tools, conditions, output)?);
    Ok(())
}

/// The preview of the gates in a saved `surface`, with a note when a variant
/// sets its own tool gating, since only the surface's own gating is read.
fn render_surface_tool_gate_preview(
    surface: &Value,
    tools: &[String],
    conditions: &[String],
    output: Output,
) -> Result<String> {
    let gating = tool_gate_preview::read_gating(surface, MCP_TOOL_GATING_PATH)?;
    render_tool_gate_preview(&gating, tools, conditions, variant_gating_notes(surface), output)
}

/// Notes on the variants of `surface` that change its tool gating. The gateway
/// builds the surface's gating from its default variant, so a default variant
/// that sets gating replaces the saved gating, and a complete one with none
/// clears it.
fn variant_gating_notes(surface: &Value) -> Vec<String> {
    let default_id = surface
        .get("default_variant_id")
        .and_then(Value::as_str);
    let mut others: Vec<String> = Vec::new();
    let mut notes = Vec::new();
    for variant in surface
        .get("variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let overrides = variant.get("overrides");
        let sets_gating = overrides
            .and_then(|overrides| overrides.get("target"))
            .and_then(|target| target.get("mcp_tool_gating"))
            .is_some_and(|gating| !gating.is_null());
        let has_target = overrides
            .and_then(|overrides| overrides.get("target"))
            .is_some_and(|target| !target.is_null());
        let enabled = variant
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        let complete = overrides
            .and_then(|overrides| overrides.get("complete"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let id = variant
            .get("id")
            .and_then(Value::as_str);
        let label = ["alias", "name", "id"]
            .iter()
            .find_map(|key| {
                variant
                    .get(*key)
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
            })
            .unwrap_or("unnamed");
        let is_default = id.is_some() && id == default_id;
        match (is_default, sets_gating, complete && has_target) {
            (true, true, _) => notes.push(format!(
                "The default variant '{label}' sets its own tool gating, and the gateway builds the surface's gating \
                 from the default variant, so this preview does not match what the gateway serves."
            )),
            (true, false, true) => notes.push(format!(
                "The default variant '{label}' is complete and has no tool gating, and the gateway builds the \
                 surface's gating from the default variant, so the gateway serves no gates and this preview does not \
                 match."
            )),
            (false, true, _) => others.push(format!("'{label}'")),
            (false, false, true) => notes.push(format!(
                "The variant '{label}' is complete and has no tool gating, so the gateway serves it with no gates and \
                 this preview does not match."
            )),
            _ => {}
        }
    }
    match others.as_slice() {
        [] => {}
        [one] => notes.push(format!(
            "The variant {one} sets its own tool gating, and this preview reads only the surface's gating."
        )),
        many => notes.push(format!(
            "The variants {} set their own tool gating, and this preview reads only the surface's gating.",
            many.join(", ")
        )),
    }
    notes
}

/// The preview of `tools` under `gating` as text in the `output` format, with
/// the tool names trimmed and repeats dropped. `notes` come before the
/// warnings found in the gates.
fn render_tool_gate_preview(
    gating: &Gating,
    tools: &[String],
    conditions: &[String],
    notes: Vec<String>,
    output: Output,
) -> Result<String> {
    let mut names: Vec<String> = Vec::new();
    for tool in tools {
        let tool = tool.trim();
        if !tool.is_empty()
            && !names
                .iter()
                .any(|name| name == tool)
        {
            names.push(tool.to_owned());
        }
    }
    if names.is_empty() {
        bail!("--tool needs at least one tool name");
    }
    let pinned = tool_gate_preview::parse_pins(conditions)?;
    let previewed = tool_gate_preview::preview(gating, &names, &pinned)?;
    let mut warnings = notes;
    warnings.extend(tool_gate_preview::warnings(gating, &names));
    Ok(match output {
        Output::Json => {
            format!("{}\n", serde_json::to_string_pretty(&tool_gate_preview_json(gating, &previewed, &warnings))?)
        }
        Output::Table => tool_gate_preview_table(gating, &previewed, &warnings),
    })
}

fn effect_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allowed => "allow",
        Verdict::Blocked => "deny",
    }
}

/// The conditions as `admins met, contractors not met`.
fn conditions_text(conditions: &Conditions) -> String {
    conditions
        .iter()
        .map(|(policy, met)| {
            format!(
                "{} {}",
                table_cell(policy),
                if *met {
                    "met"
                } else {
                    "not met"
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn conditions_json(conditions: &Conditions) -> Value {
    Value::Object(
        conditions
            .iter()
            .map(|(policy, met)| {
                (
                    policy.clone(),
                    json!(if *met {
                        "met"
                    } else {
                        "unmet"
                    }),
                )
            })
            .collect(),
    )
}

fn tool_gate_preview_json(
    gating: &Gating,
    previewed: &Preview,
    warnings: &[String],
) -> Value {
    let tools: Vec<Value> = previewed
        .tools
        .iter()
        .map(|preview| {
            let results: Vec<Value> = preview
                .outcomes
                .iter()
                .map(|outcome| {
                    json!({
                        "conditions": conditions_json(&outcome.conditions),
                        "result": effect_word(outcome.decision.verdict),
                        "decided_by": outcome.decision.decided_by,
                    })
                })
                .collect();
            json!({"tool": preview.tool, "results": results})
        })
        .collect();
    json!({
        "default_effect": effect_word(gating.default_verdict()),
        "assumed": conditions_json(&previewed.assumed),
        "tools": tools,
        "warnings": warnings,
    })
}

fn tool_gate_preview_table(
    gating: &Gating,
    previewed: &Preview,
    warnings: &[String],
) -> String {
    let with_condition = previewed
        .tools
        .iter()
        .any(ToolPreview::depends_on_conditions);
    let default = format!("default ({})", effect_word(gating.default_verdict()));
    let mut rows: Vec<[String; 4]> = Vec::new();
    for preview in &previewed.tools {
        for outcome in &preview.outcomes {
            let condition = if outcome.conditions.is_empty() {
                "either way".to_owned()
            } else {
                conditions_text(&outcome.conditions)
            };
            let decided_by = outcome
                .decision
                .decided_by
                .as_deref()
                .map_or_else(|| default.clone(), table_cell);
            rows.push([
                table_cell(&preview.tool),
                condition,
                effect_word(outcome.decision.verdict).to_uppercase(),
                decided_by,
            ]);
        }
    }
    let lines = if with_condition {
        format_table(&["TOOL", "CONDITION", "RESULT", "DECIDED BY"], &rows)
    } else {
        let rows: Vec<[String; 3]> = rows
            .into_iter()
            .map(|[tool, _, result, decided_by]| [tool, result, decided_by])
            .collect();
        format_table(&["TOOL", "RESULT", "DECIDED BY"], &rows)
    };
    let mut text = String::new();
    if !previewed.assumed.is_empty() {
        text.push_str(&format!("Assuming: {}\n\n", conditions_text(&previewed.assumed)));
    }
    for line in lines {
        text.push_str(&line);
        text.push('\n');
    }
    if !warnings.is_empty() {
        text.push_str("\nWarnings\n");
        for warning in warnings {
            text.push_str(&format!("  - {}\n", table_cell(warning)));
        }
    }
    text
}

fn surface_body(args: SurfaceCreateArgs) -> Result<Value> {
    let name = args
        .name
        .context("--name is required without --file")?;
    let route = args
        .route
        .unwrap_or_else(|| format!("/{}", slugify(&name)));
    Ok(json!({
        "name": name,
        "description": args.description,
        "tags": args.tags,
        "access_point": {"listen_address": args.listen_address, "route": route, "protocol": args.protocol.as_str()},
        "target": {"endpoint": args.target_endpoint}
    }))
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// List users.
    List,
    /// Get a user by ID.
    ///
    /// The ID is the user's UUID as shown by `list`, not the username.
    /// `integrations` is a reserved sibling route and returns the
    /// integration assignments rather than a user.
    Get { user_id: String },
    /// Update a user's role, status, or profile from a JSON document.
    ///
    /// Fields the document omits keep their current values.
    Update {
        user_id: String,
        /// JSON document carrying any of `role`, `status`, `first_name`,
        /// `last_name`, `email`, `department`, `job_title`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a user by ID.
    Delete { user_id: String },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// List did:webvh identities.
    List,
    /// Get an identity by ID.
    ///
    /// The ID is the identity's UUID as shown by `list`, not its DID.
    /// `integrations` is a reserved sibling route and returns the
    /// integration assignments rather than an identity.
    Get {
        id: String,
        /// Include the key pair, which carries the identity's private key.
        #[arg(long)]
        reveal: bool,
    },
    /// Create an identity, optionally from a JSON document.
    Create {
        /// JSON document `{did_path?, metadata?, key_pair?}`. Every field is
        /// optional; the gateway fills in whatever the document omits. A key
        /// pair belongs under `key_pair`: an unwrapped one is rejected,
        /// because the gateway would ignore it and install one of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Update an identity's DID document from a JSON document.
    Update {
        id: String,
        /// JSON document `{did_document, update_keys?, ttl?}`. A bare DID
        /// document is rejected: it belongs under `did_document`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Rotate an identity's signing keys.
    ///
    /// Without --file the gateway generates the replacement key pair.
    #[command(name = "rotate-keys")]
    RotateKeys {
        id: String,
        /// JSON document `{"new_key_pair": {public_key, private_key,
        /// key_type?}}`. An unwrapped key pair is rejected, because the
        /// gateway would ignore it and install one of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Transfer an identity to a new controller.
    Transfer {
        id: String,
        /// JSON document `{new_controller, current_owner_authorization,
        /// new_owner_authorization?, new_ownership_proof?, transfer_reason?}`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show an identity's version history.
    History { id: String },
    /// Read or write an identity's trust-score policy (minimum trust score
    /// and component weights).
    ///
    /// The gateway stores this policy and returns it, but does not enforce it
    /// on requests. Unrelated to `fabric agent-gateway policies`, which manages the Rego
    /// policy definitions the gateway does enforce.
    #[command(name = "trust-policy")]
    TrustPolicy {
        #[command(subcommand)]
        command: TrustPolicyCommand,
    },
    /// Deactivate an identity.
    ///
    /// The record is kept and stays readable; only its active flag is cleared.
    Deactivate { id: String },
}

#[derive(Debug, Subcommand)]
enum TrustPolicyCommand {
    /// Get an identity's trust-score policy.
    ///
    /// The gateway returns its built-in defaults for an identity that has
    /// never had a policy set, so a result does not prove one was configured.
    Get { id: String },
    /// Set an identity's trust-score policy from a JSON document.
    Set {
        id: String,
        /// JSON document `{"config": {...}}`, wrapping the policy that
        /// `trust-policy get` returns under `config`. A bare policy is
        /// rejected.
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ApiKeyCommand {
    /// List API keys across every Agent Surface, or for one of them.
    List {
        /// Agent Surface to list keys for. Omit to list every key.
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Get an API key's metadata. The secret is never returned.
    Get {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
    },
    /// Create an API key for an Agent Surface.
    ///
    /// A key cannot be edited afterwards: replace it with `rotate`.
    Create(ApiKeyCreateArgs),
    /// Revoke an API key without removing its record.
    Revoke {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
        /// Actor recorded in the audit trail.
        #[arg(long, default_value = "api")]
        actor: String,
    },
    /// Rotate an API key: revoke the current secret and issue a new one.
    Rotate {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
        /// Actor recorded in the audit trail.
        #[arg(long, default_value = "api")]
        actor: String,
    },
    /// Delete an API key.
    Delete {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
    },
}

/// The Agent Surface a single-key command acts on. The gateway addresses a
/// key by its surface and then its own id, so a command given the key alone
/// looks the surface up first.
#[derive(Debug, Args)]
struct ApiKeySurfaceArgs {
    /// Agent Surface the key belongs to. Omit to look it up by key id.
    #[arg(long)]
    agent_id: Option<String>,
}

#[derive(Debug, Args)]
struct ApiKeyCreateArgs {
    /// Agent Surface the key belongs to.
    agent_id: String,
    /// External client identifier the key is issued to.
    #[arg(long, required_unless_present = "file")]
    client_id: Option<String>,
    /// Label as name=value. Repeat for multiple labels.
    #[arg(long = "label", value_parser = parse_label)]
    labels: Vec<(String, String)>,
    /// JSON document `{client_id, labels?}`. The other creation flags are
    /// ignored when it is set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum TenantOwnershipCommand {
    /// Report what reassigning a resource would affect.
    Impact {
        /// Resource family the gateway tracks ownership for. api-keys and
        /// connection-points are rejected: they inherit ownership from their
        /// parent resource.
        kind: OwnershipKind,
        id: String,
    },
    /// Assign a resource to a tenant, or clear its tenant ownership.
    Set {
        /// Resource family the gateway tracks ownership for. api-keys and
        /// connection-points are rejected: they inherit ownership from their
        /// parent resource.
        kind: OwnershipKind,
        id: String,
        /// Tenant to assign the resource to.
        #[arg(long, conflicts_with = "clear")]
        tenant: Option<String>,
        /// Clear tenant ownership, making the resource globally owned.
        #[arg(long)]
        clear: bool,
    },
}

/// The resource families that carry their own tenant ownership, mirroring the
/// gateway's `ResourceKind` path names. `api-keys` and `connection-points` are
/// accepted by the path but always rejected: they inherit ownership from their
/// parent resource.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OwnershipKind {
    #[value(name = "secrets")]
    Secrets,
    #[value(name = "certificates")]
    Certificates,
    #[value(name = "api-keys")]
    ApiKeys,
    #[value(name = "surfaces")]
    Surfaces,
    #[value(name = "gateways")]
    Gateways,
    #[value(name = "connection-points")]
    ConnectionPoints,
    #[value(name = "mediators")]
    Mediators,
    #[value(name = "mcp-proxies")]
    McpProxies,
    #[value(name = "a2a-proxies")]
    A2aProxies,
    #[value(name = "trust-registries")]
    TrustRegistries,
    #[value(name = "issuers")]
    Issuers,
    #[value(name = "authorities")]
    Authorities,
    #[value(name = "integrations")]
    Integrations,
    #[value(name = "policy-definitions")]
    PolicyDefinitions,
    #[value(name = "surface-templates")]
    SurfaceTemplates,
    #[value(name = "credential-providers")]
    CredentialProviders,
    #[value(name = "jwt-verification-strategies")]
    JwtVerificationStrategies,
    #[value(name = "sts-clients")]
    StsClients,
}

impl OwnershipKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Certificates => "certificates",
            Self::ApiKeys => "api-keys",
            Self::Surfaces => "surfaces",
            Self::Gateways => "gateways",
            Self::ConnectionPoints => "connection-points",
            Self::Mediators => "mediators",
            Self::McpProxies => "mcp-proxies",
            Self::A2aProxies => "a2a-proxies",
            Self::TrustRegistries => "trust-registries",
            Self::Issuers => "issuers",
            Self::Authorities => "authorities",
            Self::Integrations => "integrations",
            Self::PolicyDefinitions => "policy-definitions",
            Self::SurfaceTemplates => "surface-templates",
            Self::CredentialProviders => "credential-providers",
            Self::JwtVerificationStrategies => "jwt-verification-strategies",
            Self::StsClients => "sts-clients",
        }
    }
}

#[derive(Debug, Subcommand)]
enum JwtStrategyCommand {
    #[command(flatten)]
    Crud(CrudCommand),
    /// Check that a JWKS URI is reachable and serves a parseable key set.
    #[command(name = "validate-jwks-uri")]
    ValidateJwksUri { uri: String },
}

async fn run_users(
    client: &GatewayClient,
    command: UserCommand,
) -> Result<Value> {
    match command {
        UserCommand::List => {
            client
                .request(Method::GET, "/v1/users", None)
                .await
        }
        UserCommand::Get { user_id } => {
            client
                .request(Method::GET, &entity_path("/v1/users", &user_id), None)
                .await
        }
        UserCommand::Update { user_id, file } => {
            reject_reserved_user_route(&user_id)?;
            client
                .request(Method::PUT, &entity_path("/v1/users", &user_id), Some(read_json(&file)?))
                .await
        }
        UserCommand::Delete { user_id } => {
            client
                .request(Method::DELETE, &entity_path("/v1/users", &user_id), None)
                .await
        }
    }
}

/// Rejects the static `/v1/users/integrations` route as a user id. It answers
/// PUT by replacing the gateway's whole user-integration configuration, whose
/// only field is defaulted, so any document sent there — a user record, or
/// `{}` — would clear every assignment and report success.
fn reject_reserved_user_route(user_id: &str) -> Result<()> {
    if user_id == "integrations" {
        bail!(
            "'integrations' is a reserved route, not a user id; use `fabric agent-gateway api put \
             /v1/users/integrations --file <file>` to rewrite the assignments"
        );
    }
    Ok(())
}

async fn run_identities(
    client: &GatewayClient,
    command: IdentityCommand,
) -> Result<Value> {
    match command {
        IdentityCommand::List => {
            let value = client
                .request(Method::GET, "/v1/identities", None)
                .await?;
            Ok(unwrap_collection(value, "identities"))
        }
        IdentityCommand::Get { id, reveal } => {
            let mut value = client
                .request(Method::GET, &entity_path("/v1/identities", &id), None)
                .await?;
            if !reveal && redact_key_pair(&mut value) {
                eprintln!("Hid 'key_pair', which carries this identity's private key. Pass --reveal to include it.");
            }
            Ok(value)
        }
        IdentityCommand::Create { file } => {
            client
                .request(Method::POST, "/v1/identities", Some(create_identity_body(file.as_deref())?))
                .await
        }
        IdentityCommand::Update { id, file } => {
            client
                .request(Method::POST, &identity_action(&id, "update"), Some(read_json(&file)?))
                .await
        }
        IdentityCommand::RotateKeys { id, file } => {
            client
                .request(Method::POST, &identity_action(&id, "rotate-keys"), Some(rotate_keys_body(file.as_deref())?))
                .await
        }
        IdentityCommand::Transfer { id, file } => {
            client
                .request(Method::POST, &identity_action(&id, "transfer"), Some(read_json(&file)?))
                .await
        }
        IdentityCommand::History { id } => {
            client
                .request(Method::GET, &identity_action(&id, "history"), None)
                .await
        }
        IdentityCommand::TrustPolicy { command } => match command {
            TrustPolicyCommand::Get { id } => {
                client
                    .request(Method::GET, &identity_action(&id, "policy"), None)
                    .await
            }
            TrustPolicyCommand::Set { id, file } => {
                client
                    .request(Method::PUT, &identity_action(&id, "policy"), Some(trust_policy_body(&file)?))
                    .await
            }
        },
        IdentityCommand::Deactivate { id } => {
            client
                .request(Method::DELETE, &entity_path("/v1/identities", &id), None)
                .await
        }
    }
}

/// Builds the path of an identity sub-resource such as `history`, or of a POST
/// verb such as `rotate-keys`.
fn identity_action(
    id: &str,
    action: &str,
) -> String {
    format!("{}/{action}", entity_path("/v1/identities", id))
}

/// Reads a request body from `file`, falling back to an empty JSON object.
/// The identity create, update and rotate-keys handlers deserialize the body
/// into a typed extractor, so a request that carries no body is rejected
/// before it reaches them.
fn optional_json_body(file: Option<&Path>) -> Result<Value> {
    match file {
        Some(file) => read_json(file),
        None => Ok(json!({})),
    }
}

/// Reads a create body, refusing one whose top level carries the fields of
/// a key pair. `CreateDidRequest` is optional in every field and does not
/// deny unknown ones, so a key pair that was not put under `key_pair`
/// deserializes to no key pair at all: the gateway generates one of its own,
/// installs it and answers 201, leaving the caller holding a private key
/// that does not control the DID they were just given.
fn create_identity_body(file: Option<&Path>) -> Result<Value> {
    let body = optional_json_body(file)?;
    if carries_a_bare_key_pair(&body) {
        bail!(
            "--file document must wrap the key pair. Send {CREATE_KEY_PAIR_EXAMPLE} instead, keeping any did_path \
             and metadata beside key_pair. Both keys are JWKs, not PEM: the private one carries crv, x and d. The \
             gateway ignores an unwrapped document and installs a key pair of its own instead."
        );
    }
    Ok(body)
}

/// The document a caller-supplied key pair belongs in, shown in full by the
/// refusals so that the fix can be copied from them. The gateway's own keys
/// are Ed25519 JWKs in unpadded base64url, and a PEM string is rejected by
/// its JWK parser with a 500.
const CREATE_KEY_PAIR_EXAMPLE: &str = "{\"key_pair\": {\"public_key\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \
                                       \"x\": \"<base64url>\"}, \"private_key\": {\"kty\": \"OKP\", \"crv\": \
                                       \"Ed25519\", \"x\": \"<base64url>\", \"d\": \"<base64url>\"}}}";

const ROTATE_KEY_PAIR_EXAMPLE: &str = "{\"new_key_pair\": {\"public_key\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \
                                       \"x\": \"<base64url>\"}, \"private_key\": {\"kty\": \"OKP\", \"crv\": \
                                       \"Ed25519\", \"x\": \"<base64url>\", \"d\": \"<base64url>\"}}}";

/// Reports whether a request document carries a key pair's own fields at its
/// top level, which is what a key pair left outside its wrapper looks like.
/// A sparse document that simply omits the wrapper is left alone: every field
/// of a create request is optional.
fn carries_a_bare_key_pair(body: &Value) -> bool {
    ["public_key", "private_key"]
        .iter()
        .any(|field| body.get(field).is_some())
}

/// Reads a rotate-keys body, refusing one that does not carry the
/// `new_key_pair` wrapper. `RotateKeysRequest` holds that single optional
/// field and does not deny unknown ones, so an unwrapped key pair
/// deserializes to `None`: the gateway generates a pair of its own, installs
/// it and answers 200, leaving the operator's key silently unused.
fn rotate_keys_body(file: Option<&Path>) -> Result<Value> {
    let body = optional_json_body(file)?;
    if file.is_some()
        && body
            .get("new_key_pair")
            .is_none_or(Value::is_null)
    {
        bail!(
            "--file document must wrap the key pair. Send {ROTATE_KEY_PAIR_EXAMPLE} instead. Both keys are JWKs, \
             not PEM: the private one carries crv, x and d. The gateway ignores an unwrapped document and installs \
             a key pair of its own instead."
        );
    }
    Ok(body)
}

/// Reads a trust-score policy body, refusing a bare policy. `PolicyConfig`
/// is a required field of the request, so the gateway answers one with a 422
/// naming it; refusing here says which document to send instead, and the
/// document to edit is the one `trust-policy get` returns.
fn trust_policy_body(file: &Path) -> Result<Value> {
    let body = read_json(file)?;
    if body
        .get("config")
        .is_none_or(Value::is_null)
    {
        bail!(
            "--file document must wrap the policy: {{\"config\": {{...}}}}. Take the document to edit from `fabric \
             agent-gateway identities trust-policy get <id> --output json`, which carries the policy under the same key."
        );
    }
    Ok(body)
}

/// Removes an identity's `key_pair`, reporting whether one was present.
/// `GET /v1/identities/{id}` returns the stored key pair, private JWK
/// included, so `get` drops it unless it was asked for.
fn redact_key_pair(value: &mut Value) -> bool {
    value
        .as_object_mut()
        .and_then(|identity| identity.remove("key_pair"))
        .is_some()
}

/// Unwraps a `{"<field>": [...], "count": n}` list envelope so the rows print
/// as a list rather than as one JSON document.
fn unwrap_collection(
    value: Value,
    field: &str,
) -> Value {
    match value {
        Value::Object(mut envelope) => match envelope.remove(field) {
            Some(items @ Value::Array(_)) => items,
            Some(other) => {
                envelope.insert(field.to_owned(), other);
                Value::Object(envelope)
            }
            None => Value::Object(envelope),
        },
        other => other,
    }
}

/// Runs an API key command and prints its own result. `create` and `rotate`
/// return a secret that exists only in that one response, which the shared
/// printer has no way to single out.
async fn run_api_keys(
    client: &GatewayClient,
    command: ApiKeyCommand,
    output: Output,
) -> Result<()> {
    match command {
        ApiKeyCommand::List { agent_id } => {
            let path = match &agent_id {
                Some(agent_id) => entity_path("/v1/api-keys", agent_id),
                None => "/v1/api-keys".to_owned(),
            };
            let value = client
                .request(Method::GET, &path, None)
                .await?;
            print_api_keys(&value, output)
        }
        ApiKeyCommand::Get { key_id, surface } => {
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            let value = client
                .request(Method::GET, &api_key_path(&agent_id, &key_id), None)
                .await?;
            print_value(&value, output, false)
        }
        ApiKeyCommand::Create(args) => {
            let path = entity_path("/v1/api-keys", &args.agent_id);
            let body = if let Some(file) = &args.file {
                read_json(file)?
            } else {
                api_key_body(args)?
            };
            let value = client
                .request(Method::POST, &path, Some(body))
                .await?;
            print_api_key_secret(&value, output)
        }
        ApiKeyCommand::Revoke { key_id, surface, actor } => {
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            let path = format!("{}/revoke", api_key_path(&agent_id, &key_id));
            let value = client
                .request(Method::POST, &path, Some(json!({"actor": actor})))
                .await?;
            print_outcome(&value, output, &format!("Revoked API key '{key_id}'"))
        }
        ApiKeyCommand::Rotate { key_id, surface, actor } => {
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            let path = format!("{}/rotate", api_key_path(&agent_id, &key_id));
            let value = client
                .request(Method::POST, &path, Some(json!({"actor": actor})))
                .await?;
            print_api_key_secret(&value, output)
        }
        ApiKeyCommand::Delete { key_id, surface } => {
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            let value = client
                .request(Method::DELETE, &api_key_path(&agent_id, &key_id), None)
                .await?;
            print_outcome(&value, output, &format!("Deleted API key '{key_id}'"))
        }
    }
}

/// Resolves the Agent Surface a key id belongs to, so that a key can be
/// addressed by itself: every single-key route takes both ids, but
/// `GET /v1/api-keys` reports each key's own `agent_id`. Key ids are random
/// and their uniqueness is not enforced, so a collision is refused rather
/// than guessed at. `--agent-id` skips the lookup, which a caller whose
/// token carries `api_keys.edit` or `api_keys.delete` without
/// `api_keys.view` needs: the key's own route is open to them, the
/// collection is not.
async fn resolve_api_key_surface(
    client: &GatewayClient,
    key_id: &str,
    surface: ApiKeySurfaceArgs,
) -> Result<String> {
    if let Some(agent_id) = surface.agent_id {
        return Ok(agent_id);
    }
    let keys = client
        .request(Method::GET, "/v1/api-keys", None)
        .await
        .with_context(|| {
            format!(
                "look up which Agent Surface API key '{key_id}' belongs to; pass --agent-id <surface-id> to skip \
                 the lookup"
            )
        })?;
    let surfaces = surfaces_carrying_key(&keys, key_id)?;
    match surfaces.as_slice() {
        [agent_id] => Ok((*agent_id).to_owned()),
        [] => bail!("API key '{key_id}' not found on any Agent Surface this token can see"),
        _ => bail!(
            "API key '{key_id}' is on more than one Agent Surface ({}); pass --agent-id <surface-id> to choose one",
            surfaces.join(", ")
        ),
    }
}

/// Collects the Agent Surfaces a key id appears on in a key collection.
fn surfaces_carrying_key<'a>(
    keys: &'a Value,
    key_id: &str,
) -> Result<Vec<&'a str>> {
    let rows = keys
        .as_array()
        .context("gateway answered the API key collection with something other than a list")?;
    Ok(rows
        .iter()
        .filter(|key| {
            key.get("key_id")
                .and_then(Value::as_str)
                == Some(key_id)
        })
        .filter_map(|key| {
            key.get("agent_id")
                .and_then(Value::as_str)
        })
        .collect())
}

/// Prints the outcome of a call the gateway answers with 204 and no body.
fn print_outcome(
    value: &Value,
    output: Output,
    confirmation: &str,
) -> Result<()> {
    match outcome_line(output, confirmation) {
        Some(line) => {
            println!("{line}");
            Ok(())
        }
        None => print_value(value, output, false),
    }
}

/// Chooses what an empty 204 answer puts on standard output: a confirmation
/// for a person reading a table, and the gateway's own document (`null` for
/// an empty body) in JSON mode, where prose would make the output
/// unparseable for whatever consumes it.
fn outcome_line(
    output: Output,
    confirmation: &str,
) -> Option<&str> {
    match output {
        Output::Table => Some(confirmation),
        Output::Json => None,
    }
}

/// Parses a `--label` occurrence of the form `name=value`, splitting it the
/// same way a required header is split but naming the label's own syntax.
fn parse_label(raw: &str) -> Result<(String, String), String> {
    parse_required_header(raw).map_err(|_| format!("expected name=value with both non-empty, got '{raw}'"))
}

fn api_key_body(args: ApiKeyCreateArgs) -> Result<Value> {
    let client_id = args
        .client_id
        .context("--client-id is required without --file")?;
    let mut body = json!({"client_id": client_id});
    if !args.labels.is_empty() {
        let labels: serde_json::Map<String, Value> = args
            .labels
            .into_iter()
            .map(|(name, value)| (name, json!(value)))
            .collect();
        body["labels"] = Value::Object(labels);
    }
    Ok(body)
}

/// Builds the two-segment `{agent_id}/{key_id}` path an API key is addressed
/// by; `entity_path` appends a single ID.
fn api_key_path(
    agent_id: &str,
    key_id: &str,
) -> String {
    entity_path(&entity_path("/v1/api-keys", agent_id), key_id)
}

/// Prints a create or rotate response. The secret appears in this response
/// only and the gateway stores nothing but its hash, so table output prints
/// the secret alone for capture in a variable.
fn print_api_key_secret(
    value: &Value,
    output: Output,
) -> Result<()> {
    let Some(secret) = value
        .get("secret")
        .and_then(Value::as_str)
    else {
        return print_value(value, output, false);
    };
    let key_id = value
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or("-");
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Table => println!("{secret}"),
    }
    eprintln!("Secret for API key '{key_id}'. This is the only time it is shown. Store it securely now.");
    Ok(())
}

fn print_api_keys(
    value: &Value,
    output: Output,
) -> Result<()> {
    match (output, value.as_array()) {
        (Output::Table, Some(rows)) if rows.is_empty() => println!("No results."),
        (Output::Table, Some(rows)) => {
            for row in rows {
                print_api_key_row(row);
            }
        }
        _ => return print_value(value, output, false),
    }
    Ok(())
}

fn print_api_key_row(value: &Value) {
    let Some(key) = value.as_object() else {
        println!("{value}");
        return;
    };
    let field = |name: &str| {
        key.get(name)
            .and_then(Value::as_str)
            .unwrap_or("-")
    };
    println!("{}\t{}\t{}\t{}", field("key_id"), field("agent_id"), field("client_id"), field("status"));
}

async fn run_tenant_ownership(
    client: &GatewayClient,
    command: TenantOwnershipCommand,
) -> Result<Value> {
    match command {
        TenantOwnershipCommand::Impact { kind, id } => {
            client
                .request(Method::GET, &format!("{}/impact", ownership_path(kind, &id)), None)
                .await
        }
        TenantOwnershipCommand::Set { kind, id, tenant, clear } => client
            .request(Method::PUT, &ownership_path(kind, &id), Some(ownership_body(tenant, clear)?))
            .await
            .map_err(add_ownership_conflict_hint),
    }
}

fn ownership_path(
    kind: OwnershipKind,
    id: &str,
) -> String {
    entity_path(&format!("/v1/tenant-ownership/{}", kind.as_str()), id)
}

/// Builds a reassignment body. The gateway reads a missing `tenant_id` as a
/// request to clear ownership, so clearing has to be asked for outright.
fn ownership_body(
    tenant: Option<String>,
    clear: bool,
) -> Result<Value> {
    match (tenant, clear) {
        (Some(_), true) => bail!("--tenant and --clear cannot be combined"),
        (Some(tenant), false) => Ok(json!({"tenant_id": tenant})),
        (None, true) => Ok(json!({"tenant_id": null})),
        (None, false) => bail!("provide --tenant <tenant-id>, or --clear to remove tenant ownership"),
    }
}

/// Appends a hint pointing at `impact` when a reassignment is blocked. The
/// gateway answers with the blocking references, but under a constant `error`
/// string that the shared error extraction reports in their place.
fn add_ownership_conflict_hint(error: anyhow::Error) -> anyhow::Error {
    if error
        .to_string()
        .contains("tenant_reassignment_blocked")
    {
        return error.context(
            "run `fabric agent-gateway tenant-ownership impact <kind> <id>` to see the references blocking this move",
        );
    }
    error
}

async fn run_jwt_strategies(
    client: &GatewayClient,
    command: JwtStrategyCommand,
) -> Result<Value> {
    match command {
        JwtStrategyCommand::Crud(command) => run_crud(client, "/v1/jwt-verification-strategies", command).await,
        JwtStrategyCommand::ValidateJwksUri { uri } => {
            client
                .request(Method::POST, "/v1/jwt-verification-strategies/validate-jwks-uri", Some(json!({"uri": uri})))
                .await
        }
    }
}

#[cfg(test)]
mod identity_access_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const IDENTITY_WITH_KEY_PAIR: &str = r#"{"id":"i-1","did":"did:webvh:example.com:agents/x",
        "key_pair":{"public_key":{"x":"p"},"private_key":{"d":"private-jwk"},"key_type":"Ed25519"}}"#;

    /// An address nothing listens on, for asserting that a command fails
    /// before it reaches the network.
    const UNROUTABLE_HOST: &str = "http://127.0.0.1:1";

    /// Starts a one-shot HTTP server that answers the first request with
    /// `body` and hands back the request it received. The sibling `tests`
    /// module has a similar helper, but its items are private to it.
    async fn one_shot_gateway(body: &'static str) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let (host, requests) = gateway_serving(vec![body]).await;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok(mut requests) = requests.await {
                let _ = sender.send(requests.remove(0));
            }
        });
        (host, receiver)
    }

    /// Starts an HTTP server that answers `bodies` in order, one request per
    /// connection, and hands back every request once the last has arrived.
    /// A command that looks a key's Agent Surface up makes two calls, and the
    /// paths of both are what the lookup has to be judged by.
    async fn gateway_serving(bodies: Vec<&'static str>) -> (String, tokio::sync::oneshot::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in bodies {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                requests.push(read_request(&mut socket).await);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
                     close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
            let _ = sender.send(requests);
        });
        (format!("http://{addr}"), receiver)
    }

    /// Waits for the requests a `gateway_serving` stub reports, failing rather
    /// than hanging when the command made fewer requests than the stub was
    /// given bodies for: the stub reports only once every body is served.
    async fn served(requests: tokio::sync::oneshot::Receiver<Vec<String>>) -> Vec<String> {
        tokio::time::timeout(std::time::Duration::from_secs(5), requests)
            .await
            .expect("the command never made a request the stub was waiting for")
            .expect("the stub should report the requests it received")
    }

    /// Reads one HTTP request, continuing until the declared body has arrived
    /// so that an assertion on the body cannot race the client's writes.
    async fn read_request(socket: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(read) = socket.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&request);
            let Some((head, body)) = text.split_once("\r\n\r\n") else {
                continue;
            };
            let declared = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .and_then(|value| {
                            value
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                })
                .unwrap_or(0);
            if body.len() >= declared {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    #[tokio::test]
    async fn identity_get_hides_the_private_key_by_default() {
        let (host, _request) = one_shot_gateway(IDENTITY_WITH_KEY_PAIR).await;
        let client = GatewayClient::new(host, "token").expect("client");

        let value = run_identities(
            &client,
            IdentityCommand::Get {
                id: "i-1".to_owned(),
                reveal: false,
            },
        )
        .await
        .expect("get should succeed");

        assert!(
            value
                .get("key_pair")
                .is_none(),
            "get must not hand the identity's private key to the printer: {value}"
        );
        assert_eq!(value["did"], json!("did:webvh:example.com:agents/x"));
    }

    #[tokio::test]
    async fn identity_get_returns_the_key_pair_with_reveal() {
        let (host, _request) = one_shot_gateway(IDENTITY_WITH_KEY_PAIR).await;
        let client = GatewayClient::new(host, "token").expect("client");

        let value = run_identities(
            &client,
            IdentityCommand::Get {
                id: "i-1".to_owned(),
                reveal: true,
            },
        )
        .await
        .expect("get should succeed");

        assert_eq!(value.pointer("/key_pair/private_key/d"), Some(&json!("private-jwk")));
    }

    #[tokio::test]
    async fn rotate_keys_sends_a_body_the_handler_can_extract() {
        let (host, request) = one_shot_gateway("{}").await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_identities(
            &client,
            IdentityCommand::RotateKeys {
                id: "i-1".to_owned(),
                file: None,
            },
        )
        .await
        .expect("rotate-keys should succeed");

        let request = request
            .await
            .expect("the stub should report the request it received");
        assert!(request.starts_with("POST /api/v1/identities/i-1/rotate-keys "), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "a body-less request is rejected before the handler runs: {request}"
        );
        assert!(request.ends_with("{}"), "{request}");
    }

    #[tokio::test]
    async fn users_update_refuses_the_reserved_integrations_route() {
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");

        let error = run_users(
            &client,
            UserCommand::Update {
                user_id: "integrations".to_owned(),
                file: PathBuf::from("/nonexistent/user.json"),
            },
        )
        .await
        .expect_err("a PUT there replaces every user-integration assignment");

        let message = error.to_string();
        assert!(message.contains("reserved route"), "{message}");
        assert!(message.contains("fabric agent-gateway api put"), "{message}");
        assert!(
            !message.contains("/nonexistent/user.json"),
            "the guard must run before the request body is read: {message}"
        );
    }

    #[tokio::test]
    async fn ownership_set_sends_nothing_without_a_tenant_choice() {
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");

        let error = run_tenant_ownership(
            &client,
            TenantOwnershipCommand::Set {
                kind: OwnershipKind::Surfaces,
                id: "s-1".to_owned(),
                tenant: None,
                clear: false,
            },
        )
        .await
        .expect_err("an absent tenant must not reach the gateway as a clear");

        let message = error.to_string();
        assert!(message.contains("--clear"), "{message}");
        assert!(!message.contains("127.0.0.1"), "no request should be attempted: {message}");
    }

    #[test]
    fn label_flag_reports_the_label_syntax() {
        let error = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "api-keys",
            "create",
            "surface-1",
            "--client-id",
            "billing",
            "--label",
            "team",
        ])
        .expect_err("a label without '=' should be rejected");

        let message = error.to_string();
        assert!(message.contains("name=value"), "{message}");
        assert!(!message.contains("pattern"), "--label must not describe itself as a header pattern: {message}");
    }

    #[test]
    fn parse_label_splits_a_name_and_value() {
        assert_eq!(parse_label("team=payments").unwrap(), ("team".to_owned(), "payments".to_owned()));
        assert!(parse_label("=payments").is_err());
        assert!(parse_label("team=").is_err());
    }

    #[test]
    fn json_output_carries_no_confirmation_prose() {
        assert_eq!(outcome_line(Output::Table, "Revoked API key 'k-1'"), Some("Revoked API key 'k-1'"));
        assert_eq!(
            outcome_line(Output::Json, "Revoked API key 'k-1'"),
            None,
            "prose on standard output makes `--output json` unparseable"
        );
    }

    #[test]
    fn users_have_no_create_command() {
        Cli::try_parse_from(["fabric", "agent-gateway", "users", "create", "--file", "user.json"])
            .expect_err("users cannot be created through the management API");
    }

    #[test]
    fn identities_delete_is_named_deactivate() {
        Cli::try_parse_from(["fabric", "agent-gateway", "identities", "delete", "id-1"])
            .expect_err("deactivation keeps the record, so the verb is `deactivate`");
        Cli::try_parse_from(["fabric", "agent-gateway", "identities", "deactivate", "id-1"])
            .expect("deactivate should parse");
    }

    #[test]
    fn identity_action_appends_the_verb_to_an_encoded_id() {
        assert_eq!(identity_action("a b", "rotate-keys"), "/v1/identities/a+b/rotate-keys");
    }

    #[test]
    fn rotate_keys_sends_a_body_without_a_file() {
        assert_eq!(optional_json_body(None).unwrap(), json!({}));
    }

    #[test]
    fn get_hides_the_key_pair_by_default() {
        let mut identity = json!({"id": "i-1", "key_pair": {"private_key": {"d": "secret"}}});
        assert!(redact_key_pair(&mut identity));
        assert!(
            identity
                .get("key_pair")
                .is_none()
        );
        assert_eq!(identity["id"], json!("i-1"));
    }

    #[test]
    fn redacting_reports_an_identity_that_carried_no_key_pair() {
        let mut identity = json!({"id": "i-1"});
        assert!(!redact_key_pair(&mut identity));
    }

    #[test]
    fn identities_list_unwraps_its_envelope() {
        let envelope = json!({"identities": [{"id": "i-1"}], "count": 1});
        assert_eq!(unwrap_collection(envelope, "identities"), json!([{"id": "i-1"}]));
    }

    #[test]
    fn unwrapping_leaves_a_document_that_is_not_an_envelope_alone() {
        let entity = json!({"identities": 3, "count": 1});
        assert_eq!(unwrap_collection(entity.clone(), "identities"), entity);
        assert_eq!(unwrap_collection(json!([1]), "identities"), json!([1]));
    }

    #[test]
    fn api_key_path_joins_both_identifiers() {
        assert_eq!(api_key_path("surface 1", "atgk_1"), "/v1/api-keys/surface+1/atgk_1");
    }

    /// Two keys on two surfaces, as `GET /v1/api-keys` reports them.
    const KEY_COLLECTION: &str = r#"[{"key_id":"atgk_1","agent_id":"surface-1","status":"active"},
        {"key_id":"atgk_2","agent_id":"surface-2","status":"revoked"}]"#;

    fn by_key_id(key_id: &str) -> ApiKeyCommand {
        ApiKeyCommand::Get {
            key_id: key_id.to_owned(),
            surface: ApiKeySurfaceArgs { agent_id: None },
        }
    }

    #[tokio::test]
    async fn get_resolves_the_surface_a_key_id_belongs_to() {
        let (host, requests) =
            gateway_serving(vec![KEY_COLLECTION, r#"{"key_id":"atgk_2","agent_id":"surface-2"}"#]).await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_api_keys(&client, by_key_id("atgk_2"), Output::Json)
            .await
            .expect("a key id alone should address the key");

        let requests = served(requests).await;
        assert!(requests[0].starts_with("GET /api/v1/api-keys "), "{}", requests[0]);
        assert!(requests[1].starts_with("GET /api/v1/api-keys/surface-2/atgk_2 "), "{}", requests[1]);
    }

    #[tokio::test]
    async fn an_agent_id_skips_the_lookup() {
        let (host, requests) = gateway_serving(vec![r#"{"key_id":"atgk_1","agent_id":"surface-9"}"#]).await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_api_keys(
            &client,
            ApiKeyCommand::Get {
                key_id: "atgk_1".to_owned(),
                surface: ApiKeySurfaceArgs {
                    agent_id: Some("surface-9".to_owned()),
                },
            },
            Output::Json,
        )
        .await
        .expect("a named surface should be used as it stands");

        let requests = served(requests).await;
        assert!(
            requests[0].starts_with("GET /api/v1/api-keys/surface-9/atgk_1 "),
            "the collection must not be read when the surface is named: {}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn revoke_posts_to_the_surface_the_lookup_resolved() {
        let (host, requests) = gateway_serving(vec![KEY_COLLECTION, "null"]).await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_api_keys(
            &client,
            ApiKeyCommand::Revoke {
                key_id: "atgk_1".to_owned(),
                surface: ApiKeySurfaceArgs { agent_id: None },
                actor: "ops-team".to_owned(),
            },
            Output::Json,
        )
        .await
        .expect("revoke should reach the key's own route");

        let requests = served(requests).await;
        assert!(requests[1].starts_with("POST /api/v1/api-keys/surface-1/atgk_1/revoke "), "{}", requests[1]);
        assert!(requests[1].contains(r#""actor":"ops-team""#), "{}", requests[1]);
    }

    #[tokio::test]
    async fn a_key_id_no_surface_carries_is_reported_as_not_found() {
        let (host, _requests) = gateway_serving(vec![KEY_COLLECTION]).await;
        let client = GatewayClient::new(host, "token").expect("client");

        let error = run_api_keys(&client, by_key_id("atgk_9"), Output::Json)
            .await
            .expect_err("no surface carries this key");

        let message = error.to_string();
        assert!(message.contains("not found"), "{message}");
        assert!(message.contains("atgk_9"), "{message}");
    }

    #[tokio::test]
    async fn a_key_id_two_surfaces_carry_is_refused_by_name() {
        const COLLISION: &str =
            r#"[{"key_id":"atgk_1","agent_id":"surface-1"},{"key_id":"atgk_1","agent_id":"surface-2"}]"#;
        let (host, _requests) = gateway_serving(vec![COLLISION]).await;
        let client = GatewayClient::new(host, "token").expect("client");

        let error = run_api_keys(&client, by_key_id("atgk_1"), Output::Json)
            .await
            .expect_err("key ids are random, not enforced unique, so a collision must not be guessed at");

        let message = error.to_string();
        assert!(message.contains("surface-1") && message.contains("surface-2"), "{message}");
        assert!(message.contains("--agent-id"), "{message}");
    }

    #[tokio::test]
    async fn a_lookup_that_fails_points_at_the_flag_that_skips_it() {
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");

        let error = run_api_keys(&client, by_key_id("atgk_1"), Output::Table)
            .await
            .expect_err("the lookup cannot reach a gateway here");

        let message = format!("{error:#}");
        assert!(message.contains("--agent-id"), "{message}");
        assert!(message.contains("atgk_1"), "{message}");
    }

    #[test]
    fn a_collection_that_is_not_a_list_is_not_read_as_no_match() {
        let error = surfaces_carrying_key(&json!({"error": "nope"}), "atgk_1")
            .expect_err("an answer that is not a list says nothing about the key");
        assert!(
            error
                .to_string()
                .contains("other than a list")
        );
    }

    #[test]
    fn single_key_commands_take_the_key_id_alone() {
        for arguments in [
            vec!["fabric", "agent-gateway", "api-keys", "get", "atgk_1"],
            vec!["fabric", "agent-gateway", "api-keys", "revoke", "atgk_1"],
            vec!["fabric", "agent-gateway", "api-keys", "rotate", "atgk_1", "--agent-id", "surface-1"],
            vec!["fabric", "agent-gateway", "api-keys", "delete", "atgk_1", "--agent-id", "surface-1"],
        ] {
            Cli::try_parse_from(&arguments).unwrap_or_else(|error| panic!("{arguments:?}: {error}"));
        }
        Cli::try_parse_from(["fabric", "agent-gateway", "api-keys", "get", "surface-1", "atgk_1"])
            .expect_err("the surface is a flag now, not a second positional");
    }

    #[test]
    fn the_collection_commands_keep_their_own_shape() {
        Cli::try_parse_from(["fabric", "agent-gateway", "api-keys", "list"]).expect("list should parse");
        Cli::try_parse_from(["fabric", "agent-gateway", "api-keys", "list", "--agent-id", "surface-1"])
            .expect("list --agent-id should parse");
        Cli::try_parse_from(["fabric", "agent-gateway", "api-keys", "create", "surface-1", "--client-id", "billing"])
            .expect("create still takes its surface as a positional");
    }

    #[test]
    fn creates_minimal_api_key_payload() {
        let value = api_key_body(ApiKeyCreateArgs {
            agent_id: "surface-1".into(),
            client_id: Some("billing".into()),
            labels: vec![],
            file: None,
        })
        .unwrap();
        assert_eq!(value, json!({"client_id": "billing"}));
    }

    #[test]
    fn api_key_payload_includes_labels_when_set() {
        let value = api_key_body(ApiKeyCreateArgs {
            agent_id: "surface-1".into(),
            client_id: Some("billing".into()),
            labels: vec![("team".into(), "payments".into())],
            file: None,
        })
        .unwrap();
        assert_eq!(value["labels"], json!({"team": "payments"}));
    }

    #[test]
    fn api_key_create_requires_a_client_id_without_a_file() {
        Cli::try_parse_from(["fabric", "agent-gateway", "api-keys", "create", "surface-1"])
            .expect_err("create needs --client-id or --file");
    }

    #[test]
    fn ownership_assigns_a_tenant() {
        assert_eq!(ownership_body(Some("tenant-1".into()), false).unwrap(), json!({"tenant_id": "tenant-1"}));
    }

    #[test]
    fn ownership_clears_only_when_asked() {
        assert_eq!(ownership_body(None, true).unwrap(), json!({"tenant_id": null}));
        let error = ownership_body(None, false).expect_err("an absent tenant must not silently clear ownership");
        assert!(
            error
                .to_string()
                .contains("--clear")
        );
        ownership_body(Some("tenant-1".into()), true).expect_err("--tenant and --clear are mutually exclusive");
    }

    #[test]
    fn ownership_set_leaves_the_tenant_choice_to_the_runner() {
        Cli::try_parse_from(["fabric", "agent-gateway", "tenant-ownership", "set", "surfaces", "s-1"])
            .expect("clap accepts the positional pair; the body builder rejects a missing choice");
    }

    #[test]
    fn ownership_kind_rejects_an_unknown_family() {
        Cli::try_parse_from(["fabric", "agent-gateway", "tenant-ownership", "impact", "surface", "s-1"])
            .expect_err("'surface' is not a resource family; 'surfaces' is");
    }

    #[test]
    fn ownership_path_uses_the_gateway_family_name() {
        assert_eq!(
            ownership_path(OwnershipKind::JwtVerificationStrategies, "s 1"),
            "/v1/tenant-ownership/jwt-verification-strategies/s+1"
        );
    }

    #[test]
    fn ownership_kind_value_names_match_their_paths() {
        for kind in <OwnershipKind as clap::ValueEnum>::value_variants() {
            let name = clap::ValueEnum::to_possible_value(kind).expect("every kind is selectable");
            assert_eq!(name.get_name(), kind.as_str());
        }
    }

    #[test]
    fn blocked_reassignment_points_at_the_impact_report() {
        let error = anyhow::anyhow!("gateway returned 409 Conflict: tenant_reassignment_blocked");
        let hinted = add_ownership_conflict_hint(error).to_string();
        assert!(hinted.contains("tenant-ownership impact"));
    }

    #[test]
    fn other_ownership_errors_are_not_hinted() {
        let error = anyhow::anyhow!("gateway returned 404 Not Found: surfaces 's-1' not found");
        let hinted = add_ownership_conflict_hint(error).to_string();
        assert!(!hinted.contains("tenant-ownership impact"));
    }

    #[test]
    fn jwt_strategies_expose_crud_and_the_extra_verb() {
        Cli::try_parse_from(["fabric", "agent-gateway", "jwt-verification-strategies", "list"])
            .expect("list should parse");
        Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "jwt-verification-strategies",
            "validate-jwks-uri",
            "https://idp/jwks",
        ])
        .expect("validate-jwks-uri should parse");
    }

    #[test]
    fn jwt_strategy_create_prints_its_id() {
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "jwt-verification-strategies",
            "create",
            "--file",
            "strategy.json",
        ])
        .expect("create should parse");
        assert!(is_create_command(&cli.agent_gateway().command));
    }

    #[test]
    fn api_key_create_does_not_use_the_shared_created_path() {
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "api-keys",
            "create",
            "surface-1",
            "--client-id",
            "billing",
        ])
        .expect("create should parse");
        assert!(!is_create_command(&cli.agent_gateway().command));
    }

    /// Writes `contents` to a JSON file inside `dir` and returns its path.
    fn json_file(
        dir: &tempfile::TempDir,
        contents: &str,
    ) -> PathBuf {
        let path = dir
            .path()
            .join("key-pair.json");
        std::fs::write(&path, contents).expect("write the request document");
        path
    }

    #[tokio::test]
    async fn create_refuses_a_key_pair_left_outside_its_wrapper() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = json_file(&dir, r#"{"public_key":{"x":"p"},"private_key":{"d":"k"}}"#);
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");

        let error = run_identities(&client, IdentityCommand::Create { file: Some(file) })
            .await
            .expect_err("the gateway would create a DID this key pair does not control");

        let message = error.to_string();
        assert!(
            message.contains(r#""key_pair": {"public_key""#),
            "the refusal must show the document to send: {message}"
        );
        assert!(message.contains("JWKs"), "a PEM key is a 500 from the gateway's JWK parser: {message}");
        assert!(!message.contains("127.0.0.1"), "no identity should be created: {message}");
    }

    #[tokio::test]
    async fn create_sends_a_sparse_document_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = json_file(&dir, r#"{"did_path":"agents/x","metadata":{"team":"payments"}}"#);
        let (host, request) = one_shot_gateway("{}").await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_identities(&client, IdentityCommand::Create { file: Some(file) })
            .await
            .expect("every field of a create request is optional");

        let request = request
            .await
            .expect("the stub should report the request it received");
        assert!(request.contains(r#""did_path":"agents/x""#), "a document with no key pair must be sent: {request}");
    }

    #[tokio::test]
    async fn rotate_keys_refuses_a_key_pair_the_gateway_would_discard() {
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");
        for document in [r#"{"public_key":{"x":"p"},"private_key":{"d":"k"}}"#, r#"{"new_key_pair":null}"#] {
            let dir = tempfile::tempdir().expect("temp dir");
            let file = json_file(&dir, document);

            let error = run_identities(
                &client,
                IdentityCommand::RotateKeys {
                    id: "i-1".to_owned(),
                    file: Some(file),
                },
            )
            .await
            .expect_err("the gateway would ignore this document and install a key pair of its own");

            let message = error.to_string();
            assert!(
                message.contains(r#""new_key_pair": {"public_key""#),
                "the refusal must show the document to send: {document}: {message}"
            );
            assert!(message.contains("JWKs"), "{document}: {message}");
            assert!(!message.contains("127.0.0.1"), "no request should be attempted for {document}: {message}");
        }
    }

    #[test]
    fn identities_trust_policy_replaces_the_policy_subcommand() {
        Cli::try_parse_from(["fabric", "agent-gateway", "identities", "policy", "get", "i-1"])
            .expect_err("`policy` read as the Rego policy definitions `fabric agent-gateway policies` manages");
        Cli::try_parse_from(["fabric", "agent-gateway", "identities", "trust-policy", "get", "i-1"])
            .expect("trust-policy get should parse");
        Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "identities",
            "trust-policy",
            "set",
            "i-1",
            "--file",
            "policy.json",
        ])
        .expect("trust-policy set should parse");
    }

    #[tokio::test]
    async fn trust_policy_set_refuses_a_policy_left_outside_its_wrapper() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = json_file(&dir, r#"{"minTrustScore":0.9}"#);
        let client = GatewayClient::new(UNROUTABLE_HOST, "token").expect("client");

        let error = run_identities(
            &client,
            IdentityCommand::TrustPolicy {
                command: TrustPolicyCommand::Set { id: "i-1".to_owned(), file },
            },
        )
        .await
        .expect_err("the request carries the policy under `config`");

        let message = error.to_string();
        assert!(message.contains("config"), "{message}");
        assert!(!message.contains("127.0.0.1"), "no request should be attempted: {message}");
    }

    #[tokio::test]
    async fn trust_policy_set_sends_a_wrapped_policy_to_the_policy_route() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = json_file(&dir, r#"{"config":{"minTrustScore":0.9}}"#);
        let (host, request) = one_shot_gateway("{}").await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_identities(
            &client,
            IdentityCommand::TrustPolicy {
                command: TrustPolicyCommand::Set { id: "i-1".to_owned(), file },
            },
        )
        .await
        .expect("a wrapped policy should be sent as it stands");

        let request = request
            .await
            .expect("the stub should report the request it received");
        assert!(request.starts_with("PUT /api/v1/identities/i-1/policy "), "{request}");
        assert!(
            request.contains(r#"{"config":{"minTrustScore":0.9}}"#),
            "the wrapper must reach the handler: {request}"
        );
    }

    #[tokio::test]
    async fn rotate_keys_sends_a_wrapped_key_pair_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = json_file(&dir, r#"{"new_key_pair":{"public_key":{"x":"p"},"private_key":{"d":"k"}}}"#);
        let (host, request) = one_shot_gateway("{}").await;
        let client = GatewayClient::new(host, "token").expect("client");

        run_identities(
            &client,
            IdentityCommand::RotateKeys {
                id: "i-1".to_owned(),
                file: Some(file),
            },
        )
        .await
        .expect("a wrapped key pair should be sent as it stands");

        let request = request
            .await
            .expect("the stub should report the request it received");
        assert!(request.contains(r#""new_key_pair""#), "the wrapper must reach the handler: {request}");
        assert!(request.contains(r#""d":"k""#), "the operator's key must reach the handler: {request}");
    }

    #[test]
    fn deleting_a_user_confirms_rather_than_printing_null() {
        let cli =
            Cli::try_parse_from(["fabric", "agent-gateway", "users", "delete", "u-1"]).expect("delete should parse");
        let confirmation = delete_confirmation(&cli.agent_gateway().command)
            .expect("a 204 with no body must not print the literal `null` in table mode");

        assert_eq!(outcome_line(Output::Table, &confirmation), Some("Deleted user 'u-1'"));
        assert_eq!(
            outcome_line(Output::Json, &confirmation),
            None,
            "`--output json` keeps the gateway's own document so `jq` still reads it"
        );
    }

    #[test]
    fn deleting_a_jwt_strategy_confirms_rather_than_printing_null() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "jwt-verification-strategies", "delete", "s-1"])
            .expect("delete should parse");
        let confirmation = delete_confirmation(&cli.agent_gateway().command)
            .expect("a 204 with no body must not print the literal `null` in table mode");

        assert_eq!(outcome_line(Output::Table, &confirmation), Some("Deleted JWT verification strategy 's-1'"));
        assert_eq!(
            outcome_line(Output::Json, &confirmation),
            None,
            "`--output json` keeps the gateway's own document so `jq` still reads it"
        );
    }

    #[test]
    fn deletes_with_an_answer_of_their_own_keep_the_shared_printer() {
        for arguments in [
            // `run_api_keys` prints this one itself.
            vec!["fabric", "agent-gateway", "api-keys", "delete", "atgk_1"],
            // Deactivation answers 200 with the identity it changed.
            vec!["fabric", "agent-gateway", "identities", "deactivate", "i-1"],
        ] {
            let cli = Cli::try_parse_from(&arguments).expect("the command should parse");
            assert!(
                delete_confirmation(&cli.agent_gateway().command).is_none(),
                "{arguments:?} does not answer with an empty 204",
            );
        }
    }
}

/// Runs an `access-tokens` command and prints the result. `list` renders a
/// table and `revoke` prints a confirmation for the default table output, while
/// `get`/`create`/`rotate` reuse the shared value printer and `scopes` prints one
/// grantable scope per line. `--output json` always emits the raw gateway
/// response (or, for `scopes`, the filtered scope array).
async fn run_access_tokens(
    client: &GatewayClient,
    command: AccessTokenCommand,
    output: Output,
) -> Result<()> {
    match command {
        AccessTokenCommand::List => {
            let value = client
                .request(Method::GET, "/v1/access-tokens", None)
                .await?;
            print_json_or_else(&value, output, || print_access_token_table(&value))?;
        }
        AccessTokenCommand::Revoke(args) => {
            if !args.yes && !confirm_token_action("revoke", &args.id, &format!("Revoke access token {}?", args.id))? {
                println!("Aborted. Access token '{}' was not revoked.", args.id);
                return Ok(());
            }
            let value = client
                .request(Method::DELETE, &entity_path("/v1/access-tokens", &args.id), None)
                .await?;
            print_json_or_else(&value, output, || println!("Revoked access token {}", args.id))?;
        }
        AccessTokenCommand::Rotate(args) => {
            if !args.yes
                && !confirm_token_action(
                    "rotate",
                    &args.id,
                    &format!("Rotate access token {}? Its current secret will stop working immediately.", args.id),
                )?
            {
                println!("Aborted. Access token '{}' was not rotated.", args.id);
                return Ok(());
            }
            let path = format!("{}/rotate", entity_path("/v1/access-tokens", &args.id));
            let value = client
                .request(Method::POST, &path, None)
                .await?;
            print_value(&value, output, true)?;
        }
        AccessTokenCommand::Get { id } => {
            let value = client
                .request(Method::GET, &entity_path("/v1/access-tokens", &id), None)
                .await?;
            print_value(&value, output, false)?;
        }
        AccessTokenCommand::Create(args) => {
            let body = if let Some(file) = args.file {
                read_json(&file)?
            } else {
                access_token_body(args)?
            };
            let value = client
                .request(Method::POST, "/v1/access-tokens", Some(body))
                .await
                .map_err(add_unknown_scope_hint)?;
            print_value(&value, output, true)?;
        }
        AccessTokenCommand::Scopes => {
            let permissions = client
                .request(Method::GET, "/v1/permissions", None)
                .await?;
            let scopes = grantable_scopes(&permissions);
            print_json_or_else(&json!(scopes), output, || {
                for scope in &scopes {
                    println!("{scope}");
                }
            })?;
        }
    }
    Ok(())
}

/// Extracts the sorted list of scope names granted `true` in a
/// `/v1/permissions` response — the scopes the caller may grant a new token.
fn grantable_scopes(permissions: &Value) -> Vec<String> {
    let mut scopes: Vec<String> = permissions
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, granted)| {
            granted
                .as_bool()
                .unwrap_or(false)
        })
        .map(|(scope, _)| scope.clone())
        .collect();
    scopes.sort();
    scopes
}

/// Show `prompt` to confirm a destructive access-token action (`verb`, e.g.
/// `revoke`) and return whether the operator agreed. Refuses instead of hanging
/// when standard input is not a terminal, since the prompt could never be
/// answered in that case.
fn confirm_token_action(
    verb: &str,
    id: &str,
    prompt: &str,
) -> Result<bool> {
    if !io::stdin().is_terminal() {
        bail!(
            "refusing to {verb} '{id}' without confirmation in a non-interactive session; pass --yes to skip the prompt"
        );
    }
    print!("{prompt} [y/N] ");
    io::Write::flush(&mut io::stdout()).context("flush the confirmation prompt")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read the confirmation response from this terminal")?;
    Ok(answer_is_yes(&answer))
}

/// Return whether a confirmation response means yes. Empty input (a bare
/// Enter) is treated as no.
fn answer_is_yes(answer: &str) -> bool {
    matches!(
        answer
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    )
}

fn access_token_body(args: AccessTokenCreateArgs) -> Result<Value> {
    let name = args
        .name
        .context("--name is required without --file")?;
    let mut body = json!({
        "name": name,
        "description": args.description,
        "scopes": args.scopes,
    });
    if let Some(expires_at) = args.expires_at {
        body["expires_at"] = json!(expires_at);
    }
    if let Some(resource_pattern) = args.resource_pattern {
        let resource_pattern = resource_pattern.trim();
        if resource_pattern.is_empty() {
            bail!("--resource-pattern must not be empty");
        }
        body["resource_pattern"] = json!(resource_pattern);
    }
    if !args
        .required_headers
        .is_empty()
    {
        let required_headers: Vec<Value> = args
            .required_headers
            .into_iter()
            .map(|(name, pattern)| json!({"name": name, "pattern": pattern}))
            .collect();
        body["required_headers"] = json!(required_headers);
    }
    Ok(body)
}

/// Appends a hint pointing at `fabric agent-gateway tokens scopes` when the gateway rejects
/// a token creation request for an unknown scope.
fn add_unknown_scope_hint(error: anyhow::Error) -> anyhow::Error {
    let message = error.to_string();
    if message.contains("unknown scope") {
        return anyhow::anyhow!("{message} (see `fabric agent-gateway tokens scopes`)");
    }
    error
}

/// Renders `tokens list` as a fixed-width table. The gateway wraps the list
/// in `{"access_tokens": [...]}`, so unwrap that before rendering rows.
fn print_access_token_table(value: &Value) {
    let tokens = value
        .get("access_tokens")
        .and_then(Value::as_array);
    let Some(tokens) = tokens else {
        print_table(value);
        return;
    };
    if tokens.is_empty() {
        println!("No results.");
        return;
    }
    let header = ["NAME", "ID", "STATUS", "SCOPES", "CREATED", "EXPIRES"];
    let rows: Vec<[String; 6]> = tokens
        .iter()
        .map(access_token_row)
        .collect();
    for line in format_table(&header, &rows) {
        println!("{line}");
    }
}

/// Formats a single token object as one table row of cell values.
fn access_token_row(token: &Value) -> [String; 6] {
    let field = |key: &str| {
        token
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("-")
            .to_owned()
    };
    let name = field("name");
    let id = field("id");
    let status = access_token_status(token).to_owned();
    let scopes = token
        .get("scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
        })
        .filter(|scopes| !scopes.is_empty())
        .map(|scopes| summarize_scopes(&scopes))
        .unwrap_or_else(|| "-".to_owned());
    let created = field("created_at");
    let expires = field("expires_at");
    [name, id, status, scopes, created, expires]
}

/// Maximum width of the SCOPES table cell. A token can carry many long
/// scope names, and since column widths are padded to the widest cell in
/// the column, one such token would otherwise force every row's SCOPES
/// column past a normal terminal width.
const MAX_SCOPES_COLUMN_WIDTH: usize = 40;

/// Joins scope names with commas, capped at [`MAX_SCOPES_COLUMN_WIDTH`].
/// Includes as many full scope names as fit, then appends `+N more` for any
/// scopes left out. Never truncates a scope name mid-word.
fn summarize_scopes(scopes: &[&str]) -> String {
    let full = scopes.join(",");
    if full.len() <= MAX_SCOPES_COLUMN_WIDTH {
        return full;
    }
    let mut shown = 0;
    let mut summary = String::new();
    for scope in scopes {
        let candidate = if summary.is_empty() {
            (*scope).to_owned()
        } else {
            format!("{summary},{scope}")
        };
        let remaining = scopes.len() - shown - 1;
        let suffix_width = if remaining > 0 {
            format!(" +{remaining} more").len()
        } else {
            0
        };
        if candidate.len() + suffix_width > MAX_SCOPES_COLUMN_WIDTH {
            break;
        }
        summary = candidate;
        shown += 1;
    }
    let remaining = scopes.len() - shown;
    if remaining > 0 {
        summary.push_str(&format!(" +{remaining} more"));
    }
    summary
}

/// Lays out a header and rows as fixed-width, space-padded columns, matching
/// the plain style used by tools like `kubectl`/`docker`/`gh`: each column is
/// padded (left-aligned) to the widest cell in that column (including the
/// header), with a 2-space gap between columns. The last column is left
/// unpadded so lines don't carry trailing whitespace.
fn format_table<const N: usize>(
    header: &[&str; N],
    rows: &[[String; N]],
) -> Vec<String> {
    let mut widths = header.map(str::len);
    for row in rows {
        for (width, cell) in widths
            .iter_mut()
            .zip(row.iter())
        {
            *width = (*width).max(cell.len());
        }
    }
    let format_row = |cells: &[&str; N]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index == N - 1 {
                    (*cell).to_owned()
                } else {
                    format!("{cell:<width$}", width = widths[index])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(format_row(header));
    for row in rows {
        let cells: [&str; N] = std::array::from_fn(|index| row[index].as_str());
        lines.push(format_row(&cells));
    }
    lines
}

/// A token is REVOKED when `revoked_at` is set or `active` is explicitly false,
/// otherwise ACTIVE.
fn access_token_status(token: &Value) -> &'static str {
    let revoked = token
        .get("revoked_at")
        .is_some_and(|value| !value.is_null())
        || token
            .get("active")
            .and_then(Value::as_bool)
            == Some(false);
    if revoked {
        "REVOKED"
    } else {
        "ACTIVE"
    }
}

async fn add_feature(
    client: &GatewayClient,
    args: AddFeatureArgs,
    output: Output,
) -> Result<Option<Value>> {
    let feature = features::find(&args.feature)
        .with_context(|| format!("unknown feature '{}'; run `fabric agent-gateway surfaces features`", args.feature))?;
    let placement = feature.select_placement(
        args.placement
            .edge
            .map(Into::into),
        args.placement
            .transit_point
            .is_some(),
        args.placement.response,
    )?;
    let value = build_feature_value(placement.kind, &args)?;

    let path = entity_path("/v1/surfaces", &args.surface_id);
    let surface = fetch_surface(client, &path).await?;
    let patch = features::build_patch(
        feature,
        placement,
        &surface.value,
        args.placement
            .transit_point
            .as_deref(),
        features::FeatureEdit::Add(value),
    )?;
    send_surface_patch(client, &path, &surface, patch, args.dry_run, output).await
}

async fn remove_feature(
    client: &GatewayClient,
    args: FeaturePlacementArgs,
    output: Output,
) -> Result<Option<Value>> {
    let feature = features::find(&args.feature)
        .with_context(|| format!("unknown feature '{}'; run `fabric agent-gateway surfaces features`", args.feature))?;
    let placement = feature.select_placement(
        args.placement
            .edge
            .map(Into::into),
        args.placement
            .transit_point
            .is_some(),
        args.placement.response,
    )?;

    let path = entity_path("/v1/surfaces", &args.surface_id);
    let surface = fetch_surface(client, &path).await?;
    let patch = features::build_patch(
        feature,
        placement,
        &surface.value,
        args.placement
            .transit_point
            .as_deref(),
        features::FeatureEdit::Remove,
    )?;
    send_surface_patch(client, &path, &surface, patch, args.dry_run, output).await
}

/// Response header the gateway puts on `GET /v1/surfaces/{id}` when its PATCH
/// honours `?dry_run=true`, since a gateway without dry run ignores the query
/// parameter and saves. The gateway declares its own copy in
/// `src/identity/handlers/surfaces.rs` that must match exactly, or every dry
/// run falls back to the checks on this machine only.
const SURFACE_DRY_RUN_HEADER: &str = "x-surface-dry-run";

/// Exit status of a `--dry-run` whose gateway checks did not run, distinct from
/// a refused edit (1) and from clap's invalid command line (2), so a script can
/// tell all three apart.
pub const INCOMPLETE_DRY_RUN_EXIT_CODE: i32 = 3;

/// A `--dry-run` that only ran the checks on this machine. Its report and a
/// warning are already printed, so the message only names the outcome.
#[derive(Debug)]
pub struct IncompleteDryRun;

impl std::fmt::Display for IncompleteDryRun {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str("dry run incomplete: only the checks on this machine ran, and nothing was saved")
    }
}

impl std::error::Error for IncompleteDryRun {}

/// The process exit status for a command that failed with `error`.
pub fn exit_code(error: &anyhow::Error) -> i32 {
    if error
        .downcast_ref::<IncompleteDryRun>()
        .is_some()
    {
        INCOMPLETE_DRY_RUN_EXIT_CODE
    } else {
        1
    }
}

/// A surface read ahead of an edit.
struct FetchedSurface {
    value: Value,
    /// Whether the gateway that answered honours `?dry_run=true` on PATCH.
    dry_run_supported: bool,
}

/// Swaps the surface a command names, by ID or by name, for its ID, so the
/// commands below it only ever see an ID. Commands that name no saved surface
/// pass through untouched.
async fn resolve_surface_command(
    client: &GatewayClient,
    command: SurfaceCommand,
) -> Result<SurfaceCommand> {
    Ok(match command {
        SurfaceCommand::Get { surface_id } => SurfaceCommand::Get {
            surface_id: resolve_surface_id(client, &surface_id).await?,
        },
        SurfaceCommand::Delete { surface_id } => SurfaceCommand::Delete {
            surface_id: resolve_surface_id(client, &surface_id).await?,
        },
        SurfaceCommand::Update {
            surface_id,
            file,
            set,
            unset,
            add,
            remove,
            dry_run,
        } => SurfaceCommand::Update {
            surface_id: resolve_surface_id(client, &surface_id).await?,
            file,
            set,
            unset,
            add,
            remove,
            dry_run,
        },
        SurfaceCommand::AddFeature(mut args) => {
            args.surface_id = resolve_surface_id(client, &args.surface_id).await?;
            SurfaceCommand::AddFeature(args)
        }
        SurfaceCommand::RemoveFeature(mut args) => {
            args.surface_id = resolve_surface_id(client, &args.surface_id).await?;
            SurfaceCommand::RemoveFeature(args)
        }
        SurfaceCommand::ToolGatePreview(mut args) => {
            if let Some(reference) = args.surface_id.take() {
                args.surface_id = Some(resolve_surface_id(client, &reference).await?);
            }
            SurfaceCommand::ToolGatePreview(args)
        }
        SurfaceCommand::Features { surface_id: Some(reference) } => SurfaceCommand::Features {
            surface_id: Some(resolve_surface_id(client, &reference).await?),
        },
        command
        @ (SurfaceCommand::List | SurfaceCommand::Create(_) | SurfaceCommand::Features { surface_id: None }) => command,
    })
}

/// The ID of the surface `reference` names, which is `reference` itself when
/// it is an ID. A name is looked up in the list of surfaces and prints
/// `using surface <id> (<name>)` to standard error so the operator sees which
/// surface the command acts on.
async fn resolve_surface_id(
    client: &GatewayClient,
    reference: &str,
) -> Result<String> {
    if reference.trim().is_empty() {
        bail!("give a surface ID or name; run `fabric agent-gateway surfaces list` to see them");
    }
    let surface_id = resolve_id(client, &SURFACE_LOOKUP, reference).await?;
    if let Some(note) = name_resolved_note(&surface_id, reference) {
        eprintln!("{note}");
    }
    Ok(surface_id)
}

/// The note to print when `reference` turned out to be a name, which is when
/// the ID it resolved to differs from it.
fn name_resolved_note(
    surface_id: &str,
    reference: &str,
) -> Option<String> {
    (surface_id != reference).then(|| using_surface_note(surface_id, reference))
}

/// The one-line note printed when a name was resolved to the surface it
/// stands for, so the operator sees which surface a command acts on.
fn using_surface_note(
    surface_id: &str,
    name: &str,
) -> String {
    format!("using surface {} ({})", one_line(surface_id), one_line(name))
}

async fn fetch_surface(
    client: &GatewayClient,
    path: &str,
) -> Result<FetchedSurface> {
    let (value, headers) = client
        .get_with_headers(path)
        .await?;
    Ok(FetchedSurface {
        value,
        dry_run_supported: headers.contains_key(SURFACE_DRY_RUN_HEADER),
    })
}

/// Who worked out the surface a dry run shows as its result.
enum DryRunResult {
    /// The gateway ran every check and answered with the surface it would save.
    Gateway(Value),
    /// The gateway's checks did not run, for `reason`, so the result is the
    /// patch merged on this machine.
    Local { after: Value, reason: String },
    /// The check on this machine refused the patch merged into `after` with
    /// `error`, so nothing was sent.
    Refused { after: Value, error: String },
}

/// Check `patch` against `surface` on this machine and send it as a JSON
/// Merge Patch. With `dry_run` it goes with `?dry_run=true` instead, the
/// report of what would change is printed here and `None` is returned. A dry
/// run the local check refuses prints its report and fails with that error
/// without sending anything, and one whose gateway checks could not run (no
/// dry run, no answer) reports the locally merged result with a warning and
/// fails with [`IncompleteDryRun`]. A dry run never sends the patch without
/// the query parameter.
async fn send_surface_patch(
    client: &GatewayClient,
    path: &str,
    surface: &FetchedSurface,
    patch: Value,
    dry_run: bool,
    output: Output,
) -> Result<Option<Value>> {
    let mut local = surface.value.clone();
    surface_validate::merge(&mut local, &patch);
    if let Err(error) = surface_validate::check_surface(&local) {
        if dry_run {
            let result = DryRunResult::Refused {
                after: local,
                error: format!("{error:#}"),
            };
            print_dry_run(&patch, &surface.value, &result, output)?;
        }
        return Err(error);
    }
    if !dry_run {
        return client
            .merge_patch(path, patch)
            .await
            .map(Some);
    }
    let result = if surface.dry_run_supported {
        match client
            .merge_patch(&format!("{path}?dry_run=true"), patch.clone())
            .await
        {
            Ok(after) => DryRunResult::Gateway(after),
            Err(error) if gateway_checks_did_not_run(&error) => DryRunResult::Local {
                after: local,
                reason: format!("{error:#}"),
            },
            Err(error) => return Err(error),
        }
    } else {
        DryRunResult::Local {
            after: local,
            reason: "this gateway does not support a dry run".to_owned(),
        }
    };
    let complete = matches!(result, DryRunResult::Gateway(_));
    print_dry_run(&patch, &surface.value, &result, output)?;
    if complete {
        Ok(None)
    } else {
        Err(IncompleteDryRun.into())
    }
}

fn print_dry_run(
    patch: &Value,
    before: &Value,
    result: &DryRunResult,
    output: Output,
) -> Result<()> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&dry_run_json(patch, before, result))?),
        Output::Table => {
            if let DryRunResult::Local { reason, .. } = result {
                eprintln!("warning: {}", gateway_checks_skipped_warning(reason));
            }
            print!("{}", dry_run_table(patch, before, result)?);
        }
    }
    Ok(())
}

/// A dry run failure that means the gateway's checks never ran: no answer at
/// all, or a server error. Any other status is the gateway refusing the edit,
/// 404 and 405 included, because the dry run is only sent after the surface
/// was read with [`SURFACE_DRY_RUN_HEADER`], so a 404 means the surface is
/// gone or out of the caller's reach.
fn gateway_checks_did_not_run(error: &anyhow::Error) -> bool {
    response_status(error).is_none_or(|status| status.is_server_error())
}

fn gateway_checks_skipped_warning(reason: &str) -> String {
    format!(
        "the gateway's checks did not run ({reason}), so referenced policies, secrets and credential providers, \
         route and listen path collisions and the other gateway-only checks were not made"
    )
}

fn dry_run_json(
    patch: &Value,
    before: &Value,
    result: &DryRunResult,
) -> Value {
    match result {
        DryRunResult::Gateway(after) => json!({
            "dry_run": true,
            "checked": "gateway",
            "patch": patch,
            "before": before,
            "after": after,
        }),
        DryRunResult::Local { after, reason } => json!({
            "dry_run": true,
            "checked": "local",
            "warning": gateway_checks_skipped_warning(reason),
            "patch": patch,
            "before": before,
            "after": after,
        }),
        DryRunResult::Refused { after, error } => json!({
            "dry_run": true,
            "checked": "local",
            "error": error,
            "patch": patch,
            "before": before,
            "after": after,
        }),
    }
}

fn dry_run_table(
    patch: &Value,
    before: &Value,
    result: &DryRunResult,
) -> Result<String> {
    let (after, heading) = match result {
        DryRunResult::Gateway(after) => (after, "Changes (checked by the gateway):"),
        DryRunResult::Local { after, .. } | DryRunResult::Refused { after, .. } => {
            (after, "Changes (checked on this machine only):")
        }
    };
    let describe = |value: &Option<Value>| {
        value
            .as_ref()
            .map_or_else(|| "(absent)".to_owned(), Value::to_string)
    };
    let mut text = format!("Patch:\n{}\n\n{heading}\n", serde_json::to_string_pretty(patch)?);
    let changes = surface_validate::changes(before, after);
    if changes.is_empty() {
        text.push_str("  none\n");
    }
    for change in changes {
        text.push_str(&format!("  {}: {} -> {}\n", change.path, describe(&change.before), describe(&change.after)));
    }
    text.push_str("\nDry run: nothing was saved.\n");
    Ok(text)
}

fn build_feature_value(
    kind: features::ValueKind,
    args: &AddFeatureArgs,
) -> Result<Value> {
    if let Some(json) = &args.json {
        return serde_json::from_str(json).context("parse --json as JSON");
    }
    if let Some(file) = &args.file {
        return read_json(file);
    }
    if matches!(kind, features::ValueKind::PolicyRef) {
        let policy_id = args
            .policy_id
            .as_deref()
            .context("provide --policy-id (or --json/--file) for a policy feature")?;
        return Ok(features::policy_ref(policy_id));
    }
    bail!("provide the feature configuration with --json '<json>' or --file <path>")
}

fn write_features(
    output: Output,
    out: &mut impl io::Write,
) -> io::Result<()> {
    match output {
        Output::Json => {
            let value = features::describe();
            match serde_json::to_string_pretty(&value) {
                Ok(text) => writeln!(out, "{text}")?,
                Err(_) => writeln!(out, "{value}")?,
            }
        }
        Output::Table => {
            for feature in features::FEATURES {
                let aliases = if feature.aliases.is_empty() {
                    String::new()
                } else {
                    format!("  (aliases: {})", feature.aliases.join(", "))
                };
                writeln!(out, "{}{}", feature.key, aliases)?;
                writeln!(out, "    {}", feature.description)?;
                for placement in feature.placements {
                    writeln!(
                        out,
                        "    {}/{} -> {} [{}]",
                        placement.edge.label(),
                        placement.direction.label(),
                        placement.pointer,
                        placement.kind.label()
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Reads the surface and writes its features to `out`.
async fn show_surface_features(
    client: &GatewayClient,
    surface_id: &str,
    output: Output,
    out: &mut impl io::Write,
) -> Result<()> {
    let surface = client
        .request(Method::GET, &entity_path("/v1/surfaces", surface_id), None)
        .await?;
    match output {
        Output::Json => writeln!(out, "{}", serde_json::to_string_pretty(&features::describe_on_surface(&surface))?),
        Output::Table => write!(out, "{}", surface_features_table(&surface)),
    }
    .context("print the surface's features")
}

/// A table of every feature with whether the surface has it, where it is set
/// and the flags `remove-feature` needs for that place. It has one row per
/// feature and a `;` between the places of a feature that is set in several.
fn surface_features_table(surface: &Value) -> String {
    let rows: Vec<[String; 3]> = features::on_surface(surface)
        .into_iter()
        .map(|state| {
            let (on, places) = if state.places.is_empty() {
                ("off", "-".to_owned())
            } else {
                (
                    "on",
                    state
                        .places
                        .iter()
                        .map(|place| {
                            let remove = match &place.remove {
                                features::RemoveBy::Flags(flags) if flags.is_empty() => {
                                    "remove with no flags".to_owned()
                                }
                                features::RemoveBy::Flags(flags) => format!("remove with {flags}"),
                                features::RemoveBy::NoAlias => {
                                    "remove-feature can't pick it, it has no alias".to_owned()
                                }
                                features::RemoveBy::SharedAlias => {
                                    "remove-feature can't pick it, an earlier transit point has the same alias"
                                        .to_owned()
                                }
                            };
                            one_line(&format!("{}: {} ({remove})", place.area, place.field))
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            };
            [state.feature.key.to_owned(), on.to_owned(), places]
        })
        .collect();
    let mut table = format_table(&["FEATURE", "ON", "WHERE"], &rows).join("\n");
    table.push('\n');
    table
}

async fn run_policies(
    client: &GatewayClient,
    command: PolicyCommand,
) -> Result<Value> {
    match command {
        PolicyCommand::List => {
            client
                .request(Method::GET, "/v1/policy-definitions", None)
                .await
        }
        PolicyCommand::Get { policy_id } => {
            client
                .request(Method::GET, &entity_path("/v1/policy-definitions", &policy_id), None)
                .await
        }
        PolicyCommand::Create {
            id,
            name,
            description,
            policy_type,
            policy_file,
        } => {
            let policy =
                std::fs::read_to_string(&policy_file).with_context(|| format!("read {}", policy_file.display()))?;
            let policy_type = match policy_type {
                PolicyType::Gateway => "gateway",
                PolicyType::AgentSurface => "agent_surface",
            };
            let body = json!({"id": id, "name": name, "description": description, "policy_type": policy_type, "policy": policy, "enabled": true, "created_at": ""});
            client
                .request(Method::POST, "/v1/policy-definitions", Some(body))
                .await
        }
        PolicyCommand::Update { policy_id, file } => {
            client
                .request(Method::PUT, &entity_path("/v1/policy-definitions", &policy_id), Some(read_json(&file)?))
                .await
        }
        PolicyCommand::Delete { policy_id } => {
            client
                .request(Method::DELETE, &entity_path("/v1/policy-definitions", &policy_id), None)
                .await
        }
        PolicyCommand::Versions { policy_id } => {
            client
                .request(Method::GET, &format!("{}/versions", entity_path("/v1/policy-definitions", &policy_id)), None)
                .await
        }
        PolicyCommand::Impact { policy_id } => {
            client
                .request(Method::GET, &format!("{}/impact", entity_path("/v1/policy-definitions", &policy_id)), None)
                .await
        }
    }
}

use crate::client::{REDACTED, RawAuth, clean_for_terminal, gateway_error, sanitize_for_terminal};

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// List audit events, newest first.
    ///
    /// An empty result is ambiguous: the gateway answers 200 with no events
    /// when the audit log is genuinely empty, when its audit subsystem failed
    /// to start, and when it cannot read the audit file or the file is not
    /// valid UTF-8. It also drops any line of the file it cannot parse without
    /// saying so.
    ///
    /// The audit log records gateway traffic: delegation consent and tokens,
    /// policy decisions, trust checks, VP injection, payments, and trace
    /// terminations. Admin API calls, such as creating an identity, are not
    /// audited, so they never appear here. The one exception is revoking
    /// delegation tokens, which records token_revoked or user_tokens_revoked.
    ///
    /// The gateway settings gate three kinds of event, and only while
    /// audit_enabled is on: audit_categories.policies records policy
    /// decisions, audit_categories.trust_checks records trust checks, and
    /// audit_categories.identity records VP-injection events, not changes to
    /// identities. Every other event is recorded whatever those settings say.
    ///
    /// This is the whole audit log. Delegation events are a subset of it, so
    /// there is no separate delegation-audit command; select them with
    /// --category.
    ///
    /// The caller's email and name and the embedded Verifiable Presentation
    /// JWT are replaced with a placeholder unless --reveal is passed.
    List(AuditListArgs),
}

#[derive(Debug, Args)]
struct AuditListArgs {
    /// Events per page. The gateway clamps this to 1-500.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Page to read, counting from 1.
    #[arg(long, default_value_t = 1, conflicts_with = "all")]
    page: usize,
    /// Case-insensitive substring match. The gateway matches it against the
    /// raw JSON of each event, so it also matches field names and the base64
    /// body of an embedded JWT, not only the values shown in a row.
    #[arg(long)]
    filter: Option<String>,
    /// Comma-separated event categories, for example
    /// policy_decision,trust_check,consent_granted,token_injected,payment.
    #[arg(long)]
    category: Option<String>,
    /// Restrict to policy decisions from this request flow. Setting this drops
    /// every event that is not a policy decision.
    #[arg(long, value_enum)]
    flow: Option<AuditFlow>,
    /// Restrict to policy decisions at this scope. Setting this drops every
    /// event that is not a policy decision.
    #[arg(long, value_enum)]
    scope: Option<AuditScope>,
    /// Restrict to policy decisions with this outcome. Setting this drops
    /// every event that is not a policy decision.
    #[arg(long, value_enum)]
    decision: Option<AuditDecision>,
    /// Read every page instead of one.
    #[arg(long)]
    all: bool,
    /// Print the caller's email and name and the full Verifiable Presentation
    /// JWT instead of a placeholder.
    #[arg(long)]
    reveal: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditFlow {
    #[value(name = "access_point")]
    AccessPoint,
    #[value(name = "transit_point")]
    TransitPoint,
    Fabric,
}

impl AuditFlow {
    fn as_str(self) -> &'static str {
        match self {
            Self::AccessPoint => "access_point",
            Self::TransitPoint => "transit_point",
            Self::Fabric => "fabric",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditScope {
    Gateway,
    Surface,
    #[value(name = "mcp_tool")]
    McpTool,
    Response,
}

impl AuditScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Surface => "surface",
            Self::McpTool => "mcp_tool",
            Self::Response => "response",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditDecision {
    Allow,
    Deny,
}

impl AuditDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Subcommand)]
enum PaymentsCommand {
    /// List payment records from both stores, newest first.
    List(PaymentsListArgs),
    /// Get one payment record.
    ///
    /// A full record carries the signed payment receipt and rejection
    /// credentials and the payer's signature. Those are replaced with a
    /// placeholder unless --reveal is passed.
    Get {
        id: String,
        /// Store to read. The default tries x402 and then MPP, because record
        /// IDs do not say which store they belong to.
        #[arg(long, value_enum, default_value_t = PaymentStore::All)]
        store: PaymentStore,
        /// Print the signed payment credentials and the payer signature
        /// instead of a placeholder.
        #[arg(long)]
        reveal: bool,
    },
    /// Show x402 settlement counters.
    Stats {
        /// Also report cross-gateway synchronisation health.
        #[arg(long)]
        sync: bool,
    },
    /// Delete a finalised x402 transaction. MPP records cannot be deleted.
    Delete {
        id: String,
        /// Confirm the deletion. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct PaymentsListArgs {
    /// Store to read. The default reads both and merges them into one table.
    #[arg(long, value_enum, default_value_t = PaymentStore::All)]
    store: PaymentStore,
    /// Only records for this Agent Surface.
    #[arg(long)]
    surface: Option<String>,
    /// Only records with this status. MPP has no status query parameter, so
    /// its records are filtered by the CLI after they are fetched.
    #[arg(long)]
    status: Option<String>,
    /// Maximum records to read from each store.
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PaymentStore {
    X402,
    Mpp,
    All,
}

impl PaymentStore {
    fn as_str(self) -> &'static str {
        match self {
            Self::X402 => "x402",
            Self::Mpp => "mpp",
            Self::All => "all",
        }
    }

    /// Base path of the store's transaction collection. `All` has none.
    fn transactions_path(self) -> Option<&'static str> {
        match self {
            Self::X402 => Some("/admin/x402/transactions"),
            Self::Mpp => Some("/admin/mpp/transactions"),
            Self::All => None,
        }
    }
}

#[derive(Debug, Subcommand)]
enum MetricsCommand {
    /// Manage the metrics configuration.
    Config {
        #[command(subcommand)]
        command: MetricsConfigCommand,
    },
    /// Report OpenTelemetry export health.
    Status,
    /// Fetch the Prometheus exposition.
    ///
    /// When the gateway has Prometheus authentication enabled this route needs
    /// HTTP Basic credentials in the same header the bearer token occupies, so
    /// passing --username and --password sends those instead of the token.
    Scrape(MetricsScrapeArgs),
    /// Check whether the gateway can reach an OTLP endpoint.
    #[command(name = "test-endpoint")]
    TestEndpoint {
        /// OTLP endpoint to open a connection to, including the scheme.
        url: String,
    },
    /// Delete metrics older than the configured retention period.
    Truncate {
        /// Confirm the truncation. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MetricsConfigCommand {
    /// Show the metrics configuration.
    Show,
    /// Replace the whole metrics configuration from a JSON document.
    ///
    /// This is a full replacement, not a patch, and optional settings are
    /// dropped rather than defaulted when the document omits them — omitting
    /// `opentelemetry.auth` switches collector export to unauthenticated. The
    /// submitted document is therefore compared against the live one first and
    /// refused if it would drop anything. Start from `fabric agent-gateway metrics config
    /// show --output json`. The gateway reports success once the file is saved
    /// even if re-applying it to the running collector failed, so read the
    /// `message` in the response rather than `success` alone.
    Set(MetricsFileArgs),
}

/// The replacement metrics document, plus the override for the pre-flight
/// check that refuses one dropping a stored setting.
#[derive(Debug, Args)]
struct MetricsFileArgs {
    /// JSON request body. Use '-' to read from standard input.
    #[arg(short, long)]
    file: PathBuf,
    /// Submit the document even though the pre-flight check refuses it.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct MetricsScrapeArgs {
    /// Prometheus Basic-auth user configured in the gateway's admin settings.
    /// Has an environment fallback so that setting only the password variable
    /// cannot turn an unauthenticated scrape into a usage error.
    #[arg(long, requires = "password", env = "FABRIC_METRICS_USERNAME")]
    username: Option<String>,
    /// Password for --username. Prefer FABRIC_METRICS_PASSWORD over passing it
    /// on the command line, where it lands in shell history.
    #[arg(long, requires = "username", env = "FABRIC_METRICS_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Where to write the exposition. '-' is standard output. Named
    /// --output-file because the global --output selects the display format.
    #[arg(long, default_value = "-")]
    output_file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum LogsCommand {
    /// Download every log file as one ZIP archive.
    ///
    /// The gateway builds the whole archive in memory before sending it, so
    /// this is expensive on a large log directory.
    Download {
        /// Where to write the archive. '-' is standard output. Named
        /// --output-file because the global --output selects the display format.
        #[arg(long, default_value = "logs.zip")]
        output_file: PathBuf,
    },
    /// Delete every rotated log file, keeping the current one.
    Truncate {
        /// Confirm the deletion. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

async fn run_audit(
    client: &GatewayClient,
    command: AuditCommand,
    output: Output,
) -> Result<()> {
    let AuditCommand::List(args) = command;
    let first_page = if args.all {
        1
    } else {
        args.page
    };
    let mut response = fetch_audit_page(client, &args, first_page).await?;
    if args.all {
        collect_remaining_audit_pages(client, &args, &mut response).await?;
    }
    let response = audit_document(response, args.reveal);
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        Output::Table => print_audit_table(&response)?,
    }
    Ok(())
}

/// The audit document to render: redacted unless `--reveal` was passed. The
/// choice lives here rather than inline so it is covered by a test.
fn audit_document(
    mut response: Value,
    reveal: bool,
) -> Value {
    if !reveal {
        redact_audit_events(&mut response);
    }
    response
}

/// Read pages 2..=`total_pages` and append their events to `response`, then
/// drop the counters that described a single page. Stops early on a page with
/// no events, so a gateway reporting an inconsistent `total_pages` cannot make
/// this loop forever.
async fn collect_remaining_audit_pages(
    client: &GatewayClient,
    args: &AuditListArgs,
    response: &mut Value,
) -> Result<()> {
    let total_pages = response
        .get("total_pages")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    for page in 2..=total_pages {
        let next = fetch_audit_page(client, args, page as usize).await?;
        // The gateway clamps the requested page into range rather than
        // returning an empty page, so a page beyond the end resends the last
        // one. Appending that again would duplicate rows in an export.
        if next
            .get("page")
            .and_then(Value::as_u64)
            != Some(page)
        {
            break;
        }
        let Some(events) = next
            .get("events")
            .and_then(Value::as_array)
        else {
            break;
        };
        if events.is_empty() {
            break;
        }
        let events = events.clone();
        let Some(collected) = response
            .get_mut("events")
            .and_then(Value::as_array_mut)
        else {
            break;
        };
        collected.extend(events);
    }
    // The page counters described one page that no longer exists; `total` and
    // `category_counts` cover the whole filtered set, so they stay.
    if let Some(fields) = response.as_object_mut() {
        for key in ["page", "page_size", "total_pages"] {
            fields.remove(key);
        }
    }
    Ok(())
}

async fn fetch_audit_page(
    client: &GatewayClient,
    args: &AuditListArgs,
    page: usize,
) -> Result<Value> {
    let mut pairs = vec![("limit", args.limit.to_string()), ("page", page.to_string())];
    if let Some(filter) = &args.filter {
        pairs.push(("filter", filter.clone()));
    }
    if let Some(category) = &args.category {
        pairs.push(("category", category.clone()));
    }
    if let Some(flow) = args.flow {
        pairs.push(("flow", flow.as_str().to_owned()));
    }
    if let Some(scope) = args.scope {
        pairs.push(("scope", scope.as_str().to_owned()));
    }
    if let Some(decision) = args.decision {
        pairs.push(("decision", decision.as_str().to_owned()));
    }
    client
        .request(Method::GET, &format!("/v1/audit?{}", query_string(&pairs)), None)
        .await
}

/// Printed to standard error beneath "No audit events.", for the operator who
/// expected events: why the log can be empty, and what it never records.
const EMPTY_AUDIT_NOTES: [&str; 2] = [
    "An empty result is ambiguous: the gateway answers 200 with no events when the audit log is empty, when its \
     audit subsystem failed to start, and when it cannot read the audit file or the file is not valid UTF-8. It \
     also drops any line of the file it cannot parse without saying so.",
    "The audit log records gateway traffic (delegation consent and tokens, policy decisions, trust checks, VP \
     injection, payments, trace terminations); admin API calls such as creating an identity are not audited, \
     except revoking delegation tokens.",
];

fn print_audit_table(response: &Value) -> Result<()> {
    write_audit_table(response, &mut io::stdout().lock(), &mut io::stderr().lock()).context("print the audit table")
}

/// Write one row per event to `rows`, or, for an empty result, "No audit
/// events." to `rows` and [`EMPTY_AUDIT_NOTES`] to `notes`, so piped rows stay
/// clean. `rows` is standard output and `notes` standard error.
fn write_audit_table(
    response: &Value,
    rows: &mut impl io::Write,
    notes: &mut impl io::Write,
) -> io::Result<()> {
    let events = response
        .get("events")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if events.is_empty() {
        writeln!(rows, "No audit events.")?;
        for note in EMPTY_AUDIT_NOTES {
            writeln!(notes, "{note}")?;
        }
        return Ok(());
    }
    for event in events {
        writeln!(rows, "{}", audit_row(event))?;
    }
    Ok(())
}

/// Format one audit event as `timestamp  event  surface_id  decision  detail`.
/// Audit events carry none of the `id`, `name`, or `description` keys the
/// shared list formatter looks for, so every row would otherwise render as
/// dashes. `detail` is the gateway's own note on the event, such as how many
/// tokens a revocation removed. Every cell goes through [`table_cell`].
fn audit_row(event: &Value) -> String {
    let timestamp = event
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("-");
    let action = event.get("event");
    // Actions without fields serialise as a bare string; the rest are
    // externally tagged, as `{"policy_decision": {…}}`.
    let (name, details) = match action {
        Some(Value::String(name)) => (name.as_str(), None),
        Some(Value::Object(tagged)) => match tagged.iter().next() {
            Some((name, value)) => (name.as_str(), value.as_object()),
            None => ("-", None),
        },
        _ => ("-", None),
    };
    let surface_id = event
        .get("surface_id")
        .and_then(Value::as_str)
        .or_else(|| {
            details
                .and_then(|fields| fields.get("surface_id"))
                .and_then(Value::as_str)
        })
        .unwrap_or("-");
    let decision = details
        .and_then(|fields| fields.get("decision"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    let detail = event
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("-");
    [timestamp, name, surface_id, decision, detail]
        .map(table_cell)
        .join("\t")
}

/// One cell of a tab-separated row built from gateway-supplied text: sanitised
/// like an error message, with line breaks and tabs turned into spaces so a
/// stored value can neither drive the terminal nor split or shift the row, and
/// `-` when nothing printable is left.
fn table_cell(text: &str) -> String {
    let cell = sanitize_for_terminal(text).replace(['\n', '\t'], " ");
    if cell.trim().is_empty() {
        "-".to_owned()
    } else {
        cell
    }
}

/// Replace the credential-bearing fields of every event: `vp_jwt` carries a
/// complete Verifiable Presentation JWT, and the caller context carries the
/// caller's raw email and display name. The keys stay in place so the shape of
/// `--output json` does not change with the flag.
fn redact_audit_events(response: &mut Value) {
    let Some(events) = response
        .get_mut("events")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for event in events {
        let Some(fields) = event.as_object_mut() else {
            continue;
        };
        if fields.contains_key("vp_jwt") {
            fields.insert("vp_jwt".to_owned(), json!(REDACTED));
        }
        let Some(caller) = fields
            .get_mut("caller")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        for key in ["email", "name"] {
            if caller.contains_key(key) {
                caller.insert(key.to_owned(), json!(REDACTED));
            }
        }
    }
}

async fn run_payments(
    client: &GatewayClient,
    command: PaymentsCommand,
    output: Output,
) -> Result<()> {
    match command {
        PaymentsCommand::List(args) => list_payments(client, args, output).await,
        PaymentsCommand::Get { id, store, reveal } => get_payment(client, &id, store, reveal, output).await,
        PaymentsCommand::Stats { sync } => payment_stats(client, sync, output).await,
        PaymentsCommand::Delete { id, yes } => delete_payment(client, &id, yes, output).await,
    }
}

async fn list_payments(
    client: &GatewayClient,
    args: PaymentsListArgs,
    output: Output,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut footers = Vec::new();
    let mut queried = Vec::new();
    let mut absent = Vec::new();
    // A store that is configured but unreadable must not cost the caller the
    // rows the other store already returned. The two admin routers are
    // authorised differently — MPP additionally requires the `payments.view`
    // feature — so an operator without it gets x402's rows and a 403 on MPP.
    let mut failed: Vec<String> = Vec::new();

    if args.store != PaymentStore::Mpp {
        queried.push(PaymentStore::X402);
        let mut pairs = vec![("limit", args.limit.to_string())];
        if let Some(surface) = &args.surface {
            pairs.push(("surface_id", surface.clone()));
        }
        if let Some(status) = &args.status {
            pairs.push(("status", status.clone()));
        }
        let path = format!("/admin/x402/transactions?{}", query_string(&pairs));
        match payments_get(client, PaymentStore::X402, &path).await {
            Ok(Some(response)) => {
                let records = json_array(&response, "verifications");
                // x402 computes its `total` after applying the limit, so it can
                // only ever equal the number of rows returned. Reporting it as
                // an overall total would be wrong.
                footers.push(format!("x402: {} record(s); this store reports no overall total", records.len()));
                rows.extend(
                    records
                        .iter()
                        .map(|record| payment_row(PaymentStore::X402, record)),
                );
            }
            Ok(None) => absent.push(PaymentStore::X402),
            Err(error) => failed.push(payments_unreadable(&error)),
        }
    }

    if args.store != PaymentStore::X402 {
        queried.push(PaymentStore::Mpp);
        let mut pairs = vec![("limit", args.limit.to_string())];
        if let Some(surface) = &args.surface {
            pairs.push(("surface_id", surface.clone()));
        }
        let path = format!("/admin/mpp/transactions?{}", query_string(&pairs));
        match payments_get(client, PaymentStore::Mpp, &path).await {
            Ok(Some(response)) => {
                let total = response
                    .get("total")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let mut records = json_array(&response, "transactions");
                match &args.status {
                    // MPP has no status query parameter, so this filter runs
                    // here. Both stores share the `verified` and `failed`
                    // statuses and differ only in case — x402 renders them
                    // capitalised, MPP lowercased — and x402 matches its own
                    // case-insensitively, so this one must too, or
                    // `--status Verified` would return x402 rows and silently
                    // no MPP rows.
                    Some(status) => {
                        retain_matching_status(&mut records, status);
                        // The server computes `total` before any status filter,
                        // so pairing it with a filtered count would misreport.
                        footers.push(format!("mpp: {} record(s) matching status", records.len()));
                    }
                    None => footers.push(format!("mpp: {} of {total} record(s)", records.len())),
                }
                rows.extend(
                    records
                        .iter()
                        .map(|record| payment_row(PaymentStore::Mpp, record)),
                );
            }
            Ok(None) => absent.push(PaymentStore::Mpp),
            Err(error) => failed.push(payments_unreadable(&error)),
        }
    }

    let mut notes = Vec::new();
    if !absent.is_empty() {
        notes.push(payments_disabled(&absent));
    }
    notes.extend(failed.iter().cloned());
    // Only a run that read nothing at all is a failure. A store that is missing
    // or unreadable beside one that answered is reported on standard error, so
    // the rows still reach standard output and the caller still sees the gap.
    if absent.len() + failed.len() == queried.len() {
        bail!("{}", notes.join("\n"));
    }
    for note in &notes {
        eprintln!("{note}");
    }

    sort_payments_newest_first(&mut rows);
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&Value::Array(rows))?),
        Output::Table => {
            if rows.is_empty() {
                println!("No payment records.");
            }
            for row in &rows {
                println!("{}", payment_table_row(row));
            }
            for footer in &footers {
                eprintln!("{footer}");
            }
        }
    }
    Ok(())
}

async fn get_payment(
    client: &GatewayClient,
    id: &str,
    store: PaymentStore,
    reveal: bool,
    output: Output,
) -> Result<()> {
    let mut attempts = Vec::new();
    for candidate in [PaymentStore::X402, PaymentStore::Mpp] {
        if store != PaymentStore::All && store != candidate {
            continue;
        }
        let Some(base) = candidate.transactions_path() else {
            continue;
        };
        match payments_get(client, candidate, &entity_path(base, id)).await {
            Ok(Some(record)) => return print_value(&payment_document(record, reveal), output, false),
            Ok(None) => attempts.push(format!("{}: store not configured", candidate.as_str())),
            Err(error) => attempts.push(format!("{error:#}")),
        }
    }
    bail!("no payment record '{id}' was returned:\n  {}", attempts.join("\n  "))
}

async fn payment_stats(
    client: &GatewayClient,
    sync: bool,
    output: Output,
) -> Result<()> {
    let stats = payments_get(client, PaymentStore::X402, "/admin/x402/stats")
        .await?
        .with_context(|| payments_disabled(&[PaymentStore::X402]))?;
    if !sync {
        return print_value(&stats, output, false);
    }
    let sync_status = payments_get(client, PaymentStore::X402, "/admin/x402/sync-status")
        .await?
        .unwrap_or(Value::Null);
    print_value(&json!({"stats": stats, "sync_status": sync_status}), output, false)
}

async fn delete_payment(
    client: &GatewayClient,
    id: &str,
    yes: bool,
    output: Output,
) -> Result<()> {
    if !yes {
        bail!("pass --yes to confirm deleting x402 payment '{id}'; this cannot be undone");
    }
    let path = entity_path("/admin/x402/transactions", id);
    let (status, body) = client
        .request_bytes(Method::DELETE, &path, RawAuth::Bearer)
        .await
        .with_context(|| format!("{} store", PaymentStore::X402.as_str()))?;
    if status == reqwest::StatusCode::NOT_FOUND && !carries_json_error(&body) {
        bail!("{}", payments_disabled(&[PaymentStore::X402]));
    }
    if !status.is_success() {
        return Err(payments_error(PaymentStore::X402, status, &body, &client.secrets(RawAuth::Bearer)));
    }
    match output {
        // The gateway answers 204 with no body, which would otherwise print
        // `null` where a reader expects a result.
        Output::Table => {
            println!("Deleted x402 payment {id}");
            Ok(())
        }
        // Mirror `GatewayClient::request`, which reports an empty body as a
        // null document, so a JSON consumer never has to parse prose.
        Output::Json => print_value(&serde_json::from_slice(&body).unwrap_or(Value::Null), output, false),
    }
}

/// Keep only records whose status matches, ignoring case. MPP has no status
/// query parameter so the filter runs client-side, and x402's server-side one
/// is case-insensitive. The two stores share `verified` and `failed` and write
/// them in different cases, so matching exactly here would make
/// `--status Verified` return x402 rows beside silently no MPP rows.
fn retain_matching_status(
    records: &mut Vec<Value>,
    status: &str,
) {
    records.retain(|record| {
        record
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(status))
    });
}

/// The payment record to render: redacted unless `--reveal` was passed. A full
/// record carries the signed `PaymentReceiptCredential` and
/// `PaymentRejectionCredential` JWTs and, nested inside the x402 payment
/// payload, the payer's signature. The fingerprints beside each JWT are left
/// intact, so a record stays verifiable without carrying the credential.
fn payment_document(
    mut record: Value,
    reveal: bool,
) -> Value {
    if !reveal {
        redact_payment_evidence(&mut record);
    }
    record
}

fn redact_payment_evidence(value: &mut Value) {
    const EVIDENCE_KEYS: &[&str] = &["receipt_vc_jwt", "rejection_vc_jwt", "signature"];
    match value {
        Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                if EVIDENCE_KEYS.contains(&key.as_str()) && !field.is_null() {
                    *field = json!(REDACTED);
                } else {
                    redact_payment_evidence(field);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_payment_evidence(item);
            }
        }
        _ => {}
    }
}

/// Read a payments admin route. Each store's router is only mounted when that
/// store is configured, so its absence is reported as `None` rather than as a
/// request failure.
async fn payments_get(
    client: &GatewayClient,
    store: PaymentStore,
    path: &str,
) -> Result<Option<Value>> {
    let (status, body) = client
        .request_bytes(Method::GET, path, RawAuth::Bearer)
        .await
        .with_context(|| format!("{} store", store.as_str()))?;
    // MPP answers 404 both for an unknown transaction and — because its router
    // is simply not mounted — for a gateway with no MPP store. Only the first
    // carries a JSON error body, so that is what tells them apart.
    if status == reqwest::StatusCode::NOT_FOUND && !carries_json_error(&body) {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(payments_error(store, status, &body, &client.secrets(RawAuth::Bearer)));
    }
    // An unmounted admin route can also fall through to the dashboard's
    // single-page-app handler, which answers 200 with HTML.
    Ok(serde_json::from_slice(&body).ok())
}

/// Whether a response body is a JSON object carrying an `error` message, which
/// distinguishes a handler's own rejection from a route that is not mounted.
fn carries_json_error(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some()
}

/// Turn a failed payments response into an error. Both stores go through the
/// shared [`gateway_error`] formatter, which sanitises the gateway's message,
/// replaces the request's `secrets` in it, and leaves the status out whenever
/// the body carries one. That matters most for x402, whose admin API answers
/// HTTP 500 for every failure — an unknown ID, a transaction whose settlement
/// is still pending, an unconfigured store — so the message is the only thing
/// that distinguishes them. The error names its store here, because `delete`
/// and `stats` report it as it is; a caller that combines several stores must
/// not name the store again.
fn payments_error(
    store: PaymentStore,
    status: reqwest::StatusCode,
    body: &[u8],
    secrets: &[String],
) -> anyhow::Error {
    anyhow::anyhow!("{} store: {}", store.as_str(), gateway_error(status, body, secrets))
}

fn payments_disabled(stores: &[PaymentStore]) -> String {
    let names: Vec<&str> = stores
        .iter()
        .map(|store| store.as_str())
        .collect();
    format!("payments are not enabled on this gateway: no {} payment store is configured", names.join(" or "))
}

/// Report a store that answered but could not be read, so a merged listing can
/// name the gap beside the rows the other store returned. The error already
/// names its store.
fn payments_unreadable(error: &anyhow::Error) -> String {
    format!("payment records could not be read: {error:#}")
}

/// Project a store's record onto the shared payment row, so both stores merge
/// into one table. Each store's denomination field is derived from the store
/// itself, so a call site cannot pair one store with the other's key.
fn payment_row(
    store: PaymentStore,
    record: &Value,
) -> Value {
    let currency_key = match store {
        PaymentStore::X402 => "asset",
        PaymentStore::Mpp | PaymentStore::All => "currency",
    };
    let field = |key: &str| {
        record
            .get(key)
            .cloned()
            .unwrap_or(Value::Null)
    };
    json!({
        "id": field("id"),
        "store": store.as_str(),
        "surface_id": field("surface_id"),
        "status": field("status"),
        "amount": field("amount"),
        "currency": field(currency_key),
        "created_at": field("created_at"),
    })
}

/// Sort merged rows by `created_at` — Unix seconds in both stores — newest
/// first, matching the order each store returns on its own.
fn sort_payments_newest_first(rows: &mut [Value]) {
    rows.sort_by_key(|row| {
        std::cmp::Reverse(
            row.get("created_at")
                .and_then(Value::as_i64)
                .unwrap_or(i64::MIN),
        )
    });
}

fn payment_table_row(row: &Value) -> String {
    let cell = |key: &str| match row.get(key) {
        Some(Value::String(value)) => table_cell(value),
        Some(Value::Null) | None => "-".to_owned(),
        Some(other) => table_cell(&other.to_string()),
    };
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        cell("id"),
        cell("store"),
        cell("surface_id"),
        cell("status"),
        cell("amount"),
        cell("currency"),
        cell("created_at")
    )
}

async fn run_metrics(
    client: &GatewayClient,
    command: MetricsCommand,
    output: Output,
) -> Result<()> {
    match command {
        MetricsCommand::Config {
            command: MetricsConfigCommand::Show,
        } => {
            let value = client
                .request(Method::GET, "/v1/metrics/config", None)
                .await?;
            print_value(&value, output, false)
        }
        MetricsCommand::Config {
            command: MetricsConfigCommand::Set(args),
        } => set_metrics_config(client, args, output, &mut io::stdout()).await,
        MetricsCommand::Status => {
            let value = client
                .request(Method::GET, "/v1/metrics/otlp-status", None)
                .await?;
            print_value(&value, output, false)
        }
        MetricsCommand::Scrape(args) => scrape_metrics(client, args).await,
        MetricsCommand::TestEndpoint { url } => test_metrics_endpoint(client, &url, output).await,
        MetricsCommand::Truncate { yes } => {
            if !yes {
                bail!("pass --yes to confirm truncating stored metrics; this cannot be undone");
            }
            let value = client
                .request(Method::POST, "/v1/metrics/truncate", None)
                .await?;
            print_value(&value, output, false)
        }
    }
}

/// Replace the metrics configuration and write the outcome to `out`, which is
/// standard output.
async fn set_metrics_config(
    client: &GatewayClient,
    args: MetricsFileArgs,
    output: Output,
    out: &mut impl io::Write,
) -> Result<()> {
    let body = read_json(&args.file)?;
    if !args.force {
        let current = client
            .request(Method::GET, "/v1/metrics/config", None)
            .await
            .context("read the live metrics configuration to check what this document would drop")?;
        reject_dropped_settings(&current, &body)?;
    }
    let value = client
        .request(Method::PUT, "/v1/metrics/config", Some(body))
        .await?;
    match output {
        // The gateway reports `success: true` once the file is written, even
        // when re-applying it to the running collector failed, so the message
        // is the only thing that says what actually happened.
        Output::Table => writeln!(out, "{}", metrics_update_message(&value, client))?,
        Output::Json => writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?,
    }
    Ok(())
}

/// What a metrics update actually did. The gateway answers `success: true` as
/// soon as the file is written, including when re-applying it to the running
/// collector failed, so the message is the only honest verdict and `success`
/// must never be branched on. The gateway builds that message from the apply
/// error, so it is cleaned of `client`'s credentials and control characters
/// like an error body.
fn metrics_update_message(
    value: &Value,
    client: &GatewayClient,
) -> String {
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Metrics configuration updated.");
    clean_for_terminal(message, &client.secrets(RawAuth::Bearer))
}

/// A metrics update replaces the stored document outright, and the gateway
/// treats several settings as optional — `opentelemetry.auth` above all — so
/// omitting one removes it rather than defaulting it, and the live exporter is
/// re-applied immediately. Dropping `auth` silently switches collector export
/// to unauthenticated, so refuse any document that would drop a setting the
/// gateway currently stores.
fn reject_dropped_settings(
    current: &Value,
    submitted: &Value,
) -> Result<()> {
    let mut dropped = Vec::new();
    collect_dropped_settings(current, submitted, "", &mut dropped);
    if dropped.is_empty() {
        return Ok(());
    }
    bail!(
        "this document drops {} setting(s) the gateway currently stores: {}. A metrics update replaces the whole \
         document, so each one would be removed and the live exporter reconfigured without it. Add them, or re-run \
         with --force",
        dropped.len(),
        dropped.join(", ")
    )
}

fn collect_dropped_settings(
    current: &Value,
    submitted: &Value,
    prefix: &str,
    dropped: &mut Vec<String>,
) {
    let (Some(current), Some(submitted)) = (current.as_object(), submitted.as_object()) else {
        return;
    };
    for (key, current_value) in current {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match submitted.get(key) {
            // A value where the gateway stores a section removes it just as
            // surely as leaving the key out: `"auth": null` deserialises to
            // `None` and the exporter is re-applied with no auth header. The
            // recursive call cannot see this — it takes two objects — so the
            // substitution is recorded here, against the section's own path.
            Some(submitted_value) if current_value.is_object() && !submitted_value.is_object() => {
                dropped.push(path);
            }
            Some(submitted_value) => collect_dropped_settings(current_value, submitted_value, &path, dropped),
            None => dropped.push(path),
        }
    }
}

async fn scrape_metrics(
    client: &GatewayClient,
    args: MetricsScrapeArgs,
) -> Result<()> {
    // The gateway requires HTTP Basic on this route whenever Prometheus
    // authentication is enabled, in the same header the bearer token occupies,
    // so credentials replace the token rather than accompanying it.
    let auth = match (&args.username, &args.password) {
        (Some(username), Some(password)) => RawAuth::Basic { username, password },
        _ => RawAuth::Bearer,
    };
    let (status, body) = client
        .request_bytes(Method::GET, "/v1/metrics/prometheus", auth)
        .await?;
    // This route bypasses session auth, so its only 401 comes from the
    // Prometheus Basic check — never from the bearer token, which is why the
    // shared "gateway rejected the bearer token" wording must not be used.
    if status == reqwest::StatusCode::UNAUTHORIZED {
        match &args.username {
            Some(username) => bail!("gateway rejected the Prometheus credentials for --username '{username}'"),
            None => bail!(
                "this gateway requires Prometheus credentials on /v1/metrics/prometheus; pass --username and \
                 --password, which are sent instead of the bearer token"
            ),
        }
    }
    if !status.is_success() {
        return Err(gateway_error(status, &body, &client.secrets(auth)));
    }
    write_response_body(&args.output_file, &body)
}

async fn test_metrics_endpoint(
    client: &GatewayClient,
    url: &str,
    output: Output,
) -> Result<()> {
    let value = client
        .request(Method::POST, "/v1/metrics/test-connection", Some(json!({"endpoint": url})))
        .await?;
    // The gateway answers 200 for every outcome, including a refused
    // connection and a timeout, so the verdict is the `success` field.
    let succeeded = value
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !succeeded {
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("connection test failed");
        bail!("{url}: {}", clean_for_terminal(message, &client.secrets(RawAuth::Bearer)));
    }
    print_value(&value, output, false)
}

async fn run_logs(
    client: &GatewayClient,
    command: LogsCommand,
    output: Output,
) -> Result<()> {
    match command {
        LogsCommand::Download { output_file } => {
            let (status, body) = client
                .request_bytes(Method::GET, "/v1/logs/download", RawAuth::Bearer)
                .await?;
            if !status.is_success() {
                return Err(gateway_error(status, &body, &client.secrets(RawAuth::Bearer)));
            }
            write_response_body(&output_file, &body)
        }
        LogsCommand::Truncate { yes } => {
            if !yes {
                bail!("pass --yes to confirm deleting every rotated log file; this cannot be undone");
            }
            let value = client
                .request(Method::POST, "/v1/logs/truncate", None)
                .await?;
            print_value(&value, output, false)
        }
    }
}

/// Write a raw response body to a file, or to standard output for '-'. The
/// confirmation goes to standard error so a piped body stays clean.
fn write_response_body(
    path: &Path,
    body: &[u8],
) -> Result<()> {
    use std::io::Write;

    if path == Path::new("-") {
        return io::stdout()
            .write_all(body)
            .context("write to standard output");
    }
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    eprintln!("Wrote {} bytes to {}", body.len(), path.display());
    Ok(())
}

/// Serialise query parameters for a management-API path. `GatewayClient::url`
/// rejects any path containing `..`, and percent-encoding leaves dots alone, so
/// a filter such as `a..b` would otherwise be refused before it is sent.
fn query_string(pairs: &[(&str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer
        .finish()
        .replace('.', "%2E")
}

fn json_array(
    value: &Value,
    key: &str,
) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod observability_tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Starts an HTTP server that answers each request with the next queued
    /// response and records every request start line, so a test can assert the
    /// exact paths the CLI put on the wire. Requests past the end of the queue
    /// get a 404 and are still recorded, so an unexpected extra call shows up
    /// rather than hanging the test.
    async fn recording_server(responses: &'static [(&'static str, &'static str)]) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let request_line = String::from_utf8_lossy(&buf[..read])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let index = {
                    let mut recorded = recorder
                        .lock()
                        .expect("record request");
                    recorded.push(request_line);
                    recorded.len() - 1
                };
                let (status_line, body) = responses
                    .get(index)
                    .copied()
                    .unwrap_or(("HTTP/1.1 404 Not Found", r#"{"error":"unexpected request"}"#));
                let response = format!(
                    "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
                     close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// Parses `args` and runs the observability command they name.
    async fn run_observability(
        client: &GatewayClient,
        args: &[&str],
    ) -> Result<()> {
        let command = Cli::try_parse_from(args)
            .expect("arguments should parse")
            .into_agent_gateway()
            .command;
        match command {
            Command::Audit { command } => run_audit(client, command, Output::Json).await,
            Command::Payments { command } => run_payments(client, command, Output::Json).await,
            Command::Metrics { command } => run_metrics(client, command, Output::Json).await,
            Command::Logs { command } => run_logs(client, command, Output::Json).await,
            other => panic!("not an observability command: {other:?}"),
        }
    }

    /// Runs one observability command against a recording server and returns
    /// the request start lines the gateway saw. Command failures are ignored:
    /// these assert what was requested, not what came back.
    async fn requests_for(
        args: &[&str],
        responses: &'static [(&'static str, &'static str)],
    ) -> Vec<String> {
        let (host, seen) = recording_server(responses).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let _ = run_observability(&client, args).await;
        let seen = seen
            .lock()
            .expect("read recorded requests");
        seen.clone()
    }

    /// Runs one observability command, as the client holding `agpat_test`,
    /// against a recording server, and returns the error it failed with as
    /// `main` prints it.
    async fn error_for(
        args: &[&str],
        responses: &'static [(&'static str, &'static str)],
    ) -> String {
        let (host, _) = recording_server(responses).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = run_observability(&client, args)
            .await
            .expect_err("the command should fail");
        format!("{error:#}")
    }

    /// Clears the Prometheus credential variables so a parse under
    /// [`PROCESS_ENV_LOCK`] cannot pick up a value from the developer's shell.
    fn clear_metrics_credentials() {
        unsafe {
            std::env::remove_var("FABRIC_METRICS_USERNAME");
            std::env::remove_var("FABRIC_METRICS_PASSWORD");
        }
    }

    /// Writes `contents` to a temporary JSON file kept alive by the handle.
    fn json_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), contents).expect("write JSON file");
        file
    }

    #[test]
    fn query_string_percent_encodes_dots_so_the_path_check_passes() {
        let query = query_string(&[("filter", "a..b".to_owned())]);
        assert_eq!(query, "filter=a%2E%2Eb");
        assert!(!query.contains(".."));
    }

    #[test]
    fn query_string_escapes_reserved_characters() {
        let query = query_string(&[("filter", "a b&c=d".to_owned()), ("page", "2".to_owned())]);
        assert_eq!(query, "filter=a+b%26c%3Dd&page=2");
    }

    #[test]
    fn audit_row_reads_a_tagged_policy_decision() {
        let event = json!({
            "timestamp": "2026-09-21T10:00:00Z",
            "event": {"policy_decision": {"scope": "surface", "decision": "deny", "surface_id": "sales"}},
        });
        assert_eq!(audit_row(&event), "2026-09-21T10:00:00Z\tpolicy_decision\tsales\tdeny\t-");
    }

    #[test]
    fn audit_row_reads_a_fieldless_action() {
        let event = json!({
            "timestamp": "2026-09-21T10:00:00Z",
            "event": "consent_granted",
            "surface_id": "sales",
        });
        assert_eq!(audit_row(&event), "2026-09-21T10:00:00Z\tconsent_granted\tsales\t-\t-");
    }

    /// A reviewer saw nothing after creating an identity with every audit
    /// setting on: admin API calls are never audited, so an empty result says
    /// so beside the note that it can also mean a failed audit subsystem.
    #[test]
    fn an_empty_audit_result_says_admin_calls_are_not_audited() {
        let (rows, notes) = audit_table(&json!({"events": [], "total": 0}));

        assert_eq!(rows, "No audit events.\n");
        assert!(notes.contains("audit subsystem failed to start"), "got: {notes}");
        assert!(notes.contains("cannot read the audit file or the file is not valid UTF-8"), "got: {notes}");
        assert!(notes.contains("drops any line of the file it cannot parse"), "got: {notes}");
        assert!(notes.contains("admin API calls such as creating an identity are not audited"), "got: {notes}");
        let kinds =
            ["delegation", "policy decisions", "trust checks", "VP injection", "payments", "trace terminations"];
        for kind in kinds {
            assert!(notes.contains(kind), "{kind} is missing from: {notes}");
        }
    }

    #[test]
    fn an_audit_result_with_events_prints_rows_and_no_notes() {
        let (rows, notes) = audit_table(&json!({"events": [{"timestamp": "t1", "event": "user_tokens_revoked"}]}));

        assert_eq!(rows, "t1\tuser_tokens_revoked\t-\t-\t-\n");
        assert_eq!(notes, "");
    }

    /// What `audit list` prints in table mode, as its standard output and
    /// standard error.
    fn audit_table(response: &Value) -> (String, String) {
        let (mut rows, mut notes) = (Vec::new(), Vec::new());
        write_audit_table(response, &mut rows, &mut notes).expect("write to memory");
        (String::from_utf8(rows).expect("UTF-8 rows"), String::from_utf8(notes).expect("UTF-8 notes"))
    }

    #[test]
    fn audit_row_falls_back_to_dashes() {
        assert_eq!(audit_row(&json!({})), "-\t-\t-\t-\t-");
    }

    /// The event's own `detail` is the only place some events say what they
    /// did, such as how many tokens a revocation removed.
    #[test]
    fn audit_row_carries_the_event_detail() {
        let event = json!({
            "timestamp": "2026-09-21T10:00:00Z",
            "event": "user_tokens_revoked",
            "detail": "0 tokens revoked",
            "user_identity_hash": "sha256:abc",
            "via_fabric": false,
        });
        assert_eq!(audit_row(&event), "2026-09-21T10:00:00Z\tuser_tokens_revoked\t-\t-\t0 tokens revoked");
    }

    /// The detail is gateway-supplied text, so it must not drive the terminal
    /// or split one event across rows.
    #[test]
    fn audit_row_sanitises_the_event_detail() {
        let event = json!({"event": "trace_terminated", "detail": "a\u{1b}[2J\rb\tc\nd"});
        assert_eq!(audit_row(&event), "-\ttrace_terminated\t-\t-\ta[2Jb c d");

        let blank = json!({"event": "trace_terminated", "detail": "\u{1b}"});
        assert_eq!(audit_row(&blank), "-\ttrace_terminated\t-\t-\t-");
    }

    /// Every cell is stored gateway text, so none can clear the screen or add
    /// a column, whichever field carries it.
    #[test]
    fn audit_row_sanitises_every_cell() {
        let event = json!({
            "timestamp": "2026-09-21\u{1b}[2J",
            "event": {"policy\tdecision": {"decision": "deny\u{7}", "surface_id": "sales\nsupport"}},
            "detail": "\u{1b}",
        });
        assert_eq!(audit_row(&event), "2026-09-21[2J\tpolicy decision\tsales support\tdeny\t-");
    }

    #[test]
    fn payment_table_row_sanitises_every_cell() {
        let row = payment_row(
            PaymentStore::X402,
            &json!({"id": "tx\u{1b}[2J1", "surface_id": "sales\tsupport", "status": "Verified\n", "amount": "\u{7}", "asset": "USDC", "created_at": 100}),
        );
        assert_eq!(payment_table_row(&row), "tx[2J1\tx402\tsales support\tVerified \t-\tUSDC\t100");
    }

    #[test]
    fn redaction_replaces_the_vp_jwt_and_caller_identity() {
        let mut response = json!({
            "events": [{
                "timestamp": "2026-09-21T10:00:00Z",
                "vp_jwt": "eyJhbGciOiJFZERTQSJ9.payload.signature",
                "caller": {"auth_method": "jwt_bearer", "email": "user@example.com", "name": "A User", "sub": "did:key:z6Mk"},
            }],
        });

        redact_audit_events(&mut response);

        let event = &response["events"][0];
        assert_eq!(event["vp_jwt"], json!(REDACTED));
        assert_eq!(event["caller"]["email"], json!(REDACTED));
        assert_eq!(event["caller"]["name"], json!(REDACTED));
        assert_eq!(event["caller"]["sub"], json!("did:key:z6Mk"));
        assert_eq!(event["timestamp"], json!("2026-09-21T10:00:00Z"));
    }

    #[test]
    fn redaction_does_not_add_keys_the_event_lacks() {
        let mut response = json!({"events": [{"timestamp": "2026-09-21T10:00:00Z"}]});

        redact_audit_events(&mut response);

        let event = &response["events"][0];
        assert!(event.get("vp_jwt").is_none());
        assert!(event.get("caller").is_none());
    }

    #[test]
    fn payment_rows_share_one_shape_across_both_stores() {
        let x402 = payment_row(
            PaymentStore::X402,
            &json!({"id": "tx-1", "surface_id": "sales", "status": "settled", "amount": "5", "asset": "USDC", "created_at": 100}),
        );
        let mpp = payment_row(
            PaymentStore::Mpp,
            &json!({"id": "mpp-1", "surface_id": "sales", "status": "completed", "amount": "3", "currency": "EUR", "created_at": 200}),
        );

        assert_eq!(x402["store"], json!("x402"));
        assert_eq!(x402["currency"], json!("USDC"));
        assert_eq!(mpp["store"], json!("mpp"));
        assert_eq!(mpp["currency"], json!("EUR"));
    }

    #[test]
    fn merged_payment_rows_are_sorted_newest_first() {
        let mut rows = vec![
            payment_row(PaymentStore::X402, &json!({"id": "old", "created_at": 100})),
            payment_row(PaymentStore::Mpp, &json!({"id": "new", "created_at": 300})),
            payment_row(PaymentStore::X402, &json!({"id": "mid", "created_at": 200})),
        ];

        sort_payments_newest_first(&mut rows);

        let ids: Vec<&str> = rows
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["new", "mid", "old"]);
    }

    #[test]
    fn payment_table_row_renders_missing_fields_as_dashes() {
        let row = payment_row(PaymentStore::Mpp, &json!({"id": "mpp-1", "created_at": 200}));
        assert_eq!(payment_table_row(&row), "mpp-1\tmpp\t-\t-\t-\t-\t200");
    }

    #[test]
    fn x402_errors_surface_the_message_instead_of_the_meaningless_status() {
        let error = payments_error(
            PaymentStore::X402,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"Cannot delete transaction with pending/processing settlement"}"#,
            &[],
        );
        let rendered = error.to_string();
        assert!(rendered.contains("Cannot delete transaction with pending/processing settlement"));
        assert!(!rendered.contains("500"));
    }

    /// An x402 rejection goes through the same terminal sanitisation as every
    /// other gateway error, so an error body cannot drive the operator's
    /// terminal with escape sequences or a carriage-return overwrite.
    #[test]
    fn x402_errors_are_sanitized_like_other_gateway_errors() {
        let error = payments_error(
            PaymentStore::X402,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"settlement pending\u001b[31m\rFAKE OK"}"#,
            &[],
        );
        let rendered = error.to_string();
        assert!(
            !rendered
                .chars()
                .any(char::is_control),
            "control character leaked into: {rendered:?}"
        );
        assert!(rendered.starts_with("x402 store: "), "got: {rendered:?}");
        assert!(rendered.contains("settlement pending"), "got: {rendered:?}");
        assert!(rendered.contains("FAKE OK"), "got: {rendered:?}");
        assert!(!rendered.contains("500"), "got: {rendered:?}");
    }

    #[test]
    fn mpp_errors_use_the_shared_formatter() {
        let body = br#"{"error":"Transaction not found: x"}"#;
        let error = payments_error(PaymentStore::Mpp, reqwest::StatusCode::NOT_FOUND, body, &[]);
        let rendered = error.to_string();
        assert_eq!(rendered, format!("mpp store: {}", gateway_error(reqwest::StatusCode::NOT_FOUND, body, &[])));
        assert!(rendered.contains("Transaction not found"));
    }

    #[test]
    fn payments_disabled_names_every_missing_store() {
        let message = payments_disabled(&[PaymentStore::X402, PaymentStore::Mpp]);
        assert!(message.contains("payments are not enabled on this gateway"));
        assert!(message.contains("x402 or mpp"));
    }

    /// Default `payments list` arguments: read both stores and merge them.
    fn both_stores() -> PaymentsListArgs {
        PaymentsListArgs {
            store: PaymentStore::All,
            surface: None,
            status: None,
            limit: 100,
        }
    }

    /// The two payment admin routers are authorised differently — MPP also
    /// requires the `payments.view` feature — so one store rejecting the caller
    /// must not discard the rows the other already returned.
    #[tokio::test]
    async fn payments_list_keeps_one_store_when_the_other_cannot_be_read() {
        const ONE_STORE_DOWN: &[(&str, &str)] = &[
            ("HTTP/1.1 200 OK", r#"{"verifications":[{"id":"x-1","status":"Verified","created_at":10}]}"#),
            ("HTTP/1.1 403 Forbidden", r#"{"error":"Forbidden","details":"missing feature: payments.view"}"#),
        ];
        let (host, seen) = recording_server(ONE_STORE_DOWN).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        list_payments(&client, both_stores(), Output::Json)
            .await
            .expect("x402's rows survive a store that cannot be read");

        // Both stores were queried; the second's rejection did not abandon the
        // first's rows or stop the run before it was even sent.
        assert_eq!(
            seen.lock()
                .expect("requests")
                .len(),
            2
        );
    }

    /// Only a run that read nothing at all is a failure, and it has to say why
    /// each store came back empty rather than reporting them all as disabled.
    #[tokio::test]
    async fn payments_list_fails_only_when_every_store_failed() {
        const BOTH_DOWN: &[(&str, &str)] = &[
            ("HTTP/1.1 500 Internal Server Error", r#"{"error":"Transaction store not configured"}"#),
            ("HTTP/1.1 403 Forbidden", r#"{"error":"Forbidden","details":"missing feature: payments.view"}"#),
        ];
        let (host, _) = recording_server(BOTH_DOWN).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = list_payments(&client, both_stores(), Output::Json)
            .await
            .expect_err("a run that read no store at all fails");

        let text = error.to_string();
        assert!(text.contains("Transaction store not configured"), "got: {text}");
        assert!(text.contains("missing feature: payments.view"), "got: {text}");
    }

    /// Every payments error names its store exactly once, whichever command
    /// reports it: `payments_error` supplies the name, so a command that reads
    /// several stores must not add it again.
    #[tokio::test]
    async fn payments_errors_name_the_store_exactly_once() {
        const BOTH_REJECT: &[(&str, &str)] = &[
            ("HTTP/1.1 500 Internal Server Error", r#"{"error":"Transaction not found"}"#),
            ("HTTP/1.1 404 Not Found", r#"{"error":"Transaction not found: tx-1"}"#),
        ];
        const BOTH_DOWN: &[(&str, &str)] = &[
            ("HTTP/1.1 500 Internal Server Error", r#"{"error":"Transaction store not configured"}"#),
            ("HTTP/1.1 403 Forbidden", r#"{"error":"Forbidden","details":"missing feature: payments.view"}"#),
        ];
        const X402_REJECTS: &[(&str, &str)] = &[(
            "HTTP/1.1 500 Internal Server Error",
            r#"{"error":"Cannot delete transaction with pending settlement"}"#,
        )];
        // A failure whose body is not JSON names its store too. A 404 cannot
        // show that: without a JSON error it reads as an unmounted store.
        const X402_UPSTREAM_DOWN: &[(&str, &str)] = &[("HTTP/1.1 502 Bad Gateway", "upstream down")];

        let (host, _) = recording_server(BOTH_REJECT).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = get_payment(&client, "tx-1", PaymentStore::All, false, Output::Json)
            .await
            .expect_err("a record neither store returned fails");
        let text = format!("{error:#}");
        assert_eq!(text.matches("x402").count(), 1, "get: {text}");
        assert_eq!(text.matches("mpp").count(), 1, "get: {text}");

        let (host, _) = recording_server(BOTH_DOWN).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = list_payments(&client, both_stores(), Output::Json)
            .await
            .expect_err("a run that read no store at all fails");
        let text = format!("{error:#}");
        assert_eq!(text.matches("x402").count(), 1, "list: {text}");
        assert_eq!(text.matches("mpp").count(), 1, "list: {text}");

        let (host, _) = recording_server(X402_REJECTS).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = delete_payment(&client, "tx-1", true, Output::Json)
            .await
            .expect_err("a rejected deletion fails");
        let text = format!("{error:#}");
        assert_eq!(text.matches("x402").count(), 1, "delete: {text}");

        let (host, _) = recording_server(X402_REJECTS).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = payment_stats(&client, false, Output::Json)
            .await
            .expect_err("rejected stats fail");
        let text = format!("{error:#}");
        assert_eq!(text.matches("x402").count(), 1, "stats: {text}");

        let (host, _) = recording_server(X402_UPSTREAM_DOWN).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = delete_payment(&client, "tx-1", true, Output::Json)
            .await
            .expect_err("a failed deletion fails");
        assert_eq!(format!("{error:#}"), "x402 store: upstream down", "delete");

        let (host, _) = recording_server(X402_UPSTREAM_DOWN).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let error = payment_stats(&client, false, Output::Json)
            .await
            .expect_err("failed stats fail");
        assert_eq!(format!("{error:#}"), "x402 store: upstream down", "stats");
    }

    /// A request that gets no response at all — a path the client refuses to
    /// send, or a request that fails before it is sent — still names its store
    /// exactly once, so the identical failures of a merged read stay apart.
    #[tokio::test]
    async fn payments_errors_name_the_store_when_no_response_arrives() {
        let (host, seen) = recording_server(&[]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = get_payment(&client, "a..b", PaymentStore::All, false, Output::Json)
            .await
            .expect_err("an ID the client refuses to send fails");
        let text = format!("{error:#}");
        assert!(text.contains("must not contain '..'"), "get: {text}");
        assert_eq!(
            text.matches("x402 store")
                .count(),
            1,
            "get: {text}"
        );
        assert_eq!(
            text.matches("mpp store")
                .count(),
            1,
            "get: {text}"
        );

        let error = delete_payment(&client, "a..b", true, Output::Json)
            .await
            .expect_err("an ID the client refuses to send fails");
        let text = format!("{error:#}");
        assert!(text.contains("must not contain '..'"), "delete: {text}");
        assert_eq!(
            text.matches("x402 store")
                .count(),
            1,
            "delete: {text}"
        );

        assert!(
            seen.lock()
                .expect("requests")
                .is_empty(),
            "a refused path must not reach the gateway"
        );

        // A host with no scheme fails inside the HTTP client before anything is
        // sent, the same way an unreachable gateway fails after the path check.
        let client = GatewayClient::new("not a url", "agpat_test").expect("client");

        let error = list_payments(&client, both_stores(), Output::Json)
            .await
            .expect_err("a run that reached no store fails");
        let text = format!("{error:#}");
        assert_eq!(
            text.matches("x402 store")
                .count(),
            1,
            "list: {text}"
        );
        assert_eq!(
            text.matches("mpp store")
                .count(),
            1,
            "list: {text}"
        );

        let error = payment_stats(&client, false, Output::Json)
            .await
            .expect_err("stats that reached no store fail");
        let text = format!("{error:#}");
        assert_eq!(
            text.matches("x402 store")
                .count(),
            1,
            "stats: {text}"
        );
    }

    #[test]
    fn audit_all_and_page_are_mutually_exclusive() {
        Cli::try_parse_from(["fabric", "agent-gateway", "audit", "list", "--all", "--page", "2"])
            .expect_err("--all reads every page, so a single page cannot also be selected");
    }

    #[test]
    fn audit_filters_accept_the_gateway_vocabulary() {
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "audit",
            "list",
            "--flow",
            "access_point",
            "--scope",
            "mcp_tool",
        ])
        .expect("snake_case filter values match the gateway's own");
        let Command::Audit {
            command: AuditCommand::List(args),
        } = &cli.agent_gateway().command
        else {
            panic!("expected an audit list command");
        };
        assert_eq!(
            args.flow
                .map(AuditFlow::as_str),
            Some("access_point")
        );
        assert_eq!(
            args.scope
                .map(AuditScope::as_str),
            Some("mcp_tool")
        );
    }

    #[test]
    fn a_json_error_body_separates_a_rejection_from_an_unmounted_route() {
        assert!(carries_json_error(br#"{"error":"Transaction not found: x"}"#));
        assert!(!carries_json_error(b""));
        assert!(!carries_json_error(b"<!doctype html><title>Gateway</title>"));
        assert!(!carries_json_error(br#"{"message":"not found"}"#));
    }

    #[tokio::test]
    async fn a_destination_path_does_not_shadow_the_global_output_format() {
        let _guard = PROCESS_ENV_LOCK.lock().await;
        clear_metrics_credentials();

        let scrape = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "--output",
            "json",
            "metrics",
            "scrape",
            "--output-file",
            "/tmp/metrics.txt",
        ])
        .expect("the destination path and the display format are separate options");
        assert_eq!(
            scrape
                .agent_gateway()
                .output
                .as_str(),
            "json"
        );

        let download = Cli::try_parse_from(["fabric", "agent-gateway", "logs", "download", "--output-file", "-"])
            .expect("the destination path and the display format are separate options");
        assert_eq!(
            download
                .agent_gateway()
                .output
                .as_str(),
            "table"
        );
    }

    #[tokio::test]
    async fn prometheus_credentials_must_be_supplied_as_a_pair() {
        let _guard = PROCESS_ENV_LOCK.lock().await;
        clear_metrics_credentials();

        Cli::try_parse_from(["fabric", "agent-gateway", "metrics", "scrape", "--username", "prom"])
            .expect_err("a username without a password cannot form Basic credentials");
        Cli::try_parse_from(["fabric", "agent-gateway", "metrics", "scrape"])
            .expect("an unauthenticated scrape needs no credentials at all");
    }

    #[test]
    fn write_response_body_writes_bytes_verbatim() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory
            .path()
            .join("logs.zip");

        write_response_body(&path, b"PK\x03\x04binary").expect("write the archive");

        assert_eq!(std::fs::read(&path).expect("read back"), b"PK\x03\x04binary");
    }

    const OK_JSON: &[(&str, &str)] = &[("HTTP/1.1 200 OK", "{}"), ("HTTP/1.1 200 OK", "{}")];

    #[tokio::test]
    async fn every_command_requests_the_path_it_documents() {
        // `payments` and `transactions` are different row sets, and the two
        // stores sit behind different prefixes, so a wrong path here returns
        // plausible but incorrect data rather than failing.
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["fabric", "agent-gateway", "audit", "list", "--limit", "5"],
                &["GET /api/v1/audit?limit=5&page=1 HTTP/1.1"],
            ),
            (
                &["fabric", "agent-gateway", "payments", "list", "--store", "x402", "--limit", "10"],
                &["GET /api/admin/x402/transactions?limit=10 HTTP/1.1"],
            ),
            (
                &["fabric", "agent-gateway", "payments", "list", "--store", "mpp", "--limit", "10"],
                &["GET /api/admin/mpp/transactions?limit=10 HTTP/1.1"],
            ),
            (
                &["fabric", "agent-gateway", "payments", "list", "--limit", "10"],
                &[
                    "GET /api/admin/x402/transactions?limit=10 HTTP/1.1",
                    "GET /api/admin/mpp/transactions?limit=10 HTTP/1.1",
                ],
            ),
            (
                &["fabric", "agent-gateway", "payments", "get", "tx-1", "--store", "x402"],
                &["GET /api/admin/x402/transactions/tx-1 HTTP/1.1"],
            ),
            (
                &["fabric", "agent-gateway", "payments", "get", "tx-1", "--store", "mpp"],
                &["GET /api/admin/mpp/transactions/tx-1 HTTP/1.1"],
            ),
            (&["fabric", "agent-gateway", "payments", "stats"], &["GET /api/admin/x402/stats HTTP/1.1"]),
            (
                &["fabric", "agent-gateway", "payments", "stats", "--sync"],
                &["GET /api/admin/x402/stats HTTP/1.1", "GET /api/admin/x402/sync-status HTTP/1.1"],
            ),
            (
                &["fabric", "agent-gateway", "payments", "delete", "tx-1", "--yes"],
                &["DELETE /api/admin/x402/transactions/tx-1 HTTP/1.1"],
            ),
            (&["fabric", "agent-gateway", "metrics", "status"], &["GET /api/v1/metrics/otlp-status HTTP/1.1"]),
            (&["fabric", "agent-gateway", "metrics", "config", "show"], &["GET /api/v1/metrics/config HTTP/1.1"]),
            (
                &["fabric", "agent-gateway", "metrics", "test-endpoint", "http://collector:4317"],
                &["POST /api/v1/metrics/test-connection HTTP/1.1"],
            ),
            (&["fabric", "agent-gateway", "metrics", "truncate", "--yes"], &["POST /api/v1/metrics/truncate HTTP/1.1"]),
            (&["fabric", "agent-gateway", "logs", "truncate", "--yes"], &["POST /api/v1/logs/truncate HTTP/1.1"]),
        ];
        for (args, expected) in cases {
            assert_eq!(requests_for(args, OK_JSON).await, *expected, "wrong path for {args:?}");
        }
    }

    #[tokio::test]
    async fn logs_download_requests_the_archive_route() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory
            .path()
            .join("logs.zip");
        let args = ["fabric", "agent-gateway", "logs", "download", "--output-file", path.to_str().expect("path")];

        assert_eq!(requests_for(&args, OK_JSON).await, ["GET /api/v1/logs/download HTTP/1.1"]);
    }

    #[tokio::test]
    async fn metrics_scrape_requests_the_prometheus_route() {
        let _guard = PROCESS_ENV_LOCK.lock().await;
        clear_metrics_credentials();

        let requests = requests_for(&["fabric", "agent-gateway", "metrics", "scrape"], OK_JSON).await;

        assert_eq!(requests, ["GET /api/v1/metrics/prometheus HTTP/1.1"]);
    }

    /// `scrape` sends Basic credentials in place of the bearer token, so those
    /// are what its error must not repeat when an upstream echoes the header.
    #[tokio::test]
    async fn metrics_scrape_errors_do_not_repeat_the_basic_credentials() {
        // `cHJvbTpodW50ZXIy` is `prom:hunter2` in base64, as the header carries it.
        const ECHO: &[(&str, &str)] =
            &[("HTTP/1.1 502 Bad Gateway", "upstream error; request carried Authorization: Basic cHJvbTpodW50ZXIy")];
        let _guard = PROCESS_ENV_LOCK.lock().await;
        clear_metrics_credentials();

        let error = error_for(
            &["fabric", "agent-gateway", "metrics", "scrape", "--username", "prom", "--password", "hunter2"],
            ECHO,
        )
        .await;

        assert_eq!(error, "upstream error; request carried Authorization: Basic [redacted]");
    }

    /// The gateway answers 200 for a failed endpoint test and puts the reason
    /// in `message`, which becomes the command's error, so it is cleaned like
    /// an error body.
    #[tokio::test]
    async fn a_failed_endpoint_test_message_is_redacted_and_sanitized() {
        const REFUSED: &[(&str, &str)] =
            &[("HTTP/1.1 200 OK", r#"{"success":false,"message":"refused; sent Bearer agpat_test\u001b[2J"}"#)];

        let error =
            error_for(&["fabric", "agent-gateway", "metrics", "test-endpoint", "http://collector:4317"], REFUSED).await;

        assert_eq!(error, "http://collector:4317: refused; sent Bearer [redacted][2J");
    }

    /// An error body that repeats the client's own bearer token, as an
    /// upstream echoing request headers would.
    const ECHOED_TOKEN: &[(&str, &str)] =
        &[("HTTP/1.1 500 Internal Server Error", r#"{"error":"upstream saw Bearer agpat_test"}"#)];

    #[tokio::test]
    async fn payments_get_errors_redact_the_client_token() {
        let error =
            error_for(&["fabric", "agent-gateway", "payments", "get", "tx-1", "--store", "x402"], ECHOED_TOKEN).await;

        assert!(error.contains("x402 store: upstream saw Bearer [redacted]"), "got: {error}");
        assert!(!error.contains("agpat_test"), "got: {error}");
    }

    #[tokio::test]
    async fn payments_delete_errors_redact_the_client_token() {
        let error = error_for(&["fabric", "agent-gateway", "payments", "delete", "tx-1", "--yes"], ECHOED_TOKEN).await;

        assert_eq!(error, "x402 store: upstream saw Bearer [redacted]");
    }

    #[tokio::test]
    async fn logs_download_errors_redact_the_client_token() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory
            .path()
            .join("logs.zip");
        let path = path
            .to_str()
            .expect("a UTF-8 temp path");

        let error =
            error_for(&["fabric", "agent-gateway", "logs", "download", "--output-file", path], ECHOED_TOKEN).await;

        assert_eq!(error, "upstream saw Bearer [redacted]");
        assert!(!Path::new(path).exists(), "a failed download must not write the archive");
    }

    #[tokio::test]
    async fn destructive_commands_refuse_without_yes() {
        // Each gate returns before any request, so this unroutable host is
        // never reached; a reachable error message would mean the gate is gone.
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_test").expect("client");

        for error in [
            delete_payment(&client, "tx-1", false, Output::Table)
                .await
                .expect_err("deleting a payment without --yes must be refused"),
            run_metrics(&client, MetricsCommand::Truncate { yes: false }, Output::Table)
                .await
                .expect_err("truncating metrics without --yes must be refused"),
            run_logs(&client, LogsCommand::Truncate { yes: false }, Output::Table)
                .await
                .expect_err("truncating logs without --yes must be refused"),
        ] {
            let text = error.to_string();
            assert!(text.contains("--yes"), "got: {text}");
        }
    }

    #[test]
    fn audit_events_are_redacted_unless_reveal_is_passed() {
        let response = json!({"events": [{
            "vp_jwt": "eyJhbGciOiJFZERTQSJ9.payload.signature",
            "caller": {"email": "user@example.com", "name": "A User"},
        }]});

        let redacted = audit_document(response.clone(), false);
        assert_eq!(redacted["events"][0]["vp_jwt"], json!(REDACTED));
        assert_eq!(redacted["events"][0]["caller"]["email"], json!(REDACTED));
        assert_eq!(redacted["events"][0]["caller"]["name"], json!(REDACTED));

        let revealed = audit_document(response, true);
        assert_eq!(revealed["events"][0]["vp_jwt"], json!("eyJhbGciOiJFZERTQSJ9.payload.signature"));
        assert_eq!(revealed["events"][0]["caller"]["email"], json!("user@example.com"));
    }

    #[test]
    fn payment_evidence_is_redacted_unless_reveal_is_passed() {
        let record = json!({
            "id": "tx-1",
            "receipt_vc_jwt": "eyJhbGciOiJFZERTQSJ9.receipt.sig",
            "receipt_vc_fingerprint": "sha256:abc",
            "rejection_vc_jwt": "eyJhbGciOiJFZERTQSJ9.rejection.sig",
            "payment_payload": {"payload": {"signature": "0xdeadbeef", "from": "0xpayer"}},
        });

        let redacted = payment_document(record.clone(), false);
        assert_eq!(redacted["receipt_vc_jwt"], json!(REDACTED));
        assert_eq!(redacted["rejection_vc_jwt"], json!(REDACTED));
        assert_eq!(redacted["payment_payload"]["payload"]["signature"], json!(REDACTED));
        // The fingerprint and the payer stay: they are what makes a redacted
        // record still useful as evidence.
        assert_eq!(redacted["receipt_vc_fingerprint"], json!("sha256:abc"));
        assert_eq!(redacted["payment_payload"]["payload"]["from"], json!("0xpayer"));
        assert_eq!(redacted["id"], json!("tx-1"));

        let revealed = payment_document(record, true);
        assert_eq!(revealed["receipt_vc_jwt"], json!("eyJhbGciOiJFZERTQSJ9.receipt.sig"));
        assert_eq!(revealed["payment_payload"]["payload"]["signature"], json!("0xdeadbeef"));
    }

    #[test]
    fn the_mpp_status_filter_ignores_case_as_the_x402_one_does() {
        let mut records = vec![
            json!({"id": "m-1", "status": "completed"}),
            json!({"id": "m-2", "status": "failed"}),
            json!({"id": "m-3"}),
        ];

        retain_matching_status(&mut records, "Completed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["id"], json!("m-1"));
    }

    #[tokio::test]
    async fn all_stops_when_the_gateway_clamps_the_page_instead_of_duplicating() {
        // The gateway clamps a page past the end into range, so page 3 comes
        // back as page 2 again. Appending it would duplicate rows in an export.
        const PAGES: &[(&str, &str)] = &[
            ("HTTP/1.1 200 OK", r#"{"events":[{"timestamp":"b"}],"page":2,"total_pages":3}"#),
            ("HTTP/1.1 200 OK", r#"{"events":[{"timestamp":"b"}],"page":2,"total_pages":3}"#),
        ];
        let (host, seen) = recording_server(PAGES).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let Command::Audit {
            command: AuditCommand::List(args),
        } = Cli::try_parse_from(["fabric", "agent-gateway", "audit", "list", "--all"])
            .expect("parse")
            .into_agent_gateway()
            .command
        else {
            panic!("expected an audit list command");
        };
        let mut response = json!({"events": [{"timestamp": "a"}], "page": 1, "total_pages": 3});

        collect_remaining_audit_pages(&client, &args, &mut response)
            .await
            .expect("pagination should finish");

        let events = response["events"]
            .as_array()
            .expect("events");
        assert_eq!(events.len(), 2, "the clamped repeat of page 2 must not be appended again");
        assert_eq!(
            seen.lock()
                .expect("requests")
                .len(),
            2,
            "page 3 is requested once, recognised as a clamped repeat, and the loop stops"
        );
    }

    #[tokio::test]
    async fn all_stops_on_an_empty_page_rather_than_reading_to_the_reported_end() {
        // A gateway that reports more pages than it can fill must not be
        // walked to the end; the first empty page ends the run.
        const PAGES: &[(&str, &str)] = &[("HTTP/1.1 200 OK", r#"{"events":[],"page":2,"total_pages":4}"#)];
        let (host, seen) = recording_server(PAGES).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let Command::Audit {
            command: AuditCommand::List(args),
        } = Cli::try_parse_from(["fabric", "agent-gateway", "audit", "list", "--all"])
            .expect("parse")
            .into_agent_gateway()
            .command
        else {
            panic!("expected an audit list command");
        };
        let mut response = json!({"events": [{"timestamp": "a"}], "page": 1, "total_pages": 4});

        collect_remaining_audit_pages(&client, &args, &mut response)
            .await
            .expect("pagination should finish");

        assert_eq!(
            seen.lock()
                .expect("requests")
                .len(),
            1,
            "pages 3 and 4 must not be requested after an empty page 2"
        );
        assert_eq!(
            response["events"]
                .as_array()
                .expect("events")
                .len(),
            1
        );
    }

    /// A failed connection test is reported as an error, so the gateway's
    /// message is sanitised before it reaches the terminal like every other
    /// gateway error.
    #[tokio::test]
    async fn test_endpoint_failure_message_is_sanitized() {
        const REFUSED: &[(&str, &str)] =
            &[("HTTP/1.1 200 OK", r#"{"success":false,"message":"refused\u001b[31m\rFAKE OK"}"#)];
        let (host, _) = recording_server(REFUSED).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = test_metrics_endpoint(&client, "http://collector:4317", Output::Table)
            .await
            .expect_err("a response without success: true must fail the command");

        let text = format!("{error:#}");
        assert!(
            !text
                .chars()
                .any(char::is_control),
            "control character leaked into: {text:?}"
        );
        assert!(text.contains("refused"), "got: {text:?}");
        assert!(text.contains("FAKE OK"), "got: {text:?}");
    }

    #[tokio::test]
    async fn test_endpoint_fails_when_the_gateway_does_not_report_success() {
        const CASES: &[&str] = &[r#"{"success":false,"message":"Connection refused"}"#, "{}"];
        for body in CASES {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener
                .local_addr()
                .expect("addr");
            let body = body.to_string();
            tokio::spawn(async move {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 2048];
                    let _ = socket.read(&mut buf).await;
                    let response =
                        format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    let _ = socket
                        .write_all(response.as_bytes())
                        .await;
                    let _ = socket.shutdown().await;
                }
            });
            let client = GatewayClient::new(format!("http://{addr}"), "agpat_test").expect("client");

            // The gateway answers 200 for every outcome, so a missing or false
            // `success` is the only signal that the endpoint is unreachable.
            test_metrics_endpoint(&client, "http://collector:4317", Output::Table)
                .await
                .expect_err("a response without success: true must fail the command");
        }
    }

    #[test]
    fn metrics_config_parses_show_and_a_file_backed_set() {
        assert!(matches!(
            Cli::try_parse_from(["fabric", "agent-gateway", "metrics", "config", "show"])
                .expect("parse")
                .into_agent_gateway()
                .command,
            Command::Metrics {
                command: MetricsCommand::Config {
                    command: MetricsConfigCommand::Show
                }
            }
        ));
        Cli::try_parse_from(["fabric", "agent-gateway", "metrics", "config", "set"])
            .expect_err("`metrics config set` requires --file");
    }

    #[test]
    fn metrics_set_refuses_a_document_that_would_drop_stored_settings() {
        let current = json!({
            "opentelemetry": {
                "enabled": true,
                "endpoint": "http://collector:4317",
                "auth": {"header_name": "x-api-key"}
            },
            "retention": {"days": 7},
            "advanced": {"batch_size": 512}
        });

        // Omitting an optional nested key removes it, which is how collector
        // authentication gets silently switched off.
        let error = reject_dropped_settings(
            &current,
            &json!({
                "opentelemetry": {"enabled": true, "endpoint": "http://collector:4317"},
                "retention": {"days": 7},
                "advanced": {"batch_size": 512}
            }),
        )
        .expect_err("dropping collector auth must be refused");
        let text = error.to_string();
        assert!(text.contains("opentelemetry.auth"), "got: {text}");

        // Whole sections default away the same way.
        let error = reject_dropped_settings(&current, &json!({"opentelemetry": current["opentelemetry"]}))
            .expect_err("dropping whole sections must be refused");
        let text = error.to_string();
        assert!(text.contains("retention") && text.contains("advanced"), "got: {text}");

        // Replacing a stored section with a value of any other type removes it
        // exactly as omitting the key does — `auth` is an `Option`, so `null`
        // deserialises to `None` and the exporter loses its auth header — and
        // must be refused by the same name rather than slipping through.
        for replacement in [json!(null), json!("x-api-key"), json!(1), json!([])] {
            let submitted = json!({
                "opentelemetry": {"enabled": true, "endpoint": "http://collector:4317", "auth": replacement},
                "retention": {"days": 7},
                "advanced": {"batch_size": 512}
            });
            let error = reject_dropped_settings(&current, &submitted)
                .expect_err("replacing a stored section with a non-object must be refused");
            let text = error.to_string();
            assert!(text.contains("opentelemetry.auth"), "got: {text}");
        }

        // The reverse is a change, not a removal: nothing stored goes away.
        reject_dropped_settings(
            &json!({"opentelemetry": {"auth": null}}),
            &json!({"opentelemetry": {"auth": {"header_name": "x-api-key"}}}),
        )
        .expect("filling in a setting the gateway stores as null is accepted");

        reject_dropped_settings(&current, &current).expect("an unchanged document is accepted");
        reject_dropped_settings(
            &current,
            &json!({"opentelemetry": current["opentelemetry"], "retention": {"days": 30}, "advanced": {"batch_size": 512, "extra": 1}}),
        )
        .expect("changed values and added keys are fine; only removals are refused");
    }

    #[tokio::test]
    async fn metrics_set_reads_the_live_document_before_replacing_it() {
        const LIVE: &[(&str, &str)] =
            &[("HTTP/1.1 200 OK", r#"{"opentelemetry":{"enabled":true,"auth":{"header_name":"x-api-key"}}}"#)];
        let (host, seen) = recording_server(LIVE).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let file = json_file(r#"{"opentelemetry":{"enabled":true}}"#);

        let error = set_metrics_config(
            &client,
            MetricsFileArgs {
                file: file.path().to_path_buf(),
                force: false,
            },
            Output::Json,
            &mut Vec::new(),
        )
        .await
        .expect_err("a document dropping collector auth must be refused");

        let text = error.to_string();
        assert!(text.contains("opentelemetry.auth"), "got: {text}");
        // The only request made was the pre-flight read; no PUT was sent.
        assert_eq!(*seen.lock().expect("requests"), ["GET /api/v1/metrics/config HTTP/1.1"]);
    }

    #[tokio::test]
    async fn metrics_set_sends_the_put_and_keeps_a_failed_live_apply_visible() {
        const SAVED: &[(&str, &str)] = &[(
            "HTTP/1.1 200 OK",
            r#"{"success":true,"message":"Metrics configuration saved, but applying it live failed: no collector. A gateway restart will apply it."}"#,
        )];
        let (host, seen) = recording_server(SAVED).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let file = json_file(r#"{"opentelemetry":{"enabled":false}}"#);

        let mut out = Vec::new();

        // --force skips the pre-flight read, so the PUT is the only request.
        set_metrics_config(
            &client,
            MetricsFileArgs {
                file: file.path().to_path_buf(),
                force: true,
            },
            Output::Json,
            &mut out,
        )
        .await
        .expect("a saved config is a success even when the live apply failed");

        assert_eq!(*seen.lock().expect("requests"), ["PUT /api/v1/metrics/config HTTP/1.1"]);
        let printed: Value = serde_json::from_slice(&out).expect("JSON output");
        assert_eq!(printed, serde_json::from_str::<Value>(SAVED[0].1).expect("response"));
    }

    /// Table output prints only the gateway's message, which can carry the
    /// live-apply error text, so it goes out redacted and sanitized.
    #[tokio::test]
    async fn metrics_set_prints_a_cleaned_message_in_table_mode() {
        const SAVED: &[(&str, &str)] = &[(
            "HTTP/1.1 200 OK",
            r#"{"success":true,"message":"Metrics configuration saved, but applying it live failed: sent Bearer agpat_test\u001b[2J"}"#,
        )];
        let (host, _seen) = recording_server(SAVED).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let file = json_file(r#"{"opentelemetry":{"enabled":false}}"#);
        let mut out = Vec::new();

        set_metrics_config(
            &client,
            MetricsFileArgs {
                file: file.path().to_path_buf(),
                force: true,
            },
            Output::Table,
            &mut out,
        )
        .await
        .expect("a saved config is a success even when the live apply failed");

        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "Metrics configuration saved, but applying it live failed: sent Bearer [redacted][2J\n"
        );
    }

    #[test]
    fn a_failed_live_apply_is_reported_from_the_message_not_the_success_flag() {
        // `update_metrics_config` answers `success: true` even when re-applying
        // the config to the running collector failed, so the CLI must never
        // treat `success` as the verdict.
        let saved_but_not_applied = json!({
            "success": true,
            "message": "Metrics configuration saved, but applying it live failed: no collector."
        });
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_test").expect("client");
        assert!(
            metrics_update_message(&saved_but_not_applied, &client).contains("applying it live failed"),
            "the live-apply failure must survive into the output"
        );
        assert_eq!(metrics_update_message(&json!({"success": true}), &client), "Metrics configuration updated.");
    }

    /// The gateway writes the live-apply error into the message it prints, so
    /// that text is cleaned of the client's token and control characters.
    #[test]
    fn a_metrics_update_message_is_redacted_and_sanitized() {
        let client = GatewayClient::new("http://127.0.0.1:1", "agpat_test").expect("client");
        let failed = json!({
            "success": true,
            "message": "Metrics configuration saved, but applying it live failed: sent Bearer agpat_test\u{1b}[2J",
        });

        assert_eq!(
            metrics_update_message(&failed, &client),
            "Metrics configuration saved, but applying it live failed: sent Bearer [redacted][2J"
        );
    }
}

async fn run_api(
    client: &GatewayClient,
    args: ApiArgs,
) -> Result<Value> {
    let body = match (args.data, args.file) {
        (Some(data), None) => Some(checked_body(serde_json::from_str(&data).context("parse --data as JSON")?)?),
        (None, Some(file)) => Some(read_json(&file)?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };
    client
        .request(args.method.method(), &args.path, body)
        .await
}

fn read_json(path: &Path) -> Result<Value> {
    let body = if path == Path::new("-") {
        let mut contents = String::new();
        io::stdin()
            .read_to_string(&mut contents)
            .context("read JSON from standard input")?;
        serde_json::from_str(&contents).context("parse standard input as JSON")?
    } else {
        GatewayClient::read_json_file(path)?
    };
    checked_body(body)
}

/// The one place a caller-supplied request body is admitted, whether it
/// arrived in a document or inline through `--data`, so neither route can
/// carry the masking placeholder to the gateway.
fn checked_body(body: Value) -> Result<Value> {
    reject_masked_values(&body)?;
    Ok(body)
}

fn entity_path(
    base: &str,
    id: &str,
) -> String {
    format!("{}/{}", base.trim_end_matches('/'), urlencoding(id))
}

fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn slugify(value: &str) -> String {
    let slug = value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    slug.split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Prints `value` as pretty JSON for `Output::Json`, or runs `print_table` for
/// `Output::Table`. Used by commands whose table rendering isn't the generic
/// value printer (e.g. a specialized table or a plain confirmation message).
fn print_json_or_else(
    value: &Value,
    output: Output,
    print_table: impl FnOnce(),
) -> Result<()> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Table => print_table(),
    }
    Ok(())
}

fn print_value(
    value: &Value,
    output: Output,
    created: bool,
) -> Result<()> {
    if created
        && matches!(output, Output::Table)
        && let Some(token) = value
            .get("token")
            .and_then(Value::as_str)
    {
        println!("{token}");
        eprintln!("This is the only time the token secret is shown. Store it securely now.");
        return Ok(());
    }
    if created && matches!(output, Output::Table) {
        if let Some(id) = id_from_response(value) {
            println!("{id}");
            return Ok(());
        }
    }
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Table => print_table(value),
    }
    Ok(())
}

fn print_table(value: &Value) {
    match value {
        Value::Array(rows) if rows.is_empty() => println!("No results."),
        Value::Array(rows) => {
            for row in rows {
                print_row(row);
            }
        }
        // A single entity: show the full configuration, matching the UX config view.
        Value::Object(_) => match serde_json::to_string_pretty(value) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("{value}"),
        },
        other => println!("{other}"),
    }
}

fn print_row(value: &Value) {
    if let Some(object) = value.as_object() {
        let id = ["surface_id", "id", "gateway_id", "connection_point_id", "user_id", "key_id"]
            .iter()
            .find_map(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_str)
            })
            .unwrap_or("-");
        let name = object
            .get("name")
            .or_else(|| object.get("username"))
            .or_else(|| object.get("did"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        println!("{id}\t{name}\t{description}");
    } else {
        println!("{value}");
    }
}

/// The confirmation a delete prints in table mode when the gateway answers
/// 204 with no body, the counterpart of `is_create_command`. Without one the
/// shared printer puts the literal `null` of that empty body on standard
/// output. API keys are absent because `run_api_keys` prints its own.
fn delete_confirmation(command: &Command) -> Option<String> {
    match command {
        Command::Users {
            command: UserCommand::Delete { user_id },
        } => Some(format!("Deleted user '{user_id}'")),
        Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::Delete { id }),
        } => Some(format!("Deleted JWT verification strategy '{id}'")),
        _ => None,
    }
}

fn is_create_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Surfaces {
            command: SurfaceCommand::Create(_)
        } | Command::Connections {
            command: CrudCommand::Create(_)
        } | Command::ConnectionPoints {
            command: CrudCommand::Create(_)
        } | Command::Policies {
            command: PolicyCommand::Create { .. }
        } | Command::Issuers {
            command: CrudCommand::Create(_)
        } | Command::Authorities {
            command: CrudCommand::Create(_)
        } | Command::TrustRegistries {
            command: CrudCommand::Create(_)
        } | Command::Mediators {
            command: CrudCommand::Create(_)
        } | Command::McpProxies {
            command: CrudCommand::Create(_)
        } | Command::A2aProxies {
            command: CrudCommand::Create(_)
        } | Command::StsClients {
            command: CrudCommand::Create(_)
        } | Command::CredentialProviders {
            command: CrudCommand::Create(_)
        } | Command::Certificates {
            command: CrudCommand::Create(_),
            ..
        } | Command::Secrets {
            command: SecretCommand::Create(_),
            ..
        } | Command::Integrations {
            command: CrudCommand::Create(_)
        } | Command::Identities {
            command: IdentityCommand::Create { .. }
        } | Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::Create(_))
        } | Command::AccessTokens {
            command: AccessTokenCommand::Create(_)
        }
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, String>>);

    impl CredentialStore for MemoryCredentials {
        fn get_token(
            &self,
            connection: &str,
        ) -> Result<Option<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(connection)
                .cloned())
        }

        fn set_token(
            &self,
            connection: &str,
            token: &str,
        ) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(connection.to_owned(), token.to_owned());
            Ok(())
        }

        fn delete_token(
            &self,
            connection: &str,
        ) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(connection);
            Ok(())
        }
    }

    fn config_with_connection(
        name: &str,
        host: &str,
    ) -> Config {
        let mut config = Config {
            current: Some(name.to_owned()),
            ..Config::default()
        };
        config
            .connections
            .insert(name.to_owned(), Connection::new(host.to_owned()));
        config
    }

    /// Starts a one-shot HTTP server that replies with the given status line
    /// and body to the first request it receives, then returns its base URL.
    async fn one_shot_server(
        status_line: &'static str,
        body: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response =
                    format!("{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn whoami_reports_authenticated_for_valid_pat() {
        let host = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let config = config_with_connection("local", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("local", "agpat_valid")
            .unwrap();

        let info = whoami_info(&config, &credentials, None, None, false, None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["authenticated"], json!(true));
    }

    #[tokio::test]
    async fn whoami_reports_unauthenticated_for_invalid_pat() {
        let host = one_shot_server("HTTP/1.1 401 Unauthorized", "{}").await;
        let config = config_with_connection("local", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("local", "agpat_invalid")
            .unwrap();

        let info = whoami_info(&config, &credentials, None, None, false, None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["authenticated"], json!(false));
        assert!(info.get("error").is_some());
    }

    #[tokio::test]
    async fn whoami_reports_authenticated_for_valid_session_token() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let config = config_with_connection("local", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("local", "session-token")
            .unwrap();

        let info = whoami_info(&config, &credentials, None, None, false, None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["authenticated"], json!(true));
    }

    #[tokio::test]
    async fn whoami_reports_unauthenticated_for_invalid_session_token() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": false}"#).await;
        let config = config_with_connection("local", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("local", "session-token")
            .unwrap();

        let info = whoami_info(&config, &credentials, None, None, false, None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["authenticated"], json!(false));
    }

    #[tokio::test]
    async fn insert_token_scopes_copies_pat_scopes() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"scopes": ["tokens.read"]}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").unwrap();
        let mut fields = serde_json::Map::new();

        insert_token_scopes(&mut fields, &client).await;

        assert_eq!(fields.get("scopes"), Some(&json!(["tokens.read"])));
    }

    #[tokio::test]
    async fn insert_token_scopes_leaves_fields_unchanged_on_error() {
        let host = one_shot_server("HTTP/1.1 500 Internal Server Error", "").await;
        let client = GatewayClient::new(host, "agpat_valid").unwrap();
        let mut fields = serde_json::Map::new();

        insert_token_scopes(&mut fields, &client).await;

        assert!(fields.is_empty());
    }

    fn login_args_with_pat_token(pat: Option<String>) -> LoginArgs {
        LoginArgs {
            host: None,
            token_stdin: false,
            paste: false,
            token: None,
            pat,
        }
    }

    #[tokio::test]
    async fn acquire_pat_token_rejects_token_without_prefix() {
        let args = login_args_with_pat_token(Some("not-a-pat".into()));

        let error = acquire_pat_token(&args)
            .await
            .expect_err("token without the agpat_ prefix should be rejected");

        assert!(
            error
                .to_string()
                .contains(PAT_TOKEN_PREFIX)
        );
    }

    #[tokio::test]
    async fn acquire_pat_token_accepts_token_with_prefix() {
        let args = login_args_with_pat_token(Some("agpat_valid".into()));

        let token = acquire_pat_token(&args)
            .await
            .expect("token with the agpat_ prefix should be accepted");

        assert_eq!(token, "agpat_valid");
    }

    fn login_args_with_token(
        host: &str,
        token: &str,
    ) -> LoginArgs {
        LoginArgs {
            host: Some(host.to_owned()),
            token_stdin: false,
            paste: false,
            token: Some(token.to_owned()),
            pat: None,
        }
    }

    #[tokio::test]
    async fn login_saves_a_new_connection_without_a_note() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        let note =
            login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, &path)
                .await
                .expect("login should succeed");

        assert_eq!(note, None);
        let saved = Config::load_from(&path).unwrap();
        assert_eq!(saved.current.as_deref(), Some("production"));
        assert_eq!(saved.connections["production"].host, host);
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn login_refuses_plain_http_to_a_remote_host_before_contacting_the_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        let error = login_and_save(
            &mut config,
            &credentials,
            "production",
            login_args_with_token("http://gateway.example.com", "new"),
            false,
            &path,
        )
        .await
        .expect_err("plain http to a remote host must be refused");

        assert!(
            error
                .to_string()
                .contains("--allow-http"),
            "{error}"
        );
        assert!(!path.exists());
        assert!(
            credentials
                .get_token("production")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn login_refuses_a_blank_connection_name_before_contacting_the_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for name in ["", "   ", "\t"] {
            let mut config = Config::default();
            let credentials = MemoryCredentials::default();

            // Nothing listens on the discard port, so reaching the gateway would fail differently.
            let error = login_and_save(
                &mut config,
                &credentials,
                name,
                login_args_with_token("http://127.0.0.1:9", "new"),
                false,
                &path,
            )
            .await
            .expect_err("a blank connection name must be refused");

            assert!(
                error
                    .to_string()
                    .contains("--connection must not be empty"),
                "{name:?}: {error:#}"
            );
            assert!(!path.exists());
            assert!(config.connections.is_empty());
            assert_eq!(config.current, None);
            assert_eq!(
                credentials
                    .get_token(name)
                    .unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn login_saves_the_connection_under_its_trimmed_name() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        login_and_save(&mut config, &credentials, "  production ", login_args_with_token(&host, "new"), false, &path)
            .await
            .expect("login should succeed");

        let saved = Config::load_from(&path).unwrap();
        assert_eq!(saved.current.as_deref(), Some("production"));
        assert_eq!(saved.connections.len(), 1);
        assert_eq!(saved.connections["production"].host, host);
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn login_notes_when_it_replaces_the_login_for_the_same_host() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = config_with_connection("production", &host);
        config.save_to(&path).unwrap();
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("production", "old")
            .unwrap();

        let note =
            login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, &path)
                .await
                .expect("login should succeed");

        assert_eq!(note.as_deref(), Some("note: replaced the saved login for connection 'production'"));
        let saved = Config::load_from(&path).unwrap();
        assert_eq!(saved.connections["production"].host, host);
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn login_notes_both_hosts_when_it_repoints_a_connection() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = config_with_connection("production", "https://old.example.com");
        config.save_to(&path).unwrap();
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("production", "old")
            .unwrap();

        let note =
            login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, &path)
                .await
                .expect("login should succeed");

        assert_eq!(
            note,
            Some(format!("note: connection 'production' now points at {host} (it pointed at https://old.example.com)"))
        );
        let saved = Config::load_from(&path).unwrap();
        assert_eq!(saved.connections["production"].host, host);
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn failed_login_leaves_an_existing_connection_untouched() {
        let host = one_shot_server("HTTP/1.1 401 Unauthorized", "{}").await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = config_with_connection("production", "https://old.example.com");
        config.save_to(&path).unwrap();
        let saved_before = std::fs::read_to_string(&path).unwrap();
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("production", "old")
            .unwrap();

        let error = login_and_save(
            &mut config,
            &credentials,
            "production",
            login_args_with_token(&host, "rejected"),
            false,
            &path,
        )
        .await
        .expect_err("a token the gateway rejects must not log in");

        assert!(format!("{error:#}").contains("rejected the bearer token"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), saved_before);
        assert_eq!(config.connections["production"].host, "https://old.example.com");
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("old")
        );
    }

    #[tokio::test]
    async fn failed_save_restores_the_previous_token() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_with_connection("production", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("production", "old")
            .unwrap();

        let error = login_and_save(
            &mut config,
            &credentials,
            "production",
            login_args_with_token(&host, "new"),
            false,
            dir.path(),
        )
        .await
        .expect_err("saving over a directory must fail");

        assert!(
            error
                .to_string()
                .contains(&format!("write {}", dir.path().display()))
        );
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap()
                .as_deref(),
            Some("old")
        );
    }

    #[tokio::test]
    async fn failed_save_removes_a_token_that_was_not_there_before() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        let error = login_and_save(
            &mut config,
            &credentials,
            "production",
            login_args_with_token(&host, "new"),
            false,
            dir.path(),
        )
        .await
        .expect_err("saving over a directory must fail");

        assert!(
            error
                .to_string()
                .contains(&format!("write {}", dir.path().display()))
        );
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap(),
            None
        );
    }

    #[test]
    fn replaced_note_treats_a_differently_written_saved_host_as_the_same_host() {
        let note = replaced_connection_note("production", "https://GW.example.com/", "https://gw.example.com");

        assert_eq!(note, "note: replaced the saved login for connection 'production'");
    }

    #[test]
    fn replaced_note_names_the_saved_host_as_it_was_stored() {
        let note = replaced_connection_note("production", "https://GW.example.com/", "https://new.example");

        assert_eq!(
            note,
            "note: connection 'production' now points at https://new.example (it pointed at https://GW.example.com/)"
        );
    }

    #[test]
    fn login_names_the_connection_with_the_connection_flag() {
        let before =
            ["fabric", "agent-gateway", "--connection", "production", "login", "--host", "https://example.com"];
        let after = ["fabric", "agent-gateway", "login", "--connection", "production", "--host", "https://example.com"];

        for argv in [before, after] {
            let cli = Cli::try_parse_from(argv).expect("login should accept --connection");

            assert_eq!(
                cli.agent_gateway()
                    .connection
                    .as_deref(),
                Some("production")
            );
        }
    }

    #[test]
    fn allow_http_is_accepted_before_or_after_the_subcommand() {
        for argv in [
            vec!["fabric", "agent-gateway", "--allow-http", "login", "--host", "http://gateway.example.com"],
            vec!["fabric", "agent-gateway", "login", "--host", "http://gateway.example.com", "--allow-http"],
            vec!["fabric", "agent-gateway", "--host", "http://gateway.example.com", "users", "list", "--allow-http"],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("--allow-http should parse as a global flag");

            assert!(cli.agent_gateway().allow_http, "{argv:?}");
            assert!(
                cli.interactive_prefix()
                    .contains(&"--allow-http".to_owned())
            );
        }
    }

    #[test]
    fn login_defaults_the_connection_name_when_the_flag_is_absent() {
        let _guard = FABRIC_CONNECTION_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::remove_var("FABRIC_CONNECTION");
        }

        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "login", "--host", "https://example.com"])
            .expect("login without --connection should parse");

        assert_eq!(cli.agent_gateway().connection, None);
        assert_eq!(DEFAULT_CONNECTION, "default");
    }

    #[test]
    fn login_names_the_connection_from_the_environment() {
        let _guard = FABRIC_CONNECTION_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::set_var("FABRIC_CONNECTION", "from-env");
        }

        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "login", "--host", "https://example.com"]);

        unsafe {
            std::env::remove_var("FABRIC_CONNECTION");
        }
        let cli = cli.expect("login should read FABRIC_CONNECTION");
        assert_eq!(
            cli.agent_gateway()
                .connection
                .as_deref(),
            Some("from-env")
        );
    }

    #[test]
    fn login_no_longer_accepts_the_name_flag() {
        let argv = ["fabric", "agent-gateway", "login", "--name", "production", "--host", "https://example.com"];

        let error = Cli::try_parse_from(argv).expect_err("--name must not name a connection on login");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn token_create_keeps_name_for_the_token_itself() {
        let argv = ["fabric", "agent-gateway", "--connection", "production", "tokens", "create", "--name", "ci-runner"];

        let cli = Cli::try_parse_from(argv).expect("tokens create should accept both flags");

        assert_eq!(
            cli.agent_gateway()
                .connection
                .as_deref(),
            Some("production")
        );
        let Command::AccessTokens {
            command: AccessTokenCommand::Create(args),
        } = &cli.agent_gateway().command
        else {
            panic!("expected a tokens create command");
        };
        assert_eq!(args.name.as_deref(), Some("ci-runner"));
    }

    /// Serializes tests that mutate the process-wide FABRIC_CONNECTION env var.
    static FABRIC_CONNECTION_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serializes tests that mutate the process-wide FABRIC_PAT env var.
    static FABRIC_PAT_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn login_args_do_not_select_pat_mode_from_env_var_alone() {
        let _guard = FABRIC_PAT_ENV_LOCK
            .lock()
            .await;
        unsafe {
            std::env::set_var("FABRIC_PAT", "agpat_leak");
        }

        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "login", "--host", "https://example.com"])
            .expect("login with only --host should parse");

        unsafe {
            std::env::remove_var("FABRIC_PAT");
        }

        let Command::Login(args) = &cli.agent_gateway().command else {
            panic!("expected a Login command");
        };
        assert!(args.pat.is_none(), "FABRIC_PAT alone, without --pat, must not select PAT mode");
    }

    #[tokio::test]
    async fn acquire_pat_token_falls_back_to_env_var_when_pat_flag_is_bare() {
        let _guard = FABRIC_PAT_ENV_LOCK
            .lock()
            .await;
        unsafe {
            std::env::set_var("FABRIC_PAT", "agpat_from_env");
        }

        let args = login_args_with_pat_token(Some(String::new()));
        let result = acquire_pat_token(&args).await;

        unsafe {
            std::env::remove_var("FABRIC_PAT");
        }

        assert_eq!(result.expect("bare --pat should fall back to FABRIC_PAT"), "agpat_from_env");
    }

    #[test]
    fn creates_minimal_surface_payload() {
        let value = surface_body(SurfaceCreateArgs {
            name: Some("Sales Agent".into()),
            description: "Routes sales".into(),
            file: None,
            listen_address: "0.0.0.0:8080".into(),
            route: None,
            protocol: Protocol::A2a,
            target_endpoint: "http://sales:3000".into(),
            tags: vec!["sales".into()],
        })
        .unwrap();
        assert_eq!(value.pointer("/access_point/route"), Some(&json!("/sales-agent")));
        assert_eq!(value.pointer("/target/endpoint"), Some(&json!("http://sales:3000")));
    }

    fn minimal_access_token_args() -> AccessTokenCreateArgs {
        AccessTokenCreateArgs {
            name: Some("ci-runner".into()),
            description: "Used by CI".into(),
            scopes: vec!["surfaces.view".into()],
            expires_at: None,
            resource_pattern: None,
            required_headers: vec![],
            file: None,
        }
    }

    #[test]
    fn creates_minimal_access_token_payload() {
        let value = access_token_body(minimal_access_token_args()).unwrap();
        assert_eq!(value["name"], json!("ci-runner"));
        assert_eq!(value["scopes"], json!(["surfaces.view"]));
        assert!(
            value
                .get("expires_at")
                .is_none()
        );
        assert!(
            value
                .get("resource_pattern")
                .is_none()
        );
        assert!(
            value
                .get("required_headers")
                .is_none()
        );
    }

    #[test]
    fn grantable_scopes_keeps_only_true_and_sorts_them() {
        let permissions = json!({
            "secrets.view": true,
            "secrets.edit": false,
            "gateways.view": true,
        });
        assert_eq!(grantable_scopes(&permissions), vec!["gateways.view", "secrets.view"]);
    }

    #[test]
    fn grantable_scopes_is_empty_for_a_non_object_response() {
        assert!(grantable_scopes(&json!(null)).is_empty());
    }

    #[test]
    fn access_token_payload_includes_expiry_when_set() {
        let value = access_token_body(AccessTokenCreateArgs {
            expires_at: Some("2027-01-01T00:00:00Z".into()),
            ..minimal_access_token_args()
        })
        .unwrap();
        assert_eq!(value["expires_at"], json!("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn access_token_payload_includes_resource_pattern_when_set() {
        let value = access_token_body(AccessTokenCreateArgs {
            resource_pattern: Some("TENANT:${x-tenant-id}:surfaces:.*".into()),
            required_headers: vec![("x-tenant-id".into(), "acme".into())],
            ..minimal_access_token_args()
        })
        .unwrap();
        assert_eq!(value["resource_pattern"], json!("TENANT:${x-tenant-id}:surfaces:.*"));
        assert_eq!(value["required_headers"], json!([{"name": "x-tenant-id", "pattern": "acme"}]));
    }

    #[test]
    fn access_token_payload_trims_resource_pattern_whitespace() {
        let value = access_token_body(AccessTokenCreateArgs {
            resource_pattern: Some("  TENANT:${x-tenant-id}:surfaces:.*  ".into()),
            ..minimal_access_token_args()
        })
        .unwrap();
        assert_eq!(value["resource_pattern"], json!("TENANT:${x-tenant-id}:surfaces:.*"));
    }

    #[test]
    fn access_token_payload_rejects_blank_resource_pattern() {
        let error = access_token_body(AccessTokenCreateArgs {
            resource_pattern: Some("   ".into()),
            ..minimal_access_token_args()
        })
        .expect_err("blank resource pattern should be rejected locally");
        assert!(
            error
                .to_string()
                .contains("--resource-pattern must not be empty")
        );
    }

    #[test]
    fn access_token_payload_includes_required_headers_when_set() {
        let value = access_token_body(AccessTokenCreateArgs {
            required_headers: vec![("x-tenant-id".into(), "^[a-z0-9-]+$".into())],
            ..minimal_access_token_args()
        })
        .unwrap();
        assert_eq!(value["required_headers"], json!([{"name": "x-tenant-id", "pattern": "^[a-z0-9-]+$"}]));
    }

    #[test]
    fn parse_required_header_accepts_name_and_pattern() {
        let (name, pattern) = parse_required_header("x-tenant-id=^[a-z0-9-]+$").unwrap();
        assert_eq!(name, "x-tenant-id");
        assert_eq!(pattern, "^[a-z0-9-]+$");
    }

    #[test]
    fn parse_required_header_rejects_missing_equals() {
        let error = parse_required_header("x-tenant-id").expect_err("missing '=' should be rejected");
        assert!(error.contains("name=pattern"));
    }

    #[test]
    fn parse_required_header_rejects_empty_name_or_pattern() {
        assert!(parse_required_header("=pattern").is_err());
        assert!(parse_required_header("name=").is_err());
    }

    #[test]
    fn unknown_scope_error_gets_a_discovery_hint() {
        let error = anyhow::anyhow!("gateway returned 400 Bad Request: unknown scope: secrets.delete");
        let hinted = add_unknown_scope_hint(error).to_string();
        assert!(hinted.contains("fabric agent-gateway tokens scopes"));
    }

    #[test]
    fn other_errors_are_not_hinted() {
        let error = anyhow::anyhow!("gateway returned 500 Internal Server Error: boom");
        let hinted = add_unknown_scope_hint(error).to_string();
        assert!(!hinted.contains("/v1/permissions"));
    }

    #[test]
    fn active_token_row_reports_active_status() {
        let token = json!({
            "id": "tok_1",
            "name": "ci-runner",
            "scopes": ["surfaces.view", "surfaces.edit"],
            "active": true,
            "created_at": "2027-01-01T00:00:00Z",
            "expires_at": "2028-01-01T00:00:00Z",
            "revoked_at": null,
        });
        let row = access_token_row(&token);
        assert_eq!(
            row,
            [
                "ci-runner".to_owned(),
                "tok_1".to_owned(),
                "ACTIVE".to_owned(),
                "surfaces.view,surfaces.edit".to_owned(),
                "2027-01-01T00:00:00Z".to_owned(),
                "2028-01-01T00:00:00Z".to_owned(),
            ]
        );
    }

    #[test]
    fn revoked_at_marks_token_revoked() {
        let token = json!({
            "id": "tok_2",
            "name": "old",
            "active": true,
            "revoked_at": "2027-02-01T00:00:00Z",
        });
        assert_eq!(access_token_status(&token), "REVOKED");
    }

    #[test]
    fn inactive_flag_marks_token_revoked() {
        let token = json!({"id": "tok_3", "name": "off", "active": false});
        assert_eq!(access_token_status(&token), "REVOKED");
    }

    #[test]
    fn token_without_expiry_shows_placeholder() {
        let token = json!({
            "id": "tok_4",
            "name": "forever",
            "scopes": ["surfaces.view"],
            "active": true,
            "created_at": "2027-01-01T00:00:00Z",
            "expires_at": null,
        });
        let row = access_token_row(&token);
        assert_eq!(row[4], "2027-01-01T00:00:00Z");
        assert_eq!(row[5], "-");
    }

    #[test]
    fn few_short_scopes_render_unchanged() {
        let token = json!({
            "id": "tok_5",
            "name": "small",
            "scopes": ["surfaces.view", "surfaces.edit"],
            "active": true,
        });
        let row = access_token_row(&token);
        assert_eq!(row[3], "surfaces.view,surfaces.edit");
    }

    #[test]
    fn many_scopes_are_truncated_with_remaining_count() {
        let token = json!({
            "id": "tok_6",
            "name": "wide",
            "scopes": [
                "gateways.view",
                "gateways.edit",
                "surfaces.view",
                "surfaces.edit",
                "mediators.view",
                "integrations.view",
                "logs.view",
            ],
            "active": true,
        });
        let row = access_token_row(&token);
        assert_eq!(row[3], "gateways.view,gateways.edit +5 more");
        assert!(row[3].len() <= MAX_SCOPES_COLUMN_WIDTH);
    }

    #[test]
    fn scopes_at_exactly_the_cap_are_not_truncated() {
        let scopes = [&"a".repeat(20), &"b".repeat(19)];
        let token = json!({
            "id": "tok_7",
            "name": "boundary",
            "scopes": scopes,
            "active": true,
        });
        let row = access_token_row(&token);
        let expected = format!("{},{}", "a".repeat(20), "b".repeat(19));
        assert_eq!(expected.len(), MAX_SCOPES_COLUMN_WIDTH);
        assert_eq!(row[3], expected);
    }

    #[test]
    fn scopes_one_char_past_the_cap_are_truncated() {
        let token = json!({
            "id": "tok_8",
            "name": "just-over",
            "scopes": ["a".repeat(20), "b".repeat(20)],
            "active": true,
        });
        let row = access_token_row(&token);
        assert_eq!(row[3], format!("{} +1 more", "a".repeat(20)));
    }

    #[test]
    fn format_table_pads_columns_to_widest_cell() {
        let header = ["NAME", "ID", "STATUS"];
        let rows = vec![
            ["throwaway-1".to_owned(), "agat_94fbaa37b2194533bb38dee19004bc2b".to_owned(), "ACTIVE".to_owned()],
            ["test UI PAT".to_owned(), "agat_f95c7c578c3542c98a0616b49a7068d7".to_owned(), "REVOKED".to_owned()],
        ];
        let lines = format_table(&header, &rows);
        assert_eq!(lines.len(), 3);
        // The ID column is the widest cell in that column, so every row's
        // STATUS column starts at the same offset.
        let status_offset = lines[0]
            .find("STATUS")
            .unwrap();
        assert_eq!(
            lines[1]
                .find("ACTIVE")
                .unwrap(),
            status_offset
        );
        assert_eq!(
            lines[2]
                .find("REVOKED")
                .unwrap(),
            status_offset
        );
    }

    #[test]
    fn format_table_handles_no_rows() {
        let header = ["NAME", "ID"];
        let rows: Vec<[String; 2]> = vec![];
        let lines = format_table(&header, &rows);
        assert_eq!(lines, vec!["NAME  ID".to_owned()]);
    }

    #[test]
    fn confirmation_accepts_yes_answers() {
        assert!(answer_is_yes("y"));
        assert!(answer_is_yes("Y"));
        assert!(answer_is_yes("yes"));
        assert!(answer_is_yes("YES"));
        assert!(answer_is_yes("  yes\n"));
    }

    #[test]
    fn confirmation_rejects_no_and_empty_answers() {
        assert!(!answer_is_yes(""));
        assert!(!answer_is_yes("\n"));
        assert!(!answer_is_yes("n"));
        assert!(!answer_is_yes("no"));
        assert!(!answer_is_yes("nope"));
        assert!(!answer_is_yes("maybe"));
    }

    fn surface_update_of(args: &[&str]) -> (Option<PathBuf>, Vec<String>, Vec<String>) {
        let Command::Surfaces {
            command: SurfaceCommand::Update { file, set, unset, .. },
        } = Cli::try_parse_from(args)
            .expect("arguments should parse")
            .into_agent_gateway()
            .command
        else {
            panic!("expected `surfaces update`: {args:?}");
        };
        (file, set, unset)
    }

    #[test]
    fn surface_update_collects_repeated_set_and_unset() {
        let (file, set, unset) = surface_update_of(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "update",
            "s-1",
            "--set",
            "access_point.rate_limit.requests=100",
            "--unset",
            "description",
            "--set",
            "name=Sales",
            "--unset",
            "tags",
        ]);
        assert_eq!(file, None);
        assert_eq!(set, ["access_point.rate_limit.requests=100", "name=Sales"]);
        assert_eq!(unset, ["description", "tags"]);
    }

    #[test]
    fn surface_update_still_accepts_a_file_alone() {
        let (file, set, unset) =
            surface_update_of(&["fabric", "agent-gateway", "surfaces", "update", "s-1", "--file", "surface.json"]);
        assert_eq!(file, Some(PathBuf::from("surface.json")));
        assert!(set.is_empty() && unset.is_empty());
    }

    #[test]
    fn surface_update_rejects_file_with_set_or_unset() {
        for flag in
            [["--set", "name=Sales"], ["--unset", "description"], ["--add", "tags=beta"], ["--remove", "tags=beta"]]
        {
            let error = Cli::try_parse_from(
                ["fabric", "agent-gateway", "surfaces", "update", "s-1", "--file", "surface.json"]
                    .into_iter()
                    .chain(flag),
            )
            .expect_err("--file cannot be combined with single-field changes");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict, "{flag:?}");
        }
    }

    #[test]
    fn surface_update_collects_repeated_add_and_remove() {
        let Command::Surfaces {
            command: SurfaceCommand::Update { add, remove, .. },
        } = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "update",
            "s-1",
            "--add",
            "tags=beta",
            "--remove",
            "transit.points=billing",
            "--add",
            "tags=canary",
        ])
        .expect("arguments should parse")
        .into_agent_gateway()
        .command
        else {
            panic!("expected `surfaces update`");
        };
        assert_eq!(add, ["tags=beta", "tags=canary"]);
        assert_eq!(remove, ["transit.points=billing"]);
    }

    #[test]
    fn surface_update_requires_file_set_or_unset() {
        let error = Cli::try_parse_from(["fabric", "agent-gateway", "surfaces", "update", "s-1"])
            .expect_err("an update with nothing to change should be refused");
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn dry_run_parses_on_every_surface_edit() {
        let parsed = |args: &[&str]| {
            Cli::try_parse_from(args)
                .expect("arguments should parse")
                .into_agent_gateway()
                .command
        };
        assert!(matches!(
            parsed(&["fabric", "agent-gateway", "surfaces", "update", "s-1", "--set", "name=Sales", "--dry-run"]),
            Command::Surfaces {
                command: SurfaceCommand::Update { dry_run: true, .. }
            }
        ));
        assert!(matches!(
            parsed(&[
                "fabric",
                "agent-gateway",
                "surfaces",
                "add-feature",
                "s-1",
                "rate-limit",
                "--json",
                "{}",
                "--dry-run"
            ]),
            Command::Surfaces {
                command: SurfaceCommand::AddFeature(AddFeatureArgs { dry_run: true, .. })
            }
        ));
        assert!(matches!(
            parsed(&["fabric", "agent-gateway", "surfaces", "remove-feature", "s-1", "policy", "--dry-run"]),
            Command::Surfaces {
                command: SurfaceCommand::RemoveFeature(FeaturePlacementArgs { dry_run: true, .. })
            }
        ));
        assert!(matches!(
            parsed(&["fabric", "agent-gateway", "surfaces", "update", "s-1", "--set", "name=Sales"]),
            Command::Surfaces {
                command: SurfaceCommand::Update { dry_run: false, .. }
            }
        ));
    }

    #[test]
    fn dry_run_is_refused_with_a_whole_surface_file() {
        let error = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "update",
            "s-1",
            "--file",
            "surface.json",
            "--dry-run",
        ])
        .expect_err("--file replaces the whole surface, which a dry run does not cover");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn add_feature_takes_the_surface_id_before_the_feature() {
        let Command::Surfaces {
            command: SurfaceCommand::AddFeature(args),
        } = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "add-feature",
            "my-agent",
            "rate-limit",
            "--json",
            "{}",
        ])
        .expect("add-feature should parse")
        .into_agent_gateway()
        .command
        else {
            panic!("expected `surfaces add-feature`");
        };
        assert_eq!(args.surface_id, "my-agent");
        assert_eq!(args.feature, "rate-limit");
        assert_eq!(args.json.as_deref(), Some("{}"));
    }

    #[test]
    fn remove_feature_takes_the_surface_id_before_the_feature() {
        let Command::Surfaces {
            command: SurfaceCommand::RemoveFeature(args),
        } = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "remove-feature",
            "my-agent",
            "policy",
            "--response",
        ])
        .expect("remove-feature should parse")
        .into_agent_gateway()
        .command
        else {
            panic!("expected `surfaces remove-feature`");
        };
        assert_eq!(args.surface_id, "my-agent");
        assert_eq!(args.feature, "policy");
        assert!(args.placement.response);
    }

    #[test]
    fn revoke_parses_yes_flag() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "tokens", "revoke", "tok-1", "--yes"])
            .expect("--yes should be accepted on revoke");
        assert!(matches!(
            cli.agent_gateway().command,
            Command::AccessTokens {
                command: AccessTokenCommand::Revoke(AccessTokenRevokeArgs { yes: true, .. })
            }
        ));
    }

    #[test]
    fn revoke_accepts_short_yes_alias() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "tokens", "revoke", "tok-1", "-y"])
            .expect("-y should be accepted on revoke");
        assert!(matches!(
            cli.agent_gateway().command,
            Command::AccessTokens {
                command: AccessTokenCommand::Revoke(AccessTokenRevokeArgs { yes: true, .. })
            }
        ));
    }

    #[test]
    fn revoke_defaults_to_prompting() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "tokens", "revoke", "tok-1"])
            .expect("revoke should parse without --yes");
        assert!(matches!(
            cli.agent_gateway().command,
            Command::AccessTokens {
                command: AccessTokenCommand::Revoke(AccessTokenRevokeArgs { yes: false, .. })
            }
        ));
    }

    #[test]
    fn rotate_parses_yes_flags_and_defaults_to_prompting() {
        for (args, expected_yes) in [
            (vec!["fabric", "agent-gateway", "tokens", "rotate", "tok-1", "--yes"], true),
            (vec!["fabric", "agent-gateway", "tokens", "rotate", "tok-1", "-y"], true),
            (vec!["fabric", "agent-gateway", "tokens", "rotate", "tok-1"], false),
        ] {
            let cli = Cli::try_parse_from(args.clone()).expect("rotate should parse");
            let Command::AccessTokens {
                command: AccessTokenCommand::Rotate(AccessTokenRotateArgs { id, yes }),
            } = cli
                .into_agent_gateway()
                .command
            else {
                panic!("expected tokens rotate for {args:?}");
            };
            assert_eq!(id, "tok-1");
            assert_eq!(yes, expected_yes, "{args:?}");
        }
    }

    #[tokio::test]
    async fn rotate_posts_to_the_token_rotate_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("accept");
            let mut buf = [0u8; 2048];
            let read = socket
                .read(&mut buf)
                .await
                .expect("read");
            let body = r#"{"token":"agpat_new","id":"tok-1","name":"ci","scopes":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write");
            let _ = socket.shutdown().await;
            String::from_utf8_lossy(&buf[..read])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        });
        let client = GatewayClient::new(format!("http://{addr}"), "agpat_current").expect("client");

        run_access_tokens(
            &client,
            AccessTokenCommand::Rotate(AccessTokenRotateArgs { id: "tok-1".into(), yes: true }),
            Output::Json,
        )
        .await
        .expect("rotate should succeed");

        assert_eq!(server.await.expect("server"), "POST /api/v1/access-tokens/tok-1/rotate HTTP/1.1");
    }

    #[test]
    fn agent_gateway_commands_parse_under_the_appliance() {
        let cli =
            Cli::try_parse_from(["fabric", "agent-gateway", "surfaces", "list"]).expect("surfaces list should parse");
        assert!(matches!(cli.agent_gateway().command, Command::Surfaces { command: SurfaceCommand::List }));
        assert!(!cli.is_interactive());
    }

    #[test]
    fn agent_gateway_global_flags_parse_after_the_command() {
        let cli = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "surfaces",
            "list",
            "--connection",
            "production",
            "--output",
            "json",
        ])
        .expect("global flags should be accepted after the command");
        assert_eq!(
            cli.agent_gateway()
                .connection
                .as_deref(),
            Some("production")
        );
        assert_eq!(
            cli.agent_gateway()
                .output
                .as_str(),
            "json"
        );
    }

    #[test]
    fn commands_are_rejected_without_the_appliance() {
        Cli::try_parse_from(["fabric", "surfaces", "list"]).expect_err("commands live under an appliance");
    }

    #[test]
    fn bare_fabric_prints_help_listing_the_appliances() {
        let error = Cli::try_parse_from(["fabric"]).expect_err("an appliance is required");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
        let help = error.to_string();
        assert!(help.contains("agent-gateway"), "{help}");
        assert!(help.contains("Manage Affinidi Agent Gateway"), "{help}");
    }

    #[test]
    fn bare_agent_gateway_prints_help_instead_of_opening_the_shell() {
        let _guard = FABRIC_CONNECTION_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let error = Cli::try_parse_from(["fabric", "agent-gateway"]).expect_err("a command is required");

        // An exported FABRIC_* variable counts as a supplied argument, which
        // turns clap's help into a missing-subcommand error. Neither opens the
        // shell.
        assert!(
            matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                    | clap::error::ErrorKind::MissingSubcommand
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("surfaces"),
            "{error}"
        );
    }

    #[test]
    fn shell_opens_the_interactive_shell() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "shell"]).expect("shell should parse");
        assert!(cli.is_interactive());
    }
}
