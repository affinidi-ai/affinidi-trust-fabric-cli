use std::{
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, ArgMatches, Args, Parser, Subcommand, ValueEnum, parser::ValueSource};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::{
    client::{
        GatewayClient, id_from_response, pretty_json_for_terminal, response_status, sanitize_for_terminal,
        sanitize_multiline, sanitize_whole,
    },
    config::{Config, Connection, normalize_host, normalize_user_host, saved_host_http_warning},
    credentials::{CredentialStore, OsCredentialStore, add_no_keyring_hint},
    features, surface_patch, surface_validate,
    tables::{self, Layout, Scope, table_cell},
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

    /// Gateway host for this command. Overrides the host of the selected saved
    /// connection; with no saved connection, set it together with --token to
    /// run a command without `login`.
    #[arg(long, global = true, env = "FABRIC_HOST")]
    host: Option<String>,

    /// Bearer token for this command. Overrides the token of the selected
    /// saved connection; with no saved connection, set it together with --host
    /// to run a command without `login`. Prefer the FABRIC_TOKEN environment
    /// variable, since a value typed here stays in shell history and shows in
    /// the process list.
    #[arg(long, global = true, env = "FABRIC_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Allow a plain http:// host other than this machine, typed with --host or
    /// set in FABRIC_HOST.
    /// The token is then sent unencrypted, so only use this on a network you
    /// trust.
    #[arg(long, global = true)]
    allow_http: bool,

    /// Send the saved token to a --host other than the one it was saved for.
    /// Without this the CLI refuses, so a mistyped host cannot receive your
    /// token. It has no environment variable, so it must be typed.
    #[arg(long, global = true)]
    allow_host_override: bool,

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
        if gateway.allow_host_override {
            args.push("--allow-host-override".to_owned());
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
    /// Opens a browser for the gateway's passkey or SSO login and captures the
    /// token. Use --pat for a personal access token, or --paste, --token-stdin,
    /// or FABRIC_TOKEN for a session token. Piped standard input is read as the
    /// token.
    ///
    /// The token is checked with the gateway before anything is saved. The
    /// connection is saved under --connection (or `default`) and becomes
    /// current; logging in again under the same name replaces it.
    ///
    /// See docs/AUTHENTICATION.md for details.
    #[command(after_long_help = LOGIN_EXAMPLES)]
    Login(LoginArgs),
    /// Sign out and remove a saved gateway connection.
    ///
    /// Removes the connection's name, host, and token from this machine.
    /// Without --connection it removes the current connection, and the first
    /// remaining one by name becomes current, so the next command may go to a
    /// different gateway.
    ///
    /// A browser login's session also ends on the gateway, if reachable,
    /// signing you out of the browser too. A personal access token stays valid
    /// unless you revoke it: you're asked in a terminal, or pass --revoke-token;
    /// otherwise logout prints how to revoke it.
    ///
    /// See docs/AUTHENTICATION.md for details.
    #[command(after_long_help = LOGOUT_EXAMPLES)]
    Logout(LogoutArgs),
    /// Manage local gateway profiles.
    ///
    /// Profiles are the connections saved by `fabric agent-gateway login`. These
    /// commands work only on this machine and never contact a gateway.
    #[command(after_long_help = CONFIG_EXAMPLES)]
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
    /// There is no command to accept terms. Until they are accepted, a
    /// personal access token is refused on every authenticated route, the
    /// acceptance route included, so its owner must accept in a browser. A
    /// session-token login can still run `terms status` and `terms applicable`,
    /// and accept with
    /// `fabric agent-gateway api post /v1/terms/acceptances --file <json>`.
    ///
    /// See docs/GATEWAY_CONFIGURATION.md for details.
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
    ///
    /// Checks the token live with the gateway and shows the connection, host,
    /// whether the token was read from the OS credential store
    /// (`token_stored`, false for one given with --token or FABRIC_TOKEN),
    /// whether the gateway accepts it (`authenticated`), and the signed-in
    /// user. For a personal access token it also shows the token's ID, name,
    /// and scopes. A failed check is shown as `error`.
    ///
    /// The command exits 0 even when the token is rejected, so scripts should
    /// read `authenticated`.
    #[command(after_long_help = WHOAMI_EXAMPLES)]
    Whoami,
    /// Manage Agent Surfaces.
    Surfaces {
        #[command(subcommand)]
        command: SurfaceCommand,
    },
    /// Manage connections, the Gateway records of this gateway and its peers.
    ///
    /// Each record holds a gateway's DID, type (`self` or `remote`), status and
    /// exposed surfaces. `update` changes only the name, description and status;
    /// the DID cannot change. These commands call the gateway's `/v1/gateways`
    /// routes.
    #[command(mut_subcommands(crud_help(
        "connections",
        "a connection",
        "connections",
        CrudUpdate::ChangesSentFields
    )))]
    Connections {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage connection points, the DIDComm endpoints other appliances use to
    /// connect to this one.
    ///
    /// `update` changes only `name`, `description`, `enabled` and the
    /// integration list. It takes that list as `integration_integrations`,
    /// although `get` prints it as `integrations`; other fields are ignored.
    #[command(name = "connection-points")]
    #[command(mut_subcommands(crud_help(
        "connection-points",
        "a connection point",
        "connection points",
        CrudUpdate::Custom(CONNECTION_POINTS_UPDATE_HELP)
    )))]
    ConnectionPoints {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage the Rego policy definitions the gateway enforces on traffic.
    Policies {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage issuers, the DID-carrying units that own surfaces.
    #[command(mut_subcommands(crud_help("issuers", "an issuer", "issuers", CrudUpdate::Custom(ISSUERS_UPDATE_HELP))))]
    Issuers {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage authorities, external DIDs recorded as trust anchors.
    ///
    /// An authority is operator-supplied metadata about an external DID that
    /// policies and Trust Check templates can refer to. It holds no keys, and
    /// its DID cannot be changed after it is created.
    #[command(mut_subcommands(crud_help("authorities", "an authority", "authorities", CrudUpdate::Replaces)))]
    Authorities {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage the trust registries this gateway connects to for Trust Checks.
    #[command(name = "trust-registries")]
    #[command(mut_subcommands(crud_help(
        "trust-registries",
        "a trust registry",
        "trust registries",
        CrudUpdate::ChangesSentFields
    )))]
    TrustRegistries {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage DIDComm mediator records.
    #[command(mut_subcommands(crud_help("mediators", "a mediator", "mediators", CrudUpdate::ChangesSentFields)))]
    Mediators {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage MCP proxies, the services a surface Target can route MCP traffic
    /// through.
    #[command(name = "mcp-proxies")]
    #[command(mut_subcommands(crud_help(
        "mcp-proxies",
        "an MCP proxy",
        "MCP proxies",
        CrudUpdate::ChangesSentFields
    )))]
    McpProxies {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage A2A proxies, which expose a managed agent that does not speak A2A
    /// as an A2A endpoint.
    #[command(name = "a2a-proxies")]
    #[command(mut_subcommands(crud_help(
        "a2a-proxies",
        "an A2A proxy",
        "A2A proxies",
        CrudUpdate::ChangesSentFields
    )))]
    A2aProxies {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage STS clients, the OAuth clients allowed to exchange tokens with the
    /// gateway's Security Token Service.
    ///
    /// Each client can limit the audiences and scopes it may request; an empty
    /// list allows any. The client stores no secret value: its
    /// `client_secret_ref` names the secret by `secret_id`, and the value lives
    /// in `fabric agent-gateway secrets`.
    #[command(name = "sts-clients")]
    #[command(mut_subcommands(crud_help("sts-clients", "an STS client", "STS clients", CrudUpdate::Replaces)))]
    StsClients {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage credential providers, the OAuth 2.0 and API-key providers used for
    /// outbound credential delegation.
    ///
    /// Surfaces refer to a provider from their `outbound_credentials`. A
    /// provider stores no secret values: its `client_id_secret_ref`,
    /// `client_secret_secret_ref` and `api_key_secret_ref` fields name them by
    /// `secret_id`, and the values live in `fabric agent-gateway secrets`.
    #[command(name = "credential-providers")]
    #[command(mut_subcommands(crud_help(
        "credential-providers",
        "a credential provider",
        "credential providers",
        CrudUpdate::ChangesSentFields
    )))]
    CredentialProviders {
        #[command(subcommand)]
        command: CrudCommand,
    },
    /// Manage TLS certificates and their private keys.
    #[command(
        mut_subcommand("list", |list| list.about("List certificates")),
        mut_subcommand("create", |create| create.about("Create a certificate from a JSON document")),
        mut_subcommand("get", certificate_reference_help("Get a certificate by its id or name")),
        mut_subcommand("update", |update| {
            certificate_reference_help("Update a certificate from a JSON document")(update).long_about(
                "Update a certificate from a JSON document.\n\n\
                 The gateway changes only the fields the document sets and keeps the rest. A document that still \
                 carries the masked private key is refused: re-read the certificate with --reveal, or drop \
                 `private_key_pem` to keep the stored key.",
            )
        }),
        mut_subcommand("delete", |delete| {
            certificate_reference_help("Delete a certificate by its id or name")(delete).long_about(
                "Delete a certificate by its id or name.\n\n\
                 The certificate is deleted as soon as the command runs: there is no confirmation prompt and no \
                 --yes flag.",
            )
        })
    )]
    Certificates {
        #[command(subcommand)]
        command: CrudCommand,
        /// Print the stored private key instead of masking it. Applies to get,
        /// create, and update; list and delete never print a key.
        #[arg(long, global = true)]
        reveal: bool,
    },
    /// Manage secrets.
    Secrets {
        #[command(subcommand)]
        command: SecretCommand,
        /// Print secret values instead of masking them. Applies to get,
        /// create, and update; list responses never carry values and delete
        /// prints none.
        #[arg(long, global = true)]
        reveal: bool,
    },
    /// Inspect and revoke delegated credential grants.
    #[command(name = "delegation-vault")]
    DelegationVault {
        #[command(subcommand)]
        command: DelegationVaultCommand,
    },
    /// Manage integrations, such as the email, Slack or webhook senders the
    /// gateway notifies through.
    ///
    /// Each integration has a type, a category that sets which runtime
    /// variables its message can use, its connection settings, and the message
    /// content with ${VARIABLE} placeholders. The types and categories on offer
    /// come from the gateway's configuration.
    #[command(mut_subcommands(crud_help("integrations", "an integration", "integrations", CrudUpdate::Replaces)))]
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
    ///
    /// A strategy names the issuer the gateway expects in a JWT and where it
    /// gets the keys that verify it. `create` takes a document `{name,
    /// expected_issuer, jwks_source, tenant_id?}`, where `jwks_source` is
    /// `{"type": "remote", "jwks_uri": ...}` or `{"type": "static", "jwks":
    /// [...]}`. `update` takes the same document and replaces the strategy's
    /// name, issuer and key source; it ignores `tenant_id` and keeps the
    /// current tenant, which `tenant-ownership set jwt-verification-strategies
    /// <id>` changes. `delete` runs at once, with no confirmation prompt.
    #[command(
        name = "jwt-verification-strategies",
        after_long_help = JWT_VERIFICATION_STRATEGIES_EXAMPLES,
        mut_subcommands(crud_help(
            "jwt-verification-strategies",
            "a JWT verification strategy",
            "JWT verification strategies",
            CrudUpdate::Custom(JWT_VERIFICATION_STRATEGIES_UPDATE_HELP)
        ))
    )]
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
    ///
    /// Reaches the endpoints no other command covers, with the current
    /// connection's token. Give a body with --data or --file, not both; `patch`
    /// needs one and sends it as a JSON Merge Patch. A body still carrying the
    /// masked placeholder is refused.
    ///
    /// Responses print as the gateway sent them, without the masking that
    /// commands such as `secrets` apply. In table mode a JSON array prints as a
    /// NAME ID DESCRIPTION table, anything else as JSON.
    ///
    /// See docs/SCRIPTING_AND_OUTPUT.md for details.
    #[command(after_long_help = API_EXAMPLES)]
    Api(ApiArgs),
    /// Open the interactive shell.
    ///
    /// Type commands without the `fabric agent-gateway` prefix, such as
    /// `surfaces list`. Global options given when the shell starts, such as
    /// --connection or --output, become defaults that a single command can
    /// override. A failed command prints its error and the shell keeps running.
    ///
    /// Type `help` to list commands, and `exit`, `quit` or Ctrl-D to leave.
    /// History lasts for the session only and skips any line that types a
    /// secret, such as a --token value.
    ///
    /// See docs/INTERACTIVE_SHELL.md for details.
    #[command(after_long_help = SHELL_EXAMPLES)]
    Shell,
}

/// Examples shown at the bottom of `api --help`.
const API_EXAMPLES: &str = r#"Examples:
  Read an endpoint as JSON:
    fabric agent-gateway api get /v1/limits --output json

  Send a body from a file, or from standard input with '-':
    fabric agent-gateway api post /v1/policy-definitions/<policy-id>/simulate \
      --file input.json

  Change one field of a surface (sent as a JSON Merge Patch):
    fabric agent-gateway api patch /v1/surfaces/<surface-id> \
      --data '{"description":"Updated"}'"#;

/// Examples shown at the bottom of `shell --help`.
const SHELL_EXAMPLES: &str = r#"Examples:
  Open the shell with a saved connection and JSON output as defaults:
    fabric agent-gateway --connection production --output json shell

  Then type commands without the prefix:
    fabric agent-gateway> surfaces list
    fabric agent-gateway> surfaces list --output table
    fabric agent-gateway> exit"#;

/// Examples shown at the bottom of `login --help`.
const LOGIN_EXAMPLES: &str = r#"Examples:
  Sign in through the browser and save the connection as "default":
    fabric agent-gateway login --host https://gateway.example.com

  Save another connection, named "production":
    fabric agent-gateway --connection production login \
      --host https://gateway.example.com

  Sign in with a personal access token, prompted for without echo:
    fabric agent-gateway login --host https://gateway.example.com --pat

  Sign in with a personal access token from a script:
    printf '%s' "$PAT" | fabric agent-gateway login \
      --host https://gateway.example.com --pat --token-stdin"#;

/// Examples shown at the bottom of `logout --help`.
const LOGOUT_EXAMPLES: &str = r#"Examples:
  Sign out of the current connection:
    fabric agent-gateway logout

  Sign out of a named connection:
    fabric agent-gateway --connection production logout

  Sign out and revoke the saved personal access token without asking:
    fabric agent-gateway logout --revoke-token"#;

/// Examples shown at the bottom of `whoami --help`.
const WHOAMI_EXAMPLES: &str = r#"Examples:
  Check the current connection:
    fabric agent-gateway whoami

  Check a named connection:
    fabric agent-gateway --connection production whoami

  Fail a script when the saved token no longer works:
    fabric agent-gateway whoami --output json | jq -e .authenticated"#;

#[derive(Debug, Args)]
struct LogoutArgs {
    /// Also revoke the saved personal access token on the gateway, without
    /// asking. Has no effect on a browser login, whose session always ends.
    #[arg(long)]
    revoke_token: bool,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Gateway origin, for example https://gateway.example.com.
    #[arg(long, env = "FABRIC_HOST")]
    host: Option<String>,
    /// Read the bearer token from standard input. Safer than --token, which
    /// stays in shell history. With --pat, this reads the personal access
    /// token.
    #[arg(long, conflicts_with = "token")]
    token_stdin: bool,
    /// Paste a bearer token manually instead of using the browser login.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    paste: bool,
    /// Bearer token produced by the existing passkey or SSO login. Prefer
    /// FABRIC_TOKEN or --token-stdin over typing it here.
    #[arg(long, env = "FABRIC_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Authenticate with a personal access token (agpat_...) instead of the
    /// browser login. Leave the value off to be prompted, or supply it with
    /// FABRIC_PAT (read only when --pat is given) or --token-stdin. A value
    /// typed after the flag stays in shell history.
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
    /// List saved gateway profiles, with their hosts and which one is current.
    List,
    /// Select the default gateway profile.
    ///
    /// Commands not given --connection (or FABRIC_CONNECTION) use this profile
    /// from now on.
    Use {
        /// Name of a saved profile (see `fabric agent-gateway config list`).
        name: String,
    },
    /// Remove a gateway profile and its saved token, without contacting the
    /// gateway.
    ///
    /// The token is deleted from the OS credential store only. A browser
    /// session stays open and a personal access token stays valid on the
    /// gateway; use `fabric agent-gateway logout` to end the session or revoke
    /// the token as well. When the removed profile was current, another saved
    /// profile, if any, becomes current (the first by name).
    Remove {
        /// Name of the saved profile to remove.
        name: String,
    },
}

/// Examples shown at the bottom of `config --help`.
const CONFIG_EXAMPLES: &str = r#"Examples:
  List saved profiles and see which one is current:
    fabric agent-gateway config list

  Make "production" the profile later commands use:
    fabric agent-gateway config use production

  Use another profile for one command only:
    fabric agent-gateway --connection staging surfaces list

  Forget a profile on this machine, without contacting the gateway:
    fabric agent-gateway config remove staging"#;

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Show one of the gateway's read-only runtime configuration views.
    Show {
        #[arg(value_enum)]
        view: RuntimeView,
    },
    /// Reload surface configuration from the configured source.
    ///
    /// Re-reads the configured source and swaps surfaces in place. It changes
    /// no configuration you set, though a full reload can persist housekeeping
    /// fixes, such as upgrading legacy `channel.policy` definitions. Surfaces
    /// changed through this CLI or the dashboard already reload themselves;
    /// this covers configuration edited outside the gateway, such as a direct
    /// `_storage/` edit.
    #[command(after_long_help = RUNTIME_RELOAD_EXAMPLES)]
    Reload {
        /// Reload only this surface, by the id `fabric agent-gateway surfaces
        /// list` shows. The gateway answers an unknown id with a 500, so after
        /// a server error the CLI checks the id and reports a missing one as
        /// not found.
        #[arg(long)]
        surface: Option<String>,
    },
}

/// Examples shown at the bottom of `runtime reload --help`.
const RUNTIME_RELOAD_EXAMPLES: &str = r#"Examples:
  Reload every surface:
    fabric agent-gateway runtime reload

  Reload one surface, by the id `fabric agent-gateway surfaces list` shows:
    fabric agent-gateway runtime reload --surface <surface-id>

Reading the result:
  A full reload prints channels_count, surfaces_count and is_fallback. With
  --surface it prints the surface's channel_name and is_fallback. Either one
  adds a warning when the gateway sends one."#;

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
    /// stored map wholesale, so a flag missing from it is removed.
    /// `payments_min_display` is ignored here; set it per user with
    /// `fabric agent-gateway user-settings set`. A document carrying
    /// `feature_flags.terms` is refused. Prints the settings as read back after
    /// the write.
    ///
    /// See docs/GATEWAY_CONFIGURATION.md for details.
    #[command(after_long_help = SETTINGS_SET_EXAMPLES)]
    Set(JsonFileArgs),
    /// Overwrite the whole document with the built-in defaults and show them.
    ///
    /// This clears settings rather than restoring omitted ones: Prometheus
    /// authentication and audit logging are switched off, `feature_flags` is
    /// emptied, and every window, interval and threshold goes back to its
    /// default. Refused without --force, because the Prometheus password it
    /// erases cannot be restored from a `fabric agent-gateway settings show` backup.
    #[command(after_long_help = SETTINGS_RESET_EXAMPLES)]
    Reset {
        /// Confirm the reset. Without it the command lists what it would
        /// clear and sends nothing.
        #[arg(long)]
        force: bool,
    },
}

/// Examples shown at the bottom of `settings set --help`.
const SETTINGS_SET_EXAMPLES: &str = r#"Examples:
  Change one setting and leave the rest as they are:
    echo '{"audit_enabled": true}' | fabric agent-gateway settings set --file -

  Edit a full copy. A `show` document always carries feature_flags.terms, which
  is refused, so delete it first:
    fabric agent-gateway settings show --output json | jq \
      'del(.feature_flags.terms)' > settings.json
    fabric agent-gateway settings set --file settings.json

  Change the Prometheus password, from a file holding
  {"prometheus_auth_password": "<password>"} so it stays out of shell history.
  It is sent as plaintext and hashed by the gateway:
    fabric agent-gateway settings set --file prometheus-password.json

Fields the gateway will not store as sent (payments_min_display,
prometheus_auth_password_hash) and a feature_flags map that replaces the stored
one draw a warning on stderr."#;

/// Examples shown at the bottom of `settings reset --help`.
const SETTINGS_RESET_EXAMPLES: &str = r#"Examples:
  Keep a copy, then reset (a copy does not bring back the Prometheus password):
    fabric agent-gateway settings show --output json > settings-backup.json
    fabric agent-gateway settings reset --force"#;

#[derive(Debug, Subcommand)]
enum UserSettingsCommand {
    /// Show this user's settings.
    ///
    /// Without --overrides this is the effective document — appliance defaults
    /// merged with this user's overrides — so a field that was never set still
    /// looks set. Pass --overrides to see only what is stored for your
    /// account, the view to start a `set` document from.
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
    /// personal override. A document carrying `feature_flags.terms` is always
    /// refused.
    ///
    /// See docs/GATEWAY_CONFIGURATION.md for details.
    #[command(after_long_help = USER_SETTINGS_SET_EXAMPLES)]
    Set(GuardedJsonFileArgs),
    /// Clear every personal override and show the resulting settings.
    ///
    /// Runs without a prompt and needs no --force. It deletes only this
    /// account's overrides and touches no appliance setting or other account.
    /// A `show --overrides` copy taken beforehand restores them through `set`.
    #[command(after_long_help = USER_SETTINGS_RESET_EXAMPLES)]
    Reset,
}

/// Examples shown at the bottom of `user-settings set --help`.
const USER_SETTINGS_SET_EXAMPLES: &str = r#"Examples:
  Set one personal override:
    echo '{"refresh_interval_seconds": 30}' | fabric agent-gateway \
      user-settings set --file -

  Edit your stored overrides as a whole, starting from --overrides (a plain
  `show` document is refused):
    fabric agent-gateway user-settings show --overrides --output json > \
      overrides.json
    fabric agent-gateway user-settings set --file overrides.json

Fields a personal override can hold: refresh_interval_seconds,
log_timestamp_format, bucket_seconds, badge_threshold_minutes,
payments_min_display, feature_flags."#;

/// Examples shown at the bottom of `user-settings reset --help`.
const USER_SETTINGS_RESET_EXAMPLES: &str = r#"Examples:
  Keep a copy of your overrides, clear them, and restore them later:
    fabric agent-gateway user-settings show --overrides --output json > \
      overrides.json
    fabric agent-gateway user-settings reset
    fabric agent-gateway user-settings set --file overrides.json"#;

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
    ///
    /// The document carries `version`, `title` and `url` (an absolute https
    /// URL), plus an optional `requires_reconsent` that defaults to false.
    /// Saving replaces any earlier draft. Nothing applies to users until
    /// `fabric agent-gateway terms publish`.
    #[command(after_long_help = TERMS_DRAFT_EXAMPLES)]
    Draft(JsonFileArgs),
    /// Publish the saved customer Terms of Use draft as a new version.
    ///
    /// Runs without a prompt. The published version becomes the current
    /// customer Terms of Use, the draft is used up, and the new version is
    /// printed. Refused with TERMS_DRAFT_REQUIRED when no draft is saved, and
    /// with TERMS_INVALID when a version with the same `version` was already
    /// published.
    Publish,
    /// Deactivate the published customer Terms of Use.
    ///
    /// Runs without a prompt. The customer Terms of Use stop applying, and
    /// the versions published so far are kept. To apply customer terms again,
    /// save and publish a draft with a new `version`. Prints a confirmation
    /// line, or `null` with --output json.
    Deactivate,
}

/// Examples shown at the bottom of `terms draft --help`.
const TERMS_DRAFT_EXAMPLES: &str = r#"Examples:
  Save a draft from terms.json, then publish it:
    fabric agent-gateway terms draft --file terms.json
    fabric agent-gateway terms publish
  where terms.json is:
    {
      "version": "2.0",
      "title": "Acme Terms of Use",
      "url": "https://example.com/terms-2.0",
      "requires_reconsent": true
    }"#;

#[derive(Debug, Subcommand)]
enum NotificationCommand {
    /// Manage the welcome notification sent to newly approved users.
    #[command(name = "welcome-template")]
    WelcomeTemplate {
        #[command(subcommand)]
        command: WelcomeTemplateCommand,
    },
    /// Send a welcome notification to a user.
    ///
    /// The gateway accepts any recipient id, so the CLI looks the user up
    /// first and refuses an unknown id. A caller without the `users.view`
    /// permission cannot look another user up, and is warned that the
    /// recipient went unverified instead.
    #[command(name = "send-welcome", after_long_help = NOTIFICATIONS_SEND_WELCOME_EXAMPLES)]
    SendWelcome(SendWelcomeArgs),
}

/// Examples shown at the bottom of `notifications send-welcome --help`.
const NOTIFICATIONS_SEND_WELCOME_EXAMPLES: &str = r#"Examples:
  Send a welcome notification:
    fabric agent-gateway notifications send-welcome --user-id <user-id> \
      --title "Welcome" --message "Your account is ready"

The recipient lookup is an ordinary user read: it records an accessed user event
and fires any integration bound to the user.accessed event. Prints a
confirmation line, or null with --output json."#;

#[derive(Debug, Subcommand)]
enum WelcomeTemplateCommand {
    /// Show the welcome notification template.
    Show,
    /// Replace the welcome notification template from a JSON document.
    ///
    /// The document carries "title" and "message". The gateway sends the
    /// template to each user approved from now on, except administrators.
    /// Prints a confirmation line, or `null` with --output json.
    #[command(after_long_help = NOTIFICATIONS_WELCOME_TEMPLATE_SET_EXAMPLES)]
    Set(JsonFileArgs),
}

/// Examples shown at the bottom of `notifications welcome-template set --help`.
const NOTIFICATIONS_WELCOME_TEMPLATE_SET_EXAMPLES: &str = r#"Examples:
  Replace the template, starting from the current one:
    fabric agent-gateway notifications welcome-template show --output json > \
      template.json
    fabric agent-gateway notifications welcome-template set --file template.json

  Replace it from standard input:
    echo '{"title": "Welcome", "message": "Your account is ready"}' | fabric \
      agent-gateway notifications welcome-template set --file -"#;

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
    /// Update an entity from a JSON document.
    Update {
        id: String,
        /// JSON document to send. Use '-' to read from standard input.
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
    ///
    /// With flags, only --name is required. Unless told otherwise, the surface
    /// listens on 0.0.0.0:8080 with the a2a protocol, forwards to
    /// http://127.0.0.1:3000, and its route is a URL-safe form of the name.
    /// With --file, the JSON document is sent as it is and the other creation
    /// flags are ignored.
    ///
    /// Table output prints the new surface's id, name, route, protocol and
    /// target. Use --output json to get the whole surface, for example to read
    /// its id in a script.
    #[command(after_long_help = SURFACES_CREATE_EXAMPLES)]
    Create(SurfaceCreateArgs),
    /// Update an Agent Surface's fields, or replace it from a JSON document.
    ///
    /// --set, --unset, --add and --remove send one merge patch: fields they
    /// don't name keep their values, objects are merged, and a list you set is
    /// replaced whole. --file replaces the whole surface, checking only the
    /// file.
    ///
    /// The other flags read the surface first and check the result; without
    /// surfaces.view, --set and --unset are sent unchecked, with a warning.
    /// --add and --remove send the whole list they change, overwriting any
    /// change someone else made to it meanwhile.
    ///
    /// See docs/SURFACES.md for details.
    #[command(after_long_help = SURFACES_UPDATE_EXAMPLES)]
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
        /// the same way as a --set value (`tags=beta`). An item already in the
        /// list is refused. To add one tool pattern, name its gate in brackets,
        /// as in the examples. Repeatable.
        #[arg(long, value_name = "PATH=ITEM")]
        add: Vec<String>,
        /// Remove one item from a list: text by its value (`tags=beta`), an
        /// object by its `id`, else its `alias` (`transit.points=billing`), else
        /// some of its fields as JSON. Removes run before adds, so removing an
        /// item and adding it back replaces it. A tool pattern on a transit
        /// point is named like
        /// `'transit.points[billing].mcp_tool_gating.gates[g-1].action.patterns=fs_.*'`.
        /// Repeatable.
        #[arg(long, value_name = "PATH=ITEM")]
        remove: Vec<String>,
        /// Check the change with the gateway and show what it would change,
        /// without saving anything. Not available with --file, which
        /// replaces the whole surface.
        #[arg(long, conflicts_with = "file")]
        dry_run: bool,
    },
    /// Delete an Agent Surface by ID or name.
    ///
    /// The surface is deleted as soon as the command runs. There is no
    /// confirmation prompt. A name must belong to only one surface: when more
    /// than one surface has it, the CLI lists their IDs and asks for the ID.
    Delete {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: String,
    },
    /// List the features a surface can have, or the ones a given surface has.
    ///
    /// With a surface given, it also shows where each feature is set. The
    /// names shown are the ones `add-feature` and `remove-feature` take.
    #[command(after_long_help = SURFACES_FEATURES_EXAMPLES)]
    Features {
        /// Surface ID or name (see `fabric agent-gateway surfaces list`).
        surface_id: Option<String>,
    },
    /// Add a feature to an Agent Surface.
    ///
    /// Feature names come from `fabric agent-gateway surfaces features`.
    /// Configure it with --json or --file, or --policy-id for a policy. An
    /// object feature replaces what was there; a list feature, such as
    /// trust-check, gets the new item appended.
    ///
    /// The place is worked out from the name: the request place unless you add
    /// --response, or one transit point with --transit-point. A transit-point
    /// feature sends the whole transit.points list, overwriting any change
    /// someone else made to it meanwhile.
    #[command(after_long_help = SURFACES_ADD_FEATURE_EXAMPLES)]
    AddFeature(AddFeatureArgs),
    /// Remove a feature from an Agent Surface.
    ///
    /// Where the feature is found is worked out from its name, the same as
    /// for add-feature, and --response, --transit-point and --edge pick
    /// another place. `fabric agent-gateway surfaces features <surface>` shows
    /// each place the surface has the feature and the flags needed to remove
    /// it from there. A feature that is not set is refused.
    #[command(after_long_help = SURFACES_REMOVE_FEATURE_EXAMPLES)]
    RemoveFeature(FeaturePlacementArgs),
    /// Add a transit point to an Agent Surface from its alias and endpoint.
    ///
    /// The point is appended to the surface's transit points and takes the
    /// protocol of the surface's access point, so on a didcomm surface the
    /// gateway refuses it. An alias the surface already uses is refused. The
    /// CLI sends the whole transit.points list, so a change someone else makes
    /// to it between the read and the write is overwritten.
    #[command(after_long_help = SURFACES_ADD_TRANSIT_POINT_EXAMPLES)]
    AddTransitPoint(AddTransitPointArgs),
    /// Remove a transit point from an Agent Surface by its alias or id.
    ///
    /// The point is matched by its id first, then by its alias. When no point
    /// has that name, the CLI lists the ones the surface has. The CLI sends the
    /// surface's whole transit.points list, so a change someone else makes to
    /// that list between the read and the write is overwritten.
    #[command(after_long_help = SURFACES_REMOVE_TRANSIT_POINT_EXAMPLES)]
    RemoveTransitPoint(RemoveTransitPointArgs),
    /// Preview which tools a set of MCP tool gates would allow or deny.
    ///
    /// The gates come from a saved surface's own `target.mcp_tool_gating` (not
    /// its variants or transit points) or from --gates-file. Nothing is saved.
    ///
    /// Pin what you know about the caller with --condition; other conditions
    /// are tried both ways (at most 3). A missing or disabled condition policy
    /// keeps a block gate on and an allow gate off, which the preview can't
    /// detect.
    ///
    /// See docs/SURFACES.md for pattern rules and details.
    #[command(after_long_help = TOOL_GATE_PREVIEW_EXAMPLES)]
    ToolGatePreview(ToolGatePreviewArgs),
}

/// Long help for `issuers update`, which keeps omitted fields but always
/// requires `name`.
const ISSUERS_UPDATE_HELP: &str = r#"Update an issuer from a JSON document.

The gateway changes only the fields the document sets and keeps the rest, but
`name` is always required: a document without it, or with an empty one, is
refused. Start from the current issuer:

  fabric agent-gateway issuers get <ID> \
    --output json > record.json
  fabric agent-gateway issuers update <ID> \
    --file record.json

Use `--file -` to read the document from standard input."#;

/// Long help for `connection-points update`. Its integration list is read
/// under a different name than `get` prints, so a `get` round trip would
/// silently drop an integration edit.
const CONNECTION_POINTS_UPDATE_HELP: &str = r#"Update a connection point from a JSON document.

The gateway changes only name, description, enabled, and the integration list,
and ignores other fields. It reads the integration list as
`integration_integrations`, not as the `integrations` field that `get` prints,
so send only the fields you change rather than editing `get` output:

  echo '{"description": "EU partners", "enabled": true}' | \
    fabric agent-gateway connection-points update <ID> --file -

Use `--file -` to read the document from standard input."#;

/// Long help for `jwt-verification-strategies update`, which always replaces
/// the strategy rather than following the shared CRUD wording.
const JWT_VERIFICATION_STRATEGIES_UPDATE_HELP: &str = r#"Update a JWT verification strategy from a JSON document.

The document replaces the strategy's name, expected_issuer and jwks_source, so
send all three. tenant_id is ignored and the strategy keeps its tenant; change
it with `fabric agent-gateway tenant-ownership set jwt-verification-strategies
<ID>`. Start from the current strategy:

  fabric agent-gateway jwt-verification-strategies get <ID> \
    --output json > record.json
  fabric agent-gateway jwt-verification-strategies update <ID> \
    --file record.json

Use `--file -` to read the document from standard input."#;

/// Examples shown at the bottom of `tool-gate-preview --help`.
const TOOL_GATE_PREVIEW_EXAMPLES: &str = r#"Examples:
  Check the gates a surface has saved, named by its name or ID:
    fabric agent-gateway surfaces tool-gate-preview my-agent \
      --tool delete_user,get_user

  Check gates that are not saved yet, from a file:
    fabric agent-gateway surfaces tool-gate-preview --gates-file gates.json \
      --tool delete_user

  Say what you know about the caller (an admin who is not a contractor):
    fabric agent-gateway surfaces tool-gate-preview my-agent \
      --tool delete_user --condition admins=met --condition contractors=unmet

Reading the result:
  RESULT is ALLOW or DENY. DECIDED BY is the gate that decided, or the default
  when no gate matched. A tool gets one row per combination of conditions, named
  in a CONDITION column, only when its answer or deciding gate depends on them.
  Otherwise each tool gets a single row and the CONDITION column is left out."#;

/// Examples shown at the bottom of `surfaces create --help`.
const SURFACES_CREATE_EXAMPLES: &str = r#"Examples:
  Create a surface with the default listener, protocol and target:
    fabric agent-gateway surfaces create --name "Sales Agent" \
      --description "Routes sales traffic"

  Create an MCP surface that forwards to your own server, with two tags:
    fabric agent-gateway surfaces create --name "Sales Agent" --protocol mcp \
      --target-endpoint http://sales:3000 --tags sales,beta

  Create a surface from a complete AgentSurface JSON document:
    fabric agent-gateway surfaces create --file surface.json

  Print only the new surface's id, for a script:
    fabric agent-gateway surfaces create --name "Sales Agent" --output json | \
      jq -r .surface_id"#;

/// Examples shown at the bottom of `surfaces update --help`.
const SURFACES_UPDATE_EXAMPLES: &str = r#"Examples:
  Change one field and remove another, naming the surface by its name:
    fabric agent-gateway surfaces update "Sales Agent" \
      --set access_point.rate_limit.requests=100 --unset description

  Add a tag and remove a transit point by its alias:
    fabric agent-gateway surfaces update <surface-id> --add tags=beta \
      --remove transit.points=billing

  Add one tool pattern to gate g-1, quoted so the shell leaves the brackets
  alone:
    fabric agent-gateway surfaces update <surface-id> \
      --add 'target.mcp_tool_gating.gates[g-1].action.patterns=fs_.*'

  Replace the whole surface, starting from its current JSON:
    fabric agent-gateway surfaces get <surface-id> --output json > surface.json
    fabric agent-gateway surfaces update <surface-id> --file surface.json"#;

/// Examples shown at the bottom of `surfaces features --help`.
const SURFACES_FEATURES_EXAMPLES: &str = r#"Examples:
  List every feature that can be added, with the places it can go:
    fabric agent-gateway surfaces features

  Show which features a surface has, and how to remove each one:
    fabric agent-gateway surfaces features "Sales Agent"

Reading the result:
  For one surface, FEATURE is the name add-feature and remove-feature take, ON
  is on or off for the surface itself, and WHERE lists each place the feature is
  set with the remove-feature flags it needs, such as "remove with
  --transit-point billing" or "remove with no flags". A Notes section under the
  table says when an enabled variant changes what the table shows."#;

/// Examples shown at the bottom of `surfaces add-feature --help`.
const SURFACES_ADD_FEATURE_EXAMPLES: &str = r#"Examples:
  Enforce a policy on requests, by its policy definition id:
    fabric agent-gateway surfaces add-feature "Sales Agent" policy \
      --policy-id allow-sales

  Limit inbound requests:
    fabric agent-gateway surfaces add-feature <surface-id> rate-limit \
      --json '{"requests":100,"window_secs":60}'

  Add a trust check on the target leg:
    fabric agent-gateway surfaces add-feature <surface-id> trust-check \
      --edge ma-tp --file trust-check.json

  Enforce a policy on one transit point's responses:
    fabric agent-gateway surfaces add-feature <surface-id> policy \
      --transit-point billing --response --policy-id allow-billing"#;

/// Examples shown at the bottom of `surfaces remove-feature --help`.
const SURFACES_REMOVE_FEATURE_EXAMPLES: &str = r#"Examples:
  See where a surface has each feature and the flags to remove it:
    fabric agent-gateway surfaces features "Sales Agent"

  Remove a feature that is set in one place:
    fabric agent-gateway surfaces remove-feature "Sales Agent" rate-limit

  Remove the response policy:
    fabric agent-gateway surfaces remove-feature <surface-id> policy --response

  Remove tool gating from one transit point:
    fabric agent-gateway surfaces remove-feature <surface-id> mcp-tool-gating \
      --transit-point billing"#;

/// Examples shown at the bottom of `surfaces add-transit-point --help`.
const SURFACES_ADD_TRANSIT_POINT_EXAMPLES: &str = r#"Examples:
  Add a transit point:
    fabric agent-gateway surfaces add-transit-point "Sales Agent" \
      --alias billing --endpoint http://billing:3000

  Preview it without saving:
    fabric agent-gateway surfaces add-transit-point <surface-id> \
      --alias billing --endpoint http://billing:3000 --dry-run

  Then enforce a policy on that transit point:
    fabric agent-gateway surfaces add-feature <surface-id> policy \
      --transit-point billing --policy-id allow-billing"#;

/// Examples shown at the bottom of `surfaces remove-transit-point --help`.
const SURFACES_REMOVE_TRANSIT_POINT_EXAMPLES: &str = r#"Examples:
  Remove a transit point by its alias:
    fabric agent-gateway surfaces remove-transit-point "Sales Agent" billing

  Preview it without saving:
    fabric agent-gateway surfaces remove-transit-point <surface-id> billing \
      --dry-run"#;

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
    /// Surface name. Required unless --file is given.
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    /// What the surface is for.
    #[arg(long, default_value = "")]
    description: String,
    /// Complete AgentSurface JSON. Other creation flags are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Address the gateway listens on for this surface's inbound traffic.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen_address: String,
    /// Inbound route. Defaults to a URL-safe form of the name.
    #[arg(long)]
    route: Option<String>,
    /// Protocol of the surface's inbound traffic.
    #[arg(long, value_enum, default_value_t = Protocol::A2a)]
    protocol: Protocol,
    /// Endpoint of the agent or service the surface forwards requests to.
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    target_endpoint: String,
    /// Tags to attach, comma-separated or with the flag repeated.
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
    /// Pipeline edge, needed only when the command asks you to choose. Use
    /// ma-tp for the target leg of trust-check.
    #[arg(long, value_enum, conflicts_with = "transit_point")]
    edge: Option<EdgeOpt>,
    /// Alias of the transit point whose place to use, instead of the
    /// surface's own place (implies the ma-tp edge).
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
    /// Shortcut for policy features: the policy definition id. Ignored when
    /// --json or --file is given.
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
struct AddTransitPointArgs {
    /// Surface ID or name (see `fabric agent-gateway surfaces list`).
    surface_id: String,
    /// Alias the new transit point is known by: a lowercase letter, then
    /// lowercase letters, digits or `-`, at most 63 characters long.
    #[arg(long)]
    alias: String,
    /// Endpoint the transit point sends requests to.
    #[arg(long)]
    endpoint: String,
    /// Check the change with the gateway and show what it would change,
    /// without saving anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RemoveTransitPointArgs {
    /// Surface ID or name (see `fabric agent-gateway surfaces list`).
    surface_id: String,
    /// Alias or id of the transit point to remove.
    transit_point: String,
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
    ///
    /// STATUS is REVOKED for a token that has been revoked or has expired, and
    /// ACTIVE otherwise. SCOPES is shortened to fit and ends with
    /// "+N more" for the scopes left out; a token with no scope list holds its
    /// creator's whole role and shows "full role". EXPIRES is "never" for a
    /// token without an expiry. Use `tokens get` or --output json for the full
    /// scope list.
    List,
    /// Get a personal access token by ID.
    Get {
        /// ID of the personal access token (see `fabric agent-gateway tokens
        /// list`).
        id: String,
    },
    /// Create a personal access token using flags or a complete JSON document.
    ///
    /// Give at least one --scope (or a `scopes` list in --file), or --full-role
    /// for your whole role. The token expires after 90 days unless you set
    /// --expires-at, at most 3650 days ahead; it can't be made to never expire.
    ///
    /// The secret is shown only once. In table output it is printed alone on
    /// standard output, so `PAT=$(...)` captures it; with --output json the
    /// whole response is printed.
    ///
    /// See docs/AUTHENTICATION.md for details.
    #[command(after_long_help = TOKENS_CREATE_EXAMPLES)]
    Create(AccessTokenCreateArgs),
    /// Revoke a personal access token.
    ///
    /// Takes the token's ID, not its name. There is no command to undo a
    /// revoke, and if this CLI is logged in with the token, its saved
    /// connection stops working too. You are asked to confirm, and only `y` or
    /// `yes` revokes. Without a terminal the command refuses before sending
    /// anything unless --yes is given.
    #[command(after_long_help = TOKENS_REVOKE_EXAMPLES)]
    Revoke(AccessTokenRevokeArgs),
    /// List the scopes your role holds, which you can give a new token.
    ///
    /// The list comes from your role only. When you are signed in with a
    /// scoped personal access token, a new token can get only scopes that
    /// token also holds.
    Scopes,
    /// Replace a personal access token's secret, keeping its ID, name, and scopes.
    ///
    /// The current secret stops working immediately, so update every script
    /// that uses it; if this CLI is logged in with the token, log in again with
    /// the new secret. The new secret is shown only once: in table output it is
    /// printed alone on standard output, and the "Rotated access token" line
    /// goes to standard error. You are asked to confirm; without a terminal the
    /// command refuses unless --yes is given.
    #[command(after_long_help = TOKENS_ROTATE_EXAMPLES)]
    Rotate(AccessTokenRotateArgs),
}

/// Examples shown at the bottom of `tokens create --help`.
const TOKENS_CREATE_EXAMPLES: &str = r#"Examples:
  Create a token for a CI job and capture its secret:
    PAT=$(fabric agent-gateway tokens create --name ci-deploy \
      --scope surfaces.view --scope surfaces.edit \
      --expires-at 2027-01-01T00:00:00Z)

  Limit a token to one tenant's surfaces:
    fabric agent-gateway tokens create --name acme-surfaces \
      --scope surfaces.view --required-header x-tenant-id=acme \
      --resource-pattern 'TENANT:${x-tenant-id}:surfaces:.*'

  Create a token from a JSON document on standard input:
    echo '{"name": "ci-read", "scopes": ["surfaces.view"]}' | fabric \
      agent-gateway tokens create --file -"#;

/// Examples shown at the bottom of `tokens revoke --help`.
const TOKENS_REVOKE_EXAMPLES: &str = r#"Examples:
  Find the token's ID, then revoke it after confirming:
    fabric agent-gateway tokens list
    fabric agent-gateway tokens revoke <token-id>

  Revoke without the prompt, for scripts:
    fabric agent-gateway tokens revoke <token-id> --yes"#;

/// Examples shown at the bottom of `tokens rotate --help`.
const TOKENS_ROTATE_EXAMPLES: &str = r#"Examples:
  Rotate a token after confirming:
    fabric agent-gateway tokens rotate <token-id>

  Rotate from a script and capture the new secret:
    PAT=$(fabric agent-gateway tokens rotate <token-id> --yes)"#;

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
    /// Token name. Required unless --file is given.
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    /// What the token is for.
    #[arg(long, default_value = "")]
    description: String,
    /// Scope to grant the token. Repeat for multiple scopes. Required unless
    /// --full-role is given; run `fabric agent-gateway tokens scopes` to see
    /// what you can grant.
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// Give the token everything your own role can do, instead of listing
    /// scopes. Use it only when a limited token will not do.
    #[arg(long, conflicts_with = "scopes")]
    full_role: bool,
    /// RFC 3339 expiry timestamp, for example 2027-01-01T00:00:00Z. Defaults
    /// to 90 days from now.
    #[arg(long)]
    expires_at: Option<String>,
    /// Resource the token is limited to, as
    /// TENANT:${header}:<resource-kind>:<id-pattern>, where ${header} names
    /// one of the --required-header flags. Omit for an appliance-wide token.
    #[arg(long)]
    resource_pattern: Option<String>,
    /// Header the caller must send, as name=pattern, where pattern is a regex
    /// the whole header value must match. Repeat for more headers. The header
    /// named in --resource-pattern must normally be one exact value, such as
    /// acme.
    #[arg(long = "required-header", value_parser = parse_required_header)]
    required_headers: Vec<(String, String)>,
    /// JSON request body, or - for standard input. Other creation flags except
    /// --full-role are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

/// How long a token lives when `tokens create` is not told.
const DEFAULT_TOKEN_LIFETIME_DAYS: u64 = 90;

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
    /// List policy definitions.
    List,
    /// Get a policy definition by ID.
    Get {
        /// Policy definition ID (see `fabric agent-gateway policies list`).
        policy_id: String,
    },
    /// Create a policy definition from a Rego file.
    ///
    /// The file holds Rego source, not JSON, and must declare
    /// `package surface.policy` (or `package gateway.policy` with
    /// --policy-type gateway); any other package is refused. The new policy is
    /// enabled as soon as it is created. To enforce it on an Agent Surface,
    /// use `fabric agent-gateway surfaces add-feature <surface> policy
    /// --policy-id <id>`.
    #[command(after_long_help = POLICY_CREATE_EXAMPLES)]
    Create {
        /// ID for the new policy definition, used to refer to it from surfaces
        /// and other commands.
        #[arg(long)]
        id: String,
        /// Human-readable name.
        #[arg(long)]
        name: String,
        /// What the policy is for.
        #[arg(long, default_value = "")]
        description: String,
        /// Whether the policy is for an Agent Surface or for the gateway as a
        /// whole. It cannot be changed after creation.
        #[arg(long, value_enum, default_value_t = PolicyType::AgentSurface)]
        policy_type: PolicyType,
        /// File holding the policy's Rego source.
        #[arg(long)]
        policy_file: PathBuf,
    },
    /// Replace a policy definition from a JSON document.
    ///
    /// The document replaces the stored definition. Its `id` must match
    /// POLICY_ID and its `policy_type` cannot change. Start from the output of
    /// `fabric agent-gateway policies get <policy-id> --output json`, where the
    /// Rego source is the `policy` field, as a string.
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
    /// confirmation prompt, and the gateway does not check whether surfaces or
    /// gateways still use it. To see how many do, run `fabric agent-gateway
    /// policies impact <policy-id>` first.
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
    /// Show how many surfaces and gateways use a policy definition.
    ///
    /// The report also says whether the policy is enforced appliance-wide.
    Impact {
        /// Policy definition ID.
        policy_id: String,
    },
}

/// Examples shown at the bottom of `policies create --help`.
const POLICY_CREATE_EXAMPLES: &str = r#"Examples:
  Create a policy for Agent Surfaces from a Rego file:
    fabric agent-gateway policies create --id allow-sales --name "Allow sales" \
      --policy-file allow-sales.rego

  Enforce it on a surface:
    fabric agent-gateway surfaces add-feature "Sales Agent" policy \
      --policy-id allow-sales"#;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PolicyType {
    Gateway,
    AgentSurface,
}

#[derive(Debug, Args)]
struct ApiArgs {
    /// HTTP method.
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

/// Warnings for secrets typed straight into the arguments, where shell history
/// and the process list keep them. `args` are the words of one command line.
/// Reading from the environment, standard input or a prompt is not flagged.
/// `--token-stdin` is only suggested on `login`, the one command that has it.
/// Words after `--` are not read as flags.
pub fn inline_secret_warnings(args: &[String]) -> Vec<String> {
    let on_login = args
        .iter()
        .any(|arg| arg == "login");
    let token_source = if on_login {
        "the FABRIC_TOKEN environment variable or --token-stdin"
    } else {
        "the FABRIC_TOKEN environment variable"
    };
    let secret_flags: [(&str, &str); 4] = [
        ("--token", token_source),
        ("--pat", "the prompt, FABRIC_PAT or --token-stdin"),
        ("--value", "--value-stdin"),
        ("--password", "the FABRIC_METRICS_PASSWORD environment variable"),
    ];
    let mut warnings = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            break;
        }
        for (flag, instead) in secret_flags {
            let typed_value = arg.starts_with(&format!("{flag}="))
                || (arg == flag
                    && args
                        .get(index + 1)
                        .is_some_and(|next| !next.starts_with('-') && (flag != "--pat" || !next.is_empty())));
            if typed_value {
                warnings.push(format!(
                    "warning: {flag} on the command line stays in your shell history and shows in the process list; \
                     use {instead} instead"
                ));
            }
        }
        index += 1;
    }
    warnings
}

/// A note for standard error when both the token and the host of this run came
/// from environment variables, so a token set in a shell profile and a host set
/// by a project's `.envrc` do not meet without a word. A token or host typed on
/// the command line, or a host that comes from the saved connection, is the
/// user's own choice and gets no note. `matches` is the parsed command line.
pub fn env_token_and_host_note(matches: &ArgMatches) -> Option<String> {
    let gateway = matches.subcommand_matches("agent-gateway")?;
    let login = gateway.subcommand_matches("login");
    let source = |id: &str| {
        login
            .and_then(|login| login.value_source(id))
            .or_else(|| gateway.value_source(id))
    };
    if source("token") != Some(ValueSource::EnvVariable) || source("host") != Some(ValueSource::EnvVariable) {
        return None;
    }
    let host = login
        .and_then(|login| login.get_one::<String>("host"))
        .or_else(|| gateway.get_one::<String>("host"))?;
    Some(format!(
        "note: sending the token from FABRIC_TOKEN to the host from FABRIC_HOST ({})",
        sanitize_for_terminal(host)
    ))
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
    for warning in new_hash_name_warnings(&config) {
        eprintln!("{warning}");
    }
    if !skips_the_credential_store(&cli) {
        config.migrate_legacy_tokens(&credentials)?;
    }
    dispatch_with(cli, config, &credentials)
        .await
        .map_err(add_no_keyring_hint)
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
        Command::Logout(args) => logout(&mut config, credentials, cli.connection.as_deref(), args.revoke_token).await,
        Command::Config { command } => run_config(&mut config, credentials, command, cli.output),
        Command::Whoami => {
            whoami(
                &config,
                credentials,
                cli.connection.as_deref(),
                cli.host.as_deref(),
                HostFlags {
                    allow_http: cli.allow_http,
                    allow_host_override: cli.allow_host_override,
                },
                cli.token.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Surfaces {
            command: SurfaceCommand::Features { surface_id: None },
        } => write_features(cli.output, &mut io::stdout()).context("print the features"),
        command => {
            let target = command_target(
                &config,
                credentials,
                cli.connection.as_deref(),
                cli.host.as_deref(),
                HostFlags {
                    allow_http: cli.allow_http,
                    allow_host_override: cli.allow_host_override,
                },
                cli.token.as_deref(),
            )?;
            let host = target.host;
            let token = target
                .token
                .with_context(|| {
                    let name = target
                        .connection
                        .as_deref()
                        .unwrap_or(DEFAULT_CONNECTION);
                    format!(
                        "no token stored for connection '{name}'; run `fabric agent-gateway login --connection \
                         {name} --host {host}`"
                    )
                })?;
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
            let created = create_kind(&command);
            let confirmation = delete_confirmation(&command).or_else(|| update_confirmation(&command));
            let layout = list_layout(&command);
            let scope = list_scope(&command);
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
                // These four print their own output (the audit and payments
                // tables, the metrics commands, and log files written to disk),
                // so they finish here instead of returning a value to the
                // shared printer.
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
                // API keys print themselves, since create and rotate answer with
                // a secret shown once, which goes alone to standard output while
                // the confirmation goes to standard error.
                Command::ApiKeys { command } => return run_api_keys(&client, command, cli.output).await,
                Command::TenantOwnership { command } => run_tenant_ownership(&client, command).await?,
                Command::JwtVerificationStrategies { command } => run_jwt_strategies(&client, command).await?,
                Command::Api(args) => run_api(&client, args).await?,
                Command::AccessTokens { .. }
                | Command::Login(_)
                | Command::Logout(_)
                | Command::Config { .. }
                | Command::Whoami
                | Command::Shell => unreachable!(),
            };
            match confirmation {
                Some(confirmation) => print_outcome(&value, cli.output, &confirmation),
                None => match layout {
                    Some(layout) => print_list(&value, cli.output, layout, scope),
                    None => print_created_or_value(&value, cli.output, created),
                },
            }
        }
    }
}

/// What a command may do about the host it sends a token to.
#[derive(Clone, Copy, Default)]
struct HostFlags {
    allow_http: bool,
    allow_host_override: bool,
}

/// The warnings already shown in this process, so the interactive shell, which
/// runs every line as a command, says each one once instead of before every
/// line. Keys name the kind of warning and what it is about.
static WARNED_ONCE: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Whether `key` has not been warned about yet, and marks it as warned.
fn first_warning_for(key: String) -> bool {
    let mut warned = WARNED_ONCE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if warned.contains(&key) {
        return false;
    }
    warned.push(key);
    true
}

/// The `#` name warnings of `config` not shown yet in this process.
fn new_hash_name_warnings(config: &Config) -> Vec<String> {
    config
        .hash_name_warnings()
        .into_iter()
        .filter(|warning| first_warning_for(format!("hash-name:{warning}")))
        .collect()
}

/// [`first_warning_for`] the http warning of `host`, compared as the host is
/// normalized to `scheme://host[:port]`, so a different case, a default port, a
/// trailing slash, a login name or a path is the same host.
fn first_http_warning_for(host: &str) -> bool {
    let key = normalize_host(host)
        .ok()
        .and_then(|normalized| url::Url::parse(&normalized).ok())
        .and_then(|url| {
            let name = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{name}:{port}", url.scheme()),
                None => format!("{}://{name}", url.scheme()),
            })
        })
        .unwrap_or_else(|| host.to_lowercase());
    first_warning_for(format!("http:{key}"))
}

/// Whether this run never reads or writes the credential store: a command
/// other than `login`, `logout` and `config` that was given both a host and a
/// token (see [`given_host_and_token`]). It sends the given token to the given
/// host, whether or not a saved connection is selected, so it also works on a
/// server with no desktop session to reach the OS keyring.
fn skips_the_credential_store(cli: &AgentGatewayArgs) -> bool {
    !matches!(cli.command, Command::Login(_) | Command::Logout(_) | Command::Config { .. })
        && given_host_and_token(cli.host.as_deref(), cli.token.as_deref()).is_some()
}

/// The host and token given for this run (`--host`/FABRIC_HOST and
/// `--token`/FABRIC_TOKEN), when both were.
fn given_host_and_token<'a>(
    host: Option<&'a str>,
    token: Option<&'a str>,
) -> Option<(&'a str, &'a str)> {
    host.zip(token)
}

/// Whether neither `connection` nor the configuration's current connection
/// names a saved connection to use.
fn no_saved_connection_selected(
    config: &Config,
    connection: Option<&str>,
) -> bool {
    connection.is_none() && config.current.is_none()
}

/// The gateway a command talks to and the token it sends there.
struct CommandTarget {
    /// The saved connection used, or `None` when the run uses only the host
    /// and token it was given.
    connection: Option<String>,
    host: String,
    token: Option<String>,
    /// Whether `token` was read from the credential store, rather than given
    /// with `--token`/FABRIC_TOKEN.
    token_stored: bool,
}

/// Works out where a command goes and with which token. With no saved
/// connection selected and both a host and a token given, those two are used
/// as they are and the credential store is never touched. Otherwise the
/// selected saved connection supplies whatever was not given, and a saved
/// token is only sent to the host it was saved for (see [`check_token_host`]).
fn command_target(
    config: &Config,
    credentials: &impl CredentialStore,
    connection: Option<&str>,
    host_override: Option<&str>,
    flags: HostFlags,
    token_override: Option<&str>,
) -> Result<CommandTarget> {
    if no_saved_connection_selected(config, connection)
        && let Some((host, token)) = given_host_and_token(host_override, token_override)
    {
        return Ok(CommandTarget {
            connection: None,
            host: normalize_user_host(host, flags.allow_http)?,
            token: Some(token.to_owned()),
            token_stored: false,
        });
    }
    let (name, saved) = config.resolve(connection)?;
    let host = command_host(saved, host_override, flags.allow_http)?;
    let (token, token_stored) = match token_override {
        Some(token) => (Some(token.to_owned()), false),
        None => {
            check_token_host(credentials, name, saved, &host, flags.allow_host_override)?;
            let token = credentials.get_token(name)?;
            let stored = token.is_some();
            (token, stored)
        }
    };
    Ok(CommandTarget {
        connection: Some(name.to_owned()),
        host,
        token,
        token_stored,
    })
}

/// The host a command talks to: the typed `--host` when there is one, else the
/// saved connection's host, which gets a warning on stderr (once per host in a run) when
/// it is plain http to a remote machine.
fn command_host(
    saved: &Connection,
    host_override: Option<&str>,
    allow_http: bool,
) -> Result<String> {
    match host_override {
        Some(host) => normalize_user_host(host, allow_http),
        None => {
            if let Some(warning) = saved_host_http_warning(&saved.host)
                && first_http_warning_for(&saved.host)
            {
                eprintln!("{warning}");
            }
            Ok(saved.host.clone())
        }
    }
}

/// Refuses to send a saved token to a host it was not saved for. Login records
/// the host beside the token; a connection saved before that falls back to the
/// host in the configuration, and that host is recorded on its first use so a
/// later edit of the configuration cannot move the token. `allow_host_override`
/// lets the token go anyway, with a warning.
fn check_token_host(
    credentials: &impl CredentialStore,
    name: &str,
    saved: &Connection,
    host: &str,
    allow_host_override: bool,
) -> Result<()> {
    let recorded = credentials.get_bound_host(name)?;
    let bound = recorded
        .clone()
        .unwrap_or_else(|| saved.host.clone());
    let bound = normalize_host(&bound).unwrap_or(bound);
    let requested = normalize_host(host).unwrap_or_else(|_| host.to_owned());
    if requested == bound {
        if recorded.is_none()
            && credentials
                .get_token(name)?
                .is_some()
        {
            // A store that cannot be written leaves the token following the
            // configuration, as it did before, so say so and carry on.
            if let Err(error) = credentials.set_bound_host(name, &bound)
                && first_warning_for(format!("bound-host:{name}"))
            {
                eprintln!(
                    "warning: could not save the host for connection '{}' ({}); its token keeps following the \
                     host in config.toml",
                    sanitize_whole(name),
                    sanitize_for_terminal(&error.to_string())
                );
            }
        }
        return Ok(());
    }
    if allow_host_override {
        eprintln!("warning: sending the token saved for {bound} to {requested}");
        return Ok(());
    }
    bail!(
        "the token saved for connection '{name}' belongs to {bound}, so it was not sent to {requested}; to log in \
         there run `fabric agent-gateway login --connection {name} --host {requested}`, or pass \
         --allow-host-override to send the saved token anyway"
    )
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
    if connection.contains('#') {
        bail!("--connection must not contain '#'");
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
    let previous_host = credentials.get_bound_host(connection)?;
    credentials.set_token(connection, &token)?;
    if let Err(error) = credentials.set_bound_host(connection, &host) {
        restore_credentials(credentials, connection, previous_token, previous_host)?;
        return Err(error);
    }
    let previous = config
        .connections
        .insert(connection.to_owned(), Connection::new(host.clone()));
    config.current = Some(connection.to_owned());
    if let Err(error) = config.save_to(config_path) {
        restore_credentials(credentials, connection, previous_token, previous_host)?;
        return Err(error);
    }
    Ok(previous.map(|previous| replaced_connection_note(connection, &previous.host, &host)))
}

/// Puts back the token and bound host a failed login replaced, or removes
/// them when there were none.
fn restore_credentials(
    credentials: &impl CredentialStore,
    connection: &str,
    token: Option<String>,
    host: Option<String>,
) -> Result<()> {
    match token {
        Some(token) => credentials.set_token(connection, &token)?,
        None => credentials.delete_token(connection)?,
    }
    match host {
        Some(host) => credentials.set_bound_host(connection, &host),
        None => credentials.delete_bound_host(connection),
    }
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
    flags: HostFlags,
    token_override: Option<&str>,
    output: Output,
) -> Result<()> {
    let info = whoami_info(config, credentials, connection, host_override, flags, token_override).await?;
    match output {
        Output::Json => println!("{}", pretty_json_for_terminal(&info)?),
        Output::Table => print_info_table(&info),
    }
    Ok(())
}

/// The connection and host a command would use, whether its token came from
/// the credential store, and the identity behind that token as the gateway
/// reports it live, as a JSON object.
async fn whoami_info(
    config: &Config,
    credentials: &impl CredentialStore,
    connection: Option<&str>,
    host_override: Option<&str>,
    flags: HostFlags,
    token_override: Option<&str>,
) -> Result<Value> {
    let CommandTarget {
        connection: name,
        host,
        token,
        token_stored,
    } = command_target(config, credentials, connection, host_override, flags, token_override)?;

    let mut info = json!({
        "connection": name,
        "host": host,
        "token_stored": token_stored,
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
                    insert_token_details(fields, &client).await;
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
                        insert_token_details(fields, &client).await;
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

/// The id of the token the gateway says is held, from its `/v1/token-info`
/// answer. An id that is not text or is blank counts as none.
fn held_token_id(token_info: &Value) -> Option<&str> {
    token_info
        .get("token_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
}

/// Add the held token's `scopes`, `token_id` and `token_name` to `fields`.
/// A session/passkey login has none of them, so nothing is inserted. The name
/// comes from the token's own record and is left out, without a warning, when
/// the token lacks `access_tokens.view` or the record is gone. Any other
/// failure warns on stderr without the body and `fields` keeps the rest.
async fn insert_token_details(
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
            if let Some(token_id) = held_token_id(&token_info) {
                fields.insert("token_id".to_owned(), json!(token_id));
                match client
                    .request(Method::GET, &entity_path("/v1/access-tokens", token_id), None)
                    .await
                {
                    Ok(record) => {
                        if let Some(name) = record
                            .get("name")
                            .and_then(Value::as_str)
                        {
                            fields.insert("token_name".to_owned(), json!(name));
                        }
                    }
                    Err(error) => match response_status(&error) {
                        Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) => {}
                        Some(status) => eprintln!("warning: could not load token name: gateway answered {status}"),
                        None => eprintln!("warning: could not load token name: the request failed"),
                    },
                }
            }
        }
        Err(error) => {
            eprintln!("warning: could not load token scopes: {error:#}");
        }
    }
}

fn print_info_table(value: &Value) {
    for line in info_table_lines(value) {
        println!("{line}");
    }
}

/// The `whoami` table as lines. Every value came from the gateway or from what
/// the user typed, so each is stripped of control characters first.
fn info_table_lines(value: &Value) -> Vec<String> {
    const ORDER: &[&str] = &[
        "connection",
        "host",
        "token_stored",
        "authenticated",
        "username",
        "role",
        "email",
        "user_id",
        "token_id",
        "token_name",
        "first_name",
        "last_name",
        "scopes",
        "error",
    ];
    let Some(object) = value.as_object() else {
        return vec![value.to_string()];
    };
    let mut lines = Vec::new();
    for key in ORDER {
        if let Some(field) = object
            .get(*key)
            .filter(|field| *key != "connection" || !field.is_null())
        {
            let rendered = match field {
                Value::String(text) => tables::flatten_capped(text),
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(tables::flatten_capped)
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            lines.push(format!("{key}: {}", sanitize_for_terminal(&rendered)));
        }
    }
    lines
}

/// Signs out of a connection: ends the session on the gateway when the saved
/// token is a session token, tells the user how to revoke it when it is a
/// personal access token, then removes the local copy. The gateway part is best
/// effort, so an unreachable gateway never stops the local removal.
async fn logout(
    config: &mut Config,
    credentials: &impl CredentialStore,
    requested: Option<&str>,
    revoke_token: bool,
) -> Result<()> {
    let name = requested
        .or(config.current.as_deref())
        .context("no gateway connection selected")?
        .to_owned();
    let remote_note = match config.connections.get(&name) {
        Some(connection) => {
            let pat_choice = if revoke_token {
                PatChoice::Revoke
            } else if io::stdin().is_terminal() {
                PatChoice::Ask
            } else {
                PatChoice::Keep
            };
            end_remote_credential(credentials, &name, connection, pat_choice).await
        }
        None => None,
    };
    remove_connection(config, credentials, &name, &crate::config::config_path()?)?;
    if let Some(note) = remote_note {
        eprintln!("{note}");
    }
    Ok(())
}

/// What logout does about a saved personal access token, which a session
/// logout cannot cancel by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PatChoice {
    /// Revoke it on the gateway without asking (`--revoke-token`).
    Revoke,
    /// Ask in the terminal whether to revoke it.
    Ask,
    /// Leave it valid and say how to revoke it later.
    Keep,
}

/// Does what can be done on the gateway about the token saved for `name`, and
/// returns the line to show about it. The token is only ever sent to the host
/// it was saved for. A personal access token is revoked while it is still in
/// hand when `pat_choice` says so; a browser session is always ended.
async fn end_remote_credential(
    credentials: &impl CredentialStore,
    name: &str,
    connection: &Connection,
    pat_choice: PatChoice,
) -> Option<String> {
    let token = credentials
        .get_token(name)
        .ok()
        .flatten()?;
    let host = credentials
        .get_bound_host(name)
        .ok()
        .flatten()
        .unwrap_or_else(|| connection.host.clone());
    if let Some(warning) = saved_host_http_warning(&host) {
        eprintln!("{warning}");
    }
    let client = GatewayClient::new(&host, &token).ok()?;
    if token.starts_with(PAT_TOKEN_PREFIX) {
        let id = client
            .request(Method::GET, "/v1/token-info", None)
            .await
            .ok()
            .and_then(|info| held_token_id(&info).map(str::to_owned));
        let shown_id = id
            .as_deref()
            .map(sanitize_whole);
        let revoke = match (pat_choice, &id) {
            (PatChoice::Revoke, Some(_)) => true,
            (PatChoice::Ask, Some(_)) => ask_to_revoke_pat(
                &host,
                shown_id
                    .as_deref()
                    .unwrap_or_default(),
            ),
            _ => false,
        };
        let Some(id) = id.filter(|_| revoke) else {
            return Some(pat_still_valid_note(&host, shown_id.as_deref()));
        };
        return Some(
            match client
                .request(Method::DELETE, &entity_path("/v1/access-tokens", &id), None)
                .await
            {
                Ok(_) => format!("note: revoked this personal access token on {host}"),
                Err(error) => format!(
                    "warning: could not revoke this personal access token on {host} ({}). {}",
                    sanitize_for_terminal(&error.to_string()),
                    pat_still_valid_note(&host, shown_id.as_deref())
                ),
            },
        );
    }
    Some(match client.end_session().await {
        Ok(()) => format!("note: ended the session on {host}"),
        Err(error) if response_status(&error).is_none() => {
            format!("warning: could not reach {host} to end the session, so it stays valid there until it expires")
        }
        Err(error) => format!(
            "warning: {host} would not end the session ({}), so it stays valid there until it expires",
            sanitize_for_terminal(&error.to_string())
        ),
    })
}

/// Asks on the terminal whether logout should also revoke the personal access
/// token `id` (already sanitized) on `host`. An unreadable answer counts as no.
fn ask_to_revoke_pat(
    host: &str,
    id: &str,
) -> bool {
    eprint!("{} [y/N] ", revoke_pat_prompt(host, id));
    let _ = io::Write::flush(&mut io::stderr());
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .is_ok()
        && answer_is_yes(&answer)
}

fn revoke_pat_prompt(
    host: &str,
    id: &str,
) -> String {
    format!("Also revoke personal access token {id} on {host}?")
}

/// What to tell a user who logged out of a personal access token, which logging
/// out cannot cancel: it is still valid on the gateway until revoked.
fn pat_still_valid_note(
    host: &str,
    id: Option<&str>,
) -> String {
    match id {
        Some(id) => format!(
            "note: this personal access token is still valid on {host}; logging out only removed the local copy. To \
             revoke it, log in again and run: fabric agent-gateway tokens revoke {id}"
        ),
        None => format!(
            "note: this personal access token is still valid on {host}; logging out only removed the local copy. To \
             revoke it, log in again, find its ID with `fabric agent-gateway tokens list`, and run: fabric \
             agent-gateway tokens revoke <token-id>"
        ),
    }
}

/// Removes a connection and its token from this machine only.
fn remove_connection(
    config: &mut Config,
    credentials: &impl CredentialStore,
    name: &str,
    config_path: &Path,
) -> Result<()> {
    credentials.delete_token(name)?;
    credentials.delete_bound_host(name)?;
    if config
        .connections
        .remove(name)
        .is_none()
    {
        bail!("gateway connection '{name}' does not exist");
    }
    if config.current.as_deref() == Some(name) {
        config.current = config
            .connections
            .keys()
            .next()
            .cloned();
    }
    config.save_to(config_path)?;
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
            print_list(&Value::Array(rows), output, &tables::CONNECTION_SETTINGS, Scope::All)
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
        ConfigCommand::Remove { name } => remove_connection(config, credentials, &name, &crate::config::config_path()?),
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

    const CREATED_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"route":"/sales","protocol":"mcp"},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;

    fn surface_lines(surface: &Value) -> Vec<String> {
        created_surface_lines(surface).expect("lines")
    }

    #[test]
    fn a_created_surface_is_confirmed_by_its_id_and_shows_its_name_route_protocol_and_target() {
        let surface: Value = serde_json::from_str(CREATED_SURFACE).expect("surface");

        assert_eq!(
            surface_lines(&surface),
            [
                "Created surface 's-1'",
                "  id: s-1",
                "  name: Sales",
                "  route: /sales",
                "  protocol: mcp",
                "  target: http://127.0.0.1:3000"
            ]
        );
        assert_eq!(surface_lines(&json!({"surface_id": "s-1"})), ["Created surface 's-1'", "  id: s-1"]);
    }

    #[test]
    fn a_created_surface_target_row_shows_only_scheme_host_and_port() {
        let target =
            |endpoint: &str| surface_lines(&json!({"surface_id": "s-1", "target": {"endpoint": endpoint}}))[2].clone();

        assert_eq!(target("https://user:pass@host:8443/mcp?key=abc#frag"), "  target: https://host:8443");
        assert_eq!(target("https://token@host/mcp#frag"), "  target: https://host");
        assert_eq!(target("https://mcp.example.com/api/mcp/s/sekret/mcp"), "  target: https://mcp.example.com");
        assert_eq!(target("http://127.0.0.1:3000"), "  target: http://127.0.0.1:3000");
        assert_eq!(target("http://host/"), "  target: http://host");
    }

    #[test]
    fn a_created_surface_target_row_for_text_that_is_not_a_url_never_shows_a_password() {
        let rows = |endpoint: &str| surface_lines(&json!({"surface_id": "s-1", "target": {"endpoint": endpoint}}));

        assert_eq!(rows("http://u:a/b@host/x")[2], "  target: host/x");
        assert_eq!(rows("user:pass@host:8443/mcp?key=abc")[2], "  target: host:8443/mcp");
        assert_eq!(rows("host:8443/mcp")[2], "  target: host:8443/mcp");
        assert_eq!(rows("not a url?key=abc")[2], "  target: not a url");
        assert_eq!(rows("a@b@c")[2], "  target: c");
        for endpoint in ["http://u:p#ss@host", "http://u:p?x=@y", "@", "user:pass@", "?key=abc", "#frag"] {
            assert_eq!(rows(endpoint), ["Created surface 's-1'", "  id: s-1"], "{endpoint}");
        }
    }

    #[test]
    fn a_created_surface_with_a_control_only_route_protocol_or_target_has_no_row_for_it() {
        let surface = json!({
            "surface_id": "s-1",
            "access_point": {"route": "\u{1b}\u{7}", "protocol": " \t"},
            "target": {"endpoint": "\n\u{1b}"}
        });

        assert_eq!(surface_lines(&surface), ["Created surface 's-1'", "  id: s-1"]);
    }

    #[test]
    fn a_created_surface_with_an_empty_blank_or_control_only_name_has_no_name_row() {
        for name in ["", "   ", "\t\n", "\u{1b}\u{7}"] {
            assert_eq!(
                surface_lines(&json!({"surface_id": "s-1", "name": name})),
                ["Created surface 's-1'", "  id: s-1"],
                "name {name:?}"
            );
        }
    }

    #[test]
    fn a_created_surface_with_no_usable_id_has_no_lines_so_the_whole_answer_is_printed() {
        assert_eq!(created_surface_lines(&json!({})), None);
        assert_eq!(created_surface_lines(&json!({"name": "Sales"})), None);
        for id in ["", "   ", "\t\n", "\u{1b}\u{7}"] {
            assert_eq!(created_surface_lines(&json!({"surface_id": id, "name": "Sales"})), None, "id {id:?}");
        }
    }

    #[test]
    fn a_created_surface_is_cleaned_of_control_characters() {
        let surface = json!({"surface_id": "s\u{1b}[2J-1", "name": "Sa\nles", "access_point": {"route": "/a\tb"}});

        let lines = surface_lines(&surface);

        assert!(
            lines
                .iter()
                .all(|line| !line.contains(['\u{1b}', '\n', '\t'])),
            "{lines:?}"
        );
        assert_eq!(lines[0], "Created surface 's[2J-1'");
        assert_eq!(lines[1], "  id: s[2J-1");
    }

    #[test]
    fn a_created_surface_caps_a_very_long_name_in_its_name_row() {
        let long = "n".repeat(600);

        let lines = surface_lines(&json!({"surface_id": "s-1", "name": long}));

        assert_eq!(lines[2], format!("  name: {}", tables::flatten_capped(&long)));
        assert!(lines[2].len() < 600, "{}", lines[2].len());
    }

    #[test]
    fn surfaces_create_does_not_use_the_shared_created_path() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "surfaces", "create", "--name", "Sales"])
            .expect("create should parse");
        assert!(create_kind(&cli.agent_gateway().command).is_none());
    }

    #[tokio::test]
    async fn surface_create_prints_a_table_itself_and_hands_json_back_unchanged() {
        let command = || surface_command(&["fabric", "agent-gateway", "surfaces", "create", "--name", "Sales"]);
        let (host, _) = scripted_server(vec![("HTTP/1.1 201 Created", CREATED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let table = run_surfaces(&client, command(), Output::Table)
            .await
            .expect("create");
        let (host, _) = scripted_server(vec![("HTTP/1.1 201 Created", CREATED_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let json = run_surfaces(&client, command(), Output::Json)
            .await
            .expect("create");

        assert_eq!(table, None, "the table is printed by the create itself");
        assert_eq!(json, serde_json::from_str::<Value>(CREATED_SURFACE).ok());
    }

    const TOKEN_INFO: &str = r#"{"user_id":"u-1","token_id":"tok-1","scopes":["tokens.read"]}"#;

    async fn token_fields(
        responses: Vec<(&'static str, &'static str)>
    ) -> (serde_json::Map<String, Value>, Vec<String>) {
        let (host, requests) = scripted_server(responses).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let mut fields = serde_json::Map::new();
        insert_token_details(&mut fields, &client).await;
        (fields, request_lines(requests))
    }

    #[tokio::test]
    async fn insert_token_details_copies_pat_token_id_and_name() {
        let (fields, requests) = token_fields(vec![
            ("HTTP/1.1 200 OK", TOKEN_INFO),
            ("HTTP/1.1 200 OK", r#"{"id":"tok-1","name":"ci","secret_hint":"abc"}"#),
        ])
        .await;

        assert_eq!(fields.get("token_id"), Some(&json!("tok-1")));
        assert_eq!(fields.get("token_name"), Some(&json!("ci")));
        assert_eq!(fields.get("scopes"), Some(&json!(["tokens.read"])));
        assert_eq!(fields.len(), 3, "only the name is taken from the token record");
        assert_eq!(requests, ["GET /api/v1/token-info HTTP/1.1", "GET /api/v1/access-tokens/tok-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn insert_token_details_keeps_the_token_id_when_the_name_lookup_is_refused() {
        let (fields, _) = token_fields(vec![
            ("HTTP/1.1 200 OK", TOKEN_INFO),
            ("HTTP/1.1 403 Forbidden", r#"{"error":"Forbidden","details":"needs access_tokens.view"}"#),
        ])
        .await;

        assert_eq!(fields.get("token_id"), Some(&json!("tok-1")));
        assert!(!fields.contains_key("token_name"));
    }

    #[tokio::test]
    async fn insert_token_details_skips_the_token_for_a_login_without_a_token_id() {
        let (fields, requests) =
            token_fields(vec![("HTTP/1.1 200 OK", r#"{"user_id":"u-1","token_id":null,"scopes":null}"#)]).await;

        assert!(fields.is_empty());
        assert_eq!(requests, ["GET /api/v1/token-info HTTP/1.1"]);
    }

    #[tokio::test]
    async fn insert_token_details_keeps_the_token_id_and_name_as_the_gateway_sent_them() {
        let (fields, _) = token_fields(vec![
            ("HTTP/1.1 200 OK", r#"{"token_id":"t\u001b[2Jk\nx","scopes":null}"#),
            ("HTTP/1.1 200 OK", r#"{"name":"ci\u001b[2J\nnext"}"#),
        ])
        .await;

        assert_eq!(fields.get("token_id"), Some(&json!("t\u{1b}[2Jk\nx")));
        assert_eq!(fields.get("token_name"), Some(&json!("ci\u{1b}[2J\nnext")));
    }

    #[test]
    fn held_token_id_gives_text_ids_only_and_none_for_blank_or_other_values() {
        assert_eq!(held_token_id(&json!({"token_id": "t-1"})), Some("t-1"));
        assert_eq!(held_token_id(&json!({"token_id": ""})), None);
        assert_eq!(held_token_id(&json!({"token_id": " \t"})), None);
        assert_eq!(held_token_id(&json!({"token_id": 7})), None);
        assert_eq!(held_token_id(&json!({"token_id": null})), None);
        assert_eq!(held_token_id(&json!({})), None);
    }

    #[test]
    fn the_whoami_json_escapes_terminal_unsafe_text_and_parses_back_to_the_same_values() {
        let info = json!({
            "username": "a\u{202e}b",
            "token_id": "t\u{9b}1\u{2028}x\u{2029}\u{61c}\u{200f}\u{2066}",
            "token_name": "ci \u{1b}[2J",
            "scopes": ["s"],
        });

        let printed = pretty_json_for_terminal(&info).expect("json");

        for unsafe_char in ['\u{202e}', '\u{9b}', '\u{2028}', '\u{2029}', '\u{61c}', '\u{200f}', '\u{2066}', '\u{1b}'] {
            assert!(!printed.contains(unsafe_char), "{unsafe_char:?} in {printed}");
        }
        assert!(printed.contains(r"a\u202eb"), "{printed}");
        assert_eq!(serde_json::from_str::<Value>(&printed).expect("parses"), info);
    }

    #[test]
    fn the_whoami_json_leaves_a_normal_answer_as_serde_prints_it() {
        let info = json!({"username": "admin", "token_name": "ci \u{e9}\u{4e2d}", "scopes": ["a", "b"]});

        assert_eq!(pretty_json_for_terminal(&info).expect("json"), serde_json::to_string_pretty(&info).expect("json"));
    }

    #[test]
    fn a_surface_printed_as_json_escapes_terminal_unsafe_text_and_parses_back_to_the_same_value() {
        let surface = json!({
            "surface_id": "s-1",
            "name": "a\u{202e}b\u{9b}c\u{7f}d\u{2028}e\u{2029}f",
            "tags": ["\u{1b}[2J", "x\ny"],
        });

        let printed = pretty_json_for_terminal(&surface).expect("json");

        for unsafe_char in ['\u{202e}', '\u{9b}', '\u{7f}', '\u{2028}', '\u{2029}', '\u{1b}'] {
            assert!(!printed.contains(unsafe_char), "{unsafe_char:?} in {printed}");
        }
        assert!(printed.contains(r"a\u202eb\u009bc"), "{printed}");
        assert!(printed.contains(r"c\u007fd"), "{printed}");
        assert_eq!(serde_json::from_str::<Value>(&printed).expect("parses"), surface);
    }

    #[test]
    fn the_whoami_table_cleans_every_text_value_and_scope() {
        let info = json!({
            "username": "ad\u{1b}[2Ja",
            "token_id": "t\u{1b}[2Jk\nx",
            "token_name": format!("ci\n{}", "n".repeat(600)),
            "scopes": ["a\tb", "c"],
        });

        let lines = info_table_lines(&info);

        assert_eq!(lines[0], "username: ad[2Ja");
        assert_eq!(lines[1], "token_id: t[2Jk x");
        assert_eq!(lines[2], format!("token_name: {}", tables::flatten_capped(&format!("ci\n{}", "n".repeat(600)))));
        assert!(lines[2].len() < 600, "{}", lines[2].len());
        assert_eq!(lines[3], "scopes: a b, c");
    }

    #[test]
    fn the_whoami_table_lists_the_token_rows_after_the_user_id() {
        let info = json!({
            "user_id": "u-1",
            "token_id": "tok-1",
            "token_name": "ci",
            "first_name": "Ada",
        });

        assert_eq!(info_table_lines(&info), ["user_id: u-1", "token_id: tok-1", "token_name: ci", "first_name: Ada"]);
    }

    #[tokio::test]
    async fn insert_token_details_leaves_out_a_token_id_that_is_not_text() {
        let (fields, requests) = token_fields(vec![("HTTP/1.1 200 OK", r#"{"token_id":7,"scopes":["a"]}"#)]).await;

        assert!(!fields.contains_key("token_id"));
        assert!(!fields.contains_key("token_name"));
        assert_eq!(requests, ["GET /api/v1/token-info HTTP/1.1"]);
    }

    #[tokio::test]
    async fn insert_token_details_leaves_out_a_blank_token_id() {
        for body in [r#"{"token_id":"","scopes":null}"#, r#"{"token_id":"   ","scopes":null}"#] {
            let (fields, requests) = token_fields(vec![("HTTP/1.1 200 OK", body)]).await;

            assert!(!fields.contains_key("token_id"), "{body}");
            assert!(!fields.contains_key("token_name"), "{body}");
            assert_eq!(requests, ["GET /api/v1/token-info HTTP/1.1"], "{body}");
        }
    }

    #[tokio::test]
    async fn insert_token_details_leaves_out_a_token_name_that_is_not_text() {
        let (fields, _) =
            token_fields(vec![("HTTP/1.1 200 OK", TOKEN_INFO), ("HTTP/1.1 200 OK", r#"{"name":5}"#)]).await;

        assert_eq!(fields.get("token_id"), Some(&json!("tok-1")));
        assert!(!fields.contains_key("token_name"));
    }

    #[tokio::test]
    async fn insert_token_details_keeps_the_rest_when_the_name_lookup_fails_with_a_server_error() {
        let (fields, _) = token_fields(vec![
            ("HTTP/1.1 200 OK", TOKEN_INFO),
            ("HTTP/1.1 500 Internal Server Error", r#"{"error":"secret-body-text"}"#),
        ])
        .await;

        assert_eq!(fields.get("token_id"), Some(&json!("tok-1")));
        assert_eq!(fields.get("scopes"), Some(&json!(["tokens.read"])));
        assert!(!fields.contains_key("token_name"));
        assert!(!format!("{fields:?}").contains("secret-body-text"), "the response body must not reach the output");
    }

    #[tokio::test]
    async fn insert_token_details_path_encodes_a_plain_token_id_in_the_name_lookup() {
        let (_, requests) = token_fields(vec![
            ("HTTP/1.1 200 OK", r#"{"token_id":"tok:1","scopes":null}"#),
            ("HTTP/1.1 404 Not Found", "{}"),
        ])
        .await;

        assert_eq!(requests[1], "GET /api/v1/access-tokens/tok%3A1 HTTP/1.1");
    }

    #[tokio::test]
    async fn insert_token_details_does_not_look_up_a_token_id_the_client_refuses() {
        let (fields, requests) = token_fields(vec![
            ("HTTP/1.1 200 OK", r#"{"token_id":"a/b","scopes":null}"#),
            ("HTTP/1.1 200 OK", r#"{"name":"must-not-be-read"}"#),
        ])
        .await;

        assert_eq!(requests, ["GET /api/v1/token-info HTTP/1.1"]);
        assert_eq!(fields.get("token_id"), Some(&json!("a/b")));
        assert!(!fields.contains_key("token_name"));
        assert!(!format!("{fields:?}").contains("must-not-be-read"));
    }

    fn api_patch(
        data: Option<&str>,
        file: Option<PathBuf>,
    ) -> ApiArgs {
        ApiArgs {
            method: ApiMethod::Patch,
            path: "/v1/surfaces/s-1".to_owned(),
            data: data.map(str::to_owned),
            file,
        }
    }

    #[tokio::test]
    async fn api_patch_sends_the_merge_patch_content_type_and_the_data() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", r#"{"id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let answer = run_api(&client, api_patch(Some(r#"{"description":null}"#), None))
            .await
            .expect("patch");

        let sent = full_requests(requests)
            .remove(0)
            .to_lowercase();
        assert_eq!(answer, json!({"id": "s-1"}));
        assert!(sent.starts_with("patch /api/v1/surfaces/s-1 http/1.1"), "{sent}");
        assert!(sent.contains("content-type: application/merge-patch+json"), "{sent}");
        assert!(sent.ends_with(r#"{"description":null}"#), "{sent}");
    }

    #[tokio::test]
    async fn api_patch_reads_its_body_from_a_file() {
        let (host, requests) = scripted_server(vec![("HTTP/1.1 200 OK", "{}")]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");
        let file = json_file(r#"{"tags":["a"]}"#);

        run_api(&client, api_patch(None, Some(file.path().to_path_buf())))
            .await
            .expect("patch");

        let sent = full_requests(requests)
            .remove(0)
            .to_lowercase();
        assert!(sent.contains("content-type: application/merge-patch+json"), "{sent}");
        assert!(sent.ends_with(r#"{"tags":["a"]}"#), "{sent}");
    }

    #[tokio::test]
    async fn api_patch_without_a_body_is_refused_before_anything_is_sent() {
        let (host, requests) = scripted_server(vec![]).await;
        let client = GatewayClient::new(host, "agpat_test").expect("client");

        let error = run_api(&client, api_patch(None, None))
            .await
            .expect_err("a patch needs a body");

        assert_eq!(error.to_string(), "api patch needs a body: give --data or --file");
        assert!(request_lines(requests).is_empty());
    }

    #[tokio::test]
    async fn api_patch_refuses_a_hostile_path_before_anything_is_sent() {
        for path in ["/v1/%2e%2e/x", "/v1/../x", "v1/surfaces/s-1"] {
            let (host, requests) = scripted_server(vec![]).await;
            let client = GatewayClient::new(host, "agpat_test").expect("client");
            let mut args = api_patch(Some(r#"{"description":null}"#), None);
            args.path = path.to_owned();

            run_api(&client, args)
                .await
                .expect_err(path);

            assert!(request_lines(requests).is_empty(), "{path}");
        }
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

    const PATTERN_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000","mcp_tool_gating":{"default_effect":"allow","gates":[{"id":"g-1","name":"files","action":{"effect":"deny","patterns":["fs_.*"]}},{"id":"g-2","action":{"effect":"deny","patterns":["rm_.*"]}}]}},"transit":{"points":[{"id":"tp-1","alias":"gh","mcp_tool_gating":{"gates":[{"id":"tg-1","action":{"effect":"deny","patterns":["push_.*"]}}]}}]}}"#;

    const ADD_OWN_PATTERN: &str = "target.mcp_tool_gating.gates[g-1].action.patterns=shell_.*";

    /// What the patch for `ADD_OWN_PATTERN` holds: the surface's gates, with
    /// only the first gate's patterns changed.
    fn own_pattern_patch() -> Value {
        json!({"target": {"mcp_tool_gating": {"gates": [
            {"id": "g-1", "name": "files", "action": {"effect": "deny", "patterns": ["fs_.*", "shell_.*"]}},
            {"id": "g-2", "action": {"effect": "deny", "patterns": ["rm_.*"]}}
        ]}}})
    }

    fn body_of(request: &str) -> Value {
        let body = request
            .split_once("\r\n\r\n")
            .expect("request body")
            .1;
        serde_json::from_str(body).expect("patch body is JSON")
    }

    #[tokio::test]
    async fn a_pattern_swap_on_a_transit_point_gate_sends_the_transit_point_list() {
        let requests = feature_dry_run(
            &[
                "update",
                "s-1",
                "--add",
                "transit.points[gh].mcp_tool_gating.gates[tg-1].action.patterns=pull_.*",
                "--remove",
                "transit.points[gh].mcp_tool_gating.gates[tg-1].action.patterns=push_.*",
            ],
            PATTERN_SURFACE,
        )
        .await
        .expect("the pattern should be swapped");

        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [{"id": "tp-1", "alias": "gh", "mcp_tool_gating": {"gates": [
                {"id": "tg-1", "action": {"effect": "deny", "patterns": ["pull_.*"]}}
            ]}}]}})
        );
    }

    #[tokio::test]
    async fn a_refused_tool_pattern_edit_sends_nothing_after_the_read() {
        let (host, requests) = scripted_server(vec![(DRY_RUN_GATEWAY_OK, PATTERN_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let edit = "target.mcp_tool_gating.gates[g-9].action.patterns=a";
        let command = surface_command(&["fabric", "agent-gateway", "surfaces", "update", "s-1", "--add", edit]);

        let error = run_surfaces(&client, command, Output::Json)
            .await
            .expect_err("the edit should be refused");

        assert!(format!("{error:#}").contains("the gates are g-1, g-2"), "{error:#}");
        assert_eq!(request_lines(requests), [S1_REQUEST]);
    }

    #[tokio::test]
    async fn a_tool_pattern_dry_run_sends_only_that_gates_list_as_a_dry_run() {
        let requests = feature_dry_run(&["update", "s-1", "--add", ADD_OWN_PATTERN], PATTERN_SURFACE)
            .await
            .expect("the dry run should succeed");

        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(patch_body(&requests), own_pattern_patch());
    }

    #[tokio::test]
    async fn a_tool_pattern_is_saved_to_a_surface_picked_by_name() {
        let (host, requests) = scripted_server(vec![
            LIST_OK,
            (DRY_RUN_GATEWAY_OK, PATTERN_SURFACE),
            ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1"}"#),
        ])
        .await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = resolve_surface_command(
            &client,
            surface_command(&["fabric", "agent-gateway", "surfaces", "update", "Sales", "--add", ADD_OWN_PATTERN]),
        )
        .await
        .expect("the surface should resolve");

        run_surfaces(&client, command, Output::Json)
            .await
            .expect("the pattern should be saved");

        let requests = full_requests(requests);
        assert_eq!(start_lines(&requests), [LIST_REQUEST, S1_REQUEST, "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]);
        assert_eq!(body_of(&requests[2]), own_pattern_patch());
    }

    const ADD_BILLING: [&str; 6] =
        ["add-transit-point", "s-1", "--alias", "billing", "--endpoint", "http://billing:3000"];

    #[tokio::test]
    async fn add_transit_point_sends_the_whole_list_with_the_new_point_appended() {
        let requests = feature_dry_run(&ADD_BILLING, TRANSIT_SURFACE)
            .await
            .expect("a new alias should be added");
        assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [
                {"alias": "gh"},
                {"alias": "billing", "target_endpoint": "http://billing:3000"}
            ]}})
        );
    }

    #[tokio::test]
    async fn add_transit_point_to_a_surface_without_a_transit_block_sends_a_one_point_list() {
        let requests = feature_dry_run(&ADD_BILLING, STORED_SURFACE)
            .await
            .expect("the first point should be added");
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [{"alias": "billing", "target_endpoint": "http://billing:3000"}]}})
        );
    }

    const MCP_TRANSIT_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","protocol":"mcp"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"alias":"gh","protocol":"http"}]}}"#;

    #[tokio::test]
    async fn add_transit_point_gives_the_new_point_the_protocol_of_the_surface() {
        let requests = feature_dry_run(&ADD_BILLING, MCP_TRANSIT_SURFACE)
            .await
            .expect("a new alias should be added");
        let body = patch_body(&requests);
        assert_eq!(body["transit"]["points"][1]["alias"], "billing");
        assert_eq!(body["transit"]["points"][1]["protocol"], "mcp");
    }

    #[tokio::test]
    async fn add_transit_point_keeps_the_protocol_a_point_already_on_the_surface_names() {
        let requests = feature_dry_run(&ADD_BILLING, MCP_TRANSIT_SURFACE)
            .await
            .expect("a new alias should be added");
        assert_eq!(patch_body(&requests)["transit"]["points"][0], json!({"alias": "gh", "protocol": "http"}));
    }

    /// Runs a surface command that saves, against a gateway that answers the
    /// read of the surface and then the patch, and returns the requests made.
    async fn saving_command(
        args: &[&str],
        stored: &'static str,
    ) -> Result<Vec<String>> {
        let (host, requests) =
            scripted_server(vec![(DRY_RUN_GATEWAY_OK, stored), ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1"}"#)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let mut argv = vec!["fabric", "agent-gateway", "surfaces"];
        argv.extend_from_slice(args);
        run_surfaces(&client, surface_command(&argv), Output::Json).await?;
        Ok(full_requests(requests))
    }

    #[tokio::test]
    async fn add_transit_point_without_dry_run_saves_the_patch() {
        let requests = saving_command(&ADD_BILLING, TRANSIT_SURFACE)
            .await
            .expect("a new alias should be saved");
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [
                {"alias": "gh"},
                {"alias": "billing", "target_endpoint": "http://billing:3000"}
            ]}})
        );
    }

    #[tokio::test]
    async fn add_transit_point_refuses_an_alias_the_surface_already_has_before_sending() {
        let (host, requests) = scripted_server(vec![(DRY_RUN_GATEWAY_OK, TRANSIT_SURFACE)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let command = surface_command(&[
            "fabric",
            "agent-gateway",
            "surfaces",
            "add-transit-point",
            "s-1",
            "--alias",
            "gh",
            "--endpoint",
            "http://gh:3000",
        ]);
        let error = run_surfaces(&client, command, Output::Json)
            .await
            .expect_err("a duplicate alias should be refused");
        assert_eq!(
            error.to_string(),
            "this surface already has a transit point with alias 'gh': run remove-transit-point on it first"
        );
        assert_eq!(request_lines(requests), ["GET /api/v1/surfaces/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn add_transit_point_refuses_a_blank_or_badly_formed_alias_or_endpoint_before_any_request() {
        let too_long = "a".repeat(MAX_TRANSIT_ALIAS_LEN + 1);
        let too_long_flags = ["--alias", too_long.as_str(), "--endpoint", "http://a:1"];
        let too_long_message = format!("the alias '{too_long}' is too long: use at most 63 characters");
        let cases: [(&[&str], &str); 10] = [
            (&["--alias", " ", "--endpoint", "http://a:1"], "give a transit point alias with --alias"),
            (&["--alias", "a", "--endpoint", "  "], "give the transit point's endpoint with --endpoint"),
            (&["--alias", "Billing", "--endpoint", "http://a:1"], "the alias 'Billing' is not allowed"),
            (&["--alias", "1abc", "--endpoint", "http://a:1"], "the alias '1abc' is not allowed"),
            (&["--alias", "a_b", "--endpoint", "http://a:1"], "the alias 'a_b' is not allowed"),
            (&["--alias=-a", "--endpoint", "http://a:1"], "the alias '-a' is not allowed"),
            (&["--alias", "caf\u{e9}", "--endpoint", "http://a:1"], "the alias 'caf\u{e9}' is not allowed"),
            (&["--alias", "a.b", "--endpoint", "http://a:1"], "the alias 'a.b' is not allowed"),
            (&["--alias", "a[0]", "--endpoint", "http://a:1"], "the alias 'a[0]' is not allowed"),
            (&too_long_flags, too_long_message.as_str()),
        ];
        for (flags, expected) in cases {
            let (host, requests) = scripted_server(vec![]).await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let mut argv = vec!["fabric", "agent-gateway", "surfaces", "add-transit-point", "Sales"];
            argv.extend_from_slice(flags);
            let error = resolve_surface_command(&client, surface_command(&argv))
                .await
                .expect_err("the arguments should be refused before the surface is looked up")
                .to_string();
            assert!(error.contains(expected), "{error}");
            argv[4] = "s-1";
            let error = run_surfaces(&client, surface_command(&argv), Output::Json)
                .await
                .expect_err("the arguments should be refused before the surface is read")
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(full_requests(requests).is_empty(), "{flags:?} sent a request");
        }
    }

    #[tokio::test]
    async fn add_transit_point_accepts_digits_and_dashes_after_the_first_letter() {
        let requests = feature_dry_run(
            &["add-transit-point", "s-1", "--alias", "bill-2", "--endpoint", " http://b:1 "],
            TRANSIT_SURFACE,
        )
        .await
        .expect("the alias is well formed");
        assert_eq!(
            patch_body(&requests)["transit"]["points"][1],
            json!({"alias": "bill-2", "target_endpoint": "http://b:1"})
        );
    }

    #[tokio::test]
    async fn add_transit_point_accepts_an_alias_of_63_characters() {
        let alias = "a".repeat(MAX_TRANSIT_ALIAS_LEN);
        let requests = feature_dry_run(
            &["add-transit-point", "s-1", "--alias", alias.as_str(), "--endpoint", "http://b:1"],
            TRANSIT_SURFACE,
        )
        .await
        .expect("an alias at the limit is accepted");
        assert_eq!(patch_body(&requests)["transit"]["points"][1]["alias"], json!(alias));
    }

    const TWO_POINT_SURFACE: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"id":"tp-1","alias":"billing","target_endpoint":"http://billing:3000"},{"id":"tp-2","alias":"gh","target_endpoint":"http://gh:3000"}]}}"#;

    #[tokio::test]
    async fn remove_transit_point_matches_by_alias_or_by_id() {
        for name in ["billing", "tp-1"] {
            let requests = feature_dry_run(&["remove-transit-point", "s-1", name], TWO_POINT_SURFACE)
                .await
                .expect("an existing point should be removed");
            assert_eq!(start_lines(&requests), READ_AND_DRY_RUN);
            assert_eq!(
                patch_body(&requests),
                json!({"transit": {"points": [{"id": "tp-2", "alias": "gh", "target_endpoint": "http://gh:3000"}]}}),
                "removing by {name}"
            );
        }
    }

    #[tokio::test]
    async fn remove_transit_point_without_dry_run_saves_the_patch() {
        let requests = saving_command(&["remove-transit-point", "s-1", "billing"], TWO_POINT_SURFACE)
            .await
            .expect("an existing point should be removed");
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/surfaces/s-1 HTTP/1.1", "PATCH /api/v1/surfaces/s-1 HTTP/1.1"]
        );
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [{"id": "tp-2", "alias": "gh", "target_endpoint": "http://gh:3000"}]}})
        );
    }

    #[tokio::test]
    async fn remove_transit_point_ignores_spaces_around_the_name() {
        let requests = feature_dry_run(&["remove-transit-point", "s-1", " billing "], TWO_POINT_SURFACE)
            .await
            .expect("the name should be trimmed");
        assert_eq!(
            patch_body(&requests),
            json!({"transit": {"points": [{"id": "tp-2", "alias": "gh", "target_endpoint": "http://gh:3000"}]}})
        );
    }

    #[tokio::test]
    async fn remove_transit_point_refuses_a_blank_name_before_any_request() {
        for blank in ["", "  "] {
            let (host, requests) = scripted_server(vec![]).await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let argv = ["fabric", "agent-gateway", "surfaces", "remove-transit-point", "Sales", blank];
            let error = resolve_surface_command(&client, surface_command(&argv))
                .await
                .expect_err("a blank name should be refused before the surface is looked up")
                .to_string();
            assert_eq!(error, "give the alias or id of the transit point to remove");
            let argv = ["fabric", "agent-gateway", "surfaces", "remove-transit-point", "s-1", blank];
            run_surfaces(&client, surface_command(&argv), Output::Json)
                .await
                .expect_err("a blank name should be refused before the surface is read");
            assert!(full_requests(requests).is_empty(), "{blank:?} sent a request");
        }
    }

    #[tokio::test]
    async fn remove_transit_point_unknown_name_lists_the_points_that_exist() {
        let error = feature_dry_run(&["remove-transit-point", "s-1", "nope"], TWO_POINT_SURFACE)
            .await
            .expect_err("an unknown point should be refused")
            .to_string();
        assert!(error.contains("no transit point 'nope'"), "{error}");
        assert!(error.contains("billing, gh"), "{error}");
    }

    #[tokio::test]
    async fn remove_transit_point_on_a_surface_without_points_says_it_has_none() {
        for stored in [
            STORED_SURFACE,
            r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[]}}"#,
        ] {
            let error = feature_dry_run(&["remove-transit-point", "s-1", "gh"], stored)
                .await
                .expect_err("there is nothing to remove")
                .to_string();
            assert!(error.contains("no transit point 'gh': it has no transit points yet"), "{error}");
        }
    }

    #[tokio::test]
    async fn remove_transit_point_with_an_alias_shared_by_two_points_asks_for_the_id() {
        const SHARED_ALIAS: &str = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"id":"tp-1","alias":"gh"},{"id":"tp-2","alias":"gh"}]}}"#;
        let error = feature_dry_run(&["remove-transit-point", "s-1", "gh"], SHARED_ALIAS)
            .await
            .expect_err("two points have this alias")
            .to_string();
        assert!(error.contains("more than one transit point has the alias 'gh': use its id"), "{error}");
    }

    #[tokio::test]
    async fn the_transit_point_commands_find_the_surface_by_name() {
        let runs: [(&[&str], &'static str, &str); 2] = [
            (
                &["add-transit-point", "Sales", "--alias", "billing", "--endpoint", "http://billing:3000"],
                TRANSIT_SURFACE,
                "billing",
            ),
            (&["remove-transit-point", "Sales", "billing"], TWO_POINT_SURFACE, "tp-2"),
        ];
        for (args, stored, in_patch) in runs {
            let (host, requests) = scripted_server(vec![
                LIST_OK,
                (DRY_RUN_GATEWAY_OK, stored),
                ("HTTP/1.1 200 OK", r#"{"surface_id":"s-1"}"#),
            ])
            .await;
            let client = GatewayClient::new(host, "agpat_valid").expect("client");
            let mut argv = vec!["fabric", "agent-gateway", "surfaces"];
            argv.extend_from_slice(args);
            let command = resolve_surface_command(&client, surface_command(&argv))
                .await
                .expect("the surface should resolve");
            run_surfaces(&client, command, Output::Json)
                .await
                .expect("the edit should be saved");
            let requests = full_requests(requests);
            assert_eq!(
                start_lines(&requests),
                [LIST_REQUEST, S1_REQUEST, "PATCH /api/v1/surfaces/s-1 HTTP/1.1"],
                "{args:?}"
            );
            assert!(requests[2].contains(in_patch), "{args:?}: {}", requests[2]);
        }
    }

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

    /// Prints the features of `surface` through a gateway that serves it.
    async fn printed_features_of(
        surface: &Value,
        output: Output,
    ) -> String {
        let body: &'static str = Box::leak(
            surface
                .to_string()
                .into_boxed_str(),
        );
        let (host, _) = scripted_server(vec![("HTTP/1.1 200 OK", body)]).await;
        let client = GatewayClient::new(host, "agpat_valid").expect("client");
        let mut printed = Vec::new();
        show_surface_features(&client, "s-1", output, &mut printed)
            .await
            .expect("the features should print");
        String::from_utf8(printed).expect("utf-8 output")
    }

    fn surface_with_default_variant(overrides: Value) -> Value {
        json!({
            "surface_id": "s-1",
            "target": {"policy": {"policy_definition_id": "p"}, "networking": {"timeout_secs": 5}},
            "default_variant_id": "v1",
            "variants": [{"id": "v1", "alias": "blue", "overrides": overrides}],
        })
    }

    #[tokio::test]
    async fn a_default_variant_that_overrides_a_feature_is_noted_in_the_table_and_the_json() {
        let surface = surface_with_default_variant(json!({"target": {"policy": {"policy_definition_id": "q"}}}));
        let note = "The default variant 'blue' sets policy; this table reads only the surface itself.";

        let table = printed_features_of(&surface, Output::Table).await;
        assert!(table.ends_with(&format!("\nNotes\n  - {note}\n")), "{table}");

        let json: Value = serde_json::from_str(&printed_features_of(&surface, Output::Json).await).expect("json");
        let rows = json
            .as_array()
            .expect("still a list of features");
        assert_eq!(rows.len(), features::FEATURES.len());
        for row in rows {
            if row["feature"] == "policy" {
                assert_eq!(row["variant_notes"], json!([note]));
            } else {
                assert!(
                    row.get("variant_notes")
                        .is_none(),
                    "{row}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_null_override_in_a_sparse_variant_gives_no_note() {
        let surface = surface_with_default_variant(json!({"target": {"policy": null}}));

        assert!(
            !printed_features_of(&surface, Output::Table)
                .await
                .contains("Notes")
        );
    }

    #[tokio::test]
    async fn a_variant_that_sets_two_features_names_both() {
        let surface = surface_with_default_variant(
            json!({"target": {"policy": {"policy_definition_id": "q"}, "networking": {"timeout_secs": 1}}}),
        );

        let table = printed_features_of(&surface, Output::Table).await;

        assert!(
            table.contains(
                "The default variant 'blue' sets policy, networking; this table reads only the surface itself."
            ),
            "{table}"
        );
    }

    #[tokio::test]
    async fn a_variant_that_is_not_the_default_is_noted_as_a_variant() {
        let mut surface = surface_with_default_variant(json!({}));
        surface["variants"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "v2", "alias": "green", "overrides": {"target": {"networking": {"timeout_secs": 1}}}}));

        let table = printed_features_of(&surface, Output::Table).await;

        assert!(
            table.ends_with(
                "\nNotes\n  - The variant 'green' sets networking; this table reads only the surface itself.\n"
            ),
            "{table}"
        );
    }

    #[tokio::test]
    async fn a_variant_with_no_overrides_or_only_an_endpoint_gives_no_note() {
        for overrides in [json!({}), json!({"target": {"endpoint": "http://x"}})] {
            let surface = surface_with_default_variant(overrides);
            assert!(
                !printed_features_of(&surface, Output::Table)
                    .await
                    .contains("Notes")
            );
        }
    }

    #[tokio::test]
    async fn a_sparse_variant_with_an_empty_list_says_it_sets_the_feature() {
        let surface = surface_with_default_variant(json!({"outbound_credentials": []}));

        let table = printed_features_of(&surface, Output::Table).await;

        assert!(
            table.ends_with(
                "\nNotes\n  - The default variant 'blue' sets credential-delegation; this table reads only the surface itself.\n"
            ),
            "{table}"
        );
    }

    #[tokio::test]
    async fn a_sparse_variant_whose_transit_has_no_points_and_is_not_disabled_gives_no_note() {
        for transit in [json!({}), json!({"shared": {"sign_requests": true}}), json!({"disabled": false})] {
            let surface = surface_with_default_variant(json!({"transit": transit}));
            assert!(
                !printed_features_of(&surface, Output::Table)
                    .await
                    .contains("Notes")
            );
        }
    }

    #[tokio::test]
    async fn a_sparse_variant_that_sets_points_or_disables_transit_gets_the_transit_note() {
        for transit in [json!({"points": []}), json!({"disabled": true})] {
            let surface = surface_with_default_variant(json!({"transit": transit}));
            let table = printed_features_of(&surface, Output::Table).await;
            assert!(
                table.contains("changes its transit points; transit point features here may not match."),
                "{table}"
            );
        }
    }

    #[tokio::test]
    async fn a_sparse_variant_with_transit_points_notes_the_features_that_can_sit_on_one() {
        let surface = surface_with_default_variant(
            json!({"transit": {"points": [{"alias": "gh", "policy": {"policy_definition_id": "q"}}]}}),
        );
        let note = "The default variant 'blue' changes its transit points; transit point features here may not match.";

        let table = printed_features_of(&surface, Output::Table).await;
        assert!(table.ends_with(&format!("\nNotes\n  - {note}\n")), "{table}");

        let json: Value = serde_json::from_str(&printed_features_of(&surface, Output::Json).await).expect("json");
        for row in json
            .as_array()
            .expect("still a list of features")
        {
            let noted = row.get("variant_notes") == Some(&json!([note]));
            let can_sit_on_one = ["policy", "networking", "mcp-tool-gating"].contains(
                &row["feature"]
                    .as_str()
                    .unwrap(),
            );
            assert_eq!(noted, can_sit_on_one, "{row}");
        }
    }

    #[tokio::test]
    async fn a_complete_variant_that_adds_a_feature_says_it_sets_it_and_marks_the_row() {
        let surface = json!({
            "surface_id": "s-1",
            "default_variant_id": "v1",
            "variants": [{"id": "v1", "alias": "blue", "overrides": {
                "complete": true,
                "target": {"policy": {"policy_definition_id": "q"}},
            }}],
        });
        let note = "The default variant 'blue' is complete, so it replaces the target and sets policy, and features it leaves out of them are off for the gateway even if this table shows them on.";

        let table = printed_features_of(&surface, Output::Table).await;
        assert!(table.contains("policy                 off  -"), "{table}");
        assert!(table.ends_with(&format!("\nNotes\n  - {note}\n")), "{table}");

        let json: Value = serde_json::from_str(&printed_features_of(&surface, Output::Json).await).expect("json");
        let policy = json
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["feature"] == "policy")
            .unwrap();
        assert_eq!(policy["on"], false);
        assert_eq!(policy["variant_notes"], json!([note]));
    }

    #[tokio::test]
    async fn a_complete_variant_note_is_on_every_feature_that_can_sit_in_a_replaced_block() {
        let surface = json!({
            "surface_id": "s-1",
            "default_variant_id": "v1",
            "variants": [{"id": "v1", "alias": "blue", "overrides": {"complete": true, "target": {"endpoint": "http://x"}}}],
        });

        let json: Value = serde_json::from_str(&printed_features_of(&surface, Output::Json).await).expect("json");
        for row in json.as_array().unwrap() {
            let noted = row
                .get("variant_notes")
                .is_some();
            let in_target = ["policy", "networking", "payment", "mcp-tool-gating", "workload-binding"].contains(
                &row["feature"]
                    .as_str()
                    .unwrap(),
            );
            let in_access_point = row["feature"] == "rate-limit";
            assert!(!(in_access_point && noted), "{row}");
            assert!(!in_target || noted, "{row}");
        }
    }

    #[tokio::test]
    async fn a_variant_label_with_control_characters_cannot_break_the_notes() {
        let mut surface = surface_with_default_variant(json!({"target": {"policy": {"policy_definition_id": "q"}}}));
        surface["variants"][0]["alias"] = json!("blue\u{1b}[2J\nx");

        let table = printed_features_of(&surface, Output::Table).await;

        assert!(!table.contains('\u{1b}'), "{table:?}");
        assert!(
            table.ends_with(
                "\nNotes\n  - The default variant 'blue[2J x' sets policy; this table reads only the surface itself.\n"
            ),
            "{table:?}"
        );
        let json = printed_features_of(&surface, Output::Json).await;
        assert!(json.contains("blue[2J x"), "{json}");
    }

    #[tokio::test]
    async fn a_complete_variant_says_which_blocks_it_replaces() {
        let mut surface = surface_with_default_variant(json!({
            "complete": true,
            "target": {"endpoint": "http://x"},
            "transit": {"points": []},
            "outbound_credentials": [],
        }));
        surface["access_point"] = json!({"rate_limit": {"requests": 1}});
        let note = "The default variant 'blue' is complete, so it replaces the target, the transit points and the outbound credentials, and features it leaves out of them are off for the gateway even if this table shows them on.";

        let table = printed_features_of(&surface, Output::Table).await;
        assert!(table.ends_with(&format!("\nNotes\n  - {note}\n")), "{table}");

        let json: Value = serde_json::from_str(&printed_features_of(&surface, Output::Json).await).expect("json");
        for row in json
            .as_array()
            .expect("still a list of features")
        {
            let noted = row.get("variant_notes") == Some(&json!([note]));
            let in_a_replaced_block = ["policy", "networking", "payment", "credential-delegation"].contains(
                &row["feature"]
                    .as_str()
                    .unwrap(),
            );
            assert!(!in_a_replaced_block || noted, "{row}");
            assert!(row["feature"] != "rate-limit" || !noted, "{row}");
        }
    }

    #[tokio::test]
    async fn a_complete_variant_with_a_null_feature_does_not_say_it_clears_it() {
        let surface = surface_with_default_variant(json!({"complete": true, "target": {"policy": null}}));

        let table = printed_features_of(&surface, Output::Table).await;

        assert!(table.contains("is complete, so it replaces the target,"), "{table}");
        assert!(!table.contains("clears") && !table.contains("sets policy"), "{table}");
    }

    #[tokio::test]
    async fn a_surface_with_no_variants_or_only_disabled_ones_has_no_notes() {
        let plain = json!({"surface_id": "s-1", "target": {"policy": {"policy_definition_id": "p"}}});
        let mut disabled = surface_with_default_variant(json!({"target": {"policy": {"policy_definition_id": "q"}}}));
        disabled["variants"][0]["enabled"] = json!(false);

        for surface in [plain, disabled] {
            assert!(
                !printed_features_of(&surface, Output::Table)
                    .await
                    .contains("Notes")
            );
            assert!(
                !printed_features_of(&surface, Output::Json)
                    .await
                    .contains("variant_notes")
            );
        }
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
    fn every_shared_crud_group_names_its_own_resource() {
        use clap::CommandFactory;
        let groups = [
            ("connections", "connections"),
            ("connection-points", "connection points"),
            ("issuers", "issuers"),
            ("authorities", "authorities"),
            ("trust-registries", "trust registries"),
            ("mediators", "mediators"),
            ("mcp-proxies", "MCP proxies"),
            ("a2a-proxies", "A2A proxies"),
            ("sts-clients", "STS clients"),
            ("credential-providers", "credential providers"),
            ("integrations", "integrations"),
            ("jwt-verification-strategies", "JWT verification strategies"),
        ];
        let mut cli = Cli::command();
        cli.build();
        let gateway = cli
            .find_subcommand("agent-gateway")
            .expect("agent-gateway");
        for (group, many) in groups {
            let command = gateway
                .find_subcommand(group)
                .unwrap_or_else(|| panic!("group {group}"));
            for name in ["list", "get", "create", "update", "delete"] {
                let about = command
                    .find_subcommand(name)
                    .unwrap_or_else(|| panic!("{group} {name}"))
                    .get_about()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                assert!(!about.contains("entit"), "{group} {name} kept the generic help: {about}");
            }
            let list = command
                .find_subcommand("list")
                .and_then(clap::Command::get_about)
                .map(ToString::to_string);
            assert_eq!(list.as_deref(), Some(format!("List {many}").as_str()), "{group}");
        }
    }

    #[test]
    fn every_example_command_in_the_help_parses() {
        use clap::CommandFactory;
        fn help_texts(
            command: &clap::Command,
            path: &str,
            texts: &mut Vec<(String, String)>,
        ) {
            let path = format!("{path} {}", command.get_name());
            for text in [command.get_after_long_help(), command.get_long_about()]
                .into_iter()
                .flatten()
            {
                texts.push((path.clone(), text.to_string()));
            }
            for subcommand in command.get_subcommands() {
                help_texts(subcommand, &path, texts);
            }
        }
        let mut cli = Cli::command();
        cli.build();
        let mut texts = Vec::new();
        help_texts(&cli, "", &mut texts);

        let mut checked = 0;
        for (path, text) in texts {
            let mut lines: Vec<String> = Vec::new();
            for line in text.lines() {
                match lines.last_mut() {
                    Some(last) if last.ends_with('\\') => {
                        last.pop();
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                    _ => lines.push(line.to_owned()),
                }
            }
            for line in lines
                .iter()
                .filter(|line| line.starts_with("  "))
            {
                let Some(start) = line.find("fabric agent-gateway") else {
                    continue;
                };
                let mut example = &line[start..];
                if line[..start].ends_with('`') {
                    example = example
                        .split('`')
                        .next()
                        .unwrap_or(example);
                }
                // A line of an interactive shell session shows the prompt; what
                // follows it is an Agent Gateway command typed without the prefix.
                let shell_line;
                if let Some(typed) = example.strip_prefix("fabric agent-gateway>") {
                    if matches!(typed.trim(), "" | "exit" | "quit") {
                        continue;
                    }
                    shell_line = format!("fabric agent-gateway {}", typed.trim());
                    example = &shell_line;
                }
                let words: Vec<String> = shell_words::split(example)
                    .unwrap_or_else(|error| panic!("{path}: cannot split `{example}`: {error}"))
                    .into_iter()
                    .take_while(|word| !matches!(word.as_str(), "|" | ">" | ">>" | "<"))
                    .map(|word| {
                        word.trim_end_matches(')')
                            .to_owned()
                    })
                    .collect();
                if let Err(error) = Cli::try_parse_from(&words) {
                    panic!("{path}: example does not parse: {example}\n{error}");
                }
                checked += 1;
            }
        }
        assert!(checked > 50, "only {checked} examples were found");
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
    /// Get a secret by its id, secret_id or name. The value is masked unless
    /// --reveal is given.
    Get {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
    /// Create a secret using flags or a complete JSON document.
    ///
    /// With no --file, give --name, --secret-id and a value through --value
    /// or --value-stdin. Prefer --value-stdin: a value typed after --value
    /// stays in shell history and shows in the process list.
    ///
    /// The secret_id must be unique and cannot be changed later. Other
    /// configuration refers to the secret as $SECRET:<secret-id>.
    #[command(after_long_help = SECRETS_CREATE_EXAMPLES)]
    Create(SecretCreateArgs),
    /// Update a secret from a JSON document.
    ///
    /// Fields the document leaves out keep their stored values, except
    /// description, which is always replaced: leave it out and the stored
    /// description is cleared, so restate it. The secret_id cannot be changed;
    /// the gateway ignores it in the document.
    ///
    /// To change the value, set "update_value": true beside "value". The
    /// gateway ignores "value" without it and still reports success, so the
    /// CLI refuses a document that has "value" but no "update_value" key.
    #[command(after_long_help = SECRETS_UPDATE_EXAMPLES)]
    Update {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
        /// JSON document with the fields to change: name, description,
        /// secret_type, tags, and value with update_value. Use '-' to read from
        /// standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a secret by its id, secret_id or name.
    ///
    /// The secret is deleted immediately: there is no confirmation prompt and
    /// no --yes flag. Check which secret a secret_id or name matches with
    /// `fabric agent-gateway secrets get` first.
    #[command(after_long_help = SECRETS_DELETE_EXAMPLES)]
    Delete {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
}

/// Examples shown at the bottom of `secrets create --help`.
const SECRETS_CREATE_EXAMPLES: &str = r#"Examples:
  Read the value from a file, keeping it out of shell history:
    fabric agent-gateway secrets create --name "Stripe live" \
      --secret-id stripe-live --value-stdin < key.txt

  Pipe the value in from an environment variable, with a description, type and
  tags:
    printf '%s' "$STRIPE_KEY" | fabric agent-gateway secrets create \
      --name "Stripe live" --secret-id stripe-live --value-stdin \
      --description "Billing API key" --type ApiKey --tag billing --tag stripe

  Create from a complete JSON document:
    fabric agent-gateway secrets create --file secret.json"#;

/// Examples shown at the bottom of `secrets update --help`.
const SECRETS_UPDATE_EXAMPLES: &str = r#"Examples:
  Replace the value, restating the description so it is kept:
    printf \
      '{"value":"%s","update_value":true,"description":"Billing API key"}' \
      "$NEW_KEY" | fabric agent-gateway secrets update stripe-live --file -

  Change the tags and keep the value, restating the description:
    echo '{"tags":["billing","prod"],"description":"Billing API key"}' | \
      fabric agent-gateway secrets update stripe-live --file -"#;

/// Examples shown at the bottom of `secrets delete --help`.
const SECRETS_DELETE_EXAMPLES: &str = r#"Examples:
  Check which secret a name matches, then delete it:
    fabric agent-gateway secrets get "Stripe live"
    fabric agent-gateway secrets delete "Stripe live""#;

#[derive(Debug, Args)]
struct SecretCreateArgs {
    /// Human-readable name.
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    /// Machine-readable identifier used by $SECRET:<secret-id> references.
    #[arg(long, required_unless_present = "file")]
    secret_id: Option<String>,
    /// Secret value, stored exactly as given including any whitespace. It
    /// stays in shell history; prefer --value-stdin.
    #[arg(long, conflicts_with = "value_stdin")]
    value: Option<String>,
    /// Read the secret value from standard input. One trailing line ending
    /// is removed; use --file when a final newline matters, as in a PEM block.
    #[arg(long)]
    value_stdin: bool,
    /// What the secret is for.
    #[arg(long)]
    description: Option<String>,
    /// Secret type, as configured on the gateway. Omit for the gateway
    /// default, General.
    #[arg(long = "type")]
    secret_type: Option<String>,
    /// Tag to attach. Repeat for multiple tags.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Complete JSON document with name, secret_id, value, description,
    /// secret_type and tags. Use '-' to read from standard input. Other
    /// creation flags are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum DelegationVaultCommand {
    /// List delegated credential grants.
    List,
    /// Get a grant by ID.
    Get {
        /// Grant ID, from the ID column of `fabric agent-gateway
        /// delegation-vault list`.
        id: String,
    },
    /// Revoke a single grant by ID.
    ///
    /// The grant is revoked immediately: there is no confirmation prompt and
    /// no --yes flag, and it cannot be undone. To revoke every grant a user
    /// holds, use `revoke-user`. Revoking needs the delegation_vault.delete
    /// permission (administrators by default) through a session or an
    /// appliance-wide personal access token, not one created with
    /// --resource-pattern.
    #[command(after_long_help = DELEGATION_VAULT_REVOKE_EXAMPLES)]
    Revoke {
        /// Grant ID, from the ID column of `fabric agent-gateway
        /// delegation-vault list`.
        id: String,
    },
    /// Revoke every grant held for one user identity hash (sha256:...).
    ///
    /// Revokes all of that user's grants at once, immediately and with no
    /// confirmation prompt; it cannot be undone. Table output reports how many
    /// grants were revoked; `--output json` prints {"revoked": N}.
    #[command(name = "revoke-user")]
    #[command(after_long_help = DELEGATION_VAULT_REVOKE_USER_EXAMPLES)]
    RevokeUser {
        /// The user's identity hash, as sha256:<hex>, from the
        /// user_identity_hash field of `delegation-vault list --output json`.
        user_hash: String,
    },
}

/// Examples shown at the bottom of `delegation-vault revoke --help`.
const DELEGATION_VAULT_REVOKE_EXAMPLES: &str = r#"Examples:
  Find the grant's ID, then revoke it:
    fabric agent-gateway delegation-vault list
    fabric agent-gateway delegation-vault revoke <grant-id>"#;

/// Examples shown at the bottom of `delegation-vault revoke-user --help`.
const DELEGATION_VAULT_REVOKE_USER_EXAMPLES: &str = r#"Examples:
  Show each grant's ID, agent and user hash, then revoke every grant one user
  holds:
    fabric agent-gateway delegation-vault list --output json | jq \
      -r '.[] | [.id, .agent_did, .user_identity_hash] | @tsv'
    fabric agent-gateway delegation-vault revoke-user sha256:<hex>"#;

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

/// Rewrites the generic "entity" help of the shared `CrudCommand`
/// subcommands with one command group's names, as
/// [`certificate_reference_help`] does for certificates. `a_one` is the
/// resource with its article, such as "an issuer", and `many` its plural.
/// The help only: the commands send the same requests for every group.
/// `update` says what the group's gateway route does with fields the
/// document leaves out, which differs between resources.
fn crud_help(
    group: &'static str,
    a_one: &'static str,
    many: &'static str,
    update: CrudUpdate,
) -> impl FnMut(clap::Command) -> clap::Command {
    let one = a_one
        .split_once(' ')
        .map_or(a_one, |(_, noun)| noun);
    move |subcommand| {
        let name = subcommand
            .get_name()
            .to_owned();
        match name.as_str() {
            "list" => subcommand.about(format!("List {many}")),
            "get" => subcommand.about(format!("Get {a_one} by ID")).long_about(format!(
                "Get {a_one} by ID.\n\n\
                 The ID is the ID column of `fabric agent-gateway {group} list`. It is sent as given: a name is not looked up."
            )),
            "create" => subcommand
                .about(format!("Create {a_one} from a JSON document"))
                .long_about(format!(
                    "Create {a_one} from a JSON document.\n\n\
                     `fabric agent-gateway {group} get <ID> --output json` prints an existing {one}, which shows the fields the gateway stores. Use `--file -` to read the document from standard input."
                )),
            "update" => {
                let behaviour = match update {
                    CrudUpdate::Replaces => format!(
                        "The document is sent as an HTTP PUT and replaces the whole {one}: a field it leaves out is cleared. Start from the current {one}:\n\n"
                    ),
                    CrudUpdate::ChangesSentFields => format!(
                        "The document is sent as an HTTP PUT. The gateway changes only the fields it sets and keeps the rest. To see the current fields, start from the current {one}:\n\n"
                    ),
                    CrudUpdate::Custom(text) => {
                        return subcommand.about(format!("Update {a_one} from a JSON document")).long_about(text);
                    }
                };
                subcommand.about(format!("Update {a_one} from a JSON document")).long_about(format!(
                    "Update {a_one} from a JSON document.\n\n\
                     {behaviour}  \
                     fabric agent-gateway {group} get <ID> \\\n    --output json > record.json\n  \
                     fabric agent-gateway {group} update <ID> \\\n    --file record.json\n\n\
                     Use `--file -` to read the document from standard input."
                ))
            }
            "delete" => subcommand.about(format!("Delete {a_one} by ID")).long_about(format!(
                "Delete {a_one} by ID.\n\n\
                 The request is sent as soon as the command runs: there is no confirmation prompt and no --yes flag. The ID is sent as given: a name is not looked up."
            )),
            _ => subcommand,
        }
    }
}

/// What a shared-CRUD group's gateway route does with fields an `update`
/// document leaves out, for [`crud_help`].
#[derive(Clone, Copy)]
enum CrudUpdate {
    /// The record is replaced whole, so an omitted field is cleared.
    Replaces,
    /// Only the fields sent change; the rest are kept.
    ChangesSentFields,
    /// The group needs its own `update` long help.
    Custom(&'static str),
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
    let mut updated = None;
    let mut value = match command {
        // The document is read and checked before the lookup, as for secrets,
        // so a bad file fails without a request and `--file -` is read once.
        CrudCommand::Update { id, file } => {
            let body = read_json(&file)?;
            let id = resolve_id(client, &CERTIFICATE_LOOKUP, &id).await?;
            updated = Some(id.clone());
            client
                .request(Method::PUT, &entity_path(CERTIFICATES_PATH, &id), Some(body))
                .await?
        }
        command => run_crud(client, CERTIFICATES_PATH, command).await?,
    };
    if let Some(id) = deleted {
        return Ok(confirm_empty(value, &confirmation_line("Deleted", "certificate", &id), output));
    }
    if !reveal {
        mask_keys(&mut value, &["private_key_pem"]);
    }
    if let Some(id) = updated {
        return Ok(report_update(value, confirmation_line("Updated", "certificate", &id), output));
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
    let mut updated = None;
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
            updated = Some(id.clone());
            client
                .request(Method::PUT, &encoded_path(SECRETS_PATH, &id), Some(body))
                .await?
        }
        SecretCommand::Delete { secret } => {
            let id = resolve_id(client, &SECRET_LOOKUP, &secret).await?;
            let value = client
                .request(Method::DELETE, &encoded_path(SECRETS_PATH, &id), None)
                .await?;
            return Ok(confirm_empty(value, &confirmation_line("Deleted", "secret", &id), output));
        }
    };
    if !reveal {
        mask_keys(&mut value, &["value"]);
    }
    if let Some(id) = updated {
        return Ok(report_update(value, confirmation_line("Updated", "secret", &id), output));
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
            Ok(confirm_empty(value, &confirmation_line("Revoked", "grant", &id), output))
        }
        // A mass revoke answers with `{"revoked": N}`. Table output says how
        // many went in one line and `--output json` keeps the answer.
        DelegationVaultCommand::RevokeUser { user_hash } => {
            let path = encoded_path(&format!("{DELEGATION_VAULT_PATH}/by-user"), &user_hash);
            let value = client
                .request(Method::DELETE, &path, None)
                .await?;
            if matches!(output, Output::Table) {
                println!("{}", revoked_grants_line(&value, &user_hash));
                return Ok(None);
            }
            Ok(Some(value))
        }
    }
}

/// `Revoked 2 grants for user '<hash>'`, with the count from the gateway's
/// answer, or `Revoked grants for user '<hash>'` when the answer carries none.
fn revoked_grants_line(
    answer: &Value,
    user_hash: &str,
) -> String {
    let hash = tables::flatten(user_hash);
    match answer
        .get("revoked")
        .and_then(Value::as_u64)
    {
        Some(1) => format!("Revoked 1 grant for user '{hash}'"),
        Some(count) => format!("Revoked {count} grants for user '{hash}'"),
        None => format!("Revoked grants for user '{hash}'"),
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
    let shown = tables::flatten_capped(reference);
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
                        .map(|name| {
                            format!("{name}: {}", tables::flatten_capped(string_field(entity, name).unwrap_or("-")))
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("  {}  ({details})", tables::flatten_capped(id))
                })
                .collect::<Vec<_>>()
                .join("\n");
            bail!("'{shown}' matches more than one {noun}; pass one of these ids instead:\n{candidates}")
        }
    }
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

/// Reports an update by the resolved id. Table output prints the confirmation
/// line and has nothing left to print; JSON output keeps the gateway's answer.
fn report_update(
    value: Value,
    line: String,
    output: Output,
) -> Option<Value> {
    match output {
        Output::Table => {
            println!("{line}");
            None
        }
        Output::Json => Some(value),
    }
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
            Output::Json,
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
    fn only_the_create_subcommands_have_a_created_kind() {
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

        assert_eq!(
            create_kind(
                &create
                    .into_agent_gateway()
                    .command
            ),
            Some("secret")
        );
        assert_eq!(
            create_kind(
                &list
                    .into_agent_gateway()
                    .command
            ),
            None
        );
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
            let created = client
                .request(Method::POST, "/v1/surfaces", Some(body))
                .await?;
            if matches!(output, Output::Table) {
                match created_surface_lines(&created) {
                    Some(lines) => {
                        for line in lines {
                            println!("{line}");
                        }
                    }
                    None => print_value(&created, output)?,
                }
                return Ok(None);
            }
            Ok(Some(created))
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
        SurfaceCommand::AddTransitPoint(args) => add_transit_point(client, args, output).await,
        SurfaceCommand::RemoveTransitPoint(args) => remove_transit_point(client, args, output).await,
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

/// The lines printed for a created surface: the confirmation with its id, then
/// its id, name, route, protocol and target as the gateway answered them. A
/// field the answer lacks is left out. An answer with no usable id has nothing
/// to confirm, so this returns `None` and the caller prints the whole answer.
/// A value that is empty, only whitespace or only control characters counts as
/// missing. The target row shows the endpoint's scheme, host and port only, so
/// credentials, paths and query strings never reach a terminal or CI log.
fn created_surface_lines(surface: &Value) -> Option<Vec<String>> {
    let text_at = |path: &[&str]| {
        path.iter()
            .try_fold(surface, |value, key| value.get(*key))
            .and_then(Value::as_str)
    };
    let cleaned = |text: Option<&str>| {
        text.map(tables::flatten_capped)
            .filter(|shown| !shown.trim().is_empty())
    };
    let id = id_from_response(surface).filter(|id| {
        !tables::flatten(id)
            .trim()
            .is_empty()
    })?;
    let mut lines = vec![confirmation_line("Created", "surface", id), format!("  id: {}", tables::flatten_capped(id))];
    for (label, text) in [
        ("name", cleaned(text_at(&["name"]))),
        ("route", cleaned(text_at(&["access_point", "route"]))),
        ("protocol", cleaned(text_at(&["access_point", "protocol"]))),
        (
            "target",
            cleaned(
                text_at(&["target", "endpoint"])
                    .and_then(target_without_secrets)
                    .as_deref(),
            ),
        ),
    ] {
        if let Some(text) = text {
            lines.push(format!("  {label}: {text}"));
        }
    }
    Some(lines)
}

/// An endpoint reduced to `scheme://host[:port]`. Text that does not parse as
/// a URL with a host keeps its own text after the last `@` that comes before
/// the first `?` or `#`, cut at that `?` or `#`. When nothing sensible remains,
/// or an `@` is still left anywhere (a password could hold a `?` or `#`), there
/// is no target to show and this returns `None`.
fn target_without_secrets(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    if let Ok(url) = url::Url::parse(endpoint)
        && let Some(host) = url.host_str()
    {
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        return Some(format!("{}://{host}{port}", url.scheme()));
    }
    let query_at = endpoint
        .find(['?', '#'])
        .unwrap_or(endpoint.len());
    if endpoint[query_at..].contains('@') {
        return None;
    }
    let after_userinfo = match endpoint[..query_at].rfind('@') {
        Some(at) => &endpoint[at + 1..],
        None => endpoint,
    };
    let kept = after_userinfo
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    (!kept.trim().is_empty() && !kept.contains('@')).then(|| kept.to_owned())
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

/// What an enabled variant of a surface overrides at some JSON pointers.
struct VariantOverrides {
    /// The variant's alias, name or id, whichever is first set.
    label: String,
    /// Whether it is the surface's default variant.
    is_default: bool,
    /// The pointers (among those asked for) the variant gives a value. A
    /// `null` is not one, since in a sparse variant it means inherit the
    /// surface's value. An empty list is one in a sparse variant, which
    /// replaces the surface's list with it, but not in a complete one, whose
    /// blocks are covered by their own note.
    sets: Vec<&'static str>,
    /// Whether the variant is complete and has its own `target`.
    complete_with_target: bool,
    /// Whether the variant is complete.
    complete: bool,
    /// Whether the variant's `transit` replaces the points or turns transit
    /// off, which is what changes the features on transit points.
    changes_transit_points: bool,
    /// The blocks the variant has, which a complete variant replaces whole:
    /// among `target`, `access_point`, `transit`, `identity_slots` and
    /// `outbound_credentials`.
    blocks: Vec<&'static str>,
}

/// The enabled variants of `surface` with what each overrides at `pointers`.
fn enabled_variant_overrides(
    surface: &Value,
    pointers: &[&'static str],
) -> Vec<VariantOverrides> {
    let default_id = surface
        .get("default_variant_id")
        .and_then(Value::as_str);
    let mut found = Vec::new();
    for variant in surface
        .get("variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let enabled = variant
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        let overrides = variant.get("overrides");
        let complete = overrides
            .and_then(|overrides| overrides.get("complete"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut sets = Vec::new();
        for pointer in pointers {
            if overrides
                .and_then(|overrides| overrides.pointer(pointer))
                .is_some_and(|value| {
                    !value.is_null()
                        && (!complete
                            || value
                                .as_array()
                                .is_none_or(|list| !list.is_empty()))
                })
            {
                sets.push(*pointer);
            }
        }
        let blocks = ["target", "access_point", "transit", "identity_slots", "outbound_credentials"]
            .into_iter()
            .filter(|block| {
                overrides
                    .and_then(|overrides| overrides.get(*block))
                    .is_some_and(|value| !value.is_null())
            })
            .collect();
        let transit = overrides.and_then(|overrides| overrides.get("transit"));
        let changes_transit_points = transit
            .and_then(|transit| transit.get("points"))
            .is_some_and(|points| !points.is_null())
            || transit
                .and_then(|transit| transit.get("disabled"))
                .and_then(Value::as_bool)
                == Some(true);
        let has_target = overrides
            .and_then(|overrides| overrides.get("target"))
            .is_some_and(|target| !target.is_null());
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
        found.push(VariantOverrides {
            label: label.to_owned(),
            is_default: id.is_some() && id == default_id,
            sets,
            complete_with_target: complete && has_target,
            complete,
            changes_transit_points,
            blocks,
        });
    }
    found
}

/// Notes on the variants of `surface` that change its tool gating. The gateway
/// builds the surface's gating from its default variant, so a default variant
/// that sets gating replaces the saved gating, and a complete one with none
/// clears it.
fn variant_gating_notes(surface: &Value) -> Vec<String> {
    let mut others: Vec<String> = Vec::new();
    let mut notes = Vec::new();
    for variant in enabled_variant_overrides(surface, &["/target/mcp_tool_gating"]) {
        let label = &variant.label;
        match (variant.is_default, !variant.sets.is_empty(), variant.complete_with_target) {
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
    /// `integrations` is a reserved sibling route and returns the
    /// integration assignments rather than a user.
    Get {
        /// User's UUID, as `list` prints it, not the username.
        user_id: String,
    },
    /// Update a user's role, status, or profile from a JSON document.
    ///
    /// Fields the document omits keep their current values. `role` is
    /// `administrator`, `poweruser` or `user`, and `status` is `new`,
    /// `approved` or `disabled`. Changing a user's role, or moving them out of
    /// `approved`, ends their active sessions. The ID `integrations` is
    /// refused: it is a reserved route, not a user.
    #[command(after_long_help = USERS_UPDATE_EXAMPLES)]
    Update {
        /// User's UUID, as `list` prints it.
        user_id: String,
        /// JSON document carrying any of `role`, `status`, `first_name`,
        /// `last_name`, `email`, `department`, `job_title`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a user by ID.
    ///
    /// The user is removed permanently and their active sessions end. It runs
    /// at once, with no confirmation prompt. The gateway refuses to delete an
    /// administrator or your own account.
    Delete {
        /// User's UUID, as `list` prints it, not the username.
        user_id: String,
    },
}

/// Examples shown at the bottom of `users update --help`.
const USERS_UPDATE_EXAMPLES: &str = r#"Examples:
  Approve a new user:
    echo '{"status": "approved"}' | fabric agent-gateway users update \
      <user-id> --file -

  Make a user a power user and set their job title:
    fabric agent-gateway users update <user-id> --file user.json
  where user.json is:
    {"role": "poweruser", "job_title": "Platform engineer"}

  Disable a user, which also ends their sessions:
    echo '{"status": "disabled"}' | fabric agent-gateway users update \
      <user-id> --file -"#;

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// List did:webvh identities.
    List,
    /// Get an identity by ID.
    ///
    /// `integrations` is a reserved sibling route and returns the
    /// integration assignments rather than an identity.
    Get {
        /// Identity's UUID, as `list` prints it, not its DID.
        id: String,
        /// Include the key pair, which carries the identity's private key.
        #[arg(long)]
        reveal: bool,
    },
    /// Create an identity, optionally from a JSON document.
    ///
    /// Without --file the gateway generates an Ed25519 key pair and uses a DID
    /// path of `agents/<uuid>`. To bring your own keys, put them under
    /// `key_pair` as JWKs, not PEM.
    #[command(after_long_help = IDENTITIES_CREATE_EXAMPLES)]
    Create {
        /// JSON document `{did_path?, metadata?, key_pair?}`. Every field is
        /// optional; the gateway fills in whatever the document omits. A key
        /// pair belongs under `key_pair`: an unwrapped one is rejected,
        /// because the gateway would ignore it and install one of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Update an identity's DID document from a JSON document.
    ///
    /// A deactivated identity cannot be updated.
    #[command(after_long_help = IDENTITIES_UPDATE_EXAMPLES)]
    Update {
        id: String,
        /// JSON document `{did_document, update_keys?, ttl?}`. The gateway
        /// rejects a bare DID document with a 422: it belongs under
        /// `did_document`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Rotate an identity's signing keys.
    ///
    /// The new key takes over at once, with no confirmation prompt, and the
    /// response carries its public key as `new_public_key`. Without --file the
    /// gateway generates the new key pair. A deactivated identity cannot be
    /// rotated.
    #[command(name = "rotate-keys", after_long_help = IDENTITIES_ROTATE_KEYS_EXAMPLES)]
    RotateKeys {
        id: String,
        /// JSON document `{"new_key_pair": {public_key, private_key,
        /// key_type?}}`, both keys JWKs, not PEM. A document without
        /// `new_key_pair` is rejected, because the gateway would ignore it and
        /// install a key pair of its own.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Transfer an identity to a new controller.
    ///
    /// The transfer takes effect at once, with no confirmation prompt.
    /// `new_controller` must be a DID. `current_owner_authorization` proves
    /// control of the identity's current signing key: a compact JWS (alg
    /// EdDSA, with a `kid` naming a verification method of this DID) whose
    /// payload carries a fresh `iat` and the challenge
    /// `transfer-ownership:<did>:<version-id>:<new-controller>`, where
    /// <version-id> is the identity's latest `version_id` (see `history`). A
    /// deactivated identity cannot be transferred.
    #[command(after_long_help = IDENTITIES_TRANSFER_EXAMPLES)]
    Transfer {
        id: String,
        /// JSON document `{new_controller, current_owner_authorization,
        /// new_owner_authorization?, new_ownership_proof?, transfer_reason?}`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show an identity's version history.
    History { id: String },
    /// Read or write an identity's trust-score policy.
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
    /// This is the identity's delete route, and it runs at once with no
    /// confirmation prompt. The gateway appends a deactivation entry to the DID
    /// log and clears the identity's active flag. The record is kept and stays
    /// readable, but a deactivated identity cannot be updated, rotated,
    /// transferred or deactivated again.
    Deactivate { id: String },
}

/// Examples shown at the bottom of `identities create --help`.
const IDENTITIES_CREATE_EXAMPLES: &str = r#"Examples:
  Let the gateway generate the keys:
    fabric agent-gateway identities create

  Choose the DID path and bring your own Ed25519 key pair:
    fabric agent-gateway identities create --file identity.json
  where identity.json is:
    {
      "did_path": "agents/billing",
      "key_pair": {
        "public_key":  {"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"},
        "private_key": {"kty": "OKP", "crv": "Ed25519",
                        "x": "<base64url>", "d": "<base64url>"},
        "key_type": "Ed25519"
      }
    }"#;

/// Examples shown at the bottom of `identities update --help`.
const IDENTITIES_UPDATE_EXAMPLES: &str = r#"Examples:
  Replace the DID document:
    fabric agent-gateway identities update <id> --file identity-update.json
  where identity-update.json wraps the complete new DID document:
    {"did_document": {"id": "did:webvh:...", "verificationMethod": [...]}}"#;

/// Examples shown at the bottom of `identities rotate-keys --help`.
const IDENTITIES_ROTATE_KEYS_EXAMPLES: &str = r#"Examples:
  Let the gateway generate the new key pair:
    fabric agent-gateway identities rotate-keys <id>

  Supply your own Ed25519 key pair:
    fabric agent-gateway identities rotate-keys <id> --file rotate-keys.json
  where rotate-keys.json is:
    {
      "new_key_pair": {
        "public_key":  {"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"},
        "private_key": {"kty": "OKP", "crv": "Ed25519",
                        "x": "<base64url>", "d": "<base64url>"}
      }
    }"#;

/// Examples shown at the bottom of `identities transfer --help`.
const IDENTITIES_TRANSFER_EXAMPLES: &str = r#"Examples:
  Find the latest version_id to sign into the challenge:
    fabric agent-gateway identities history <id> --output json

  Transfer the identity:
    fabric agent-gateway identities transfer <id> --file transfer.json
  where transfer.json is:
    {
      "new_controller": "did:web:partner.example.com",
      "current_owner_authorization": "<compact JWS>",
      "transfer_reason": "Handed over to partner"
    }"#;

#[derive(Debug, Subcommand)]
enum TrustPolicyCommand {
    /// Get an identity's trust-score policy.
    ///
    /// The gateway returns its built-in defaults for an identity that has
    /// never had a policy set, so a result does not prove one was configured.
    Get { id: String },
    /// Set an identity's trust-score policy from a JSON document.
    ///
    /// Send the document `trust-policy get <id> --output json` returns, edited:
    /// the policy under `config`, holding `minTrustScore` (0.0 to 1.0) and,
    /// for each of five components, a threshold, a weight and whether it is
    /// required. The stored policy is replaced as a whole.
    #[command(after_long_help = IDENTITIES_TRUST_POLICY_SET_EXAMPLES)]
    Set {
        id: String,
        /// JSON document `{"config": {...}}`. A bare policy, without the
        /// `config` wrapper, is rejected before anything is sent.
        #[arg(short, long)]
        file: PathBuf,
    },
}

/// Examples shown at the bottom of `identities trust-policy set --help`.
const IDENTITIES_TRUST_POLICY_SET_EXAMPLES: &str = r#"Examples:
  Save the current policy, edit it, and send it back:
    fabric agent-gateway identities trust-policy get <id> --output json > \
      trust-policy.json
    fabric agent-gateway identities trust-policy set <id> \
      --file trust-policy.json"#;

#[derive(Debug, Subcommand)]
enum ApiKeyCommand {
    /// List API keys across every Agent Surface, or for one of them.
    List {
        /// ID of the Agent Surface to list keys for; a surface name is not
        /// accepted. Omit to list every key.
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
    /// The key's secret is printed once and never again: the gateway keeps
    /// only its hash. In table mode the secret goes alone to standard output,
    /// so `$(...)` captures just the secret, and the confirmation goes to
    /// standard error. `--output json` prints the whole response, secret
    /// included.
    ///
    /// A key cannot be edited afterwards: to change its client_id or labels,
    /// create a new key and revoke or delete the old one.
    #[command(after_long_help = API_KEYS_CREATE_EXAMPLES)]
    Create(ApiKeyCreateArgs),
    /// Revoke an API key without removing its record.
    ///
    /// The gateway stops accepting the key, and `list` keeps showing it with a
    /// revoked status. A revoked key cannot be rotated; create a new key
    /// instead. The command asks for confirmation first unless you pass --yes.
    #[command(after_long_help = API_KEYS_REVOKE_EXAMPLES)]
    Revoke {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
        /// Name the gateway logs as having revoked the key.
        #[arg(long, default_value = "api")]
        actor: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Replace an API key's secret, keeping its id, client_id and labels.
    ///
    /// The current secret stops working immediately. The new secret is printed
    /// once, the same way `create` prints it: alone on standard output in table
    /// mode. A revoked key cannot be rotated. The command asks for confirmation
    /// first unless you pass --yes.
    #[command(after_long_help = API_KEYS_ROTATE_EXAMPLES)]
    Rotate {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
        /// Name the gateway logs for the rotation and stores as the key's
        /// `issuer.actor`.
        #[arg(long, default_value = "api")]
        actor: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
    /// Delete an API key.
    ///
    /// The key and its record are removed, so unlike `revoke` it no longer
    /// shows in `list`. The command asks for confirmation first unless you pass
    /// --yes. Pass --agent-id to skip looking up the key's surface, for example
    /// when your token can delete keys but not list them.
    #[command(after_long_help = API_KEYS_DELETE_EXAMPLES)]
    Delete {
        /// Key's own id, as `list` prints it.
        key_id: String,
        #[command(flatten)]
        surface: ApiKeySurfaceArgs,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// The Agent Surface a single-key command acts on. The gateway addresses a
/// key by its surface and then its own id, so a command given the key alone
/// looks the surface up first.
#[derive(Debug, Args)]
struct ApiKeySurfaceArgs {
    /// ID of the Agent Surface the key belongs to; a surface name is not
    /// accepted. Omit to look it up by key id.
    #[arg(long)]
    agent_id: Option<String>,
}

#[derive(Debug, Args)]
struct ApiKeyCreateArgs {
    /// ID of the Agent Surface the key belongs to; a surface name is not
    /// accepted (see `fabric agent-gateway surfaces list`).
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

/// Examples shown at the bottom of `api-keys create --help`.
const API_KEYS_CREATE_EXAMPLES: &str = r#"Examples:
  Create a key and keep its secret in a shell variable:
    KEY=$(fabric agent-gateway api-keys create <surface-id> \
      --client-id billing --label team=ops)

  Create a key from a document:
    fabric agent-gateway api-keys create <surface-id> --file api-key.json
  where api-key.json is:
    {"client_id": "billing", "labels": {"team": "ops"}}"#;

/// Examples shown at the bottom of `api-keys revoke --help`.
const API_KEYS_REVOKE_EXAMPLES: &str = r#"Examples:
  Revoke a key, confirming at the prompt:
    fabric agent-gateway api-keys revoke <key-id>

  Revoke from a script, naming who did it:
    fabric agent-gateway api-keys revoke <key-id> --actor ops-team --yes"#;

/// Examples shown at the bottom of `api-keys rotate --help`.
const API_KEYS_ROTATE_EXAMPLES: &str = r#"Examples:
  Rotate from a script and keep the new secret in a shell variable:
    SECRET=$(fabric agent-gateway api-keys rotate <key-id> --yes)

  Rotate, naming who did it:
    fabric agent-gateway api-keys rotate <key-id> --actor ops-team"#;

/// Examples shown at the bottom of `api-keys delete --help`.
const API_KEYS_DELETE_EXAMPLES: &str = r#"Examples:
  Delete a key from a script:
    fabric agent-gateway api-keys delete <key-id> --yes

  Name the key's surface to skip the lookup:
    fabric agent-gateway api-keys delete <key-id> --agent-id <surface-id> --yes"#;

#[derive(Debug, Subcommand)]
enum TenantOwnershipCommand {
    /// Report what reassigning a resource would affect.
    ///
    /// Shows the resource's current tenant, whether it is system-owned (and
    /// so cannot be reassigned), and its references: `incoming` from resources
    /// that use it and `outgoing` to resources it uses. `set` refuses a move
    /// that would make one of these references cross tenants, or that leaves
    /// one pointing at a resource that no longer exists.
    Impact {
        /// Resource family the gateway tracks ownership for. `gateways` are
        /// what `connections` manages, and `policy-definitions` what
        /// `policies` manages. api-keys and connection-points are rejected:
        /// they inherit ownership from their parent resource.
        kind: OwnershipKind,
        /// ID of the resource. Names are not looked up.
        id: String,
    },
    /// Assign a resource to a tenant, or clear its tenant ownership.
    ///
    /// Pass exactly one of --tenant or --clear; with neither, nothing is sent.
    /// The change applies at once, with no confirmation prompt. The gateway
    /// blocks a move that would make one of the resource's references cross
    /// tenants, and any move of a system-owned resource; the error then points
    /// to `impact`, which lists the references.
    #[command(after_long_help = TENANT_OWNERSHIP_SET_EXAMPLES)]
    Set {
        /// Resource family the gateway tracks ownership for. `gateways` are
        /// what `connections` manages, and `policy-definitions` what
        /// `policies` manages. api-keys and connection-points are rejected:
        /// they inherit ownership from their parent resource.
        kind: OwnershipKind,
        /// ID of the resource. Names are not looked up.
        id: String,
        /// Tenant to assign the resource to.
        #[arg(long, conflicts_with = "clear")]
        tenant: Option<String>,
        /// Clear tenant ownership, making the resource globally owned.
        #[arg(long)]
        clear: bool,
    },
}

/// Examples shown at the bottom of `tenant-ownership set --help`.
const TENANT_OWNERSHIP_SET_EXAMPLES: &str = r#"Examples:
  Check what moving a surface would cross, then move it to tenant acme:
    fabric agent-gateway tenant-ownership impact surfaces <surface-id>
    fabric agent-gateway tenant-ownership set surfaces <surface-id> \
      --tenant acme

  Make a policy definition globally owned again:
    fabric agent-gateway tenant-ownership set policy-definitions <policy-id> \
      --clear"#;

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
    ///
    /// The gateway fetches the URI and reports `valid` and `key_count`.
    /// Nothing is saved. A URI that cannot be fetched or parsed exits non-zero
    /// with the gateway's reason. Run this before pointing a strategy's
    /// `jwks_source` at the URI.
    #[command(name = "validate-jwks-uri")]
    ValidateJwksUri {
        /// URI of the JSON Web Key Set, for example
        /// https://idp.example.com/.well-known/jwks.json.
        uri: String,
    },
}

/// Examples shown at the bottom of `jwt-verification-strategies --help`.
const JWT_VERIFICATION_STRATEGIES_EXAMPLES: &str = r#"Examples:
  Check a remote key set, then create a strategy that uses it:
    JWKS=https://idp.example.com/.well-known/jwks.json
    fabric agent-gateway jwt-verification-strategies validate-jwks-uri "$JWKS"
    fabric agent-gateway jwt-verification-strategies create --file strategy.json
  where strategy.json is:
    {
      "name": "Partner IdP",
      "expected_issuer": "https://idp.example.com/",
      "jwks_source": {
        "type": "remote",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json"
      }
    }

  Pin the keys in the document instead of fetching them:
    "jwks_source": {
      "type": "static",
      "jwks": [{"kty": "RSA", "kid": "2026-09", "n": "...", "e": "AQAB"}]
    }

  Change a strategy: save it, edit it, send it back:
    fabric agent-gateway jwt-verification-strategies get <id> --output json > \
      strategy.json
    fabric agent-gateway jwt-verification-strategies update <id> \
      --file strategy.json"#;

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
                eprintln!(
                    "note: hid 'key_pair', which carries this identity's private key. Pass --reveal to include it."
                );
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
            print_api_keys(&value, output, agent_id.is_some())
        }
        ApiKeyCommand::Get { key_id, surface } => {
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            let value = client
                .request(Method::GET, &api_key_path(&agent_id, &key_id), None)
                .await?;
            print_value(&value, output)
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
            print_api_key_secret(&value, output, "Created")
        }
        ApiKeyCommand::Revoke { key_id, surface, actor, yes } => {
            refuse_without_terminal("revoke", &key_id, yes)?;
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            if !yes
                && !confirm_action("revoke", &key_id, async {
                    format!(
                        "Revoke API key {} of Agent Surface {}?",
                        describe_target(client, &api_key_path(&agent_id, &key_id), &key_id).await,
                        sanitize_whole(&agent_id)
                    )
                })
                .await?
            {
                println!("Aborted. API key '{}' was not revoked.", sanitize_whole(&key_id));
                return Ok(());
            }
            let path = format!("{}/revoke", api_key_path(&agent_id, &key_id));
            let value = client
                .request(Method::POST, &path, Some(json!({"actor": actor})))
                .await?;
            print_outcome(&value, output, &confirmation_line("Revoked", "API key", &key_id))
        }
        ApiKeyCommand::Rotate { key_id, surface, actor, yes } => {
            refuse_without_terminal("rotate", &key_id, yes)?;
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            if !yes
                && !confirm_action("rotate", &key_id, async {
                    format!(
                        "Rotate API key {} of Agent Surface {}? Its current secret will stop working immediately.",
                        describe_target(client, &api_key_path(&agent_id, &key_id), &key_id).await,
                        sanitize_whole(&agent_id)
                    )
                })
                .await?
            {
                println!("Aborted. API key '{}' was not rotated.", sanitize_whole(&key_id));
                return Ok(());
            }
            let path = format!("{}/rotate", api_key_path(&agent_id, &key_id));
            let value = client
                .request(Method::POST, &path, Some(json!({"actor": actor})))
                .await?;
            print_api_key_secret(&value, output, "Rotated")
        }
        ApiKeyCommand::Delete { key_id, surface, yes } => {
            refuse_without_terminal("delete", &key_id, yes)?;
            let agent_id = resolve_api_key_surface(client, &key_id, surface).await?;
            if !yes
                && !confirm_action("delete", &key_id, async {
                    format!(
                        "Delete API key {} of Agent Surface {}?",
                        describe_target(client, &api_key_path(&agent_id, &key_id), &key_id).await,
                        sanitize_whole(&agent_id)
                    )
                })
                .await?
            {
                println!("Aborted. API key '{}' was not deleted.", sanitize_whole(&key_id));
                return Ok(());
            }
            let value = client
                .request(Method::DELETE, &api_key_path(&agent_id, &key_id), None)
                .await?;
            print_outcome(&value, output, &confirmation_line("Deleted", "API key", &key_id))
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

/// Prints the outcome of a delete or an update: the confirmation line in table
/// mode, even when the gateway sent a document back, and the gateway's own
/// answer with `--output json`.
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
        None => print_value(value, output),
    }
}

/// Chooses what a delete or revoke puts on standard output, whether the
/// gateway answered with nothing or with a document: a confirmation for a
/// person reading a table, and the gateway's own document (`null` for an
/// empty body) in JSON mode, where prose would break whatever parses it.
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

/// Prints a create or rotate response for an API key. The secret appears in
/// this response only and the gateway stores nothing but its hash, so table
/// output prints it alone on standard output and the confirmation on standard
/// error.
fn print_api_key_secret(
    value: &Value,
    output: Output,
    verb: &str,
) -> Result<()> {
    let key_id = value
        .get("key_id")
        .and_then(Value::as_str);
    print_issued(value, output, verb, "API key", key_id, Some("secret"))
}

fn print_api_keys(
    value: &Value,
    output: Output,
    filtered: bool,
) -> Result<()> {
    let scope = if filtered {
        Scope::Filtered
    } else {
        Scope::All
    };
    print_list(value, output, &tables::API_KEYS, scope)
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
                yes: true,
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
        assert!(create_kind(&cli.agent_gateway().command).is_some());
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
        assert!(create_kind(&cli.agent_gateway().command).is_none());
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
    fn every_delete_on_the_shared_commands_confirms_with_its_kind_and_id() {
        for (arguments, line) in [
            (["surfaces", "delete", "x-1"], "Deleted surface 'x-1'"),
            (["policies", "delete", "x-1"], "Deleted policy 'x-1'"),
            (["connections", "delete", "x-1"], "Deleted connection 'x-1'"),
            (["connection-points", "delete", "x-1"], "Deleted connection point 'x-1'"),
            (["issuers", "delete", "x-1"], "Deleted issuer 'x-1'"),
            (["authorities", "delete", "x-1"], "Deleted authority 'x-1'"),
            (["trust-registries", "delete", "x-1"], "Deleted trust registry 'x-1'"),
            (["mediators", "delete", "x-1"], "Deleted mediator 'x-1'"),
            (["mcp-proxies", "delete", "x-1"], "Deleted MCP proxy 'x-1'"),
            (["a2a-proxies", "delete", "x-1"], "Deleted A2A proxy 'x-1'"),
            (["sts-clients", "delete", "x-1"], "Deleted STS client 'x-1'"),
            (["credential-providers", "delete", "x-1"], "Deleted credential provider 'x-1'"),
            (["integrations", "delete", "x-1"], "Deleted integration 'x-1'"),
        ] {
            let mut full = vec!["fabric", "agent-gateway"];
            full.extend(arguments);
            let cli = Cli::try_parse_from(&full).expect("delete should parse");

            assert_eq!(delete_confirmation(&cli.agent_gateway().command).as_deref(), Some(line), "{full:?}");
        }
    }

    #[test]
    fn a_delete_confirmation_never_carries_control_characters() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "issuers", "delete", "i\u{1b}[31m-1"])
            .expect("delete should parse");

        let line = delete_confirmation(&cli.agent_gateway().command).expect("a confirmation");

        assert_eq!(line, "Deleted issuer 'i[31m-1'");
    }

    #[test]
    fn a_confirmation_line_keeps_a_typed_id_on_one_line_and_whole() {
        assert_eq!(confirmation_line("Deleted", "issuer", "a\nb\tc\rd"), "Deleted issuer 'a b c d'");

        let long = "i".repeat(800);
        assert_eq!(confirmation_line("Revoked", "grant", &long), format!("Revoked grant '{long}'"));
    }

    #[test]
    fn each_list_command_prints_the_header_of_its_own_resource() {
        for (arguments, header) in [
            (vec!["surfaces", "list"], "NAME  ID  PROTOCOL  ROUTE  TARGET  TRANSIT POINTS"),
            (vec!["policies", "list"], "NAME  ID  DESCRIPTION  ENABLED  VERSION  UPDATED"),
            (vec!["policies", "versions", "p-1"], "VERSION  HASH  CREATED  BY  NOTE"),
            (vec!["connections", "list"], "NAME  ID  TYPE  STATUS  UPDATED"),
            (vec!["connection-points", "list"], "NAME  ID  CONNECTION  ENABLED  USES  EXPIRES"),
            (vec!["issuers", "list"], "NAME  ID  DID  DESCRIPTION"),
            (vec!["authorities", "list"], "NAME  ID  DID  DESCRIPTION"),
            (vec!["trust-registries", "list"], "NAME  ID  DID  DESCRIPTION"),
            (vec!["mediators", "list"], "NAME  ID  STATUS  DID  DESCRIPTION"),
            (vec!["mcp-proxies", "list"], "NAME  ID  STATUS  BASE URL  DESCRIPTION"),
            (vec!["a2a-proxies", "list"], "NAME  ID  STATUS  DESCRIPTION  UPDATED"),
            (vec!["sts-clients", "list"], "NAME  ID  CLIENT ID  SCOPES"),
            (vec!["credential-providers", "list"], "NAME  ID  PROVIDER ID  TYPE"),
            (vec!["certificates", "list"], "NAME  ID  KIND  ACTIVE  UPDATED"),
            (vec!["secrets", "list"], "NAME  ID  SECRET ID  TYPE  DESCRIPTION"),
            (vec!["integrations", "list"], "NAME  ID  TYPE  STATUS  DESCRIPTION"),
            (vec!["users", "list"], "USERNAME  ID  ROLE  STATUS  EMAIL"),
            (vec!["identities", "list"], "DID  ID  VERSION  ACTIVE  UPDATED"),
            (vec!["delegation-vault", "list"], "ID  AGENT DID  PROVIDER  EXPIRES  EXPIRED"),
            (vec!["jwt-verification-strategies", "list"], "NAME  ID  ISSUER  UPDATED"),
        ] {
            let mut full = vec!["fabric", "agent-gateway"];
            full.extend(&arguments);
            let cli = Cli::try_parse_from(&full).expect("command should parse");
            let layout = list_layout(&cli.agent_gateway().command).expect("a list has a layout");

            assert_eq!(tables::render_list(layout, &[json!({})])[0], header, "{full:?}");
        }
    }

    #[test]
    fn lists_that_print_themselves_use_their_own_headers() {
        for (layout, header) in [
            (&tables::API_KEYS, "KEY ID  SURFACE  CLIENT ID  STATUS"),
            (&tables::CONNECTION_SETTINGS, "NAME  HOST  CURRENT"),
            (&tables::PAYMENTS, "ID  STORE  SURFACE  STATUS  AMOUNT  CURRENCY  CREATED"),
            (&tables::AUDIT, "TIMESTAMP  EVENT  SURFACE  DECISION  DETAIL"),
            (&tables::GENERIC, "NAME  ID  DESCRIPTION"),
            (&tables::TOKENS, "NAME  ID  STATUS  SCOPES  CREATED  EXPIRES"),
        ] {
            assert_eq!(tables::render_list(layout, &[json!({})])[0], header);
        }
    }

    #[test]
    fn a_token_name_and_id_are_never_cut_but_the_other_cells_are_cleaned() {
        let long = "n".repeat(700);
        let row = access_token_row(&json!({"id": long, "name": long, "created_at": "2026-09-01\r"}));

        assert_eq!(row[0].len(), 700);
        assert_eq!(row[1].len(), 700);
        assert_eq!(row[4], "2026-09-01 ");
    }

    #[test]
    fn a_token_name_with_a_line_break_or_escape_code_stays_in_its_cell() {
        let row = access_token_row(&json!({"id": "t-1", "name": "ci\nbot\u{1b}[31m", "scopes": ["a\tb"]}));

        assert_eq!(row[0], "ci bot[31m");
        assert_eq!(row[3], "a b");
    }

    #[test]
    fn every_create_kind_has_its_exact_name() {
        for (arguments, kind) in [
            (vec!["connections", "create", "-f", "x"], "connection"),
            (vec!["connection-points", "create", "-f", "x"], "connection point"),
            (vec!["policies", "create", "--id", "p", "--name", "n", "--policy-file", "x"], "policy"),
            (vec!["issuers", "create", "-f", "x"], "issuer"),
            (vec!["authorities", "create", "-f", "x"], "authority"),
            (vec!["trust-registries", "create", "-f", "x"], "trust registry"),
            (vec!["mediators", "create", "-f", "x"], "mediator"),
            (vec!["mcp-proxies", "create", "-f", "x"], "MCP proxy"),
            (vec!["a2a-proxies", "create", "-f", "x"], "A2A proxy"),
            (vec!["sts-clients", "create", "-f", "x"], "STS client"),
            (vec!["credential-providers", "create", "-f", "x"], "credential provider"),
            (vec!["certificates", "create", "-f", "x"], "certificate"),
            (vec!["secrets", "create", "-f", "x"], "secret"),
            (vec!["integrations", "create", "-f", "x"], "integration"),
            (vec!["identities", "create"], "identity"),
            (vec!["jwt-verification-strategies", "create", "-f", "x"], "JWT verification strategy"),
        ] {
            let mut full = vec!["fabric", "agent-gateway"];
            full.extend(&arguments);
            let cli = Cli::try_parse_from(&full).expect("create should parse");

            assert_eq!(create_kind(&cli.agent_gateway().command), Some(kind), "{full:?}");
        }
    }

    #[test]
    fn one_notice_wording_serves_tokens_and_api_keys() {
        assert_eq!(
            shown_once_notice("access token"),
            "note: this is the only time the access token secret is shown, so store it securely now."
        );
        assert_eq!(
            shown_once_notice("API key"),
            "note: this is the only time the API key secret is shown, so store it securely now."
        );
    }

    #[test]
    fn unix_seconds_become_iso_utc_times() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_790_000_000), "2026-09-21T14:13:20Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59Z");
        assert_eq!(iso_utc(-2_208_988_800), "1900-01-01T00:00:00Z");
        assert_eq!(iso_utc(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(iso_utc(4_107_456_000), "2100-02-28T00:00:00Z");
        assert_eq!(iso_utc(32_503_680_000), "3000-01-01T00:00:00Z");
        assert_eq!(iso_utc(253_402_300_799), "9999-12-31T23:59:59Z");
        let row = payment_row_with_iso_time(&json!({"created_at": 1_790_000_000, "id": "x"}));
        assert_eq!(row["created_at"], json!("2026-09-21T14:13:20Z"));
        let fraction = payment_row_with_iso_time(&json!({"created_at": 1.5}));
        assert_eq!(fraction["created_at"], json!(1.5));
        let text = payment_row_with_iso_time(&json!({"created_at": "yesterday"}));
        assert_eq!(text["created_at"], json!("yesterday"));
    }

    #[test]
    fn every_shared_update_names_its_kind_and_the_id_the_user_passed() {
        for (arguments, line) in [
            (vec!["issuers", "update", "i-1", "-f", "x.json"], "Updated issuer 'i-1'"),
            (vec!["connections", "update", "c-1", "-f", "x.json"], "Updated connection 'c-1'"),
            (vec!["mcp-proxies", "update", "m-1", "-f", "x.json"], "Updated MCP proxy 'm-1'"),
            (
                vec!["jwt-verification-strategies", "update", "j-1", "-f", "x.json"],
                "Updated JWT verification strategy 'j-1'",
            ),
            (vec!["identities", "update", "i-1", "-f", "x.json"], "Updated identity 'i-1'"),
            (vec!["surfaces", "update", "s-1", "-f", "x.json"], "Updated surface 's-1'"),
            (
                vec!["surfaces", "add-transit-point", "s-1", "--alias", "billing", "--endpoint", "http://b:1"],
                "Updated surface 's-1'",
            ),
            (vec!["surfaces", "remove-transit-point", "s-1", "billing"], "Updated surface 's-1'"),
        ] {
            let mut full = vec!["fabric", "agent-gateway"];
            full.extend(&arguments);
            let cli = Cli::try_parse_from(&full).expect("update should parse");

            assert_eq!(update_confirmation(&cli.agent_gateway().command).as_deref(), Some(line), "{full:?}");
        }
    }

    #[test]
    fn only_list_commands_have_a_table_layout() {
        for (arguments, listed) in [
            (vec!["surfaces", "list"], true),
            (vec!["policies", "list"], true),
            (vec!["secrets", "list", "--tag", "x"], true),
            (vec!["certificates", "list"], true),
            (vec!["jwt-verification-strategies", "list"], true),
            (vec!["surfaces", "get", "s-1"], false),
            (vec!["issuers", "get", "i-1"], false),
        ] {
            let mut full = vec!["fabric", "agent-gateway"];
            full.extend(&arguments);
            let cli = Cli::try_parse_from(&full).expect("command should parse");

            assert_eq!(list_layout(&cli.agent_gateway().command).is_some(), listed, "{full:?}");
        }
    }

    #[test]
    fn deletes_with_an_answer_of_their_own_keep_the_shared_printer() {
        // `run_api_keys` prints this one itself.
        let arguments = ["fabric", "agent-gateway", "api-keys", "delete", "atgk_1"];
        let cli = Cli::try_parse_from(arguments).expect("the command should parse");

        assert!(delete_confirmation(&cli.agent_gateway().command).is_none(), "{arguments:?} prints its own line");
    }

    #[test]
    fn deactivating_an_identity_confirms_even_when_the_gateway_sends_the_identity_back() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "identities", "deactivate", "i-1"])
            .expect("deactivate should parse");

        assert_eq!(delete_confirmation(&cli.agent_gateway().command).as_deref(), Some("Deactivated identity 'i-1'"));
    }

    #[test]
    fn the_revoke_user_line_uses_the_count_from_the_answer() {
        assert_eq!(revoked_grants_line(&json!({"revoked": 2}), "sha256:a"), "Revoked 2 grants for user 'sha256:a'");
        assert_eq!(revoked_grants_line(&json!({"revoked": 1}), "sha256:a"), "Revoked 1 grant for user 'sha256:a'");
        assert_eq!(revoked_grants_line(&json!({"revoked": 0}), "sha256:a"), "Revoked 0 grants for user 'sha256:a'");
        assert_eq!(revoked_grants_line(&Value::Null, "sha256:a\nb"), "Revoked grants for user 'sha256:a b'");
        assert_eq!(revoked_grants_line(&json!({"revoked": "x"}), "h"), "Revoked grants for user 'h'");
    }
}

/// Runs an `access-tokens` command and prints the result. `list` renders the
/// shared table, `revoke` prints a confirmation line, `create` and `rotate`
/// print the new secret alone with their confirmation on standard error, `get`
/// uses the shared value printer and `scopes` prints one grantable scope per
/// line. `--output json` always emits the raw gateway response (or, for
/// `scopes`, the filtered scope array).
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
            if !args.yes
                && !confirm_action("revoke", &args.id, async {
                    format!(
                        "Revoke access token {}?",
                        describe_target(client, &entity_path("/v1/access-tokens", &args.id), &args.id).await
                    )
                })
                .await?
            {
                println!("Aborted. Access token '{}' was not revoked.", args.id);
                return Ok(());
            }
            let value = client
                .request(Method::DELETE, &entity_path("/v1/access-tokens", &args.id), None)
                .await?;
            print_json_or_else(&value, output, || {
                println!("{}", confirmation_line("Revoked", "access token", &args.id))
            })?;
        }
        AccessTokenCommand::Rotate(args) => {
            if !args.yes
                && !confirm_action("rotate", &args.id, async {
                    format!(
                        "Rotate access token {}? Its current secret will stop working immediately.",
                        describe_target(client, &entity_path("/v1/access-tokens", &args.id), &args.id).await
                    )
                })
                .await?
            {
                println!("Aborted. Access token '{}' was not rotated.", args.id);
                return Ok(());
            }
            let path = format!("{}/rotate", entity_path("/v1/access-tokens", &args.id));
            let value = client
                .request(Method::POST, &path, None)
                .await?;
            print_issued(&value, output, "Rotated", "access token", Some(&args.id), Some("token"))?;
        }
        AccessTokenCommand::Get { id } => {
            let value = client
                .request(Method::GET, &entity_path("/v1/access-tokens", &id), None)
                .await?;
            print_value(&value, output)?;
        }
        AccessTokenCommand::Create(args) => {
            let full_role = args.full_role;
            let mut body = if let Some(file) = args.file {
                read_json(&file)?
            } else {
                access_token_body(args)?
            };
            if let Some(expires_at) = require_scopes_and_expiry(&mut body, full_role, unix_now())? {
                eprintln!(
                    "note: no expiry was given, so this token expires on {expires_at} ({DEFAULT_TOKEN_LIFETIME_DAYS} days from now)"
                );
            }
            let value = client
                .request(Method::POST, "/v1/access-tokens", Some(body))
                .await
                .map_err(add_unknown_scope_hint)?;
            print_issued(&value, output, "Created", "access token", None, Some("token"))?;
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

/// Names what a prompt is about as `'name' (id) on host`, reading the name
/// from the entity's own route. The name is left out when the gateway has none
/// or cannot be asked, so the prompt still shows the id and host.
async fn describe_target(
    client: &GatewayClient,
    path: &str,
    id: &str,
) -> String {
    let name = client
        .request(Method::GET, path, None)
        .await
        .ok()
        .and_then(|entity| {
            ["name", "client_id"]
                .iter()
                .find_map(|key| {
                    entity
                        .get(*key)
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(sanitize_for_terminal)
                })
        });
    let id = sanitize_whole(id);
    let host = sanitize_for_terminal(client.host());
    match name {
        Some(name) => format!("'{name}' ({id}) on {host}"),
        None => format!("{id} on {host}"),
    }
}

/// Fails when a destructive action needs a confirmation (`yes` is not set) and
/// standard input is not a terminal, so the prompt could never be answered.
/// Called before any lookup, so a refused command sends nothing at all.
fn refuse_without_terminal(
    verb: &str,
    id: &str,
    yes: bool,
) -> Result<()> {
    if !yes && !io::stdin().is_terminal() {
        bail!(
            "refusing to {verb} '{}' without confirmation in a non-interactive session; pass --yes to skip the prompt",
            sanitize_whole(id)
        );
    }
    Ok(())
}

/// Show the prompt on standard error to confirm a destructive action (`verb`,
/// e.g. `revoke`) and return whether the operator agreed. The prompt goes to
/// standard error so a piped standard output never swallows it, and is only
/// built (it may ask the gateway for a name) once a terminal is known to be
/// there. Refuses instead of hanging when standard input is not a terminal,
/// since the prompt could never be answered in that case.
async fn confirm_action(
    verb: &str,
    id: &str,
    prompt: impl std::future::Future<Output = String>,
) -> Result<bool> {
    refuse_without_terminal(verb, id, false)?;
    eprint!("{} [y/N] ", prompt.await);
    io::Write::flush(&mut io::stderr()).context("flush the confirmation prompt")?;
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

/// Seconds since the Unix epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Checks a new token's request body before it is sent. A token with no scopes
/// holds the creator's whole role on the whole appliance, so that has to be
/// asked for with `--full-role`. A body with no expiry gets one
/// [`DEFAULT_TOKEN_LIFETIME_DAYS`] days after `now`, which is returned so the
/// caller can say so.
fn require_scopes_and_expiry(
    body: &mut Value,
    full_role: bool,
    now: u64,
) -> Result<Option<String>> {
    let has_scopes = body
        .get("scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| !scopes.is_empty());
    if !has_scopes && !full_role {
        bail!(
            "a token with no scopes would hold your whole role, so name what it may do with --scope (see `fabric \
             agent-gateway tokens scopes`), or pass --full-role if that is what you want"
        );
    }
    let object = body
        .as_object_mut()
        .context("the token request must be a JSON object")?;
    // A missing, null or empty expiry all mean "not chosen", so the default
    // applies; a far-future date is the way to ask for a long-lived token.
    if object
        .get("expires_at")
        .is_some_and(|expires_at| !expires_at.is_null() && expires_at.as_str() != Some(""))
    {
        return Ok(None);
    }
    let expires_at = rfc3339_utc(now + DEFAULT_TOKEN_LIFETIME_DAYS * 86_400);
    object.insert("expires_at".to_owned(), json!(expires_at));
    Ok(Some(expires_at))
}

/// `seconds` since the Unix epoch as an RFC 3339 UTC timestamp.
fn rfc3339_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    // Civil date from a day count (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        remainder % 3_600 / 60,
        remainder % 60
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
    let entries: Vec<Value> = tokens
        .iter()
        .map(access_token_entry)
        .collect();
    print_rows(&tables::TOKENS, &entries, Scope::All);
}

/// A token as the cells of [`tables::TOKENS`]: the status and the scope
/// summary are worked out here, since the gateway sends neither as one value.
fn access_token_entry(token: &Value) -> Value {
    let [name, id, status, scopes, created_at, expires_at] = access_token_row(token);
    json!({
        "name": name,
        "id": id,
        "status": status,
        "scopes": scopes,
        "created_at": created_at,
        "expires_at": expires_at,
    })
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
    let name = tables::whole_cell(&field("name"));
    let id = tables::whole_cell(&field("id"));
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
        .map(|scopes| table_cell(&summarize_scopes(&scopes)))
        .unwrap_or_else(|| FULL_ROLE_SCOPES.to_owned());
    let created = table_cell(&field("created_at"));
    let expires = match field("expires_at").as_str() {
        "-" => "never".to_owned(),
        expires => table_cell(expires),
    };
    [name, id, status, scopes, created, expires]
}

/// SCOPES cell of a token with no scope list, which holds its creator's whole
/// role.
const FULL_ROLE_SCOPES: &str = "full role";

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

/// Lays out a header and rows with the same padding every list uses.
fn format_table<const N: usize>(
    header: &[&str; N],
    rows: &[[String; N]],
) -> Vec<String> {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.to_vec())
        .collect();
    tables::format_rows(header, &rows)
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

/// Longest transit point alias the gateway accepts. This and the character
/// rule in [`new_transit_point`] mirror `TransitPoint::validate_alias` in the
/// gateway's `src/config/agent_surface.rs`, so change them together.
const MAX_TRANSIT_ALIAS_LEN: usize = 63;

/// The alias or id `remove-transit-point` looks up, without surrounding
/// spaces, refusing a blank one.
fn transit_point_to_remove(args: &RemoveTransitPointArgs) -> Result<&str> {
    let named = args.transit_point.trim();
    if named.is_empty() {
        bail!("give the alias or id of the transit point to remove");
    }
    Ok(named)
}

/// The transit point `add-transit-point` sends, after refusing a blank alias,
/// a blank endpoint, or an alias the gateway would not accept.
fn new_transit_point(args: &AddTransitPointArgs) -> Result<Value> {
    let alias = args.alias.trim();
    let endpoint = args.endpoint.trim();
    if alias.is_empty() {
        bail!("give a transit point alias with --alias");
    }
    if endpoint.is_empty() {
        bail!("give the transit point's endpoint with --endpoint");
    }
    let well_formed = alias.starts_with(|c: char| c.is_ascii_lowercase())
        && alias
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        bail!(
            "the alias '{alias}' is not allowed: start with a lowercase letter and use only lowercase letters, digits and '-'"
        );
    }
    if alias.len() > MAX_TRANSIT_ALIAS_LEN {
        bail!("the alias '{alias}' is too long: use at most {MAX_TRANSIT_ALIAS_LEN} characters");
    }
    Ok(json!({"alias": alias, "target_endpoint": endpoint}))
}

async fn add_transit_point(
    client: &GatewayClient,
    args: AddTransitPointArgs,
    output: Output,
) -> Result<Option<Value>> {
    let point = new_transit_point(&args)?;
    let path = entity_path("/v1/surfaces", &args.surface_id);
    let surface = fetch_surface(client, &path).await?;
    surface_patch::require_new_transit_alias(&surface.value, args.alias.trim())?;
    let patch = surface_patch::build_patch(&[], &[], &[format!("transit.points={point}")], &[], &surface.value)?;
    send_surface_patch(client, &path, &surface, patch, args.dry_run, output).await
}

async fn remove_transit_point(
    client: &GatewayClient,
    args: RemoveTransitPointArgs,
    output: Output,
) -> Result<Option<Value>> {
    let named = transit_point_to_remove(&args)?;
    let path = entity_path("/v1/surfaces", &args.surface_id);
    let surface = fetch_surface(client, &path).await?;
    surface_patch::require_transit_point(&surface.value, named)?;
    let patch = surface_patch::build_patch(&[], &[], &[], &[format!("transit.points={named}")], &surface.value)?;
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
        SurfaceCommand::AddTransitPoint(mut args) => {
            new_transit_point(&args)?;
            args.surface_id = resolve_surface_id(client, &args.surface_id).await?;
            SurfaceCommand::AddTransitPoint(args)
        }
        SurfaceCommand::RemoveTransitPoint(mut args) => {
            transit_point_to_remove(&args)?;
            args.surface_id = resolve_surface_id(client, &args.surface_id).await?;
            SurfaceCommand::RemoveTransitPoint(args)
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
        eprintln!("note: {note}");
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
    format!("using surface {} ({})", tables::flatten_capped(surface_id), tables::flatten_capped(name))
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
    let notes = variant_feature_notes(&surface);
    match output {
        Output::Json => {
            let mut rows = features::describe_on_surface(&surface);
            for row in rows
                .as_array_mut()
                .into_iter()
                .flatten()
            {
                let about: Vec<&String> = notes
                    .iter()
                    .filter(|(_, keys)| {
                        row["feature"]
                            .as_str()
                            .is_some_and(|key| keys.contains(&key))
                    })
                    .map(|(text, _)| text)
                    .collect();
                if !about.is_empty() {
                    row["variant_notes"] = json!(about);
                }
            }
            writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)
        }
        Output::Table => {
            write!(out, "{}", surface_features_table(&surface))?;
            if notes.is_empty() {
                return Ok(());
            }
            let lines: Vec<String> = notes
                .iter()
                .map(|(text, _)| format!("  - {}", tables::whole_cell(text)))
                .collect();
            write!(out, "\nNotes\n{}\n", lines.join("\n"))
        }
    }
    .context("print the surface's features")
}

/// Notes on the enabled variants of `surface` that change what the gateway
/// serves, each with the features it is about. A sparse variant that gives a
/// feature a value gets a note naming it, and one with transit points gets a
/// note that transit point features may not match, since those are not
/// itemized. A complete variant replaces whole the blocks it has, so it gets
/// one note naming the blocks and is about every feature that can sit in them,
/// on or off, and any it sets. The table and JSON read only the surface
/// itself.
fn variant_feature_notes(surface: &Value) -> Vec<(String, Vec<&'static str>)> {
    let mut pointers: Vec<&'static str> = Vec::new();
    for placement in features::FEATURES
        .iter()
        .flat_map(|feature| feature.placements)
    {
        if !placement
            .pointer
            .contains("{tp}")
            && !pointers.contains(&placement.pointer)
        {
            pointers.push(placement.pointer);
        }
    }
    let keys_where = |matches: &dyn Fn(&str) -> bool| -> Vec<&'static str> {
        features::FEATURES
            .iter()
            .filter(|feature| {
                feature
                    .placements
                    .iter()
                    .any(|placement| matches(placement.pointer))
            })
            .map(|feature| feature.key)
            .collect()
    };
    let mut notes = Vec::new();
    for variant in enabled_variant_overrides(surface, &pointers) {
        let label = tables::flatten_capped(&variant.label);
        let who = if variant.is_default {
            format!("The default variant '{label}'")
        } else {
            format!("The variant '{label}'")
        };
        let sets = keys_where(&|pointer| {
            variant
                .sets
                .contains(&pointer)
        });
        if variant.complete {
            let replaced: Vec<(&str, &str)> = variant
                .blocks
                .iter()
                .filter_map(|block| match *block {
                    "target" => Some(("the target", "/target/")),
                    "access_point" => Some(("the access point", "/access_point/")),
                    "transit" => Some(("the transit points", "/transit/points/")),
                    "identity_slots" => Some(("the identity slots", "/identity_slots/")),
                    "outbound_credentials" => Some(("the outbound credentials", "/outbound_credentials")),
                    _ => None,
                })
                .collect();
            if replaced.is_empty() {
                continue;
            }
            let names: Vec<&str> = replaced
                .iter()
                .map(|(name, _)| *name)
                .collect();
            let list = match names.split_last() {
                Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
                _ => names.join(", "),
            };
            let also_sets = if sets.is_empty() {
                String::new()
            } else {
                format!(" and sets {}", sets.join(", "))
            };
            let keys = keys_where(&|pointer| {
                variant
                    .sets
                    .contains(&pointer)
                    || replaced
                        .iter()
                        .any(|(_, prefix)| pointer.starts_with(prefix))
            });
            notes.push((
                format!(
                    "{who} is complete, so it replaces {list}{also_sets}, and features it leaves out of them are off for the gateway even if this table shows them on."
                ),
                keys,
            ));
            continue;
        }
        if !sets.is_empty() {
            notes.push((format!("{who} sets {}; this table reads only the surface itself.", sets.join(", ")), sets));
        }
        if variant.changes_transit_points {
            notes.push((
                format!("{who} changes its transit points; transit point features here may not match."),
                keys_where(&|pointer| pointer.starts_with("/transit/points/")),
            ));
        }
    }
    notes
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
                            tables::flatten_capped(&format!("{}: {} ({remove})", place.area, place.field))
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

use crate::client::{REDACTED, RawAuth, clean_for_terminal, gateway_error};

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// List audit events, newest first.
    ///
    /// The log records gateway traffic, such as delegation, policy decisions,
    /// trust checks, VP injection and payments, but not admin API calls (except
    /// revoking delegation tokens). Policy decisions, trust checks and VP
    /// injection are recorded only while audit_enabled and their category are
    /// both on.
    ///
    /// An empty result can also mean the gateway couldn't read its log. Callers'
    /// email and name and each vp_jwt are redacted unless you pass --reveal.
    ///
    /// See docs/OBSERVABILITY.md for details.
    #[command(after_long_help = AUDIT_LIST_EXAMPLES)]
    List(AuditListArgs),
}

/// Examples shown at the bottom of `audit list --help`.
const AUDIT_LIST_EXAMPLES: &str = r#"Examples:
  Policy decisions and trust checks only:
    fabric agent-gateway audit list --category policy_decision,trust_check

  Requests denied at access points:
    fabric agent-gateway audit list --flow access_point --decision deny

  Events that mention "stripe" anywhere, second page of 50:
    fabric agent-gateway audit list --filter stripe --limit 50 --page 2

  Export the whole log as JSON (redacted; add --reveal for the raw values):
    fabric agent-gateway audit list --all --output json > audit.json"#;

#[derive(Debug, Args)]
struct AuditListArgs {
    /// Events per page. The gateway clamps this to 1-500.
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
    /// policy_decision,trust_check,consent_granted,token_injected,payment.
    #[arg(long)]
    category: Option<String>,
    /// Only policy decisions from this request flow; other events are dropped.
    #[arg(long, value_enum)]
    flow: Option<AuditFlow>,
    /// Only policy decisions at this scope; other events are dropped.
    #[arg(long, value_enum)]
    scope: Option<AuditScope>,
    /// Only policy decisions with this outcome; other events are dropped.
    #[arg(long, value_enum)]
    decision: Option<AuditDecision>,
    /// Read every page instead of one. With --output json the per-page
    /// counters are dropped and total is kept.
    #[arg(long)]
    all: bool,
    /// Print the caller's email and name and the full vp_jwt of each event
    /// instead of a placeholder.
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
    ///
    /// The gateway keeps x402 and MPP payments in separate stores. This reads
    /// both and merges them into one table, or reads one with --store. If a
    /// store cannot be read or is not enabled, the rows from the other are
    /// still printed and a warning names it on standard error; the command
    /// fails only when no store could be read.
    #[command(after_long_help = PAYMENTS_LIST_EXAMPLES)]
    List(PaymentsListArgs),
    /// Get one payment record.
    ///
    /// A full record carries the signed payment receipt and rejection
    /// credentials and the payer's signature. Those are replaced with a
    /// placeholder unless --reveal is passed.
    Get {
        /// Payment record ID, from the ID column of `fabric agent-gateway
        /// payments list`.
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
    ///
    /// Pass --yes to confirm: there is no prompt, and without --yes the command
    /// refuses. The deletion cannot be undone. The gateway refuses a
    /// transaction whose verification or settlement is still pending.
    #[command(after_long_help = PAYMENTS_DELETE_EXAMPLES)]
    Delete {
        /// x402 transaction ID, from the ID column of `fabric agent-gateway
        /// payments list --store x402`.
        id: String,
        /// Confirm the deletion. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `payments list --help`.
const PAYMENTS_LIST_EXAMPLES: &str = r#"Examples:
  Verified x402 payments for one surface (pass the surface ID, not its name):
    fabric agent-gateway payments list --store x402 --surface <surface-id> \
      --status verified

  Up to 100 records from each store as JSON, with created_at in Unix seconds:
    fabric agent-gateway payments list --output json"#;

/// Examples shown at the bottom of `payments delete --help`.
const PAYMENTS_DELETE_EXAMPLES: &str = r#"Examples:
  Check the record, then delete it:
    fabric agent-gateway payments get <transaction-id> --store x402
    fabric agent-gateway payments delete <transaction-id> --yes"#;

#[derive(Debug, Args)]
struct PaymentsListArgs {
    /// Store to read. The default reads both and merges them into one table.
    #[arg(long, value_enum, default_value_t = PaymentStore::All)]
    store: PaymentStore,
    /// Only records for the Agent Surface with this ID; a surface name is
    /// not accepted.
    #[arg(long)]
    surface: Option<String>,
    /// Only records with this status, matched case-insensitively. x402
    /// statuses are Pending, Verified, Failed and Timeout; MPP statuses are
    /// verified, failed and challengeissued. MPP records are filtered by the
    /// CLI after --limit is applied, so fewer than --limit may come back.
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
    /// When the gateway has Prometheus authentication on, pass --username and
    /// --password; they are sent as HTTP Basic credentials instead of the
    /// bearer token.
    ///
    /// On standard output, control characters are removed from the
    /// exposition; a file named with --output-file gets it exactly as sent.
    #[command(after_long_help = METRICS_SCRAPE_EXAMPLES)]
    Scrape(MetricsScrapeArgs),
    /// Check whether the gateway can reach an OTLP endpoint.
    ///
    /// The gateway only opens a TCP connection to the endpoint, with a
    /// 5-second timeout, and sends no telemetry. The command exits non-zero
    /// when the connection fails. The gateway refuses some URLs without
    /// trying them, such as one whose scheme is not http or https, or a
    /// loopback address.
    #[command(name = "test-endpoint")]
    TestEndpoint {
        /// OTLP endpoint to open a connection to, including the scheme.
        url: String,
    },
    /// Delete metrics older than the configured retention period.
    ///
    /// Pass --yes to confirm: there is no prompt, and without --yes the command
    /// refuses. Deleted metrics cannot be recovered.
    #[command(after_long_help = METRICS_TRUNCATE_EXAMPLES)]
    Truncate {
        /// Confirm the truncation. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `metrics scrape --help`.
const METRICS_SCRAPE_EXAMPLES: &str = r#"Examples:
  Check the exposition with promtool:
    fabric agent-gateway metrics scrape | promtool check metrics

  With Prometheus authentication on, read the password without echoing it and
  save to a file:
    export FABRIC_METRICS_USERNAME=prometheus
    read -rs FABRIC_METRICS_PASSWORD && export FABRIC_METRICS_PASSWORD
    fabric agent-gateway metrics scrape --output-file metrics.txt"#;

/// Examples shown at the bottom of `metrics truncate --help`.
const METRICS_TRUNCATE_EXAMPLES: &str = r#"Examples:
  Check the retention period, then delete older metrics:
    fabric agent-gateway metrics config show
    fabric agent-gateway metrics truncate --yes"#;

#[derive(Debug, Subcommand)]
enum MetricsConfigCommand {
    /// Show the metrics configuration.
    Show,
    /// Replace the whole metrics configuration from a JSON document.
    ///
    /// This is not a patch: leaving out `opentelemetry.auth` removes it, which
    /// switches collector export to unauthenticated, and leaving out
    /// `retention`, `advanced` or `opentelemetry.protocol` resets it to the
    /// gateway's default. So the CLI first compares the document with the live
    /// configuration and refuses one that would drop a stored setting.
    ///
    /// The gateway reports success once the file is saved, even if applying it
    /// to the running collector failed, so read the `message` it returns.
    #[command(after_long_help = METRICS_CONFIG_SET_EXAMPLES)]
    Set(MetricsFileArgs),
}

/// Examples shown at the bottom of `metrics config set --help`.
const METRICS_CONFIG_SET_EXAMPLES: &str = r#"Examples:
  Edit the live configuration and send it back whole:
    fabric agent-gateway metrics config show --output json > metrics.json
    fabric agent-gateway metrics config set --file metrics.json

  Remove a stored setting on purpose, such as opentelemetry.auth, by skipping
  the check:
    fabric agent-gateway metrics config set --file metrics.json --force"#;

/// The replacement metrics document, plus the override for the pre-flight
/// check that refuses one dropping a stored setting.
#[derive(Debug, Args)]
struct MetricsFileArgs {
    /// JSON request body. Use '-' to read from standard input.
    #[arg(short, long)]
    file: PathBuf,
    /// Skip the check against the live configuration, to remove a stored
    /// setting on purpose.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct MetricsScrapeArgs {
    /// Prometheus Basic-auth user configured in the gateway's admin settings.
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

#[derive(Debug, Subcommand)]
enum LogsCommand {
    /// Download every log file as one ZIP archive.
    ///
    /// The gateway builds the whole archive in memory before sending it, so
    /// this is expensive on a large log directory. An existing file at
    /// --output-file is overwritten without asking.
    ///
    /// There is no overall time limit: the download stops only if the gateway
    /// sends nothing for 120 seconds.
    #[command(after_long_help = LOGS_DOWNLOAD_EXAMPLES)]
    Download {
        /// Where to write the archive. '-' is standard output.
        #[arg(long, default_value = "logs.zip")]
        output_file: PathBuf,
    },
    /// Delete every rotated log file, keeping the current one.
    ///
    /// The gateway keeps agent-gateway.log and removes the rotated
    /// agent-gateway*.log* files. Pass --yes to confirm: there is no prompt,
    /// and without --yes the command refuses. Download the logs first if you
    /// may need them.
    #[command(after_long_help = LOGS_TRUNCATE_EXAMPLES)]
    Truncate {
        /// Confirm the deletion. Required; there is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `logs download --help`.
const LOGS_DOWNLOAD_EXAMPLES: &str = r#"Examples:
  Save the archive under a dated name:
    fabric agent-gateway logs download \
      --output-file "gateway-logs-$(date +%F).zip""#;

/// Examples shown at the bottom of `logs truncate --help`.
const LOGS_TRUNCATE_EXAMPLES: &str = r#"Examples:
  Keep a copy, then delete the rotated log files:
    fabric agent-gateway logs download --output-file logs.zip
    fabric agent-gateway logs truncate --yes"#;

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
        Output::Table => {
            let filtered = args.page > 1
                || args.filter.is_some()
                || args.category.is_some()
                || args.flow.is_some()
                || args.scope.is_some()
                || args.decision.is_some();
            print_audit_table(
                &response,
                if filtered {
                    Scope::Filtered
                } else {
                    Scope::All
                },
            )?
        }
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

/// Printed to standard error beneath "No audit events yet.", for the operator who
/// expected events: why the log can be empty, and what it never records.
const EMPTY_AUDIT_NOTES: [&str; 2] = [
    "An empty result is ambiguous: the gateway answers 200 with no events when the audit log is empty, when its \
     audit subsystem failed to start, and when it cannot read the audit file or the file is not valid UTF-8. It \
     also drops any line of the file it cannot parse without saying so.",
    "The audit log records gateway traffic (delegation consent and tokens, policy decisions, trust checks, VP \
     injection, payments, trace terminations); admin API calls such as creating an identity are not audited, \
     except revoking delegation tokens.",
];

fn print_audit_table(
    response: &Value,
    scope: Scope,
) -> Result<()> {
    write_audit_table(response, &mut io::stdout().lock(), &mut io::stderr().lock(), scope)
        .context("print the audit table")
}

/// Writes the events to `rows` as the shared audit table, or, for an empty
/// result, "No audit events yet." (or "No matching audit events." when a filter
/// was given) to `rows` and [`EMPTY_AUDIT_NOTES`] to `notes`,
/// so piped output stays clean. `rows` is standard output and `notes` standard
/// error.
fn write_audit_table(
    response: &Value,
    rows: &mut impl io::Write,
    notes: &mut impl io::Write,
    scope: Scope,
) -> io::Result<()> {
    let events: Vec<Value> = response
        .get("events")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(audit_row)
        .collect();
    for line in tables::render_scoped(&tables::AUDIT, &events, scope) {
        writeln!(rows, "{line}")?;
    }
    if events.is_empty() {
        for note in EMPTY_AUDIT_NOTES {
            writeln!(notes, "note: {note}")?;
        }
    }
    Ok(())
}

/// Flattens one audit event into the `timestamp`, `event`, `surface_id`,
/// `decision` and `detail` fields of [`tables::AUDIT`]. Events carry none of
/// the `id`, `name` or `description` keys the generic list looks for, and the
/// event itself is either a bare string or a tagged object such as
/// `{"policy_decision": {...}}`, so the table cannot read them in place. A
/// missing field is left out and prints as `-`; `detail` is the gateway's own
/// note on the event, such as how many tokens a revocation removed.
fn audit_row(event: &Value) -> Value {
    let (name, details) = match event.get("event") {
        Some(Value::String(name)) => (Some(name.as_str()), None),
        Some(Value::Object(tagged)) => match tagged.iter().next() {
            Some((name, value)) => (Some(name.as_str()), value.as_object()),
            None => (None, None),
        },
        _ => (None, None),
    };
    let field = |key: &str| {
        details
            .and_then(|fields| fields.get(key))
            .and_then(Value::as_str)
    };
    json!({
        "timestamp": event.get("timestamp"),
        "event": name,
        "surface_id": event
            .get("surface_id")
            .and_then(Value::as_str)
            .or_else(|| field("surface_id")),
        "decision": field("decision"),
        "detail": event.get("detail"),
    })
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
        eprintln!("warning: {note}");
    }

    sort_payments_newest_first(&mut rows);
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(&Value::Array(rows))?),
        Output::Table => {
            let shown: Vec<Value> = rows
                .iter()
                .map(payment_row_with_iso_time)
                .collect();
            let scope = if args.surface.is_some() || args.status.is_some() {
                Scope::Filtered
            } else if !failed.is_empty() {
                Scope::Partial
            } else {
                Scope::All
            };
            print_rows(&tables::PAYMENTS, &shown, scope);
            for footer in &footers {
                eprintln!("note: {footer}");
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
            Ok(Some(record)) => {
                let document = payment_document(record, reveal);
                let document = match output {
                    Output::Table => payment_row_with_iso_time(&document),
                    Output::Json => document,
                };
                return print_value(&document, output);
            }
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
        return print_value(&stats, output);
    }
    let sync_status = payments_get(client, PaymentStore::X402, "/admin/x402/sync-status")
        .await?
        .unwrap_or(Value::Null);
    print_value(&json!({"stats": stats, "sync_status": sync_status}), output)
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
            println!("{}", confirmation_line("Deleted", "x402 payment", id));
            Ok(())
        }
        // Mirror `GatewayClient::request`, which reports an empty body as a
        // null document, so a JSON consumer never has to parse prose.
        Output::Json => print_value(&serde_json::from_slice(&body).unwrap_or(Value::Null), output),
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

/// A payment row for table output, with `created_at`, which both stores keep
/// as Unix seconds, shown as an ISO 8601 UTC time like the tokens and audit
/// tables. A value that is not a whole number of seconds is left alone.
fn payment_row_with_iso_time(row: &Value) -> Value {
    let mut row = row.clone();
    if let Some(seconds) = row
        .get("created_at")
        .and_then(Value::as_i64)
    {
        row["created_at"] = json!(iso_utc(seconds));
    }
    row
}

/// `1790000000` as `2026-09-21T14:13:20Z`.
fn iso_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    // Civil date from a day count since 1970-01-01 (proleptic Gregorian).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", time / 3_600, time % 3_600 / 60, time % 60)
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
            print_value(&value, output)
        }
        MetricsCommand::Config {
            command: MetricsConfigCommand::Set(args),
        } => set_metrics_config(client, args, output, &mut io::stdout()).await,
        MetricsCommand::Status => {
            let value = client
                .request(Method::GET, "/v1/metrics/otlp-status", None)
                .await?;
            print_value(&value, output)
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
            print_value(&value, output)
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
    write_response_body(&args.output_file, &scrape_output(&args.output_file, &body))
}

/// The bytes a scrape writes. Metric names and labels come from the gateway, so
/// what goes to standard output (the terminal) is stripped of control
/// characters like any other server text; a file gets the body as sent.
fn scrape_output(
    path: &Path,
    body: &[u8],
) -> Vec<u8> {
    if path == Path::new("-") {
        sanitize_multiline(&String::from_utf8_lossy(body)).into_bytes()
    } else {
        body.to_vec()
    }
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
    print_value(&value, output)
}

async fn run_logs(
    client: &GatewayClient,
    command: LogsCommand,
    output: Output,
) -> Result<()> {
    match command {
        LogsCommand::Download { output_file } => {
            let (status, body) = client
                .download_bytes("/v1/logs/download")
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
            print_value(&value, output)
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
    eprintln!("note: wrote {} bytes to {}", body.len(), path.display());
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
        assert_eq!(audit_line(&event), "2026-09-21T10:00:00Z  policy_decision  sales    deny      -");
    }

    #[test]
    fn audit_row_reads_a_fieldless_action() {
        let event = json!({
            "timestamp": "2026-09-21T10:00:00Z",
            "event": "consent_granted",
            "surface_id": "sales",
        });
        assert_eq!(audit_line(&event), "2026-09-21T10:00:00Z  consent_granted  sales    -         -");
    }

    /// A reviewer saw nothing after creating an identity with every audit
    /// setting on: admin API calls are never audited, so an empty result says
    /// so beside the note that it can also mean a failed audit subsystem.
    #[test]
    fn an_empty_audit_result_says_admin_calls_are_not_audited() {
        let (rows, notes) = audit_table(&json!({"events": [], "total": 0}));

        assert_eq!(rows, "No audit events yet.\n");
        assert!(
            notes
                .lines()
                .all(|line| line.starts_with("note: ")),
            "got: {notes}"
        );
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

        assert_eq!(
            rows,
            "TIMESTAMP  EVENT                SURFACE  DECISION  DETAIL\nt1         user_tokens_revoked  -        -         -\n"
        );
        assert_eq!(notes, "");
    }

    /// What `audit list` prints in table mode, as its standard output and
    /// standard error.
    fn audit_table(response: &Value) -> (String, String) {
        let (mut rows, mut notes) = (Vec::new(), Vec::new());
        write_audit_table(response, &mut rows, &mut notes, Scope::All).expect("write to memory");
        (String::from_utf8(rows).expect("UTF-8 rows"), String::from_utf8(notes).expect("UTF-8 notes"))
    }

    /// The data line `audit list` prints for one event, without the header.
    fn audit_line(event: &Value) -> String {
        tables::render_list(&tables::AUDIT, &[audit_row(event)]).remove(1)
    }

    #[test]
    fn audit_row_falls_back_to_dashes() {
        assert_eq!(audit_line(&json!({})), "-          -      -        -         -");
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
        assert_eq!(
            audit_line(&event),
            "2026-09-21T10:00:00Z  user_tokens_revoked  -        -         0 tokens revoked"
        );
    }

    /// The detail is gateway-supplied text, so it must not drive the terminal
    /// or split one event across rows.
    #[test]
    fn audit_row_sanitises_the_event_detail() {
        let event = json!({"event": "trace_terminated", "detail": "a\u{1b}[2J\rb\tc\nd"});
        assert_eq!(audit_line(&event), "-          trace_terminated  -        -         a[2J b c d");

        let blank = json!({"event": "trace_terminated", "detail": "\u{1b}"});
        assert_eq!(audit_line(&blank), "-          trace_terminated  -        -         -");
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
        assert_eq!(audit_line(&event), "2026-09-21[2J  policy decision  sales support  deny      -");
    }

    #[test]
    fn payment_table_row_sanitises_every_cell() {
        let row = payment_row(
            PaymentStore::X402,
            &json!({"id": "tx\u{1b}[2J1", "surface_id": "sales\tsupport", "status": "Verified\n", "amount": "\u{7}", "asset": "USDC", "created_at": 100}),
        );
        assert_eq!(
            tables::render_list(&tables::PAYMENTS, &[row])[1],
            "tx[2J1  x402   sales support  Verified   -       USDC      100"
        );
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
        assert_eq!(
            tables::render_list(&tables::PAYMENTS, &[row])[1],
            "mpp-1  mpp    -        -       -       -         200"
        );
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
    // The gateway's PATCH routes (surfaces and variants) take only a JSON Merge Patch, which needs its own content type.
    if matches!(args.method, ApiMethod::Patch) {
        let patch = body.context("api patch needs a body: give --data or --file")?;
        return client
            .merge_patch(&args.path, patch)
            .await;
    }
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
) -> Result<()> {
    match output {
        Output::Json => println!("{}", pretty_json_for_terminal(value)?),
        Output::Table => print_table(value),
    }
    Ok(())
}

/// The line shown beneath what a create or rotate printed, when the answer
/// carries a secret that is never shown again. `kind` is `access token` or
/// `API key`.
fn shown_once_notice(kind: &str) -> String {
    format!("note: this is the only time the {kind} secret is shown, so store it securely now.")
}

/// Prints the answer to a create or a rotate. Table output is the confirmation
/// line, `Created <kind> '<id>'`, using `requested_id` when the command knows
/// the id and else the one in the answer. When the answer carries a secret in
/// `secret_field` (a token or key the user has to keep), standard output is
/// that secret alone and the confirmation goes to standard error. A secret
/// with control characters is refused, after the gateway made it, with an
/// error that names the id. `--output json` prints the answer as it
/// is, and an answer with neither an id nor a secret is printed as the shared
/// printer would.
fn print_issued(
    value: &Value,
    output: Output,
    verb: &str,
    kind: &str,
    requested_id: Option<&str>,
    secret_field: Option<&str>,
) -> Result<()> {
    let secret = secret_field
        .and_then(|field| value.get(field))
        .and_then(Value::as_str);
    let id = requested_id.or_else(|| id_from_response(value));
    if matches!(output, Output::Table)
        && secret.is_some_and(|secret| {
            secret
                .chars()
                .any(char::is_control)
                || sanitize_whole(secret) != secret
        })
    {
        let what = match id {
            Some(id) => confirmation_line(verb, kind, id),
            None => format!("{verb} {kind}"),
        };
        let remedy = if verb == "Created" {
            "Revoke it, or rotate it with --output json to get a new secret."
        } else {
            "Run the rotate command again with --output json to get a new secret."
        };
        bail!("{what} but its secret contains control characters and was not printed. {remedy}");
    }
    // The reminder goes to standard error in both modes, so it never touches
    // what a script reads from standard output.
    if secret.is_some() {
        eprintln!("{}", shown_once_notice(kind));
    }
    if matches!(output, Output::Json) {
        return print_value(value, output);
    }
    if id.is_none() && secret.is_none() {
        return print_value(value, output);
    }
    // A secret goes alone to standard output, so `$(...)` captures just that;
    // the confirmation then moves to standard error.
    if let Some(id) = id {
        let line = confirmation_line(verb, kind, id);
        if secret.is_some() {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
    if let Some(secret) = secret {
        println!("{secret}");
    }
    Ok(())
}

/// Prints the answer to a shared create: [`print_issued`] for a resource kind
/// that a create command was given, otherwise the shared printer.
fn print_created_or_value(
    value: &Value,
    output: Output,
    created: Option<&str>,
) -> Result<()> {
    match created {
        Some(kind) => print_issued(value, output, "Created", kind, None, None),
        None => print_value(value, output),
    }
}

fn print_table(value: &Value) {
    match value {
        Value::Array(rows) => print_rows(&tables::GENERIC, rows, Scope::All),
        // A single entity: show the full configuration, matching the UX config view.
        Value::Object(_) => match serde_json::to_string_pretty(value) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("{value}"),
        },
        other => println!("{other}"),
    }
}

fn print_rows(
    layout: &Layout,
    rows: &[Value],
    scope: Scope,
) {
    for line in tables::render_scoped(layout, rows, scope) {
        println!("{line}");
    }
}

/// Prints a list in the layout of its resource. `--output json` and anything
/// that is not a plain list go through the shared printer unchanged.
fn print_list(
    value: &Value,
    output: Output,
    layout: &Layout,
    scope: Scope,
) -> Result<()> {
    match (output, value) {
        (Output::Table, Value::Array(rows)) => {
            print_rows(layout, rows, scope);
            Ok(())
        }
        _ => print_value(value, output),
    }
}

/// Why an empty list from this command is empty: nothing exists yet, or
/// nothing matched the filter the command was given.
fn list_scope(command: &Command) -> Scope {
    match command {
        Command::Secrets {
            command: SecretCommand::List { tag: Some(_) },
            ..
        } => Scope::Filtered,
        _ => Scope::All,
    }
}

/// The columns a command that prints a list of records uses, or `None` for
/// any other command.
fn list_layout(command: &Command) -> Option<&'static Layout> {
    Some(match command {
        Command::Surfaces { command: SurfaceCommand::List } => &tables::SURFACES,
        Command::Connections { command: CrudCommand::List } => &tables::CONNECTIONS,
        Command::ConnectionPoints { command: CrudCommand::List } => &tables::CONNECTION_POINTS,
        Command::Policies { command: PolicyCommand::List } => &tables::POLICIES,
        Command::Policies {
            command: PolicyCommand::Versions { .. },
        } => &tables::POLICY_VERSIONS,
        Command::Issuers { command: CrudCommand::List } => &tables::ISSUERS,
        Command::Authorities { command: CrudCommand::List } => &tables::AUTHORITIES,
        Command::TrustRegistries { command: CrudCommand::List } => &tables::TRUST_REGISTRIES,
        Command::Mediators { command: CrudCommand::List } => &tables::MEDIATORS,
        Command::McpProxies { command: CrudCommand::List } => &tables::MCP_PROXIES,
        Command::A2aProxies { command: CrudCommand::List } => &tables::A2A_PROXIES,
        Command::StsClients { command: CrudCommand::List } => &tables::STS_CLIENTS,
        Command::CredentialProviders { command: CrudCommand::List } => &tables::CREDENTIAL_PROVIDERS,
        Command::Certificates { command: CrudCommand::List, .. } => &tables::CERTIFICATES,
        Command::Secrets {
            command: SecretCommand::List { .. },
            ..
        } => &tables::SECRETS,
        Command::Integrations { command: CrudCommand::List } => &tables::INTEGRATIONS,
        Command::Users { command: UserCommand::List } => &tables::USERS,
        Command::Identities { command: IdentityCommand::List } => &tables::IDENTITIES,
        Command::DelegationVault {
            command: DelegationVaultCommand::List,
        } => &tables::GRANTS,
        Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::List),
        } => &tables::JWT_STRATEGIES,
        _ => return None,
    })
}

/// The line a delete prints in table mode, such as `Deleted issuer 'i-1'`.
/// Most deletes answer with an empty body, which the shared printer would show
/// as the word `null`, and a surface answers with a document nobody asked to
/// read. `--output json` still prints whatever the gateway returned. Deletes
/// that print their own line (certificates, secrets, grant revoke, token
/// revoke, API keys, payments) are absent.
fn delete_confirmation(command: &Command) -> Option<String> {
    let (kind, id) = match command {
        Command::Users {
            command: UserCommand::Delete { user_id },
        } => ("user", user_id),
        Command::Identities {
            command: IdentityCommand::Deactivate { id },
        } => return Some(confirmation_line("Deactivated", "identity", id)),
        Command::Surfaces {
            command: SurfaceCommand::Delete { surface_id },
        } => ("surface", surface_id),
        Command::Policies {
            command: PolicyCommand::Delete { policy_id },
        } => ("policy", policy_id),
        Command::Connections {
            command: CrudCommand::Delete { id },
        } => ("connection", id),
        Command::ConnectionPoints {
            command: CrudCommand::Delete { id },
        } => ("connection point", id),
        Command::Issuers {
            command: CrudCommand::Delete { id },
        } => ("issuer", id),
        Command::Authorities {
            command: CrudCommand::Delete { id },
        } => ("authority", id),
        Command::TrustRegistries {
            command: CrudCommand::Delete { id },
        } => ("trust registry", id),
        Command::Mediators {
            command: CrudCommand::Delete { id },
        } => ("mediator", id),
        Command::McpProxies {
            command: CrudCommand::Delete { id },
        } => ("MCP proxy", id),
        Command::A2aProxies {
            command: CrudCommand::Delete { id },
        } => ("A2A proxy", id),
        Command::StsClients {
            command: CrudCommand::Delete { id },
        } => ("STS client", id),
        Command::CredentialProviders {
            command: CrudCommand::Delete { id },
        } => ("credential provider", id),
        Command::Integrations {
            command: CrudCommand::Delete { id },
        } => ("integration", id),
        Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::Delete { id }),
        } => ("JWT verification strategy", id),
        _ => return None,
    };
    Some(confirmation_line("Deleted", kind, id))
}

/// The one line every delete, revoke, create or update prints in table mode,
/// such as `Deleted issuer 'i-1'`. The id may be what the user typed, so it is
/// cleaned with [`tables::flatten`] and never cut.
fn confirmation_line(
    verb: &str,
    kind: &str,
    id: &str,
) -> String {
    format!("{verb} {kind} '{}'", tables::flatten(id))
}

/// The kind a shared create command makes, named as the delete lines name it.
/// Surface, access token and API key creates print themselves.
fn create_kind(command: &Command) -> Option<&'static str> {
    Some(match command {
        Command::Connections {
            command: CrudCommand::Create(_),
        } => "connection",
        Command::ConnectionPoints {
            command: CrudCommand::Create(_),
        } => "connection point",
        Command::Policies {
            command: PolicyCommand::Create { .. },
        } => "policy",
        Command::Issuers {
            command: CrudCommand::Create(_),
        } => "issuer",
        Command::Authorities {
            command: CrudCommand::Create(_),
        } => "authority",
        Command::TrustRegistries {
            command: CrudCommand::Create(_),
        } => "trust registry",
        Command::Mediators {
            command: CrudCommand::Create(_),
        } => "mediator",
        Command::McpProxies {
            command: CrudCommand::Create(_),
        } => "MCP proxy",
        Command::A2aProxies {
            command: CrudCommand::Create(_),
        } => "A2A proxy",
        Command::StsClients {
            command: CrudCommand::Create(_),
        } => "STS client",
        Command::CredentialProviders {
            command: CrudCommand::Create(_),
        } => "credential provider",
        Command::Certificates {
            command: CrudCommand::Create(_),
            ..
        } => "certificate",
        Command::Secrets {
            command: SecretCommand::Create(_),
            ..
        } => "secret",
        Command::Integrations {
            command: CrudCommand::Create(_),
        } => "integration",
        Command::Identities {
            command: IdentityCommand::Create { .. },
        } => "identity",
        Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::Create(_)),
        } => "JWT verification strategy",
        _ => return None,
    })
}

/// The line an update prints in table mode, such as `Updated issuer 'i-1'`,
/// with the id the user passed, which for a surface is already the resolved id.
/// Certificate and secret updates print their own line from the resolved id.
/// `--output json` still prints what the gateway returned. A surface dry run
/// never gets here, since it prints its own result.
fn update_confirmation(command: &Command) -> Option<String> {
    let (kind, id) = match command {
        Command::Users {
            command: UserCommand::Update { user_id, .. },
        } => ("user", user_id),
        Command::Surfaces {
            command: SurfaceCommand::Update { surface_id, .. },
        } => ("surface", surface_id),
        Command::Policies {
            command: PolicyCommand::Update { policy_id, .. },
        } => ("policy", policy_id),
        Command::Connections {
            command: CrudCommand::Update { id, .. },
        } => ("connection", id),
        Command::ConnectionPoints {
            command: CrudCommand::Update { id, .. },
        } => ("connection point", id),
        Command::Issuers {
            command: CrudCommand::Update { id, .. },
        } => ("issuer", id),
        Command::Authorities {
            command: CrudCommand::Update { id, .. },
        } => ("authority", id),
        Command::TrustRegistries {
            command: CrudCommand::Update { id, .. },
        } => ("trust registry", id),
        Command::Mediators {
            command: CrudCommand::Update { id, .. },
        } => ("mediator", id),
        Command::McpProxies {
            command: CrudCommand::Update { id, .. },
        } => ("MCP proxy", id),
        Command::A2aProxies {
            command: CrudCommand::Update { id, .. },
        } => ("A2A proxy", id),
        Command::StsClients {
            command: CrudCommand::Update { id, .. },
        } => ("STS client", id),
        Command::CredentialProviders {
            command: CrudCommand::Update { id, .. },
        } => ("credential provider", id),
        Command::Integrations {
            command: CrudCommand::Update { id, .. },
        } => ("integration", id),
        Command::JwtVerificationStrategies {
            command: JwtStrategyCommand::Crud(CrudCommand::Update { id, .. }),
        } => ("JWT verification strategy", id),
        Command::Identities {
            command: IdentityCommand::Update { id, .. },
        } => ("identity", id),
        Command::Surfaces {
            command: SurfaceCommand::AddFeature(AddFeatureArgs { surface_id, .. }),
        }
        | Command::Surfaces {
            command: SurfaceCommand::RemoveFeature(FeaturePlacementArgs { surface_id, .. }),
        }
        | Command::Surfaces {
            command: SurfaceCommand::AddTransitPoint(AddTransitPointArgs { surface_id, .. }),
        }
        | Command::Surfaces {
            command: SurfaceCommand::RemoveTransitPoint(RemoveTransitPointArgs { surface_id, .. }),
        } => ("surface", surface_id),
        _ => return None,
    };
    Some(confirmation_line("Updated", kind, id))
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

        let info = whoami_info(&config, &credentials, None, None, HostFlags::default(), None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["token_stored"], json!(true));
        assert_eq!(info["authenticated"], json!(true));
    }

    #[tokio::test]
    async fn whoami_reports_a_typed_token_for_a_saved_connection_as_not_stored() {
        let host = one_shot_server("HTTP/1.1 200 OK", "{}").await;
        let config = config_with_connection("local", &host);

        let info = whoami_info(&config, &UnreachableKeyring, None, None, HostFlags::default(), Some("agpat_typed"))
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["connection"], json!("local"));
        assert_eq!(info["token_stored"], json!(false));
    }

    #[tokio::test]
    async fn whoami_reports_unauthenticated_for_invalid_pat() {
        let host = one_shot_server("HTTP/1.1 401 Unauthorized", "{}").await;
        let config = config_with_connection("local", &host);
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("local", "agpat_invalid")
            .unwrap();

        let info = whoami_info(&config, &credentials, None, None, HostFlags::default(), None)
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

        let info = whoami_info(&config, &credentials, None, None, HostFlags::default(), None)
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

        let info = whoami_info(&config, &credentials, None, None, HostFlags::default(), None)
            .await
            .expect("whoami_info should succeed");

        assert_eq!(info["authenticated"], json!(false));
    }

    #[tokio::test]
    async fn insert_token_details_copies_pat_scopes() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"scopes": ["tokens.read"]}"#).await;
        let client = GatewayClient::new(host, "agpat_valid").unwrap();
        let mut fields = serde_json::Map::new();

        insert_token_details(&mut fields, &client).await;

        assert_eq!(fields.get("scopes"), Some(&json!(["tokens.read"])));
    }

    #[tokio::test]
    async fn insert_token_details_leaves_fields_unchanged_on_error() {
        let host = one_shot_server("HTTP/1.1 500 Internal Server Error", "").await;
        let client = GatewayClient::new(host, "agpat_valid").unwrap();
        let mut fields = serde_json::Map::new();

        insert_token_details(&mut fields, &client).await;

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

    /// Serves one canned response per connection, in order, and records every
    /// request it receives. Returns its base URL and the recorded requests.
    async fn recording_server(responses: Vec<&'static str>) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            for response in responses {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..read]).into_owned());
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), requests)
    }

    /// A 200 answer carrying `body`, as the one canned response of a recording server.
    fn ok_json(body: &str) -> &'static str {
        Box::leak(
            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                .into_boxed_str(),
        )
    }

    const OK_EMPTY: &str = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
    const OK_EMPTY_LIST: &str = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n[]";

    fn gateway_args(args: &[&str]) -> AgentGatewayArgs {
        Cli::try_parse_from(
            ["fabric", "agent-gateway"]
                .into_iter()
                .chain(args.iter().copied()),
        )
        .expect("arguments should parse")
        .into_agent_gateway()
    }

    fn credentials_bound_to(
        connection: &str,
        token: &str,
        host: &str,
    ) -> MemoryCredentials {
        let credentials = MemoryCredentials::default();
        credentials
            .set_token(connection, token)
            .unwrap();
        credentials
            .set_bound_host(connection, host)
            .unwrap();
        credentials
    }

    #[test]
    fn the_saved_token_goes_to_the_host_it_was_saved_for() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = credentials_bound_to("prod", "agpat_x", "https://gateway.example.com");
        check_token_host(&credentials, "prod", &saved, "https://gateway.example.com", false).unwrap();
        check_token_host(&credentials, "prod", &saved, "https://GATEWAY.example.com:443/", false).unwrap();
    }

    #[test]
    fn the_saved_token_is_not_sent_to_another_host() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = credentials_bound_to("prod", "agpat_x", "https://gateway.example.com");
        let error = check_token_host(&credentials, "prod", &saved, "https://evil.example.net", false)
            .expect_err("another host must be refused");
        let message = error.to_string();
        assert!(message.contains("belongs to https://gateway.example.com"), "{message}");
        assert!(message.contains("not sent to https://evil.example.net"), "{message}");
        assert!(message.contains("--allow-host-override"), "{message}");
        assert!(!message.contains("agpat_x"), "{message}");
    }

    #[test]
    fn the_saved_token_goes_to_another_host_when_asked_to() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = credentials_bound_to("prod", "agpat_x", "https://gateway.example.com");
        check_token_host(&credentials, "prod", &saved, "https://other.example.net", true).unwrap();
    }

    #[test]
    fn a_connection_saved_before_hosts_were_bound_uses_its_configured_host() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("prod", "agpat_x")
            .unwrap();
        check_token_host(&credentials, "prod", &saved, "https://gateway.example.com", false).unwrap();
        check_token_host(&credentials, "prod", &saved, "https://evil.example.net", false)
            .expect_err("an unbound token must still stay with its configured host");
    }

    #[test]
    fn an_edited_configuration_host_does_not_move_a_bound_token() {
        let edited = Connection::new("https://evil.example.net".into());
        let credentials = credentials_bound_to("prod", "agpat_x", "https://gateway.example.com");
        check_token_host(&credentials, "prod", &edited, "https://evil.example.net", false)
            .expect_err("the host the token was issued for wins over the configuration file");
    }

    #[tokio::test]
    async fn a_command_with_another_host_sends_nothing_without_the_opt_in() {
        let (other, requests) = recording_server(vec![OK_EMPTY_LIST]).await;
        let config = config_with_connection("prod", "https://gateway.example.com");
        let credentials = credentials_bound_to("prod", "agpat_secret", "https://gateway.example.com");

        let error =
            dispatch_with(gateway_args(&["--host", &other, "--allow-http", "surfaces", "list"]), config, &credentials)
                .await
                .expect_err("the saved token must not go to another host");

        assert!(
            error
                .to_string()
                .contains("belongs to https://gateway.example.com"),
            "{error}"
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_command_with_another_host_sends_the_saved_token_with_the_opt_in() {
        let (other, requests) = recording_server(vec![OK_EMPTY_LIST]).await;
        let config = config_with_connection("prod", "https://gateway.example.com");
        let credentials = credentials_bound_to("prod", "agpat_secret", "https://gateway.example.com");

        dispatch_with(
            gateway_args(&["--host", &other, "--allow-http", "--allow-host-override", "surfaces", "list"]),
            config,
            &credentials,
        )
        .await
        .expect("the opt-in lets the token go");

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer agpat_secret"),
            "{}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn an_explicit_token_goes_to_an_explicit_host() {
        let (other, requests) = recording_server(vec![OK_EMPTY_LIST]).await;
        let config = config_with_connection("prod", "https://gateway.example.com");
        let credentials = credentials_bound_to("prod", "agpat_saved", "https://gateway.example.com");

        dispatch_with(
            gateway_args(&["--host", &other, "--allow-http", "--token", "agpat_typed", "surfaces", "list"]),
            config,
            &credentials,
        )
        .await
        .expect("a token the user typed for this command is theirs to send");

        let requests = requests.lock().unwrap();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer agpat_typed"),
            "{}",
            requests[0]
        );
        assert!(!requests[0].contains("agpat_saved"));
    }

    #[tokio::test]
    async fn whoami_does_not_send_the_saved_token_to_another_host() {
        let (other, requests) = recording_server(vec![OK_EMPTY]).await;
        let config = config_with_connection("prod", "https://gateway.example.com");
        let credentials = credentials_bound_to("prod", "agpat_secret", "https://gateway.example.com");
        let flags = HostFlags {
            allow_http: true,
            allow_host_override: false,
        };

        whoami_info(&config, &credentials, None, Some(&other), flags, None)
            .await
            .expect_err("whoami must not leak the saved token");

        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    /// A credential store that fails the test if it is used at all, standing in
    /// for an OS keyring that a server with no desktop session cannot reach.
    struct UnreachableKeyring;

    impl CredentialStore for UnreachableKeyring {
        fn get_token(
            &self,
            connection: &str,
        ) -> Result<Option<String>> {
            panic!("the keyring was read for connection '{connection}'")
        }

        fn set_token(
            &self,
            connection: &str,
            _token: &str,
        ) -> Result<()> {
            panic!("the keyring was written for connection '{connection}'")
        }

        fn delete_token(
            &self,
            connection: &str,
        ) -> Result<()> {
            panic!("the keyring was cleared for connection '{connection}'")
        }
    }

    const GIVEN_TOKEN: &str = "agpat_given";

    #[tokio::test]
    async fn whoami_with_a_host_and_token_and_no_saved_connection_skips_the_keyring() {
        let (host, requests) = recording_server(vec![OK_EMPTY, OK_EMPTY, OK_EMPTY]).await;

        let info = whoami_info(
            &Config::default(),
            &UnreachableKeyring,
            None,
            Some(&host),
            HostFlags::default(),
            Some(GIVEN_TOKEN),
        )
        .await
        .expect("whoami should run with only a host and a token");

        assert_eq!(info["connection"], Value::Null);
        assert_eq!(info["host"], json!(host));
        assert_eq!(info["token_stored"], json!(false));
        assert_eq!(info["authenticated"], json!(true));
        assert!(
            requests.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {GIVEN_TOKEN}"))
        );
    }

    #[tokio::test]
    async fn a_gateway_command_with_a_host_and_token_and_no_saved_connection_skips_the_keyring() {
        let (host, requests) = recording_server(vec![OK_EMPTY_LIST]).await;

        dispatch_with(
            gateway_args(&["--host", &host, "--token", GIVEN_TOKEN, "api", "get", "/v1/gateways"]),
            Config::default(),
            &UnreachableKeyring,
        )
        .await
        .expect("the command should run with only a host and a token");

        let requests = requests.lock().unwrap();
        assert!(requests[0].starts_with("GET /api/v1/gateways "), "{}", requests[0]);
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {GIVEN_TOKEN}"))
        );
    }

    #[tokio::test]
    async fn a_host_and_token_do_not_stand_in_for_a_named_connection_that_is_not_saved() {
        let error = dispatch_with(
            gateway_args(&[
                "--connection",
                "missing",
                "--host",
                "http://127.0.0.1:9",
                "--token",
                GIVEN_TOKEN,
                "api",
                "get",
                "/v1/gateways",
            ]),
            Config::default(),
            &UnreachableKeyring,
        )
        .await
        .expect_err("a named connection must exist");

        assert!(
            error
                .to_string()
                .contains("'missing' does not exist"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_host_without_a_token_and_no_saved_connection_asks_for_a_login_or_both_variables() {
        let error = dispatch_with(
            gateway_args(&["--host", "http://127.0.0.1:9", "api", "get", "/v1/gateways"]),
            Config::default(),
            &UnreachableKeyring,
        )
        .await
        .expect_err("there is no token to send");

        let text = error.to_string();
        assert!(text.contains("no gateway connection configured"), "{text}");
        assert!(text.contains("login --host <URL>`, or set both FABRIC_HOST and FABRIC_TOKEN"), "{text}");
    }

    #[tokio::test]
    async fn a_given_host_and_token_override_a_saved_connection_without_the_keyring() {
        let (host, requests) = recording_server(vec![OK_EMPTY_LIST]).await;

        dispatch_with(
            gateway_args(&["--host", &host, "--token", GIVEN_TOKEN, "api", "get", "/v1/gateways"]),
            config_with_connection("default", "https://gateway.example.com"),
            &UnreachableKeyring,
        )
        .await
        .expect("the command should run on the given host and token");

        assert!(
            requests.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {GIVEN_TOKEN}"))
        );
    }

    #[test]
    fn a_given_plain_http_remote_host_needs_allow_http_without_a_saved_connection() {
        let target = |allow_http| {
            command_target(
                &Config::default(),
                &UnreachableKeyring,
                None,
                Some("http://gateway.example.com"),
                HostFlags {
                    allow_http,
                    allow_host_override: false,
                },
                Some(GIVEN_TOKEN),
            )
        };

        let error = target(false)
            .err()
            .expect("plain http to a remote host must be refused");
        assert!(
            error
                .to_string()
                .contains("--allow-http"),
            "{error}"
        );
        let allowed = target(true).expect("--allow-http accepts the plain http host");
        assert_eq!(allowed.host, "http://gateway.example.com");
        assert!(allowed.connection.is_none());
    }

    #[test]
    fn only_gateway_commands_given_a_host_and_token_skip_the_credential_store() {
        let host_and_token = ["--host", "https://gateway.example.com", "--token", GIVEN_TOKEN];
        let with = |extra: &[&str]| {
            gateway_args(
                &host_and_token
                    .iter()
                    .chain(extra)
                    .copied()
                    .collect::<Vec<_>>(),
            )
        };

        assert!(skips_the_credential_store(&with(&["whoami"])));
        assert!(skips_the_credential_store(&with(&["surfaces", "list"])));
        assert!(skips_the_credential_store(&with(&["--connection", "prod", "whoami"])));
        assert!(!skips_the_credential_store(&with(&["login", "--pat"])));
        assert!(!skips_the_credential_store(&with(&["logout"])));
        assert!(!skips_the_credential_store(&with(&["config", "list"])));
        assert!(!skips_the_credential_store(&gateway_args(&["--host", "https://gateway.example.com", "whoami"])));
        assert!(!skips_the_credential_store(&gateway_args(&["--token", GIVEN_TOKEN, "whoami"])));
    }

    #[tokio::test]
    async fn login_binds_the_token_to_the_host() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, &path)
            .await
            .expect("login should succeed");

        assert_eq!(
            credentials
                .get_bound_host("production")
                .unwrap()
                .as_deref(),
            Some(host.as_str())
        );
    }

    #[tokio::test]
    async fn failed_save_restores_the_previous_bound_host() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_with_connection("production", &host);
        let credentials = credentials_bound_to("production", "old", "https://old.example.com");

        login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, dir.path())
            .await
            .expect_err("saving over a directory must fail");

        assert_eq!(
            credentials
                .get_bound_host("production")
                .unwrap()
                .as_deref(),
            Some("https://old.example.com")
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
    async fn failed_save_removes_a_bound_host_that_was_not_there_before() {
        let host = one_shot_server("HTTP/1.1 200 OK", r#"{"authenticated": true}"#).await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();

        login_and_save(&mut config, &credentials, "production", login_args_with_token(&host, "new"), false, dir.path())
            .await
            .expect_err("saving over a directory must fail");

        assert_eq!(
            credentials
                .get_bound_host("production")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn pat_login_is_refused_when_the_host_answers_404() {
        let host = one_shot_server("HTTP/1.1 404 Not Found", "").await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();
        let mut args = login_args_with_token(&host, "unused");
        args.token = None;
        args.pat = Some("agpat_valid".to_owned());

        let error = login_and_save(&mut config, &credentials, "production", args, false, &path)
            .await
            .expect_err("a 404 must not count as a valid token");

        assert!(format!("{error:#}").contains("gateway answered 404"), "{error:#}");
        assert!(!path.exists());
        assert_eq!(
            credentials
                .get_token("production")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn logout_ends_a_session_on_the_gateway() {
        let (host, requests) = recording_server(vec![OK_EMPTY]).await;
        let credentials = credentials_bound_to("prod", "session-token", &host);
        let connection = Connection::new(host.clone());

        let note = end_remote_credential(&credentials, "prod", &connection, PatChoice::Keep)
            .await
            .expect("a note");

        assert_eq!(note, format!("note: ended the session on {host}"));
        let requests = requests.lock().unwrap();
        assert!(requests[0].starts_with("POST /api/auth/logout HTTP/1.1"), "{}", requests[0]);
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer session-token")
        );
    }

    #[tokio::test]
    async fn logout_sends_the_session_token_only_to_its_bound_host() {
        let (other, requests) = recording_server(vec![OK_EMPTY]).await;
        let (bound, bound_requests) = recording_server(vec![OK_EMPTY]).await;
        let credentials = credentials_bound_to("prod", "session-token", &bound);
        let edited = Connection::new(other);

        end_remote_credential(&credentials, "prod", &edited, PatChoice::Keep).await;

        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            bound_requests
                .lock()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn logout_still_removes_the_local_copy_when_the_gateway_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = config_with_connection("prod", &host);
        let credentials = credentials_bound_to("prod", "session-token", &host);

        let note = end_remote_credential(&credentials, "prod", &config.connections["prod"].clone(), PatChoice::Keep)
            .await
            .expect("a note");
        remove_connection(&mut config, &credentials, "prod", &path).expect("local removal");

        assert!(note.starts_with(&format!("warning: could not reach {host} to end the session")), "{note}");
        assert!(note.contains("stays valid there until it expires"), "{note}");
        assert!(!note.contains("session-token"), "{note}");
        assert_eq!(
            credentials
                .get_token("prod")
                .unwrap(),
            None
        );
        assert_eq!(
            credentials
                .get_bound_host("prod")
                .unwrap(),
            None
        );
        assert!(config.connections.is_empty());
    }

    #[tokio::test]
    async fn logout_reports_a_gateway_that_refuses_to_end_the_session() {
        let host = one_shot_server("HTTP/1.1 500 Internal Server Error", "storage down").await;
        let credentials = credentials_bound_to("prod", "session-token", &host);

        let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Keep)
            .await
            .expect("a note");

        assert_eq!(
            note,
            format!(
                "warning: {host} would not end the session (storage down), so it stays valid there until it expires"
            )
        );
    }

    #[tokio::test]
    async fn logout_of_a_personal_access_token_says_how_to_revoke_it() {
        let (host, requests) = recording_server(vec![ok_json(r#"{"user_id":"u","token_id":"tok-9"}"#)]).await;
        let credentials = credentials_bound_to("prod", "agpat_secret", &host);
        let connection = Connection::new(host.clone());

        let note = end_remote_credential(&credentials, "prod", &connection, PatChoice::Keep)
            .await
            .expect("a note");

        assert!(note.contains(&format!("still valid on {host}")), "{note}");
        assert!(note.ends_with("fabric agent-gateway tokens revoke tok-9"), "{note}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /api/v1/token-info"), "{}", requests[0]);
    }

    #[tokio::test]
    async fn logout_with_the_revoke_flag_revokes_the_personal_access_token_while_it_is_held() {
        let (host, requests) = recording_server(vec![ok_json(r#"{"user_id":"u","token_id":"tok-9"}"#), OK_EMPTY]).await;
        let credentials = credentials_bound_to("prod", "agpat_secret", &host);

        let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Revoke)
            .await
            .expect("a note");

        assert_eq!(note, format!("note: revoked this personal access token on {host}"));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("DELETE /api/v1/access-tokens/tok-9 HTTP/1.1"), "{}", requests[1]);
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("authorization: bearer agpat_secret")
        );
    }

    #[tokio::test]
    async fn logout_treats_an_empty_token_id_as_no_id_and_sends_no_revoke() {
        for body in [r#"{"user_id":"u","token_id":""}"#, r#"{"user_id":"u","token_id":"  "}"#] {
            let (host, requests) = recording_server(vec![ok_json(body)]).await;
            let credentials = credentials_bound_to("prod", "agpat_secret", &host);

            let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Revoke)
                .await
                .expect("a note");

            assert!(note.contains("tokens revoke <token-id>"), "{note}");
            assert_eq!(requests.lock().unwrap().len(), 1, "{body}");
        }
    }

    #[test]
    fn the_logout_prompt_names_the_token_and_the_host() {
        assert_eq!(
            revoke_pat_prompt("https://gateway.example", "tok-9"),
            "Also revoke personal access token tok-9 on https://gateway.example?"
        );
    }

    #[test]
    fn the_saved_http_warning_is_shown_once_per_host() {
        assert!(first_http_warning_for("http://first-warning-host.example"));
        assert!(!first_http_warning_for("http://first-warning-host.example"));
        assert!(first_http_warning_for("http://second-warning-host.example"));
    }

    #[test]
    fn the_saved_http_warning_treats_spellings_of_one_host_as_one() {
        assert!(first_http_warning_for("http://Spelling-Host.example:80/"));
        assert!(!first_http_warning_for("http://spelling-host.example"));
        assert!(!first_http_warning_for("HTTP://SPELLING-HOST.EXAMPLE:80"));
    }

    #[test]
    fn the_saved_http_warning_ignores_login_name_and_path() {
        assert!(first_http_warning_for("http://user:pw@userinfo-host.example/api/v1"));
        assert!(!first_http_warning_for("http://userinfo-host.example"));
        assert!(!first_http_warning_for("http://other@USERINFO-HOST.example:80/x/"));
    }

    #[test]
    fn the_saved_http_warning_keeps_other_ports_and_ipv6_literals_apart() {
        assert!(first_http_warning_for("http://port-host.example:8080/"));
        assert!(!first_http_warning_for("http://user@port-host.example:8080/path"));
        assert!(first_http_warning_for("http://port-host.example"));
        assert!(first_http_warning_for("http://[2001:db8::7]:80/a"));
        assert!(!first_http_warning_for("http://u@[2001:DB8::7]"));
        assert!(first_http_warning_for("https://tls-port-host.example:443/"));
        assert!(!first_http_warning_for("https://tls-port-host.example"));
    }

    #[test]
    fn the_hash_name_warning_is_shown_once_per_name() {
        let mut config = Config::default();
        config
            .connections
            .insert("once#name".into(), Connection::new("https://gateway.example".into()));

        assert_eq!(new_hash_name_warnings(&config).len(), 1);
        assert!(new_hash_name_warnings(&config).is_empty());

        config
            .connections
            .insert("twice#name".into(), Connection::new("https://gateway.example".into()));
        let later = new_hash_name_warnings(&config);
        assert_eq!(later.len(), 1);
        assert!(later[0].contains("twice#name"), "{later:?}");
    }

    struct UnwritableCredentials(MemoryCredentials);

    impl CredentialStore for UnwritableCredentials {
        fn get_token(
            &self,
            connection: &str,
        ) -> Result<Option<String>> {
            self.0.get_token(connection)
        }

        fn set_token(
            &self,
            _connection: &str,
            _token: &str,
        ) -> Result<()> {
            bail!("store is read-only")
        }

        fn delete_token(
            &self,
            connection: &str,
        ) -> Result<()> {
            self.0
                .delete_token(connection)
        }
    }

    #[test]
    fn an_unwritable_store_still_lets_an_unrecorded_token_go_to_its_config_host() {
        let memory = MemoryCredentials::default();
        memory
            .set_token("unwritable-conn", "agpat_x")
            .unwrap();
        let credentials = UnwritableCredentials(memory);
        let saved = Connection::new("https://gateway.example.com".into());

        for _ in 0..3 {
            check_token_host(&credentials, "unwritable-conn", &saved, "https://gateway.example.com", false).unwrap();
        }

        assert!(
            !first_warning_for("bound-host:unwritable-conn".into()),
            "the first failed write should have used up the warning for this connection"
        );
    }

    #[tokio::test]
    async fn logout_without_the_revoke_flag_keeps_the_token_valid_and_sends_no_revoke() {
        let (host, requests) = recording_server(vec![ok_json(r#"{"user_id":"u","token_id":"tok-9"}"#)]).await;
        let credentials = credentials_bound_to("prod", "agpat_secret", &host);

        let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Keep)
            .await
            .expect("a note");

        assert!(note.contains("still valid"), "{note}");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with("DELETE"))
        );
    }

    #[tokio::test]
    async fn logout_reports_a_revoke_the_gateway_refuses_and_still_gives_the_hint() {
        let (host, _) = recording_server(vec![
            ok_json(r#"{"user_id":"u","token_id":"tok-9"}"#),
            "HTTP/1.1 403 Forbidden\r\ncontent-length: 6\r\nconnection: close\r\n\r\ndenied",
        ])
        .await;
        let credentials = credentials_bound_to("prod", "agpat_secret", &host);

        let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Revoke)
            .await
            .expect("a note");

        assert!(note.starts_with(&format!("warning: could not revoke this personal access token on {host}")), "{note}");
        assert!(note.contains("denied"), "{note}");
        assert!(note.contains("still valid"), "{note}");
        assert!(!note.contains("agpat_secret"), "{note}");
    }

    #[tokio::test]
    async fn the_revoke_flag_does_not_change_how_a_browser_session_ends() {
        let (host, requests) = recording_server(vec![OK_EMPTY]).await;
        let credentials = credentials_bound_to("prod", "session-token", &host);

        let note = end_remote_credential(&credentials, "prod", &Connection::new(host.clone()), PatChoice::Revoke)
            .await
            .expect("a note");

        assert_eq!(note, format!("note: ended the session on {host}"));
        assert!(requests.lock().unwrap()[0].starts_with("POST /api/auth/logout"));
    }

    #[test]
    fn logout_takes_an_explicit_revoke_token_flag() {
        let Command::Logout(args) = gateway_args(&["logout", "--revoke-token"]).command else {
            panic!("expected logout");
        };
        assert!(args.revoke_token);
        let Command::Logout(args) = gateway_args(&["logout"]).command else {
            panic!("expected logout");
        };
        assert!(!args.revoke_token);
    }

    #[test]
    fn a_personal_access_token_note_without_an_id_points_at_the_list() {
        let note = pat_still_valid_note("https://gateway.example.com", None);
        assert!(note.contains("still valid on https://gateway.example.com"), "{note}");
        assert!(note.contains("`fabric agent-gateway tokens list`"), "{note}");
        assert!(note.ends_with("fabric agent-gateway tokens revoke <token-id>"), "{note}");
    }

    #[test]
    fn removing_a_connection_that_does_not_exist_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        let error = remove_connection(&mut config, &MemoryCredentials::default(), "ghost", &dir.path().join("c.toml"))
            .expect_err("unknown connection");
        assert!(
            error
                .to_string()
                .contains("does not exist"),
            "{error}"
        );
    }

    #[test]
    fn a_token_needs_scopes_or_full_role() {
        let mut body = json!({"name": "ci", "scopes": []});
        let error = require_scopes_and_expiry(&mut body, false, 0).expect_err("no scopes, no full role");
        let message = error.to_string();
        assert!(message.contains("--scope"), "{message}");
        assert!(message.contains("--full-role"), "{message}");
        assert!(require_scopes_and_expiry(&mut json!({"name": "ci"}), false, 0).is_err());
        assert!(require_scopes_and_expiry(&mut json!({"name": "ci", "scopes": []}), true, 0).is_ok());
        assert!(require_scopes_and_expiry(&mut json!({"name": "ci", "scopes": ["surfaces.view"]}), false, 0).is_ok());
    }

    #[test]
    fn an_empty_expiry_gets_the_default_like_a_missing_one() {
        let mut body = json!({"name": "ci", "scopes": ["surfaces.view"], "expires_at": ""});
        assert!(
            require_scopes_and_expiry(&mut body, false, 1_700_000_000)
                .unwrap()
                .is_some()
        );
        assert_eq!(body["expires_at"], json!("2024-02-12T22:13:20Z"));

        let mut chosen = json!({"name": "ci", "scopes": ["surfaces.view"], "expires_at": "2030-01-01T00:00:00Z"});
        assert_eq!(require_scopes_and_expiry(&mut chosen, false, 1_700_000_000).unwrap(), None);
        assert_eq!(chosen["expires_at"], json!("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn a_token_without_an_expiry_gets_one_ninety_days_out() {
        let mut body = json!({"name": "ci", "scopes": ["surfaces.view"]});
        let note = require_scopes_and_expiry(&mut body, false, 1_700_000_000).unwrap();
        assert_eq!(note.as_deref(), Some("2024-02-12T22:13:20Z"));
        assert_eq!(body["expires_at"], json!("2024-02-12T22:13:20Z"));

        let mut null_expiry = json!({"name": "ci", "scopes": ["surfaces.view"], "expires_at": null});
        assert!(
            require_scopes_and_expiry(&mut null_expiry, false, 1_700_000_000)
                .unwrap()
                .is_some()
        );
        assert_eq!(null_expiry["expires_at"], json!("2024-02-12T22:13:20Z"));
    }

    #[test]
    fn a_token_keeps_the_expiry_it_was_given() {
        let mut body = json!({"name": "ci", "scopes": ["surfaces.view"], "expires_at": "2027-01-01T00:00:00Z"});
        assert_eq!(require_scopes_and_expiry(&mut body, false, 1_700_000_000).unwrap(), None);
        assert_eq!(body["expires_at"], json!("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn a_token_request_that_is_not_an_object_is_refused() {
        assert!(require_scopes_and_expiry(&mut json!(["x"]), true, 0).is_err());
    }

    #[test]
    fn rfc3339_formats_known_moments() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn full_role_cannot_be_combined_with_scopes() {
        let error = Cli::try_parse_from([
            "fabric",
            "agent-gateway",
            "tokens",
            "create",
            "--name",
            "ci",
            "--scope",
            "surfaces.view",
            "--full-role",
        ])
        .expect_err("--full-role conflicts with --scope");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "tokens", "create", "--name", "ci", "--full-role"])
            .expect("--full-role alone parses");
        let Command::AccessTokens {
            command: AccessTokenCommand::Create(args),
        } = cli
            .into_agent_gateway()
            .command
        else {
            panic!("expected tokens create");
        };
        assert!(args.full_role);
    }

    #[tokio::test]
    async fn token_create_without_scopes_sends_nothing() {
        let (host, requests) = recording_server(vec![OK_EMPTY]).await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();
        let args = AccessTokenCreateArgs {
            scopes: vec![],
            ..minimal_access_token_args()
        };

        run_access_tokens(&client, AccessTokenCommand::Create(args), Output::Json)
            .await
            .expect_err("no scopes and no --full-role must be refused");

        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn token_create_sends_the_default_expiry() {
        let (host, requests) = recording_server(vec![ok_json("{}")]).await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();

        run_access_tokens(&client, AccessTokenCommand::Create(minimal_access_token_args()), Output::Json)
            .await
            .expect("create");

        let requests = requests.lock().unwrap();
        let body: Value = serde_json::from_str(
            requests[0]
                .split("\r\n\r\n")
                .nth(1)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["scopes"], json!(["surfaces.view"]));
        assert!(
            body["expires_at"]
                .as_str()
                .is_some_and(|expiry| expiry.ends_with('Z')),
            "{body}"
        );
    }

    #[test]
    fn the_token_list_shows_a_full_role_token_as_such() {
        for token in [
            json!({"name": "a", "id": "1", "scopes": []}),
            json!({"name": "a", "id": "1", "scopes": null}),
            json!({"name": "a", "id": "1"}),
        ] {
            assert_eq!(access_token_row(&token)[3], "full role", "{token}");
        }
        assert_eq!(access_token_row(&json!({"name": "a", "id": "1", "scopes": ["surfaces.view"]}))[3], "surfaces.view");
    }

    #[test]
    fn inline_secrets_are_warned_about_and_other_sources_are_not() {
        let words = |line: &str| {
            line.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        for (line, flag) in [
            ("fabric agent-gateway --token abc surfaces list", "--token"),
            ("fabric agent-gateway --token=abc surfaces list", "--token"),
            ("fabric agent-gateway login --token abc", "--token"),
            ("fabric agent-gateway login --pat agpat_x", "--pat"),
            ("fabric agent-gateway login --pat=agpat_x", "--pat"),
            ("fabric agent-gateway secrets create --value hunter2", "--value"),
            ("fabric agent-gateway metrics scrape --username u --password pw", "--password"),
        ] {
            let warnings = inline_secret_warnings(&words(line));
            assert_eq!(warnings.len(), 1, "{line}: {warnings:?}");
            assert!(warnings[0].starts_with(&format!("warning: {flag} on the command line")), "{warnings:?}");
            assert!(!warnings[0].contains("abc") && !warnings[0].contains("hunter2"), "{warnings:?}");
        }
        for line in [
            "fabric agent-gateway login --pat",
            "fabric agent-gateway login --pat --token-stdin",
            "fabric agent-gateway login --token-stdin",
            "fabric agent-gateway secrets create --value-stdin",
            "fabric agent-gateway tokens create --name ci --scope surfaces.view",
            "fabric agent-gateway surfaces list",
        ] {
            assert!(inline_secret_warnings(&words(line)).is_empty(), "{line}");
        }
    }

    #[test]
    fn the_whoami_table_strips_control_characters_from_every_value() {
        let info = json!({
            "connection": "prod",
            "host": "https://gateway.example.com",
            "username": "eve\u{1b}[2Jmallory",
            "email": "a@b.c\r\u{202e}evil",
            "scopes": ["ok", "x\u{7}y"],
            "error": "bad\u{1b}]0;title\u{7}",
        });
        let lines = info_table_lines(&info);
        assert!(lines.contains(&"username: eve[2Jmallory".to_owned()), "{lines:?}");
        assert!(lines.contains(&"email: a@b.c evil".to_owned()), "{lines:?}");
        assert!(lines.contains(&"scopes: ok, xy".to_owned()), "{lines:?}");
        assert!(lines.contains(&"error: bad]0;title".to_owned()), "{lines:?}");
        assert!(
            lines.iter().all(|line| !line
                .chars()
                .any(|c| c.is_control())),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|line| !line
                .chars()
                .any(|c| matches!(c, '\r' | '\u{202e}' | '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))),
            "{lines:?}"
        );
    }

    #[test]
    fn a_whoami_table_leaves_out_a_null_connection() {
        let info = json!({"connection": null, "host": "https://gateway.example.com", "token_stored": false});

        assert_eq!(info_table_lines(&info), ["host: https://gateway.example.com", "token_stored: false"]);
    }

    #[test]
    fn a_newline_in_a_value_cannot_forge_a_whoami_line() {
        let info = json!({"username": "bob\nrole: Administrator", "scopes": ["a\tb"]});
        let lines = info_table_lines(&info);
        assert_eq!(lines, vec!["username: bob role: Administrator".to_owned(), "scopes: a b".to_owned()]);
    }

    #[tokio::test]
    async fn a_newline_in_a_name_stays_on_one_line_of_the_confirmation() {
        let (host, _) = recording_server(vec![ok_json(r#"{"name":"ci\nDelete 'prod' (x)"}"#)]).await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();

        let target = describe_target(&client, "/v1/access-tokens/tok-1", "tok\n1").await;

        assert_eq!(target, format!("'ci Delete 'prod' (x)' (tok 1) on {host}"));
    }

    #[test]
    fn the_secret_hint_only_names_token_stdin_on_login() {
        let words = |line: &str| {
            line.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let other = inline_secret_warnings(&words("fabric agent-gateway --token abc surfaces list"));
        assert!(other[0].ends_with("use the FABRIC_TOKEN environment variable instead"), "{other:?}");
        let login = inline_secret_warnings(&words("fabric agent-gateway login --token abc"));
        assert!(login[0].contains("--token-stdin"), "{login:?}");
    }

    #[test]
    fn words_after_the_end_of_options_are_not_read_as_secret_flags() {
        let words = "fabric agent-gateway api get -- --token abc"
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(inline_secret_warnings(&words).is_empty());
    }

    #[test]
    fn a_connection_name_with_a_hash_is_refused_at_login() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        let credentials = MemoryCredentials::default();
        let error = runtime
            .block_on(login_and_save(
                &mut config,
                &credentials,
                "prod#bound-host",
                login_args_with_token("http://127.0.0.1:1", "t"),
                true,
                &dir.path().join("config.toml"),
            ))
            .expect_err("a hash would collide with the bound-host key");
        assert!(
            error
                .to_string()
                .contains("must not contain '#'"),
            "{error}"
        );
    }

    #[test]
    fn a_token_saved_before_hosts_were_bound_is_bound_on_first_use() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("prod", "agpat_x")
            .unwrap();

        check_token_host(&credentials, "prod", &saved, "https://gateway.example.com", false).unwrap();
        assert_eq!(
            credentials
                .get_bound_host("prod")
                .unwrap()
                .as_deref(),
            Some("https://gateway.example.com")
        );

        let edited = Connection::new("https://evil.example.net".into());
        check_token_host(&credentials, "prod", &edited, "https://evil.example.net", false)
            .expect_err("the recorded host now wins over an edited configuration");
    }

    #[test]
    fn an_override_does_not_bind_a_token_that_has_no_recorded_host() {
        let saved = Connection::new("https://gateway.example.com".into());
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("prod", "agpat_x")
            .unwrap();

        check_token_host(&credentials, "prod", &saved, "https://other.example.net", true).unwrap();

        assert_eq!(
            credentials
                .get_bound_host("prod")
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_scrape_to_the_terminal_is_stripped_of_control_characters_but_a_file_is_not() {
        let body = b"metric{label=\"a\x1b[2Jb\"} 1\n";
        assert_eq!(scrape_output(Path::new("-"), body), b"metric{label=\"a[2Jb\"} 1\n");
        assert_eq!(scrape_output(Path::new("out.txt"), body), body);
    }

    #[tokio::test]
    async fn the_confirmation_names_the_target_with_its_id_and_host() {
        let (host, requests) = recording_server(vec![ok_json(r#"{"name":"ci\u001b[2Jrunner"}"#)]).await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();

        let target = describe_target(&client, "/v1/access-tokens/tok-1", "tok-1").await;

        assert_eq!(target, format!("'ci[2Jrunner' (tok-1) on {host}"));
        assert!(requests.lock().unwrap()[0].starts_with("GET /api/v1/access-tokens/tok-1"));
    }

    #[tokio::test]
    async fn the_confirmation_still_names_id_and_host_when_the_name_cannot_be_read() {
        let host = one_shot_server("HTTP/1.1 404 Not Found", "").await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();

        let target = describe_target(&client, "/v1/access-tokens/tok-1", "tok-1").await;

        assert_eq!(target, format!("tok-1 on {host}"));
    }

    #[tokio::test]
    async fn api_key_delete_with_yes_deletes_without_asking() {
        let (host, requests) = recording_server(vec![OK_EMPTY]).await;
        let client = GatewayClient::new(&host, "agpat_valid").unwrap();
        let command = ApiKeyCommand::Delete {
            key_id: "atgk_1".into(),
            surface: ApiKeySurfaceArgs {
                agent_id: Some("surface-1".into()),
            },
            yes: true,
        };

        run_api_keys(&client, command, Output::Json)
            .await
            .expect("delete");

        assert!(requests.lock().unwrap()[0].starts_with("DELETE /api/v1/api-keys/surface-1/atgk_1 HTTP/1.1"));
    }

    #[test]
    fn api_key_delete_accepts_yes() {
        for flag in ["--yes", "-y"] {
            let args = gateway_args(&["api-keys", "delete", "atgk_1", flag]);
            assert!(matches!(
                args.command,
                Command::ApiKeys {
                    command: ApiKeyCommand::Delete { yes: true, .. }
                }
            ));
        }
        let args = gateway_args(&["api-keys", "delete", "atgk_1"]);
        assert!(matches!(
            args.command,
            Command::ApiKeys {
                command: ApiKeyCommand::Delete { yes: false, .. }
            }
        ));
    }

    #[test]
    fn the_shell_carries_the_host_override_opt_in() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "--allow-host-override", "shell"]).unwrap();
        assert!(
            cli.interactive_prefix()
                .contains(&"--allow-host-override".to_owned())
        );
    }

    #[test]
    fn the_host_override_has_no_environment_variable() {
        use clap::CommandFactory;
        let command = Cli::command();
        let gateway = command
            .find_subcommand("agent-gateway")
            .expect("agent-gateway");
        let flag = gateway
            .get_arguments()
            .find(|argument| argument.get_id() == "allow_host_override")
            .expect("the override flag");
        assert_eq!(flag.get_env(), None);
        assert!(
            !gateway
                .clone()
                .render_long_help()
                .to_string()
                .contains("FABRIC_ALLOW_HOST_OVERRIDE")
        );
    }

    #[test]
    fn a_typed_host_and_token_get_no_environment_note() {
        use clap::CommandFactory;
        let matches = Cli::command()
            .try_get_matches_from([
                "fabric",
                "agent-gateway",
                "--host",
                "https://typed.example.com",
                "--token",
                "typed",
                "surfaces",
                "list",
            ])
            .unwrap();
        assert_eq!(env_token_and_host_note(&matches), None);
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
            full_role: false,
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
        assert_eq!(row[5], "never");
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
            parsed(&[
                "fabric",
                "agent-gateway",
                "surfaces",
                "add-transit-point",
                "s-1",
                "--alias",
                "billing",
                "--endpoint",
                "http://b:1",
                "--dry-run"
            ]),
            Command::Surfaces {
                command: SurfaceCommand::AddTransitPoint(AddTransitPointArgs { dry_run: true, .. })
            }
        ));
        assert!(matches!(
            parsed(&["fabric", "agent-gateway", "surfaces", "remove-transit-point", "s-1", "billing", "--dry-run"]),
            Command::Surfaces {
                command: SurfaceCommand::RemoveTransitPoint(RemoveTransitPointArgs { dry_run: true, .. })
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
