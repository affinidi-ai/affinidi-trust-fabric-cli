//! `fabric agent-stream surfaces`: list, read, create, change, and delete the
//! surfaces of an Agent Stream, which its API calls pipes and serves at
//! `/v1/pipes`. Adding and removing a surface's features, and reading its
//! budget, live in [`features`].
//!
//! Agent Stream drops a surface field it does not know without an error, and
//! a save replaces the whole surface with no version check. So the field names
//! are checked on this machine before anything is sent, and `update` reads the
//! surface again just before it saves and stops when it was saved meanwhile.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use rand::RngCore;
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::{
    client::{GatewayClient, pretty_json_for_terminal, response_status, sanitize_for_terminal},
    commands::{Output, confirmation_line, entity_path, print_list, print_outcome, read_json, rfc3339_utc, unix_now},
    surface_patch,
    surface_validate::{self, Change},
    tables::{self, Scope},
};

mod features;

/// Where Agent Stream serves its surfaces.
const SURFACES_PATH: &str = "/v1/pipes";

/// Longest surface id Agent Stream accepts.
const MAX_ID_LEN: usize = 128;

/// The `status` of a surface Agent Stream has deleted and keeps for its usage
/// history.
const STATUS_DELETED: &str = "deleted";

/// How to give a `pipe_type` on `create`.
const CREATE_PIPE_TYPE_HINT: &str =
    "with flags, add --set pipe_type.type=webhook --set pipe_type.endpoint=<url>, or give it in --file";

/// How to keep a `pipe_type` on `update`.
const UPDATE_PIPE_TYPE_HINT: &str = "keep the `pipe_type` from `surfaces get`, or --set pipe_type.type to one of these";

/// The end of the table-mode dry run of `update`, `add-feature`, and
/// `remove-feature`, after a blank line.
const DRY_RUN_UPDATE_NOTE: &str = "\nDry run: nothing was saved. Agent Stream's own checks, such as a route another \
                                   surface uses or the drift block, only run on a real save, and its checks on \
                                   failover targets, canary splits, and usage limits only on a real save of an `llm` \
                                   surface.";

/// The top-level fields of an Agent Stream surface: the fields of `PipeConfig`
/// in Agent Stream's `src/pipes/config.rs`, which renames and flattens none of
/// them. Agent Stream drops a field it does not know without an error, so this
/// list must follow that struct whenever Agent Stream adds or removes a field.
///
/// The credential fields hold secret ids, never the secrets: `source_auth`,
/// the `api_key_secret` of the `pipe_type` provider, of the guardrail and
/// cache settings, and of every model target (the judge, jury, and decider
/// ones, and the targets of failover, load balancing, and routing rules), and
/// the `secret_id` of each header in `upstream_headers` and in a target's
/// `headers`. Agent Stream returns the surface as stored, so the commands
/// print and send them back as they are.
const SURFACE_FIELDS: [&str; 61] = [
    "id",
    "name",
    "description",
    "pipe_type",
    "status",
    "tenant_id",
    "owner_user_id",
    "test_surface",
    "listen_address",
    "route",
    "override_policy",
    "prompt_guard",
    "judge",
    "jury",
    "decider",
    "expert_witnesses",
    "rate_limit",
    "circuit_breaker",
    "retry_policy",
    "failover",
    "load_balancing",
    "streaming",
    "cache",
    "canary",
    "routing_rules",
    "routing_enabled",
    "cost_tracking",
    "usage_alerts",
    "usage_alerts_enabled",
    "usage_limits",
    "team_attribution",
    "integrations",
    "enable_metrics",
    "metrics_enabled",
    "log_requests",
    "log_responses",
    "request_timeout_seconds",
    "created_at",
    "updated_at",
    "source_auth",
    "opa_policy",
    "governance_recording",
    "drift",
    "vp_evidence",
    "forward_caller_token",
    "upstream_headers",
    "upstream_pricing",
    "accepted_ingress_schemas",
    "max_reasoning_tokens",
    "server_tools",
    "context_management",
    "document_ingestion",
    "audio_input",
    "image_input",
    "realtime",
    "sandbox_auth",
    "sandbox_oauth_identifier_id",
    "canvas",
    "auto_canvas",
    "variants",
    "default_variant_id",
];

/// The fields the flags of `update` can't change, each with the reason.
const FIXED_ON_UPDATE: [(&str, &str); 5] = [
    ("id", "it names the surface"),
    ("created_at", "it is set once, when the surface is created"),
    ("updated_at", "Agent Stream sets it on every save"),
    ("tenant_id", "a surface can't move to another tenant or owner"),
    ("owner_user_id", "a surface can't move to another tenant or owner"),
];

/// The fields `create --set` can't set, each with the reason.
const FIXED_ON_CREATE: [(&str, &str); 6] = [
    ("id", "use --id"),
    ("name", "use --name"),
    ("created_at", "the CLI sets it to the current time; give another in --file"),
    ("updated_at", "Agent Stream sets it on every save"),
    ("tenant_id", "give it in --file, where Agent Stream checks it against your token"),
    ("owner_user_id", "Agent Stream sets it to the user who creates the surface"),
];

/// The fields of an `update --file` document that are replaced with the
/// stored ones, each with the reason given when they differed.
const KEPT_FROM_STORED: [(&str, &str); 4] = [
    ("status", "change it with --set status=<enabled|disabled>, or run `surfaces delete`"),
    ("created_at", "it is set once, when the surface is created"),
    ("tenant_id", "a surface can't move to another tenant or owner"),
    ("owner_user_id", "a surface can't move to another tenant or owner"),
];

#[derive(Debug, Subcommand)]
pub enum SurfaceCommand {
    /// List surfaces.
    ///
    /// Agent Stream leaves deleted surfaces out of the list. UPDATED is when
    /// the surface was last saved. Use --output json for the full surfaces.
    List,
    /// Get a surface by ID, as the whole JSON document Agent Stream keeps.
    ///
    /// A deleted surface is still returned, with `status` set to `deleted`,
    /// because Agent Stream keeps it for its usage history.
    Get {
        /// ID of the surface (see `fabric agent-stream surfaces list`).
        id: String,
    },
    /// Create a surface from flags or a complete JSON document.
    ///
    /// With flags, --name is required and --set fills any other field, such
    /// as `pipe_type.type`, except `id`, `created_at`, `updated_at`,
    /// `tenant_id`, and `owner_user_id`, which the CLI or Agent Stream sets.
    /// With --file, the document is sent as it is, apart from the two fields
    /// the CLI adds when the document has none: `id` (--id, else `s-` and 12
    /// random hex digits) and `created_at` (the current UTC time). An id holds
    /// letters, digits, `-`, and `_`, up to 128 characters, and can't be one
    /// an earlier surface used, deleted ones included.
    ///
    /// Before anything is sent, the CLI checks that the surface has a
    /// `pipe_type.type` of `llm`, `webhook`, or `ide_catalog`, a `status`, if
    /// given, of `enabled` or `disabled`, and only top-level field
    /// names Agent Stream knows, because Agent Stream drops a field it does
    /// not know without an error. Names below the top level are not checked,
    /// since there is no stored surface to compare them with.
    ///
    /// --dry-run prints the document and sends nothing, so it needs no saved
    /// connection; with --output json it prints the same preview as `update
    /// --dry-run`. Table output prints the new surface's id; --output json
    /// prints the surface Agent Stream answered with.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Change a surface with --set, --unset, --add and --remove, or replace it
    /// with a JSON document.
    ///
    /// The CLI reads the surface, applies the change on this machine, and
    /// checks the field names, that `pipe_type.type` is `llm`, `webhook`,
    /// `ide_catalog`, or the type the surface already has, and that `status`
    /// is `enabled` or `disabled`. It
    /// then reads the surface again, stops if it was saved meanwhile, and
    /// otherwise sends the whole surface. A surface with no `updated_at` is
    /// refused, since the CLI can't tell whether it was saved meanwhile.
    /// Agent Stream has no version check, so a save that lands in the short
    /// gap between that last read and the send is still overwritten. When the
    /// request was sent and no whole answer came back, Agent Stream answered
    /// with a server error, or a success answer can't be read, the error says
    /// to check the surface with `surfaces get` before running the command
    /// again. A change that leaves the surface as it is sends nothing.
    ///
    /// Field names are checked against the surface as read: a top-level name
    /// must be one Agent Stream knows, and a name inside an object the
    /// surface already has must be one that object already has, unless
    /// --allow-new-field is given. A name inside an object the surface does
    /// not have yet, or inside a list item, is not checked. The flags can't
    /// change `id`, `created_at`, `updated_at`, `tenant_id`, or
    /// `owner_user_id`. `status` changes only with --set status=enabled or
    /// --set status=disabled; to delete the surface, use `surfaces delete`.
    ///
    /// --file must hold the `updated_at` the surface has now, so start it
    /// from `surfaces get` or from the --output json of an update; a copy
    /// read before another save is refused. Its `status`, `created_at`,
    /// `tenant_id`, and `owner_user_id` are replaced with the stored ones,
    /// with a note for each that differed.
    ///
    /// After the save, table output lists each changed field with its old
    /// and new value, and --output json prints the surface as Agent Stream
    /// has it then, read back after the save. A deleted surface can't be
    /// changed. --dry-run prints the same list of changes, or with --output
    /// json the changes and the whole new surface, and saves nothing. Agent
    /// Stream has no dry run, so its own checks, such as a route another
    /// surface uses or the block on a surface past its drift baseline, only
    /// run on a real save.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update(UpdateArgs),
    /// Delete a surface.
    ///
    /// The surface stops serving at once, and there is no confirmation
    /// prompt. Agent Stream keeps it, marked deleted, for its usage history,
    /// so `get` still returns it and its id can't be used again.
    Delete {
        /// ID of the surface (see `fabric agent-stream surfaces list`).
        id: String,
    },
    /// List the features a surface can have, or the ones a given surface has.
    ///
    /// Each feature is one field of the surface, such as `rate_limit` or
    /// `failover`. Without an id, the table lists every feature with its
    /// alias, its field, and what it does, and needs no saved connection.
    /// With an id, it lists each feature the surface has set, whether it is
    /// on, the variants that use their own value of it, and the
    /// `remove-feature` command for it; a feature only variants set shows as
    /// `not set`. Cost tracking that is off but has a price set shows `off
    /// (prices used)`, since Agent Stream prices calls with those prices
    /// whatever `enabled` says. A deleted surface can't be changed, so it
    /// shows no `remove-feature` command and a line saying it is deleted. The
    /// names shown are the ones `add-feature` and `remove-feature` take, in
    /// any case. --output json prints the same list, or for a surface each
    /// feature with its field, state, base value, and `overridden_by`
    /// variants.
    #[command(after_long_help = FEATURES_EXAMPLES)]
    Features {
        /// ID of the surface (see `fabric agent-stream surfaces list`).
        id: Option<String>,
    },
    /// Add a feature to a surface, or replace its settings.
    ///
    /// The settings come from --json or --file, in the shape of the surface
    /// field the feature names (see `surfaces features`). A one-setting
    /// feature, such as rate-limit or failover, replaces the whole field with
    /// the JSON given, so running add-feature again changes it; to change a
    /// single setting, use `surfaces update --set <field>.<name>=<value>`.
    /// cost-tracking (alias budget) also holds the surface's own model prices,
    /// which Agent Stream uses whether or not `enabled` is true, so the
    /// stored `enabled`, `input_price_per_1k`, and `output_price_per_1k` are
    /// kept, with a note, when the JSON leaves them out; with no `enabled`
    /// given or stored it is refused, since Agent Stream needs one.
    ///
    /// A list feature, such as usage-limits or routing-rules, gets the JSON
    /// appended as one item, and an item already in the list, by its `id` or
    /// by the same fields, is refused. A new routing rule goes last, and
    /// Agent Stream uses the first rule that matches. Agent Stream ignores
    /// every usage alert while `usage_alerts_enabled` is false, and every
    /// routing rule while `routing_enabled` is false. When that switch is
    /// false, adding the first item sets it to true, and adding to a list
    /// that already has items leaves it false, with a note on how to turn the
    /// list on. A surface without the switch is left without it, since Agent
    /// Stream reads a missing switch as true.
    ///
    /// Only the base surface is read and changed. A note names any variant
    /// that uses its own value of the feature, and so does not see the
    /// change. Agent Stream serves calls only on `llm` surfaces, so a note
    /// says when a feature does nothing on a `webhook` or `ide_catalog`
    /// surface.
    ///
    /// The save works as `surfaces update` does: the CLI reads the surface,
    /// checks the field names, reads it again and stops if it was saved
    /// meanwhile, then sends the whole surface. Agent Stream has no version
    /// check, so a save that lands in the short gap between that last read
    /// and the send is still overwritten. When the request was sent and no
    /// whole answer came back, Agent Stream answered with a server error, or
    /// a success answer can't be read, the error says to check the surface
    /// before running the command again. A name inside the JSON must be one
    /// the surface's field already has, unless --allow-new-field
    /// is given; cost-tracking names are checked against every setting Agent
    /// Stream knows, even on a surface with no `cost_tracking` yet, unless
    /// --allow-new-field is given, while nothing is checked inside any other field
    /// the surface does not have yet, or inside a list item. Table output
    /// lists the changes, and --output json prints the surface read back
    /// after the save. --dry-run shows the changes and saves nothing. Agent
    /// Stream has no dry run, so its own checks, such as those on failover
    /// targets, canary splits, and usage limits, only run on a real save of
    /// an `llm` surface.
    #[command(after_long_help = ADD_FEATURE_EXAMPLES)]
    AddFeature(features::AddFeatureArgs),
    /// Remove a feature from a surface.
    ///
    /// A one-setting feature is removed whole. Removing cost-tracking removes
    /// the surface's own model prices too, with a note; to stop only the
    /// budget, set `cost_tracking.enabled` to false with `surfaces update`. A
    /// list feature needs --item to remove one item or --all to remove the
    /// whole list; with neither, the command stops before anything is sent.
    /// --item takes the item's `id`; routing rules and usage alerts have no
    /// id, so give some of the item's fields as JSON instead, which must
    /// match exactly one item. A list's switch, such as `routing_enabled`, is left
    /// as it is. A feature the surface does not have set is refused. Only the
    /// base surface is changed, as for `add-feature`, and the save, the
    /// output, and --dry-run work as for `add-feature` too. There is no
    /// confirmation prompt; use --dry-run to check first.
    #[command(after_long_help = REMOVE_FEATURE_EXAMPLES)]
    RemoveFeature(features::RemoveFeatureArgs),
    /// Show this month's spend of a surface against its monthly budget.
    ///
    /// The budget is the `monthly_budget_usd` of the cost-tracking feature
    /// (`cost_tracking`). Agent Stream counts the spend only while
    /// `cost_tracking` has `enabled` set to true, a `monthly_budget_usd`
    /// above 0, and an `alert_threshold_percent`, and it counts only the
    /// surface's own model calls, not those of the judge or jury. The
    /// command says so instead of printing a table only when nothing was
    /// counted this month. Spend counted earlier this month stays, with the
    /// limit it was counted under, until the month ends, even after cost
    /// tracking is turned off or removed, and a changed limit shows only
    /// after the next counted call. Reading it needs the `metrics.view`
    /// permission. --output json prints Agent Stream's answer.
    #[command(after_long_help = BUDGET_EXAMPLES)]
    Budget {
        /// ID of the surface (see `fabric agent-stream surfaces list`).
        id: String,
    },
}

/// Examples shown at the bottom of `surfaces create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a webhook surface with a generated id:
    fabric agent-stream surfaces create --name "Sales hook" \
      --set pipe_type.type=webhook \
      --set pipe_type.endpoint=https://hooks.example.com/in

  Check a document first, then create it:
    fabric agent-stream surfaces create --file surface.json --dry-run
    fabric agent-stream surfaces create --file surface.json"#;

/// Examples shown at the bottom of `surfaces features --help`.
const FEATURES_EXAMPLES: &str = r#"Examples:
  List every feature a surface can have:
    fabric agent-stream surfaces features

  Show which features a surface has, and how to remove each one:
    fabric agent-stream surfaces features s-1a2b3c4d5e6f"#;

/// Examples shown at the bottom of `surfaces add-feature --help`.
const ADD_FEATURE_EXAMPLES: &str = r#"Examples:
  Limit a surface to 60 requests a minute, previewing first:
    fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f rate-limit \
      --json '{"enabled":true,"requests_per_minute":60}' --dry-run
    fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f rate-limit \
      --json '{"enabled":true,"requests_per_minute":60}'

  Set a monthly budget of 100 USD, with an alert at 80%, keeping the
  surface's own prices:
    fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f cost-tracking \
      --json '{"enabled":true,"monthly_budget_usd":100,"alert_threshold_percent":80}'

  Add a monthly token cap as one usage limit:
    fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f usage-limits \
      --json '{"id":"tokens","monthly_token_cap":1000000}'

  Fail over to backup providers described in a file:
    fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f failover \
      --file failover.json

  Change one setting of a feature the surface already has:
    fabric agent-stream surfaces update s-1a2b3c4d5e6f \
      --set rate_limit.requests_per_minute=120

  Turn on routing rules that were left off:
    fabric agent-stream surfaces update s-1a2b3c4d5e6f \
      --set routing_enabled=true"#;

/// Examples shown at the bottom of `surfaces remove-feature --help`.
const REMOVE_FEATURE_EXAMPLES: &str = r#"Examples:
  Remove the rate limit:
    fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f rate-limit

  Remove one usage limit by its id, previewing first:
    fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-limits \
      --item tokens --dry-run

  Remove the usage alert on cost, by its fields:
    fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-alerts \
      --item '{"alert_type":"cost_threshold"}'

  Remove every usage limit:
    fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-limits --all"#;

/// Examples shown at the bottom of `surfaces budget --help`.
const BUDGET_EXAMPLES: &str = r#"Examples:
  Show this month's spend against the budget:
    fabric agent-stream surfaces budget s-1a2b3c4d5e6f

  Fail a script step once the budget is used up:
    fabric agent-stream surfaces budget s-1a2b3c4d5e6f --output json \
      | jq -e '.budget_exceeded | not'"#;

/// Examples shown at the bottom of `surfaces update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Preview a change, then save it:
    fabric agent-stream surfaces update s-1a2b3c4d5e6f \
      --set judge.enabled=false --dry-run
    fabric agent-stream surfaces update s-1a2b3c4d5e6f \
      --set judge.enabled=false

  Edit a fresh copy and save it whole:
    fabric agent-stream surfaces get s-1a2b3c4d5e6f > surface.json
    fabric agent-stream surfaces update s-1a2b3c4d5e6f --file surface.json"#;

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Surface name. Required unless --file is given.
    #[arg(long, required_unless_present = "file", conflicts_with = "file")]
    name: Option<String>,
    /// What the surface is for.
    #[arg(long, conflicts_with = "file")]
    description: Option<String>,
    /// ID for the new surface: letters, digits, `-`, and `_`, up to 128
    /// characters. With --file, it fills a document that has no `id`, and a
    /// document with another `id` is refused. Defaults to `s-` and 12 random
    /// hex digits.
    #[arg(long)]
    id: Option<String>,
    /// Set any other field, as a dot path such as `pipe_type.type` and a value
    /// read as JSON when it parses (`100`, `true`, `{"enabled":true}`) and as
    /// plain text otherwise. Repeatable.
    #[arg(long, value_name = "PATH=VALUE", conflicts_with = "file")]
    set: Vec<String>,
    /// JSON document of the surface, or - for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Print the document that would be sent, and send nothing. Needs no
    /// saved connection.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args(["file", "set", "unset", "add", "remove"])))]
pub struct UpdateArgs {
    /// ID of the surface (see `fabric agent-stream surfaces list`).
    id: String,
    /// Complete surface JSON that replaces the stored surface, or - for
    /// standard input. Start from a fresh `surfaces get`, or from the
    /// --output json of an update.
    #[arg(short, long, conflicts_with_all = ["set", "unset", "add", "remove"])]
    file: Option<PathBuf>,
    /// Set a field, as a dot path such as `judge.enabled` and a value read as
    /// JSON when it parses (`100`, `true`, `{"enabled":true}`) and as plain
    /// text otherwise. Wrap a value in quotes (`'"1.0"'`) to send it as text.
    /// Repeatable.
    #[arg(long, value_name = "PATH=VALUE")]
    set: Vec<String>,
    /// Remove a field, as a dot path such as `rate_limit`. Repeatable.
    #[arg(long, value_name = "PATH")]
    unset: Vec<String>,
    /// Add one item to a list, as the list's dot path and the item, read the
    /// same way as a --set value. An item already in the list is refused.
    /// Repeatable.
    #[arg(long, value_name = "PATH=ITEM")]
    add: Vec<String>,
    /// Remove one item from a list: text by its value, an object by its `id`,
    /// else its `alias`, else some of its fields as JSON. Removes run before
    /// adds. Repeatable.
    #[arg(long, value_name = "PATH=ITEM")]
    remove: Vec<String>,
    /// Let a flag or --file add a field inside an object the surface already
    /// has, which it does not have yet. Without it such a field is refused as
    /// a likely typo. Agent Stream leaves some empty optional fields out of
    /// the surface it returns, so a correct field can look new.
    #[arg(long)]
    allow_new_field: bool,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Runs one `surfaces` command. `connect` gives the client of the Agent
/// Stream to talk to. It is called only for a command that sends something,
/// and only once the checks that need no connection pass, so `create
/// --dry-run` and `features` with no id need no saved connection. `features
/// <id>`, `budget`, `add-feature`, and `remove-feature` refuse a bad id,
/// feature name, or feature flag before one is made; `get`, `update`, and
/// `delete` check the id after connecting.
pub async fn run(
    command: SurfaceCommand,
    output: Output,
    connect: impl AsyncFnOnce() -> Result<GatewayClient>,
) -> Result<()> {
    match command {
        SurfaceCommand::Create(args) if args.dry_run => {
            println!("{}", preview_create(args, output)?);
            if let Output::Table = output {
                eprintln!("Dry run: nothing was sent.");
            }
            Ok(())
        }
        SurfaceCommand::List => {
            let surfaces = connect()
                .await?
                .request(Method::GET, SURFACES_PATH, None)
                .await?;
            print_list(&surfaces, output, &tables::AGENT_STREAM_SURFACES, Scope::All)
        }
        SurfaceCommand::Get { id } => {
            println!("{}", get(&connect().await?, &id).await?);
            Ok(())
        }
        SurfaceCommand::Create(args) => create(&connect().await?, args, output).await,
        SurfaceCommand::Update(args) => print_change(update(&connect().await?, args, output).await?),
        SurfaceCommand::Delete { id } => {
            let answer = connect()
                .await?
                .request(Method::DELETE, &surface_path(&id)?, None)
                .await?;
            print_outcome(&answer, output, &confirmation_line("Deleted", "surface", &id))
        }
        SurfaceCommand::Features { id: None } => {
            println!("{}", features::catalog(output)?);
            Ok(())
        }
        SurfaceCommand::Features { id: Some(id) } => {
            check_id(&id)?;
            println!("{}", features::on_surface(&connect().await?, &id, output).await?);
            Ok(())
        }
        SurfaceCommand::AddFeature(args) => {
            let addition = args.checked()?;
            print_change(features::add(&connect().await?, addition, output).await?)
        }
        SurfaceCommand::RemoveFeature(args) => {
            let removal = args.checked()?;
            print_change(features::remove(&connect().await?, removal, output).await?)
        }
        SurfaceCommand::Budget { id } => {
            check_id(&id)?;
            println!("{}", features::budget(&connect().await?, &id, output).await?);
            Ok(())
        }
    }
}

/// Prints what a change to a surface returned to print, if anything.
fn print_change(printed: Option<String>) -> Result<()> {
    if let Some(printed) = printed {
        println!("{printed}");
    }
    Ok(())
}

/// The API path of the surface `id`, once `id` follows Agent Stream's rules.
fn surface_path(id: &str) -> Result<String> {
    check_id(id)?;
    Ok(entity_path(SURFACES_PATH, id))
}

/// Refuses an id Agent Stream would refuse: empty, longer than
/// [`MAX_ID_LEN`], or holding anything but ASCII letters, digits, `-` and `_`.
fn check_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("a surface id can't be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("a surface id may only contain letters, digits, '-' and '_'");
    }
    if id.len() > MAX_ID_LEN {
        bail!("a surface id can be at most {MAX_ID_LEN} characters");
    }
    Ok(())
}

/// The text `get` prints: the surface `id` as Agent Stream keeps it.
async fn get(
    client: &GatewayClient,
    id: &str,
) -> Result<String> {
    let surface = client
        .request(Method::GET, &surface_path(id)?, None)
        .await?;
    pretty_json_for_terminal(&surface)
}

/// A new surface id: `s-` and 12 random hex digits.
fn random_id() -> String {
    let mut bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut bytes);
    let hex: String = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("s-{hex}")
}

async fn create(
    client: &GatewayClient,
    args: CreateArgs,
    output: Output,
) -> Result<()> {
    let (id, body) = create_body(args, unix_now())?;
    let created = client
        .request(Method::POST, SURFACES_PATH, Some(body))
        .await?;
    match output {
        Output::Table => println!("{}", confirmation_line("Created", "surface", &id)),
        Output::Json => println!("{}", pretty_json_for_terminal(&created)?),
    }
    Ok(())
}

/// The text a dry run of `create` prints, sending nothing: the document it
/// would send in table mode, and [`preview_document`] with --output json.
fn preview_create(
    args: CreateArgs,
    output: Output,
) -> Result<String> {
    let (_, body) = create_body(args, unix_now())?;
    match output {
        Output::Table => pretty_json_for_terminal(&body),
        Output::Json => {
            let changes = surface_validate::changes(&json!({}), &body);
            pretty_json_for_terminal(&preview_document(&changes, &body))
        }
    }
}

/// The id and document of a new surface, from --file or the flags. Its
/// top-level field names are checked, its id is taken from the document or
/// --id, which must agree, or made, `created_at` is set to `now` when the
/// document has none, and it must have a `pipe_type.type` and not be marked
/// deleted.
fn create_body(
    args: CreateArgs,
    now: u64,
) -> Result<(String, Value)> {
    let mut body = match args.file {
        Some(file) => read_json(&file)?,
        None => {
            check_flag_paths(&surface_patch::flag_paths(&args.set, &[], &[], &[]), &FIXED_ON_CREATE)?;
            check_null_sets(&args.set, "create")?;
            let name = args
                .name
                .context("--name is required without --file")?;
            let mut body = json!({ "name": name });
            if let Some(description) = args.description {
                body["description"] = Value::String(description);
            }
            let patch = surface_patch::build_patch(&args.set, &[], &[], &[], &body)?;
            surface_validate::merge(&mut body, &patch);
            body
        }
    };
    let fields = body
        .as_object_mut()
        .context("a surface must be a JSON object")?;
    check_top_level_fields(fields.keys(), None)?;
    let id = match (fields.get("id"), args.id) {
        (None | Some(Value::Null), chosen) => chosen.unwrap_or_else(random_id),
        (Some(Value::String(given)), Some(chosen)) if *given != chosen => bail!(
            "the `id` in --file is '{}' and --id is '{}'; give one of them, or the same id in both",
            tables::flatten(given),
            tables::flatten(&chosen)
        ),
        (Some(Value::String(given)), _) => given.clone(),
        (Some(_), _) => bail!("the surface `id` must be text"),
    };
    check_id(&id)?;
    fields.insert("id".to_owned(), Value::String(id.clone()));
    if fields
        .get("created_at")
        .is_none_or(Value::is_null)
    {
        fields.insert("created_at".to_owned(), Value::String(rfc3339_utc(now)));
    }
    check_pipe_type(&body, None, CREATE_PIPE_TYPE_HINT)?;
    if status_of(&body) == Some(STATUS_DELETED) {
        bail!("a new surface can't have `status` set to `deleted`");
    }
    check_status_value(&body)?;
    Ok((id, body))
}

/// The `pipe_type.type` values Agent Stream reads, from the `PipeType`
/// deserializer in Agent Stream's `src/pipes/config.rs`. On `update`, the
/// stored surface's own type counts too, for a type a newer Agent Stream
/// added.
const PIPE_TYPES: [&str; 3] = ["llm", "webhook", "ide_catalog"];

/// The `pipe_type.type` of `surface`, if it is text.
fn pipe_type_of(surface: &Value) -> Option<&str> {
    surface
        .pointer("/pipe_type/type")
        .and_then(Value::as_str)
}

/// Refuses a surface whose `pipe_type.type` is not one Agent Stream reads
/// or the `stored` one, with `hint` saying how to give one.
fn check_pipe_type(
    surface: &Value,
    stored: Option<&str>,
    hint: &str,
) -> Result<()> {
    let known = |given: &str| PIPE_TYPES.contains(&given) || stored == Some(given);
    if !pipe_type_of(surface).is_some_and(known) {
        bail!(
            "a surface needs a `pipe_type.type` of `llm`, `webhook`, or `ide_catalog`, or Agent Stream can't read it; {hint}"
        );
    }
    Ok(())
}

/// Refuses a `status` other than `enabled` or `disabled`, the values a
/// change may set (callers refuse `deleted` first with its own message). A
/// surface with no `status` is left to Agent Stream, which reads it as
/// enabled.
fn check_status_value(surface: &Value) -> Result<()> {
    match surface.get("status") {
        None => Ok(()),
        Some(Value::String(status)) if status == "enabled" || status == "disabled" => Ok(()),
        Some(other) => bail!("`status` must be `enabled` or `disabled`, not {other}"),
    }
}

/// Changes the surface and returns the text to print, if any: the changes in
/// table mode, and with --output json the surface read back after the save,
/// or the stored one when nothing changed.
async fn update(
    client: &GatewayClient,
    args: UpdateArgs,
    output: Output,
) -> Result<Option<String>> {
    let path = surface_path(&args.id)?;
    let paths = surface_patch::flag_paths(&args.set, &args.unset, &args.add, &args.remove);
    check_flag_paths(&paths, &FIXED_ON_UPDATE)?;
    check_status_flags(&paths)?;
    check_null_sets(&args.set, "update")?;
    let before = read_live_surface(client, &path, &args.id).await?;
    let after = match args.file {
        Some(file) => {
            let replaced = replacement(read_json(&file)?, &before, &args.id, args.allow_new_field)?;
            for note in &replaced.notes {
                eprintln!("{note}");
            }
            replaced.surface
        }
        None => {
            let patch = surface_patch::build_patch(&args.set, &args.unset, &args.add, &args.remove, &before)?;
            check_patch_fields(&patch, &before, args.allow_new_field)?;
            let mut after = before.clone();
            surface_validate::merge(&mut after, &patch);
            if status_of(&after) == Some(STATUS_DELETED) {
                bail!("--set can't delete a surface; run `fabric agent-stream surfaces delete {}`", args.id);
            }
            check_status_value(&after)?;
            after
        }
    };
    check_pipe_type(&after, pipe_type_of(&before), UPDATE_PIPE_TYPE_HINT)?;
    save(
        client,
        &Edit {
            path: &path,
            id: &args.id,
            before: &before,
            dry_run: args.dry_run,
        },
        after,
        output,
    )
    .await
}

/// A surface read for a change, and how the change is to be saved.
struct Edit<'a> {
    /// The API path of the surface.
    path: &'a str,
    id: &'a str,
    /// The surface as read, before the change.
    before: &'a Value,
    /// Show the change and save nothing.
    dry_run: bool,
}

/// Saves `after` in place of the surface `edit` read, and returns the text to
/// print, if any. A dry run returns [`preview_update`] and sends nothing. A
/// change that leaves the surface as it is sends nothing either. Otherwise
/// the surface is read again, the save stops if its `updated_at` moved, and
/// the whole surface is sent; a send that fails gets the advice of
/// [`failed_save`]. Table output then lists the changes, and --output json
/// reads the saved surface back.
async fn save(
    client: &GatewayClient,
    edit: &Edit<'_>,
    after: Value,
    output: Output,
) -> Result<Option<String>> {
    let Edit { path, id, before, dry_run } = *edit;
    let changes = surface_validate::changes(before, &after);
    if dry_run {
        return preview_update(&changes, &after, output).map(Some);
    }
    if changes.is_empty() {
        eprintln!("Surface '{id}' already matches, so nothing was sent.");
        return match output {
            Output::Table => Ok(None),
            Output::Json => pretty_json_for_terminal(before).map(Some),
        };
    }
    let current = read_live_surface(client, path, id).await?;
    if present(&current, "updated_at") != present(before, "updated_at") {
        bail!(
            "surface '{id}' was saved by someone else after it was read, so nothing was saved; run the command again \
             to change the new version"
        );
    }
    client
        .request(Method::PUT, path, Some(after))
        .await
        .map_err(|error| failed_save(error, id))?;
    match output {
        Output::Table => {
            let mut lines = vec!["Changes:".to_owned()];
            lines.extend(change_lines(&changes));
            lines.push(confirmation_line("Updated", "surface", id));
            Ok(Some(lines.join("\n")))
        }
        Output::Json => {
            // Agent Stream answers a save with an `updated_at` its store then
            // replaces, so only a fresh read can go back to --file.
            let saved = client
                .request(Method::GET, path, None)
                .await
                .with_context(|| format!("surface '{id}' was saved, but reading it back failed"))?;
            pretty_json_for_terminal(&saved).map(Some)
        }
    }
}

/// How the send of a surface failed, as far as the CLI can tell, which
/// decides whether the surface may have been saved anyway.
#[derive(Debug, PartialEq)]
enum SaveFailure {
    /// The request never left this machine: looking up the host,
    /// connecting, or the TLS handshake failed. Nothing was saved.
    NotSent,
    /// Agent Stream answered with a refusal, a status below 500 such as a
    /// 400 or 409. Nothing was saved.
    Refused,
    /// Agent Stream answered with a server error, such as a 500 or 503,
    /// which can come after the surface was stored, so it may have been
    /// saved.
    ServerError,
    /// Agent Stream answered with success, but the answer was not JSON, so
    /// the CLI can't tell what was saved.
    Unreadable,
    /// The request was sent and no answer came back whole: a timeout, a
    /// dropped connection, an answer cut off while being read, or a 502 or
    /// 504, which only a proxy in front of Agent Stream sends on its surface
    /// routes. Any failure the CLI can't place counts here too, so it is
    /// never told that nothing was saved when something may have been.
    Unanswered,
}

impl SaveFailure {
    /// The kind of `error`, which [`GatewayClient::request`] returned for
    /// the send.
    fn of(error: &anyhow::Error) -> Self {
        if let Some(status) = response_status(error) {
            return if status == StatusCode::BAD_GATEWAY || status == StatusCode::GATEWAY_TIMEOUT {
                Self::Unanswered
            } else if status.is_server_error() {
                Self::ServerError
            } else {
                Self::Refused
            };
        }
        // The client parses only a success answer as JSON; any other answer
        // becomes a status error above.
        if error
            .downcast_ref::<serde_json::Error>()
            .is_some()
        {
            return Self::Unreadable;
        }
        let not_sent = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
            .is_some_and(reqwest::Error::is_connect);
        if not_sent {
            Self::NotSent
        } else {
            Self::Unanswered
        }
    }
}

/// `error` from the save of surface `id`, with advice added when the surface
/// may have been saved anyway, since running the command again would then
/// fail on the change it already made. A request that never left this
/// machine or that Agent Stream refused is returned as it is.
fn failed_save(
    error: anyhow::Error,
    id: &str,
) -> anyhow::Error {
    let check = format!(
        "check it with `fabric agent-stream surfaces get {id}` or `fabric agent-stream surfaces features {id}` \
         before running this again"
    );
    match SaveFailure::of(&error) {
        SaveFailure::NotSent | SaveFailure::Refused => error,
        SaveFailure::Unreadable => error.context(format!(
            "Agent Stream answered the save of surface '{id}' with success, but its answer could not be read; {check}"
        )),
        SaveFailure::ServerError => error.context(format!(
            "Agent Stream answered the save of surface '{id}' with a server error, so it may have been saved anyway; \
             {check}"
        )),
        SaveFailure::Unanswered => {
            error.context(format!("Agent Stream gave no answer, so surface '{id}' may have been saved anyway; {check}"))
        }
    }
}

/// Reads the surface at `path` as Agent Stream has it now, refusing one that
/// is deleted or has no `updated_at` to tell a later save by.
async fn read_live_surface(
    client: &GatewayClient,
    path: &str,
    id: &str,
) -> Result<Value> {
    let surface = client
        .request(Method::GET, path, None)
        .await?;
    if !surface.is_object() {
        bail!("Agent Stream did not answer with a surface for '{id}'");
    }
    if status_of(&surface) == Some(STATUS_DELETED) {
        bail!("surface '{id}' is deleted, so it can't be changed");
    }
    if present(&surface, "updated_at").is_none() {
        bail!(
            "surface '{id}' has no `updated_at`, so the CLI can't tell whether someone else saves it meanwhile; \
             nothing was saved"
        );
    }
    Ok(surface)
}

fn status_of(surface: &Value) -> Option<&str> {
    surface
        .get("status")
        .and_then(Value::as_str)
}

/// The value of `field` in `surface`, with `null` counted as missing.
fn present<'a>(
    surface: &'a Value,
    field: &str,
) -> Option<&'a Value> {
    surface
        .get(field)
        .filter(|value| !value.is_null())
}

/// Refuses, before anything is read, a flag path an Agent Stream surface
/// can't take: an empty one, one with square brackets or a list position,
/// which only Agent Gateway paths use, or one inside a field of `fixed`,
/// which lists the fields no flag may change with the reason.
fn check_flag_paths(
    paths: &[(&str, &str)],
    fixed: &[(&str, &str)],
) -> Result<()> {
    for (flag, path) in paths {
        if path.is_empty() {
            bail!("{flag} needs a field path, such as judge.enabled");
        }
        if path.contains('[') {
            bail!(
                "{flag} can't use brackets in '{}': an Agent Stream surface path is field names joined by '.', such \
                 as judge.enabled; to change a list, give the list's own path to --add or --remove, such as \
                 --remove variants=<id>",
                tables::flatten(path)
            );
        }
        if path.split('.').any(|key| {
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_digit())
        }) {
            bail!(
                "{flag} path '{}' points at a list item by position, which can shift before the change lands: give \
                 the list's own path to --add or --remove instead, such as --remove variants=<id>",
                tables::flatten(path)
            );
        }
        let top = top_field(path);
        if let Some((field, reason)) = fixed
            .iter()
            .find(|(field, _)| *field == top)
        {
            bail!("{flag} can't change `{field}`: {reason}");
        }
    }
    Ok(())
}

/// Refuses `--set <path>=null` where the shared advice, `--unset <path>`,
/// does not apply: on `create`, which has no --unset, and on `update` for
/// `status` and `pipe_type`, whose --unset is refused too.
fn check_null_sets(
    sets: &[String],
    command: &str,
) -> Result<()> {
    for given in sets {
        let Some((path, value)) = given.split_once('=') else {
            continue;
        };
        if value.trim() != "null" {
            continue;
        }
        if command == "create" {
            bail!("--set {path}=null: `create` sends only the fields given, so leave `{path}` out instead");
        }
        match top_field(path) {
            "status" => bail!("`status` can't be null: use --set status=enabled or --set status=disabled"),
            "pipe_type" => bail!("`{path}` can't be null: a surface needs a `pipe_type.type`"),
            _ => {}
        }
    }
    Ok(())
}

/// The top-level field of a flag path: the part before the first `.`.
fn top_field(path: &str) -> &str {
    path.split_once('.')
        .map_or(path, |(top, _)| top)
}

/// Refuses, before anything is read, a flag on `status` other than `--set
/// status=<value>`: Agent Stream reads a surface with no `status` as enabled,
/// so an --unset would turn a disabled surface back on, and a nested path
/// would replace the status with an object Agent Stream can't read.
fn check_status_flags(paths: &[(&str, &str)]) -> Result<()> {
    for (flag, path) in paths {
        let top = top_field(path);
        if top == "status" && (*flag != "--set" || *path != "status") {
            bail!(
                "{flag} can't change `{}`: change `status` with --set status=<enabled|disabled>, or run `surfaces \
                 delete`",
                tables::flatten(path)
            );
        }
    }
    Ok(())
}

/// An `update --file` document ready to send, with the notes to print on
/// standard error.
struct Replacement {
    surface: Value,
    /// One line for each field of [`KEPT_FROM_STORED`] whose value in --file
    /// differed from the stored one.
    notes: Vec<String>,
}

/// The --file document of `update`, ready to send in place of `stored`. Its
/// field names are checked against `stored` as the flags' are, its `id` must
/// be `id` (and is set when missing), and its `updated_at` must be the stored
/// one. The fields of [`KEPT_FROM_STORED`] are replaced with the stored ones,
/// with a note for each that differed.
fn replacement(
    mut file: Value,
    stored: &Value,
    id: &str,
    allow_new_field: bool,
) -> Result<Replacement> {
    let fields = file
        .as_object_mut()
        .context("the --file document must be a JSON object")?;
    check_top_level_fields(fields.keys(), stored.as_object())?;
    if let Some(stored) = stored.as_object() {
        check_nested_fields("", fields, stored, allow_new_field, Given::File)?;
    }
    match fields.get("id") {
        None | Some(Value::Null) => {
            fields.insert("id".to_owned(), Value::String(id.to_owned()));
        }
        Some(Value::String(given)) if given == id => {}
        Some(_) => bail!("the `id` in --file is not '{id}'; Agent Stream refuses a document for another surface"),
    }
    let given_updated_at = fields
        .get("updated_at")
        .filter(|value| !value.is_null());
    if given_updated_at != present(stored, "updated_at") {
        bail!(
            "surface '{id}' changed since you read it: --file does not hold the `updated_at` it has now; run \
             `fabric agent-stream surfaces get {id}` again and edit that copy"
        );
    }
    let mut notes = Vec::new();
    for (field, reason) in KEPT_FROM_STORED {
        let kept = present(stored, field);
        let given = fields
            .get(field)
            .filter(|value| !value.is_null());
        if given.is_some() && given != kept {
            notes.push(format!(
                "note: the `{field}` in --file was replaced with the stored one ({}); {reason}",
                describe(kept)
            ));
        }
        match kept {
            Some(value) => fields.insert(field.to_owned(), value.clone()),
            None => fields.remove(field),
        };
    }
    Ok(Replacement { surface: file, notes })
}

/// Refuses a top-level field name Agent Stream does not know, so it is not
/// dropped without an error. A name the stored surface already has counts as
/// known too, for a field a newer Agent Stream added.
fn check_top_level_fields<'a>(
    keys: impl IntoIterator<Item = &'a String>,
    stored: Option<&Map<String, Value>>,
) -> Result<()> {
    for key in keys {
        let known = SURFACE_FIELDS.contains(&key.as_str()) || stored.is_some_and(|stored| stored.contains_key(key));
        if !known {
            let candidates = SURFACE_FIELDS
                .iter()
                .copied()
                .chain(
                    stored
                        .into_iter()
                        .flat_map(Map::keys)
                        .map(String::as_str),
                );
            bail!(
                "`{}` is not a surface field Agent Stream knows, and it would drop it without an error{}",
                tables::flatten(key),
                suggestion("", closest(key, candidates))
            );
        }
    }
    Ok(())
}

/// Where the field names [`check_nested_fields`] checks come from, which
/// decides what a name the stored surface lacks means.
#[derive(Clone, Copy, PartialEq)]
enum Given {
    /// A patch from --set, --unset, --add and --remove, where `null` means
    /// --unset.
    Flags,
    /// An `update --file` document, where `null` means the field is left out.
    File,
    /// The settings `add-feature` replaces a field with, where `null` is sent
    /// as it is, so a new name set to `null` is checked like any other.
    Feature,
}

/// Checks the field names of a patch from the flags against `stored`: each
/// top-level name with [`check_top_level_fields`], and the names below it
/// with [`check_nested_fields`].
fn check_patch_fields(
    patch: &Value,
    stored: &Value,
    allow_new_field: bool,
) -> Result<()> {
    let (Some(patch), Some(stored)) = (patch.as_object(), stored.as_object()) else {
        return Ok(());
    };
    check_top_level_fields(patch.keys(), Some(stored))?;
    check_nested_fields("", patch, stored, allow_new_field, Given::Flags)
}

/// Walks the objects of `given` (at `path`, empty for the top level) beside
/// those of `existing`. An --unset of a field `existing` does not have is
/// refused, since it has nothing to remove. Unless `allow_new_field`, a name
/// below the top level inside an object `existing` already has must be in
/// that object. A name inside an object `existing` does not have, or inside a
/// list, is not checked, since there is nothing to compare it with.
fn check_nested_fields(
    path: &str,
    given: &Map<String, Value>,
    existing: &Map<String, Value>,
    allow_new_field: bool,
    source: Given,
) -> Result<()> {
    for (key, value) in given {
        let child = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        match (existing.get(key), value) {
            (Some(Value::Object(inner)), Value::Object(nested)) => {
                check_nested_fields(&child, nested, inner, allow_new_field, source)?;
            }
            (Some(_), _) => {}
            (None, Value::Null) if source == Given::File => {}
            (None, _) => {
                let near = || {
                    closest(
                        key,
                        existing
                            .keys()
                            .map(String::as_str),
                    )
                };
                let parent = if path.is_empty() {
                    String::new()
                } else {
                    format!("{path}.")
                };
                if source == Given::Flags {
                    if value.is_null() {
                        bail!(
                            "`{}` is not in the surface as read, so --unset has nothing to remove{}",
                            tables::flatten(&child),
                            suggestion(&parent, near())
                        );
                    }
                    if let Some(removed) = surface_patch::first_null_in_objects(&child, value) {
                        bail!(
                            "`{}` is not in the surface as read, so --unset has nothing to remove",
                            tables::flatten(&removed)
                        );
                    }
                }
                if path.is_empty() || allow_new_field {
                    continue;
                }
                let (place, verb) = match source {
                    Given::Flags => ("", "add"),
                    Given::File => (" in --file", "keep"),
                    Given::Feature => (" in the feature settings", "add"),
                };
                bail!(
                    "`{}`{place} is not in the surface as read; pass --allow-new-field to {verb} it as a new field{}",
                    tables::flatten(&child),
                    suggestion(&parent, near())
                );
            }
        }
    }
    Ok(())
}

/// `; did you mean `<prefix><near>`?` when there is a near name, else nothing.
fn suggestion(
    prefix: &str,
    near: Option<&str>,
) -> String {
    near.map(|near| format!("; did you mean `{}`?", tables::flatten(&format!("{prefix}{near}"))))
        .unwrap_or_default()
}

/// The candidate closest to `key` by edit distance, when it is close enough
/// to be a typo of it: at most 2 edits, or a third of `key`'s length for a
/// longer name, and fewer edits than `key` has characters.
fn closest<'a>(
    key: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let length = key.chars().count();
    let limit = (length / 3)
        .max(2)
        .min(length.saturating_sub(1));
    candidates
        .into_iter()
        .map(|candidate| (edit_distance(key, candidate), candidate))
        .filter(|(distance, _)| *distance <= limit)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

/// The Levenshtein distance between `a` and `b`, counted in characters.
fn edit_distance(
    a: &str,
    b: &str,
) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, left) in a.chars().enumerate() {
        let mut current = vec![i + 1; b.len() + 1];
        for (j, right) in b.iter().enumerate() {
            let substitute = previous[j] + usize::from(left != *right);
            current[j + 1] = substitute
                .min(previous[j + 1] + 1)
                .min(current[j] + 1);
        }
        previous = current;
    }
    previous[b.len()]
}

/// The text a dry run of `update` prints, saying what would change and that
/// nothing was saved: a list of changes in table mode, and
/// [`preview_document`] with --output json.
fn preview_update(
    changes: &[Change],
    after: &Value,
    output: Output,
) -> Result<String> {
    match output {
        Output::Json => pretty_json_for_terminal(&preview_document(changes, after)),
        Output::Table => {
            let mut lines = vec!["Changes:".to_owned()];
            lines.extend(change_lines(changes));
            lines.push(DRY_RUN_UPDATE_NOTE.to_owned());
            Ok(lines.join("\n"))
        }
    }
}

/// The --output json of a dry run of `create` or `update`: `dry_run`, each
/// changed path with its old and new value, and the whole surface that would
/// be sent.
fn preview_document(
    changes: &[Change],
    after: &Value,
) -> Value {
    let changes: Vec<Value> = changes
        .iter()
        .map(|change| json!({ "path": change.path, "before": change.before, "after": change.after }))
        .collect();
    json!({ "dry_run": true, "changes": changes, "after": after })
}

/// One line per changed field, `  path: old -> new`, or `  none`.
fn change_lines(changes: &[Change]) -> Vec<String> {
    if changes.is_empty() {
        return vec!["  none".to_owned()];
    }
    changes
        .iter()
        .map(|change| {
            format!(
                "  {}: {} -> {}",
                tables::flatten_capped(&change.path),
                describe(change.before.as_ref()),
                describe(change.after.as_ref())
            )
        })
        .collect()
}

/// A field's value on one line, safe for the terminal, or `(absent)`.
fn describe(value: Option<&Value>) -> String {
    value.map_or_else(|| "(absent)".to_owned(), |value| sanitize_for_terminal(&value.to_string()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{
        super::{
            AgentStreamCommand,
            test_support::{
                CUT_OFF, HANG_UP, Route, UnusedKeyring, json_file, request_body, run_stream, saved_login,
                scripted_agent_stream, sends_bearer, start_lines, stream_args,
            },
        },
        *,
    };
    use crate::{commands::Cli, config::Config};

    const ACCESS_TOKEN: &str = "aspat_live-secret";
    const STORED_UPDATED_AT: &str = "2026-11-20T10:00:00Z";
    const STORED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","tenant_id":"t-1","owner_user_id":"u-1","route":"/sales","judge":{"enabled":true,"mode":"llm","llm":{"provider_type":"openai","model":"m-1","endpoint_url":"https://llm.example/v1","timeout_secs":30},"strictness":"balanced"},"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    const MOVED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","tenant_id":"t-1","owner_user_id":"u-1","route":"/sales","judge":{"enabled":true,"mode":"llm","llm":{"provider_type":"openai","model":"m-1","endpoint_url":"https://llm.example/v1","timeout_secs":30},"strictness":"balanced"},"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:05:00Z"}"#;
    const DELETED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"deleted","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    /// A surface with no `updated_at`, which Agent Stream's store never saves.
    const UNSTAMPED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","created_at":"2026-11-01T00:00:00Z"}"#;
    /// A surface from a newer Agent Stream, with a top-level field this CLI
    /// does not list.
    const NEWER: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","shadow_mode":false,"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;

    const LISTED: &str = r#"[{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook"},"status":"enabled"}]"#;
    const NEW_SURFACE: &str =
        r#"{"name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"}}"#;

    const GET_STORED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", STORED);
    const GET_MOVED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", MOVED);
    const GET_DELETED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", DELETED);
    const GET_UNSTAMPED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", UNSTAMPED);
    /// A stored surface with a pipe type a newer Agent Stream added.
    const NEWER_TYPE: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"mcp"},"status":"enabled","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    const GET_NEWER_TYPE: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", NEWER_TYPE);
    const PUT_NEWER_TYPE: Route = ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", NEWER_TYPE);
    const GET_NEWER: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", NEWER);
    const PUT_SAVED: Route = ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", STORED);
    /// The answer to a save, with an `updated_at` Agent Stream's store then
    /// replaces.
    const PUT_ANSWERED: Route = (
        "PUT /api/v1/pipes/s-1",
        "HTTP/1.1 200 OK",
        r#"{"id":"s-1","name":"Renamed","status":"enabled","updated_at":"2026-11-20T10:10:00Z"}"#,
    );
    /// The surface as a read after the save finds it.
    const READ_BACK: &str = r#"{"id":"s-1","name":"Renamed","status":"enabled","updated_at":"2026-11-20T10:10:01Z"}"#;
    const GET_READ_BACK: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", READ_BACK);
    const GET_FAILED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 500 Internal Server Error", "");
    /// A save that gets no answer at all.
    const PUT_HUNG_UP: Route = ("PUT /api/v1/pipes/s-1", HANG_UP, "");
    /// What the CLI says when the save of `s-1` got no answer.
    const MAY_HAVE_BEEN_SAVED: &str = "Agent Stream gave no answer, so surface 's-1' may have been saved anyway; \
                                       check it with `fabric agent-stream surfaces get s-1`";
    /// What the CLI says when the save of `s-1` got a success answer it
    /// could not read.
    const ANSWER_UNREADABLE: &str = "Agent Stream answered the save of surface 's-1' with success, but its answer \
                                     could not be read; check it with `fabric agent-stream surfaces get s-1`";
    const POST_CREATED: Route = ("POST /api/v1/pipes", "HTTP/1.1 200 OK", STORED);

    const GET_LINE: &str = "GET /api/v1/pipes/s-1 HTTP/1.1";
    const PUT_LINE: &str = "PUT /api/v1/pipes/s-1 HTTP/1.1";
    const POST_LINE: &str = "POST /api/v1/pipes HTTP/1.1";

    const WEBHOOK_TYPE: &str = "pipe_type.type=webhook";
    const WEBHOOK_ENDPOINT: &str = "pipe_type.endpoint=https://hooks.example/in";

    /// Runs `fabric agent-stream <words>` with a saved access token for `host`.
    async fn run_surfaces(
        host: &str,
        words: &[&str],
    ) -> Result<()> {
        let (saved, credentials) = saved_login(host, ACCESS_TOKEN);
        run_stream(words, saved, &credentials).await
    }

    /// The JSON body of the recorded request at `index`.
    fn sent_json(
        requests: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        index: usize,
    ) -> Value {
        let requests = requests.lock().unwrap();
        serde_json::from_str(request_body(&requests[index])).expect("a JSON body")
    }

    /// The `surfaces` command of `fabric agent-stream <words>`.
    fn surface_command(words: &[&str]) -> SurfaceCommand {
        match stream_args(words).command {
            AgentStreamCommand::Surfaces { command } => command,
            other => panic!("{words:?} is not a surfaces command: {other:?}"),
        }
    }

    /// What `update` returns to print for `fabric agent-stream <words>`,
    /// against the Agent Stream at `host`.
    async fn printed_update(
        host: &str,
        words: &[&str],
        output: Output,
    ) -> Result<Option<String>> {
        let SurfaceCommand::Update(args) = surface_command(words) else {
            panic!("{words:?} is not `surfaces update`");
        };
        let client = GatewayClient::for_agent_stream(host, ACCESS_TOKEN)?;
        update(&client, args, output).await
    }

    /// What a dry run of `create` prints for `fabric agent-stream <words>`.
    fn printed_create_preview(
        words: &[&str],
        output: Output,
    ) -> String {
        let SurfaceCommand::Create(args) = surface_command(words) else {
            panic!("{words:?} is not `surfaces create`");
        };
        preview_create(args, output).expect("a create preview")
    }

    /// The path of a temporary file, as a command line word.
    fn path_of(file: &tempfile::NamedTempFile) -> &str {
        file.path().to_str().unwrap()
    }

    #[tokio::test]
    async fn list_reads_every_surface_from_the_pipes_route() {
        let (host, requests) = scripted_agent_stream(vec![("GET /api/v1/pipes", "HTTP/1.1 200 OK", LISTED)]).await;

        run_surfaces(&host, &["surfaces", "list"])
            .await
            .expect("surfaces list");

        assert_eq!(start_lines(&requests), ["GET /api/v1/pipes HTTP/1.1"]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN));
    }

    #[test]
    fn the_list_table_shows_id_name_type_status_route_and_update_time() {
        let rows = vec![serde_json::from_str::<Value>(STORED).unwrap()];

        let lines = tables::render_list(&tables::AGENT_STREAM_SURFACES, &rows);

        assert_eq!(
            lines,
            [
                "ID   NAME   TYPE     STATUS   ROUTE   UPDATED",
                "s-1  Sales  webhook  enabled  /sales  2026-11-20T10:00:00Z",
            ]
        );
    }

    #[tokio::test]
    async fn get_reads_one_surface_by_id() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let printed = get(&client, "s-1")
            .await
            .expect("surfaces get");

        assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), serde_json::from_str::<Value>(STORED).unwrap());
        assert_eq!(start_lines(&requests), [GET_LINE]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN));
    }

    #[tokio::test]
    async fn create_fills_id_and_created_at() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;

        run_surfaces(
            &host,
            &["surfaces", "create", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", WEBHOOK_ENDPOINT],
        )
        .await
        .expect("surfaces create");

        assert_eq!(start_lines(&requests), [POST_LINE]);
        let body = sent_json(&requests, 0);
        let id_shape = regex::Regex::new("^s-[0-9a-f]{12}$").unwrap();
        let time_shape = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").unwrap();
        assert!(id_shape.is_match(body["id"].as_str().unwrap()), "{body}");
        assert!(
            time_shape.is_match(
                body["created_at"]
                    .as_str()
                    .unwrap()
            ),
            "{body}"
        );
        assert_eq!(body["name"], "Sales");
        assert_eq!(body["pipe_type"], json!({"type": "webhook", "endpoint": "https://hooks.example/in"}));
    }

    #[tokio::test]
    async fn create_keeps_a_chosen_id_and_the_created_at_of_a_file() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;
        let file = json_file(
            r#"{"name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"created_at":"2026-01-01T00:00:00Z"}"#,
        );

        run_surfaces(&host, &["surfaces", "create", "--name", "Sales", "--set", WEBHOOK_TYPE, "--id", "sales_1"])
            .await
            .expect("create with --id");
        run_surfaces(&host, &["surfaces", "create", "--file", path_of(&file)])
            .await
            .expect("create with --file");

        assert_eq!(sent_json(&requests, 0)["id"], "sales_1");
        assert_eq!(sent_json(&requests, 1)["created_at"], "2026-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn create_id_fills_a_file_without_one_and_must_match_a_file_with_one() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;
        let without_id = json_file(NEW_SURFACE);
        let mut with_id: Value = serde_json::from_str(NEW_SURFACE).unwrap();
        with_id["id"] = json!("sales_1");
        let with_id = json_file(&with_id.to_string());

        run_surfaces(&host, &["surfaces", "create", "--file", path_of(&without_id), "--id", "sales_1"])
            .await
            .expect("--id fills the missing id");
        run_surfaces(&host, &["surfaces", "create", "--file", path_of(&with_id), "--id", "sales_1"])
            .await
            .expect("the same id twice");
        let error = run_surfaces(&host, &["surfaces", "create", "--file", path_of(&with_id), "--id", "sales_2"])
            .await
            .expect_err("the ids differ");

        assert_eq!(
            error.to_string(),
            "the `id` in --file is 'sales_1' and --id is 'sales_2'; give one of them, or the same id in both"
        );
        assert_eq!(start_lines(&requests), [POST_LINE, POST_LINE]);
        assert_eq!(sent_json(&requests, 0)["id"], "sales_1");
        assert_eq!(sent_json(&requests, 1)["id"], "sales_1");
    }

    #[tokio::test]
    async fn create_refuses_bad_id() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;
        let too_long = "a".repeat(MAX_ID_LEN + 1);
        let file = json_file(r#"{"id":"../s-1","name":"Sales"}"#);

        for words in [
            vec!["surfaces", "create", "--name", "Sales", "--id", "s 1"],
            vec!["surfaces", "create", "--name", "Sales", "--id", &too_long],
            vec!["surfaces", "create", "--file", path_of(&file)],
        ] {
            let error = run_surfaces(&host, &words)
                .await
                .expect_err("the id breaks Agent Stream's rules");
            assert!(
                error
                    .to_string()
                    .starts_with("a surface id"),
                "{words:?}: {error}"
            );
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn create_refuses_set_on_fields_with_their_own_source_and_a_deleted_status() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;

        for (set, expected) in [
            ("id=s-2", "--set can't change `id`: use --id"),
            ("name=Other", "--set can't change `name`: use --name"),
            (
                "created_at=2020-01-01T00:00:00Z",
                "--set can't change `created_at`: the CLI sets it to the current time; give another in --file",
            ),
            ("updated_at=2020-01-01T00:00:00Z", "--set can't change `updated_at`: Agent Stream sets it on every save"),
            (
                "tenant_id=t-2",
                "--set can't change `tenant_id`: give it in --file, where Agent Stream checks it against your token",
            ),
            (
                "owner_user_id.x=u-2",
                "--set can't change `owner_user_id`: Agent Stream sets it to the user who creates the surface",
            ),
            ("status=deleted", "a new surface can't have `status` set to `deleted`"),
        ] {
            let error =
                run_surfaces(&host, &["surfaces", "create", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", set])
                    .await
                    .expect_err("the flag is refused");
            assert_eq!(error.to_string(), expected, "{set}");
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn create_refuses_a_surface_without_a_pipe_type() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;

        let error = run_surfaces(&host, &["surfaces", "create", "--name", "Sales"])
            .await
            .expect_err("Agent Stream can't read a surface without a type");

        assert!(
            error
                .to_string()
                .starts_with("a surface needs a `pipe_type.type`"),
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
    async fn create_refuses_an_unknown_top_level_key_before_sending() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;
        let file = json_file(r#"{"name":"Sales","rate_limt":{"requests_per_minute":10}}"#);

        let error = run_surfaces(&host, &["surfaces", "create", "--file", path_of(&file)])
            .await
            .expect_err("rate_limt is a typo");

        assert_eq!(
            error.to_string(),
            "`rate_limt` is not a surface field Agent Stream knows, and it would drop it without an error; did you \
             mean `rate_limit`?"
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn create_dry_run_needs_no_saved_connection() {
        let words =
            ["surfaces", "create", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", WEBHOOK_ENDPOINT, "--dry-run"];

        run_stream(&words, Config::default(), &UnusedKeyring)
            .await
            .expect("a dry run sends nothing, so it needs no saved connection");
    }

    #[tokio::test]
    async fn create_dry_run_sends_nothing() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;

        run_surfaces(
            &host,
            &["surfaces", "create", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", WEBHOOK_ENDPOINT, "--dry-run"],
        )
        .await
        .expect("a dry run");

        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn create_dry_run_prints_the_document_it_would_send() {
        let words =
            ["surfaces", "create", "--id", "s-9", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", WEBHOOK_ENDPOINT];

        let printed: Value = serde_json::from_str(&printed_create_preview(&words, Output::Table)).expect("JSON");

        assert_eq!(printed["id"], "s-9");
        assert_eq!(printed["name"], "Sales");
        assert_eq!(printed["pipe_type"], json!({"type": "webhook", "endpoint": "https://hooks.example/in"}));
        assert!(printed["created_at"].is_string(), "{printed}");
    }

    #[tokio::test]
    async fn both_dry_runs_print_the_same_json_shape() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let create_words =
            ["surfaces", "create", "--id", "s-9", "--name", "Sales", "--set", WEBHOOK_TYPE, "--set", WEBHOOK_ENDPOINT];

        let created: Value = serde_json::from_str(&printed_create_preview(&create_words, Output::Json)).expect("JSON");
        let updated = printed_update(
            &host,
            &["surfaces", "update", "s-1", "--set", "judge.enabled=false", "--dry-run"],
            Output::Json,
        )
        .await
        .expect("a dry run")
        .expect("a dry run prints its preview");
        let updated: Value = serde_json::from_str(&updated).expect("JSON");

        let mut after: Value = serde_json::from_str(STORED).unwrap();
        after["judge"]["enabled"] = json!(false);
        assert_eq!(
            updated,
            json!({
                "dry_run": true,
                "changes": [{"path": "judge.enabled", "before": true, "after": false}],
                "after": after,
            })
        );
        assert_eq!(created["dry_run"], true);
        assert_eq!(created["after"]["id"], "s-9");
        assert_eq!(created["after"]["name"], "Sales");
        assert!(
            created["changes"]
                .as_array()
                .expect("a list of changes")
                .contains(&json!({"path": "name", "before": null, "after": "Sales"})),
            "a new surface lists each field from absent: {created}"
        );
        assert_eq!(start_lines(&requests), [GET_LINE], "a dry run reads once and sends no PUT");
    }

    #[tokio::test]
    async fn update_reads_twice_then_puts_the_whole_changed_surface() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let printed = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Table)
            .await
            .expect("surfaces update");

        assert_eq!(printed.as_deref(), Some("Changes:\n  name: \"Sales\" -> \"Renamed\"\nUpdated surface 's-1'"));
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        let sent = sent_json(&requests, 2);
        let mut expected: Value = serde_json::from_str(STORED).unwrap();
        expected["name"] = json!("Renamed");
        assert_eq!(sent, expected);
    }

    #[tokio::test]
    async fn update_json_output_reads_the_saved_surface_back() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, GET_STORED, GET_READ_BACK, PUT_ANSWERED]).await;

        let printed = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Json)
            .await
            .expect("surfaces update --output json")
            .expect("--output json prints the saved surface");

        let printed: Value = serde_json::from_str(&printed).expect("JSON");
        assert_eq!(
            printed,
            serde_json::from_str::<Value>(READ_BACK).unwrap(),
            "the read-back copy, not the PUT answer"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn update_says_the_surface_was_saved_when_reading_it_back_fails() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, GET_STORED, GET_FAILED, PUT_ANSWERED]).await;

        let error = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Json)
            .await
            .expect_err("the read after the save fails");

        assert!(
            error
                .to_string()
                .contains("surface 's-1' was saved, but reading it back failed"),
            "{error}"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn update_with_no_answer_to_the_save_says_it_may_have_been_saved() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_HUNG_UP]).await;

        let error = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Table)
            .await
            .expect_err("the save got no answer");

        let text = format!("{error:#}");
        assert!(text.starts_with(MAY_HAVE_BEEN_SAVED), "{text}");
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
    }

    #[tokio::test]
    async fn a_save_whose_answer_is_cut_off_says_it_may_have_been_saved() {
        let (host, requests) =
            scripted_agent_stream(vec![GET_STORED, ("PUT /api/v1/pipes/s-1", CUT_OFF, STORED)]).await;

        let error = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Table)
            .await
            .expect_err("the answer was cut off");

        let text = format!("{error:#}");
        assert!(text.starts_with(MAY_HAVE_BEEN_SAVED), "{text}");
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
    }

    #[tokio::test]
    async fn a_save_answered_with_success_that_is_not_json_says_the_answer_could_not_be_read() {
        let (host, requests) =
            scripted_agent_stream(vec![GET_STORED, ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", "<html>saved</html>")])
                .await;

        let error = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"], Output::Table)
            .await
            .expect_err("the answer is not JSON");

        let text = format!("{error:#}");
        assert!(text.starts_with(ANSWER_UNREADABLE), "{text}");
        assert!(!text.contains("gave no answer"), "{text}");
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
    }

    #[tokio::test]
    async fn a_save_that_never_reached_agent_stream_gets_no_advice() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let host = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("local addr")
        );
        drop(listener);
        let client = GatewayClient::for_agent_stream(host, ACCESS_TOKEN).expect("client");

        let error = client
            .request(Method::PUT, "/api/v1/pipes/s-1", Some(json!({"id": "s-1"})))
            .await
            .expect_err("nothing listens there");

        assert_eq!(SaveFailure::of(&error), SaveFailure::NotSent);
        let text = format!("{:#}", failed_save(error, "s-1"));
        assert!(!text.contains("may have been saved"), "{text}");
        assert!(!text.contains("answered the save"), "{text}");
    }

    #[tokio::test]
    async fn update_refuses_when_updated_at_moved() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, GET_MOVED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"])
            .await
            .expect_err("someone saved the surface between the reads");

        assert!(
            error
                .to_string()
                .contains("was saved by someone else after it was read"),
            "{error}"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn update_stops_when_the_surface_is_deleted_between_the_reads() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, GET_DELETED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"])
            .await
            .expect_err("the surface was deleted after the first read");

        assert_eq!(error.to_string(), "surface 's-1' is deleted, so it can't be changed");
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn update_file_refuses_stale_copy() {
        let (host, requests) = scripted_agent_stream(vec![GET_MOVED, PUT_SAVED]).await;
        let file = json_file(STORED);

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file)])
            .await
            .expect_err("the file was read before the last save");

        assert!(
            error
                .to_string()
                .contains("changed since you read it"),
            "{error}"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn update_refuses_deleted_surface() {
        let (host, requests) = scripted_agent_stream(vec![GET_DELETED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "name=Renamed"])
            .await
            .expect_err("a deleted surface can't change");

        assert_eq!(error.to_string(), "surface 's-1' is deleted, so it can't be changed");
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn update_file_keeps_server_status_created_at_tenant_and_owner() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let mut edited: Value = serde_json::from_str(STORED).unwrap();
        edited["name"] = json!("Renamed");
        edited["status"] = json!("deleted");
        edited["created_at"] = json!("2020-01-01T00:00:00Z");
        edited["tenant_id"] = json!("t-2");
        edited["owner_user_id"] = json!("u-2");
        let file = json_file(&edited.to_string());

        run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file)])
            .await
            .expect("surfaces update --file");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        let sent = sent_json(&requests, 2);
        let mut expected: Value = serde_json::from_str(STORED).unwrap();
        expected["name"] = json!("Renamed");
        assert_eq!(sent, expected, "only the name changes");
        assert_eq!(sent["updated_at"], STORED_UPDATED_AT);
        let stored: Value = serde_json::from_str(STORED).unwrap();
        let replaced = replacement(edited, &stored, "s-1", false).expect("the same --file again");
        assert_eq!(
            replaced.notes,
            [
                "note: the `status` in --file was replaced with the stored one (\"enabled\"); change it with --set \
                 status=<enabled|disabled>, or run `surfaces delete`",
                "note: the `created_at` in --file was replaced with the stored one (\"2026-11-01T00:00:00Z\"); it is \
                 set once, when the surface is created",
                "note: the `tenant_id` in --file was replaced with the stored one (\"t-1\"); a surface can't move to \
                 another tenant or owner",
                "note: the `owner_user_id` in --file was replaced with the stored one (\"u-1\"); a surface can't move \
                 to another tenant or owner",
            ]
        );
    }

    #[tokio::test]
    async fn update_refuses_flags_on_fields_it_can_not_change_before_reading() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        for (flag, path, field) in [
            ("--set", "id=s-2", "id"),
            ("--set", "created_at=2020-01-01T00:00:00Z", "created_at"),
            ("--set", "updated_at=2020-01-01T00:00:00Z", "updated_at"),
            ("--set", "tenant_id=t-2", "tenant_id"),
            ("--unset", "owner_user_id", "owner_user_id"),
            ("--set", "id.x=1", "id"),
            ("--unset", "updated_at.x", "updated_at"),
            ("--add", "tenant_id=t-2", "tenant_id"),
            ("--remove", "owner_user_id=u-1", "owner_user_id"),
        ] {
            let error = run_surfaces(&host, &["surfaces", "update", "s-1", flag, path])
                .await
                .expect_err("the field is fixed");
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("{flag} can't change `{field}`")),
                "{error}"
            );
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn update_refuses_a_surface_left_without_a_pipe_type() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let mut without_type: Value = serde_json::from_str(STORED).unwrap();
        without_type
            .as_object_mut()
            .unwrap()
            .remove("pipe_type");
        let file = json_file(&without_type.to_string());

        for words in [
            ["--unset", "pipe_type"],
            ["--unset", "pipe_type.type"],
            ["--set", "pipe_type.type=123"],
            ["--set", "pipe_type.type="],
            ["--set", "pipe_type.type=api"],
            ["--file", path_of(&file)],
        ] {
            let error = run_surfaces(&host, &[&["surfaces", "update", "s-1"][..], &words].concat())
                .await
                .expect_err("Agent Stream can't read a surface without a type");
            assert!(
                error
                    .to_string()
                    .starts_with("a surface needs a `pipe_type.type`"),
                "{words:?}: {error}"
            );
        }
        assert_eq!(start_lines(&requests), [GET_LINE; 6], "each reads once and sends no PUT");
    }

    #[tokio::test]
    async fn update_refuses_a_status_other_than_enabled_or_disabled() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        for value in ["status=paused", "status=123", r#"status={"x":1}"#, "status="] {
            let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", value])
                .await
                .expect_err("Agent Stream reads only enabled or disabled");
            assert!(
                error
                    .to_string()
                    .starts_with("`status` must be `enabled` or `disabled`"),
                "{value}: {error}"
            );
        }
        assert_eq!(start_lines(&requests), [GET_LINE; 4], "each reads once and sends no PUT");
    }

    #[tokio::test]
    async fn create_refuses_a_status_other_than_enabled_or_disabled_before_sending() {
        let (host, requests) = scripted_agent_stream(vec![POST_CREATED]).await;

        let error = run_surfaces(
            &host,
            &[
                "surfaces",
                "create",
                "--name",
                "Sales",
                "--set",
                "pipe_type.type=webhook",
                "--set",
                WEBHOOK_ENDPOINT,
                "--set",
                "status=paused",
            ],
        )
        .await
        .expect_err("Agent Stream reads only enabled or disabled");

        assert!(
            error
                .to_string()
                .starts_with("`status` must be"),
            "{error}"
        );
        assert!(start_lines(&requests).is_empty(), "nothing is sent");
    }

    #[tokio::test]
    async fn update_keeps_a_pipe_type_a_newer_agent_stream_added() {
        let (host, requests) = scripted_agent_stream(vec![GET_NEWER_TYPE, PUT_NEWER_TYPE]).await;

        run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "name=Sales EU"])
            .await
            .expect("the stored type is kept");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["pipe_type"]["type"], "mcp");
    }

    #[tokio::test]
    async fn null_sets_get_advice_that_works_for_the_command() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED]).await;

        for (words, start) in [
            (vec!["surfaces", "update", "s-1", "--set", "status=null"], "`status` can't be null"),
            (vec!["surfaces", "update", "s-1", "--set", "pipe_type.type=null"], "`pipe_type.type` can't be null"),
            (
                vec!["surfaces", "create", "--name", "Sales", "--set", "status=null", "--dry-run"],
                "--set status=null: `create` sends only the fields given",
            ),
        ] {
            let error = run_surfaces(&host, &words)
                .await
                .expect_err("a null here has no --unset to point at");
            assert!(
                error
                    .to_string()
                    .starts_with(start),
                "{words:?}: {error}"
            );
        }
        assert!(start_lines(&requests).is_empty(), "each is refused before anything is read");
    }

    #[tokio::test]
    async fn get_command_reads_the_surface_by_id() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED]).await;

        run_surfaces(&host, &["surfaces", "get", "s-1"])
            .await
            .expect("surfaces get");

        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn update_refuses_a_surface_without_updated_at() {
        let (host, requests) = scripted_agent_stream(vec![GET_UNSTAMPED, PUT_SAVED]).await;
        let mut edited: Value = serde_json::from_str(UNSTAMPED).unwrap();
        edited["name"] = json!("Renamed");
        let file = json_file(&edited.to_string());

        for words in [["--set", "name=Renamed"], ["--file", path_of(&file)]] {
            let error = run_surfaces(&host, &[&["surfaces", "update", "s-1"][..], &words].concat())
                .await
                .expect_err("nothing to tell a later save by");
            assert_eq!(
                error.to_string(),
                "surface 's-1' has no `updated_at`, so the CLI can't tell whether someone else saves it meanwhile; \
                 nothing was saved",
                "{words:?}"
            );
        }
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn update_refuses_status_flags_other_than_set_before_reading() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        for (flag, path, shown) in [
            ("--unset", "status", "status"),
            ("--unset", "status.x", "status.x"),
            ("--set", "status.x=1", "status.x"),
            ("--add", "status=disabled", "status"),
            ("--remove", "status=enabled", "status"),
        ] {
            let error = run_surfaces(&host, &["surfaces", "update", "s-1", flag, path])
                .await
                .expect_err("status changes only with --set status=<value>");
            assert_eq!(
                error.to_string(),
                format!(
                    "{flag} can't change `{shown}`: change `status` with --set status=<enabled|disabled>, or run \
                     `surfaces delete`"
                )
            );
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn update_sets_status_to_disabled() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "status=disabled"])
            .await
            .expect("--set status=disabled");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["status"], "disabled");
    }

    #[tokio::test]
    async fn update_dry_run_sends_no_put() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let printed = printed_update(
            &host,
            &["surfaces", "update", "s-1", "--set", "judge.enabled=false", "--dry-run"],
            Output::Table,
        )
        .await
        .expect("a dry run");

        assert_eq!(
            printed.as_deref(),
            Some(format!("Changes:\n  judge.enabled: true -> false\n{DRY_RUN_UPDATE_NOTE}").as_str())
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn update_file_dry_run_sends_no_put() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let mut edited: Value = serde_json::from_str(STORED).unwrap();
        edited["name"] = json!("Renamed");
        let file = json_file(&edited.to_string());

        run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file), "--dry-run"])
            .await
            .expect("a dry run of --file");

        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[test]
    fn the_preview_lists_each_changed_path_with_its_old_and_new_value() {
        let before: Value = serde_json::from_str(STORED).unwrap();
        let mut after = before.clone();
        after["judge"]["enabled"] = json!(false);
        after["description"] = json!("Inbound sales");

        let lines = change_lines(&surface_validate::changes(&before, &after));

        assert_eq!(lines, ["  description: (absent) -> \"Inbound sales\"", "  judge.enabled: true -> false"]);
    }

    #[tokio::test]
    async fn set_refuses_unknown_top_level_key() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "judeg.enabled=false"])
            .await
            .expect_err("judeg is a typo");

        assert_eq!(
            error.to_string(),
            "`judeg` is not a surface field Agent Stream knows, and it would drop it without an error; did you mean \
             `judge`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn set_refuses_unknown_nested_key() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "judge.strictnes=lenient"])
            .await
            .expect_err("strictnes is a typo");

        assert_eq!(
            error.to_string(),
            "`judge.strictnes` is not in the surface as read; pass --allow-new-field to add it as a new field; did \
             you mean `judge.strictness`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn set_refuses_unknown_key_two_levels_down() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "judge.llm.modle=m-2"])
            .await
            .expect_err("modle is a typo");

        assert_eq!(
            error.to_string(),
            "`judge.llm.modle` is not in the surface as read; pass --allow-new-field to add it as a new field; did \
             you mean `judge.llm.model`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn allow_new_field_lets_it_through() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(
            &host,
            &["surfaces", "update", "s-1", "--set", "judge.confidence_threshold=0.8", "--allow-new-field"],
        )
        .await
        .expect("the new field is allowed");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["judge"]["confidence_threshold"], 0.8);
    }

    #[tokio::test]
    async fn unset_of_a_missing_field_has_nothing_to_remove() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let typo = run_surfaces(&host, &["surfaces", "update", "s-1", "--unset", "judge.strictnes"])
            .await
            .expect_err("strictnes is a typo");
        let allowed =
            run_surfaces(&host, &["surfaces", "update", "s-1", "--unset", "judge.strictnes", "--allow-new-field"])
                .await
                .expect_err("--allow-new-field does not make a removal of nothing useful");
        let absent_parent =
            run_surfaces(&host, &["surfaces", "update", "s-1", "--unset", "rate_limit.requests_per_minute"])
                .await
                .expect_err("the surface has no rate_limit");

        let expected = "`judge.strictnes` is not in the surface as read, so --unset has nothing to remove; did you mean \
             `judge.strictness`?";
        assert_eq!(typo.to_string(), expected);
        assert_eq!(allowed.to_string(), expected);
        assert_eq!(
            absent_parent.to_string(),
            "`rate_limit.requests_per_minute` is not in the surface as read, so --unset has nothing to remove"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn a_new_top_level_object_only_needs_a_known_name() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "rate_limit.requests_per_minute=60"])
            .await
            .expect("rate_limit is a known field the surface does not have yet");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
    }

    #[tokio::test]
    async fn a_top_level_field_the_stored_surface_has_is_known() {
        let (host, requests) =
            scripted_agent_stream(vec![GET_NEWER, ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", NEWER)]).await;
        let mut edited: Value = serde_json::from_str(NEWER).unwrap();
        edited["shadow_mode"] = json!(true);
        let file = json_file(&edited.to_string());

        run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "shadow_mode=true"])
            .await
            .expect("a field the surface has, though this CLI does not list it");
        run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file)])
            .await
            .expect("the same field in --file");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE, GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["shadow_mode"], true);
        assert_eq!(sent_json(&requests, 5)["shadow_mode"], true);
    }

    #[tokio::test]
    async fn update_file_refuses_unknown_top_level_key() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let mut edited: Value = serde_json::from_str(STORED).unwrap();
        edited["rate_limt"] = json!({"requests_per_minute": 60});
        let file = json_file(&edited.to_string());

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file)])
            .await
            .expect_err("rate_limt is a typo");

        assert_eq!(
            error.to_string(),
            "`rate_limt` is not a surface field Agent Stream knows, and it would drop it without an error; did you \
             mean `rate_limit`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn update_file_refuses_unknown_nested_key_unless_allowed() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let mut edited: Value = serde_json::from_str(STORED).unwrap();
        edited["judge"]["llm"]["modle"] = json!("m-2");
        let file = json_file(&edited.to_string());

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file)])
            .await
            .expect_err("modle is a typo");
        run_surfaces(&host, &["surfaces", "update", "s-1", "--file", path_of(&file), "--allow-new-field"])
            .await
            .expect("--allow-new-field keeps it");

        assert_eq!(
            error.to_string(),
            "`judge.llm.modle` in --file is not in the surface as read; pass --allow-new-field to keep it as a new \
             field; did you mean `judge.llm.model`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 3)["judge"]["llm"]["modle"], "m-2");
    }

    #[tokio::test]
    async fn paths_with_brackets_or_positions_are_refused_with_an_agent_stream_example() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        for (words, start) in [
            (["--set", "variants[v-1].name=x"], "--set can't use brackets in 'variants[v-1].name'"),
            (["--remove", "variants[v-1]=x"], "--remove can't use brackets in 'variants[v-1]'"),
            (["--set", "variants.0.name=x"], "--set path 'variants.0.name' points at a list item by position"),
        ] {
            let error = run_surfaces(&host, &[&["surfaces", "update", "s-1"][..], &words].concat())
                .await
                .expect_err("not an Agent Stream path");
            let message = error.to_string();
            assert!(message.starts_with(start), "{message}");
            assert!(message.ends_with("such as --remove variants=<id>"), "{message}");
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn set_refuses_to_mark_a_surface_deleted() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "update", "s-1", "--set", "status=deleted"])
            .await
            .expect_err("a delete goes through surfaces delete");

        assert!(
            error
                .to_string()
                .contains("`fabric agent-stream surfaces delete s-1`"),
            "{error}"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn an_update_that_changes_nothing_sends_no_put() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let table = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Sales"], Output::Table)
            .await
            .expect("nothing to change");
        let json = printed_update(&host, &["surfaces", "update", "s-1", "--set", "name=Sales"], Output::Json)
            .await
            .expect("nothing to change, with --output json")
            .expect("--output json prints the stored surface");

        assert_eq!(table, None, "table mode prints nothing on standard output");
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), serde_json::from_str::<Value>(STORED).unwrap());
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn delete_sends_one_delete_for_the_id() {
        let (host, requests) =
            scripted_agent_stream(vec![("DELETE /api/v1/pipes/s-1", "HTTP/1.1 204 No Content", "")]).await;

        run_surfaces(&host, &["surfaces", "delete", "s-1"])
            .await
            .expect("surfaces delete");

        assert_eq!(start_lines(&requests), ["DELETE /api/v1/pipes/s-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn get_update_and_delete_refuse_a_bad_id_before_sending() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED]).await;

        for words in [
            vec!["surfaces", "get", "../access-tokens"],
            vec!["surfaces", "update", "s.1", "--set", "name=x"],
            vec!["surfaces", "delete", "s 1"],
        ] {
            run_surfaces(&host, &words)
                .await
                .expect_err("the id breaks Agent Stream's rules");
        }
        assert!(
            requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn pipes_is_not_a_command() {
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "pipes", "list"]).is_err());
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "surfaces", "list"]).is_ok());
    }

    #[tokio::test]
    async fn a_terms_gate_failure_on_a_surface_route_gets_the_terms_hint_once() {
        let body = r#"{"code":"TERMS_OPERATIONAL_FAILURE"}"#;
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/pipes", "HTTP/1.1 503 Service Unavailable", body)]).await;

        let error = run_surfaces(&host, &["surfaces", "list"])
            .await
            .expect_err("the Terms gate refuses the list");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "the upstream terms provider is unavailable; check `fabric agent-stream terms provider-health`: {body}"
            )
        );
    }

    #[test]
    fn ids_follow_the_agent_stream_rules() {
        assert!(check_id(&"a".repeat(MAX_ID_LEN)).is_ok());
        assert!(check_id("S-1_b").is_ok());
        assert!(check_id(&"a".repeat(MAX_ID_LEN + 1)).is_err());
        assert!(check_id("").is_err());
        assert!(check_id("s.1").is_err());
        assert!(check_id("é").is_err());
    }

    #[test]
    fn the_field_list_names_each_field_once() {
        let mut names = SURFACE_FIELDS.to_vec();
        names.sort_unstable();
        names.dedup();

        assert_eq!(names.len(), SURFACE_FIELDS.len());
    }

    #[test]
    fn a_far_name_gets_no_suggestion() {
        assert_eq!(closest("judeg", SURFACE_FIELDS), Some("judge"));
        assert_eq!(closest("colour", SURFACE_FIELDS), None);
        assert_eq!(closest("x", ["id"]), None);
    }
}
