//! `fabric agent-stream surfaces features`, `add-feature`, `remove-feature`,
//! and `budget`: the cost and safety settings of an Agent Stream surface.
//!
//! On Agent Stream each of these settings is a field of the surface, not a
//! route of its own. So adding or removing a feature reads the surface,
//! changes that one field on this machine, and saves the whole surface the
//! way `surfaces update` does, with the same field-name check, stale check,
//! and dry run.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args};
use reqwest::Method;
use serde_json::{Map, Value, json};

use super::{
    Edit, Given, STATUS_DELETED, check_nested_fields, closest, pipe_type_of, read_live_surface, save, status_of,
    surface_path,
};
use crate::{
    client::{GatewayClient, is_unexplained_agent_stream_forbidden, pretty_json_for_terminal},
    commands::{Output, read_json},
    surface_patch, surface_validate,
    tables::{self, format_rows},
};

/// Whether a feature's field holds one group of settings or a list of items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// An object that `add-feature` replaces whole.
    Setting,
    /// A list that `add-feature` appends one item to. `item_id` tells whether
    /// its items carry an `id` that `--item` can name one by.
    List { item_id: bool },
}

/// Which surfaces Agent Stream acts on a feature for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// Every surface: Agent Stream checks it before it serves a call, on an
    /// `ide_catalog` surface too.
    AnySurface,
    /// Only the calls an `llm` surface serves.
    ModelCalls,
    /// Only the calls an `llm` surface serves, but it makes calls of its own
    /// first, so on a `webhook` surface it runs, and can cost money, before
    /// each call fails.
    PaidModelCalls,
}

/// One feature of an Agent Stream surface: the name the commands take, the
/// surface field it is, and what it does.
#[derive(Debug)]
struct Feature {
    key: &'static str,
    /// A second name the commands take.
    alias: Option<&'static str>,
    /// The field of Agent Stream's `PipeConfig` that holds it.
    field: &'static str,
    kind: Kind,
    /// The surface flag that decides whether Agent Stream acts on the items of
    /// a list feature. Agent Stream keeps the items while it is false, but
    /// ignores them all.
    switch: Option<&'static str>,
    reach: Reach,
    about: &'static str,
}

/// The features `add-feature` and `remove-feature` take, from the fields of
/// `PipeConfig` in Agent Stream's `src/pipes/config.rs`. Each `field` must be
/// in [`SURFACE_FIELDS`](super::SURFACE_FIELDS).
const FEATURES: [Feature; 15] = [
    Feature {
        key: "rate-limit",
        alias: None,
        field: "rate_limit",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::AnySurface,
        about: "Caps requests, and optionally tokens, per minute",
    },
    Feature {
        key: "cost-tracking",
        alias: Some("budget"),
        field: COST_TRACKING,
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "The surface's own model prices, and a monthly budget with an alert threshold; see `surfaces budget`",
    },
    Feature {
        key: "usage-limits",
        alias: None,
        field: "usage_limits",
        kind: Kind::List { item_id: true },
        switch: None,
        reach: Reach::ModelCalls,
        about: "Monthly spend or token caps; a call past a cap is refused with 429",
    },
    Feature {
        key: "usage-alerts",
        alias: None,
        field: "usage_alerts",
        kind: Kind::List { item_id: false },
        switch: Some("usage_alerts_enabled"),
        reach: Reach::ModelCalls,
        about: "Alerts on cost, tokens, error rate, or a cost spike",
    },
    Feature {
        key: "prompt-guard",
        alias: Some("pii"),
        field: "prompt_guard",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Filters personal data and other sensitive content in requests and responses",
    },
    Feature {
        key: "judge",
        alias: None,
        field: "judge",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::PaidModelCalls,
        about: "A model checks each request before it is sent on",
    },
    Feature {
        key: "jury",
        alias: None,
        field: "jury",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Models check each response before it is returned",
    },
    Feature {
        key: "decider",
        alias: None,
        field: "decider",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::PaidModelCalls,
        about: "A model picks which candidate provider serves each request",
    },
    Feature {
        key: "expert-witness",
        alias: None,
        field: "expert_witnesses",
        kind: Kind::List { item_id: true },
        switch: None,
        reach: Reach::PaidModelCalls,
        about: "External safety classifiers check requests or responses",
    },
    Feature {
        key: "routing-rules",
        alias: None,
        field: "routing_rules",
        kind: Kind::List { item_id: false },
        switch: Some("routing_enabled"),
        reach: Reach::ModelCalls,
        about: "Routes a request by header, body field, or modality; the first rule that matches wins",
    },
    Feature {
        key: "canary",
        alias: None,
        field: "canary",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Splits traffic across variants by weight; off unless `enabled`",
    },
    Feature {
        key: "load-balancing",
        alias: None,
        field: "load_balancing",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Spreads requests over a weighted pool of providers",
    },
    Feature {
        key: "failover",
        alias: None,
        field: "failover",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Retries a failed request on backup providers in order",
    },
    Feature {
        key: "circuit-breaker",
        alias: None,
        field: "circuit_breaker",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Stops calling a failing provider for a while",
    },
    Feature {
        key: "retry",
        alias: None,
        field: "retry_policy",
        kind: Kind::Setting,
        switch: None,
        reach: Reach::ModelCalls,
        about: "Retries a failed call with backoff",
    },
];

/// The surface fields a variant can set its own value of, from
/// `PipeVariantOverrides` in Agent Stream's `src/pipes/pipe_variants.rs`. A
/// variant overrides one when it sets it, and a variant with `complete` set
/// takes every one of them from itself, an empty one included.
const VARIANT_FIELDS: [&str; 9] = [
    "prompt_guard",
    "judge",
    "jury",
    "expert_witnesses",
    "rate_limit",
    "circuit_breaker",
    "retry_policy",
    "cost_tracking",
    "usage_alerts",
];

/// The field of the cost-tracking feature. Agent Stream prices the surface's
/// model calls from its `input_price_per_1k` and `output_price_per_1k`
/// whatever `enabled` says, and counts the monthly budget only while
/// `enabled` is true.
const COST_TRACKING: &str = "cost_tracking";

/// The settings of `cost_tracking` that `add-feature` keeps from the stored
/// ones when the settings given leave them out.
const COST_TRACKING_KEPT: [&str; 3] = ["enabled", "input_price_per_1k", "output_price_per_1k"];

/// Every setting of `cost_tracking` (`CostTrackingConfig` in Agent Stream's
/// `src/pipes/config.rs`). Agent Stream drops a name it does not know without
/// an error, and leaves an unset setting out of the surface it returns. So
/// `add-feature` always checks the names given for cost-tracking against
/// these and any the stored object has, even on a surface with no
/// `cost_tracking` yet, and refuses any other name.
const COST_TRACKING_FIELDS: [&str; 5] =
    ["enabled", "input_price_per_1k", "output_price_per_1k", "monthly_budget_usd", "alert_threshold_percent"];

/// The prices of `cost_tracking`, which `remove-feature` removes with it.
const COST_TRACKING_PRICES: [&str; 2] = ["input_price_per_1k", "output_price_per_1k"];

/// The permission Agent Stream's budget route requires.
const BUDGET_PERMISSION: &str = "metrics.view";

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("settings").required(true).args(["json", "file"])))]
pub struct AddFeatureArgs {
    /// ID of the surface (see `fabric agent-stream surfaces list`).
    id: String,
    /// Feature name or alias (see `fabric agent-stream surfaces features`).
    feature: String,
    /// The feature's settings as inline JSON: the whole field for a
    /// one-setting feature, or one item for a list feature.
    #[arg(long, conflicts_with = "file")]
    json: Option<String>,
    /// The feature's settings from a JSON file, or - for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Let the settings hold a name the surface's field does not have yet.
    /// Without it such a name is refused as a likely typo. Agent Stream
    /// leaves some empty optional settings out of the surface it returns, so
    /// a correct name can look new.
    #[arg(long)]
    allow_new_field: bool,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveFeatureArgs {
    /// ID of the surface (see `fabric agent-stream surfaces list`).
    id: String,
    /// Feature name or alias (see `fabric agent-stream surfaces features`).
    feature: String,
    /// For a list feature, the one item to remove: its `id`, or some of its
    /// fields as JSON, which must match exactly one item.
    #[arg(long, conflicts_with = "all")]
    item: Option<String>,
    /// For a list feature, remove the whole list.
    #[arg(long)]
    all: bool,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

/// An `add-feature` whose surface id, feature, and settings passed the
/// checks that need no connection, ready for [`add`].
#[derive(Debug)]
pub struct FeatureAddition {
    id: String,
    /// The API path of the surface.
    path: String,
    feature: &'static Feature,
    /// The settings read from --json or --file, a JSON object.
    settings: Value,
    allow_new_field: bool,
    dry_run: bool,
}

/// A `remove-feature` whose surface id, feature, and --item or --all passed
/// the checks that need no connection, ready for [`remove`].
#[derive(Debug)]
pub struct FeatureRemoval {
    id: String,
    /// The API path of the surface.
    path: String,
    feature: &'static Feature,
    /// The one list item to remove, or `None` to remove the whole feature.
    item: Option<String>,
    dry_run: bool,
}

impl AddFeatureArgs {
    /// Checks, before any connection is made, that the surface id and the
    /// feature name are ones the command can use, and reads the settings
    /// from --json or --file, which must be JSON of the shape the feature
    /// takes.
    pub fn checked(self) -> Result<FeatureAddition> {
        let path = surface_path(&self.id)?;
        let feature = lookup(&self.feature)?;
        let settings = match (&self.json, &self.file) {
            (Some(text), _) => serde_json::from_str(text).context("parse --json as JSON")?,
            (None, Some(file)) => read_json(file)?,
            (None, None) => bail!("give the feature's settings with --json '<json>' or --file <path>"),
        };
        check_shape(feature, &settings)?;
        Ok(FeatureAddition {
            id: self.id,
            path,
            feature,
            settings,
            allow_new_field: self.allow_new_field,
            dry_run: self.dry_run,
        })
    }
}

impl RemoveFeatureArgs {
    /// Checks, before any connection is made, that the surface id and the
    /// feature name are ones the command can use, and that --item or --all
    /// is given for a list feature and neither for a setting.
    pub fn checked(self) -> Result<FeatureRemoval> {
        let path = surface_path(&self.id)?;
        let feature = lookup(&self.feature)?;
        check_remove_flags(feature, self.item.is_some() || self.all)?;
        Ok(FeatureRemoval {
            id: self.id,
            path,
            feature,
            item: self.item,
            dry_run: self.dry_run,
        })
    }
}

/// Refuses --item or --all (`named`) on a setting, and a list feature with
/// neither, so a whole list is never removed by leaving a flag out.
fn check_remove_flags(
    feature: &Feature,
    named: bool,
) -> Result<()> {
    match feature.kind {
        Kind::Setting if named => bail!(
            "{} is one group of settings, not a list, so --item and --all do not apply; leave them out to remove the \
             feature",
            feature.key
        ),
        Kind::List { item_id } if !named => bail!(
            "{} is a list: give --item {} to remove one item, or --all to remove the whole list",
            feature.key,
            item_placeholder(item_id)
        ),
        _ => Ok(()),
    }
}

/// How --item names an item of a list whose items do or do not have an `id`.
fn item_placeholder(item_id: bool) -> &'static str {
    if item_id {
        "<id>"
    } else {
        "'<fields as JSON>'"
    }
}

/// Refuses settings that are not one JSON object: the whole field of a
/// setting, or one item of a list.
fn check_shape(
    feature: &Feature,
    given: &Value,
) -> Result<()> {
    match (feature.kind, given) {
        (_, Value::Object(_)) => Ok(()),
        (Kind::Setting, _) => {
            bail!("{} takes a JSON object of settings, such as {{\"enabled\":true}}", feature.key)
        }
        (Kind::List { .. }, Value::Array(_)) => bail!(
            "{} adds one item at a time: give one JSON object, and run add-feature again for the next",
            feature.key
        ),
        (Kind::List { .. }, _) => bail!("{} takes one item as a JSON object", feature.key),
    }
}

/// The feature `name` names, by its key or alias, in any case.
fn lookup(name: &str) -> Result<&'static Feature> {
    if let Some(feature) = FEATURES
        .iter()
        .find(|feature| {
            feature
                .key
                .eq_ignore_ascii_case(name)
                || feature
                    .alias
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(name))
        })
    {
        return Ok(feature);
    }
    let names = FEATURES
        .iter()
        .flat_map(|feature| [Some(feature.key), feature.alias])
        .flatten();
    match closest(name, names) {
        Some(near) => bail!("unknown feature `{}`; did you mean `{near}`?", tables::flatten(name)),
        None => bail!(
            "unknown feature `{}`; run `fabric agent-stream surfaces features` to list them",
            tables::flatten(name)
        ),
    }
}

/// The text `surfaces features` prints with no surface: every feature, as a
/// table or with --output json as a list.
pub fn catalog(output: Output) -> Result<String> {
    match output {
        Output::Table => {
            let rows: Vec<Vec<String>> = FEATURES
                .iter()
                .map(|feature| {
                    vec![
                        feature.key.to_owned(),
                        feature
                            .alias
                            .unwrap_or("-")
                            .to_owned(),
                        feature.field.to_owned(),
                        kind_name(feature.kind).to_owned(),
                        feature.about.to_owned(),
                    ]
                })
                .collect();
            Ok(format_rows(&["FEATURE", "ALIAS", "FIELD", "KIND", "WHAT IT DOES"], &rows).join("\n"))
        }
        Output::Json => {
            let features: Vec<Value> = FEATURES
                .iter()
                .map(|feature| {
                    json!({
                        "feature": feature.key,
                        "alias": feature.alias,
                        "field": feature.field,
                        "kind": kind_name(feature.kind),
                        "switch": feature.switch,
                        "variants_can_override": VARIANT_FIELDS.contains(&feature.field),
                        "description": feature.about,
                    })
                })
                .collect();
            pretty_json_for_terminal(&Value::Array(features))
        }
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Setting => "setting",
        Kind::List { .. } => "list",
    }
}

/// The text `surfaces features <id>` prints: each feature the surface `id`
/// has set or one of its variants sets, with whether it is on, the variants
/// that override it, and the command that removes it from the base surface,
/// or with --output json the same with each base value. A deleted surface
/// can't be changed, so its table shows no remove command and ends with a
/// line saying it is deleted.
pub async fn on_surface(
    client: &GatewayClient,
    id: &str,
    output: Output,
) -> Result<String> {
    let surface = client
        .request(Method::GET, &surface_path(id)?, None)
        .await?;
    if !surface.is_object() {
        bail!("Agent Stream did not answer with a surface for '{id}'");
    }
    let shown: Vec<(&Feature, Option<&Value>, Vec<String>)> = FEATURES
        .iter()
        .map(|feature| (feature, set_value(&surface, feature), overriding_variants(&surface, feature)))
        .filter(|(_, value, variants)| value.is_some() || !variants.is_empty())
        .collect();
    match output {
        Output::Json => {
            let features: Vec<Value> = shown
                .iter()
                .map(|(feature, value, variants)| {
                    json!({
                        "feature": feature.key,
                        "field": feature.field,
                        "state": state(&surface, feature, *value),
                        "value": value,
                        "overridden_by": variants,
                    })
                })
                .collect();
            pretty_json_for_terminal(&Value::Array(features))
        }
        Output::Table if shown.is_empty() => Ok(format!(
            "Surface '{id}' has none of the features set; `fabric agent-stream surfaces features` lists them."
        )),
        Output::Table => {
            let deleted = status_of(&surface) == Some(STATUS_DELETED);
            let rows: Vec<Vec<String>> = shown
                .iter()
                .map(|(feature, value, variants)| {
                    let remove = match (value, feature.kind) {
                        (None, _) => "-".to_owned(),
                        (Some(_), _) if deleted => "-".to_owned(),
                        (Some(_), Kind::Setting) => {
                            format!("fabric agent-stream surfaces remove-feature {id} {}", feature.key)
                        }
                        (Some(_), Kind::List { item_id }) => format!(
                            "fabric agent-stream surfaces remove-feature {id} {} (--item {} | --all)",
                            feature.key,
                            item_placeholder(item_id)
                        ),
                    };
                    let variants = if variants.is_empty() {
                        "-".to_owned()
                    } else {
                        variants.join(", ")
                    };
                    vec![
                        feature.key.to_owned(),
                        feature.field.to_owned(),
                        state(&surface, feature, *value),
                        variants,
                        remove,
                    ]
                })
                .collect();
            let mut lines = format_rows(&["FEATURE", "FIELD", "STATE", "VARIANTS", "REMOVE WITH"], &rows);
            if deleted {
                lines.push(format!("\nSurface '{id}' is deleted, so its features can't be changed."));
            }
            Ok(lines.join("\n"))
        }
    }
}

/// The value of `feature` in `surface` when it is set: a setting that is
/// there and not `null`, or a list with at least one item.
fn set_value<'a>(
    surface: &'a Value,
    feature: &Feature,
) -> Option<&'a Value> {
    let value = surface.get(feature.field)?;
    match (feature.kind, value) {
        (_, Value::Null) => None,
        (Kind::List { .. }, Value::Array(items)) if items.is_empty() => None,
        _ => Some(value),
    }
}

/// The variants of `surface` whose calls use their own `feature` rather
/// than the base surface's: those that set it, and, while the base has it
/// set, those with `complete` set. Each is named by its alias, else its id.
fn overriding_variants(
    surface: &Value,
    feature: &Feature,
) -> Vec<String> {
    if !VARIANT_FIELDS.contains(&feature.field) {
        return Vec::new();
    }
    let base_set = set_value(surface, feature).is_some();
    surface
        .get("variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|variant| {
            let overrides = variant.get("overrides");
            let sets = overrides
                .and_then(|overrides| overrides.get(feature.field))
                .is_some_and(|value| !value.is_null());
            let complete = overrides.and_then(|overrides| overrides.get("complete")) == Some(&Value::Bool(true));
            sets || (complete && base_set)
        })
        .map(|variant| {
            let name = ["alias", "id"]
                .iter()
                .find_map(|key| {
                    variant
                        .get(*key)
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                })
                .unwrap_or("(unnamed)");
            tables::table_cell(name)
        })
        .collect()
}

/// How `features <id>` describes a feature: `on` or `off` for a setting
/// with an `enabled` flag, else `set`, and the number of items of a list,
/// with a note when its switch is off. Cost tracking that is off but has a
/// price set shows `off (prices used)`, since Agent Stream prices calls with
/// them whatever `enabled` says. `not set` when only variants set it.
fn state(
    surface: &Value,
    feature: &Feature,
    value: Option<&Value>,
) -> String {
    let Some(value) = value else {
        return "not set".to_owned();
    };
    match feature.kind {
        Kind::Setting => match value
            .get("enabled")
            .and_then(Value::as_bool)
        {
            Some(true) => "on".to_owned(),
            Some(false) if feature.field == COST_TRACKING && has_price(value) => "off (prices used)".to_owned(),
            Some(false) => "off".to_owned(),
            None => "set".to_owned(),
        },
        Kind::List { .. } => {
            let count = value
                .as_array()
                .map_or(0, Vec::len);
            let items = if count == 1 {
                "1 item".to_owned()
            } else {
                format!("{count} items")
            };
            match feature.switch {
                Some(switch) if surface.get(switch) == Some(&Value::Bool(false)) => {
                    format!("{items}, off (`{switch}` is false)")
                }
                _ => items,
            }
        }
    }
}

/// Whether `cost_tracking` has either of its prices set.
fn has_price(cost_tracking: &Value) -> bool {
    COST_TRACKING_PRICES
        .iter()
        .any(|price| {
            cost_tracking
                .get(*price)
                .is_some_and(|value| !value.is_null())
        })
}

/// A surface changed on this machine, with the notes to print about it.
#[derive(Debug)]
struct Changed {
    surface: Value,
    notes: Vec<String>,
}

/// Adds the feature to the surface or replaces its settings, and returns the
/// text to print, as `surfaces update` does.
pub async fn add(
    client: &GatewayClient,
    addition: FeatureAddition,
    output: Output,
) -> Result<Option<String>> {
    let FeatureAddition {
        id,
        path,
        feature,
        settings,
        allow_new_field,
        dry_run,
    } = addition;
    let before = read_live_surface(client, &path, &id).await?;
    let changed = with_feature_added(feature, &before, settings, allow_new_field, &id)?;
    for note in &changed.notes {
        eprintln!("{note}");
    }
    let edit = Edit {
        path: &path,
        id: &id,
        before: &before,
        dry_run,
    };
    save(client, &edit, changed.surface, output).await
}

/// `surface`, the surface `id`, with `given` as its `feature`: the whole
/// field for a setting, or one more item for a list. Unless
/// `allow_new_field`, a name inside a setting the surface already has must
/// be one it has, and a name inside cost-tracking must be one of
/// [`COST_TRACKING_FIELDS`] or one the stored object has, whether or not the
/// surface has it. An item already in the list is refused. A list's
/// switch is set to true only when it was false and the list was empty, so
/// items left off on purpose stay off, and a missing switch stays missing,
/// since Agent Stream reads it as true. The notes say what else the change
/// does or does not do.
fn with_feature_added(
    feature: &Feature,
    surface: &Value,
    given: Value,
    allow_new_field: bool,
    id: &str,
) -> Result<Changed> {
    let mut after = surface.clone();
    let Some(fields) = after.as_object_mut() else {
        bail!("a surface must be a JSON object");
    };
    let mut notes = Vec::new();
    match feature.kind {
        Kind::Setting => {
            let Value::Object(mut settings) = given else {
                bail!("{} takes a JSON object of settings, such as {{\"enabled\":true}}", feature.key);
            };
            let stored = match surface.get(feature.field) {
                Some(Value::Object(existing)) => Some(existing.clone()),
                _ => None,
            };
            let known = if feature.field == COST_TRACKING {
                let mut known = stored.unwrap_or_default();
                for name in COST_TRACKING_FIELDS {
                    known
                        .entry(name)
                        .or_insert(Value::Null);
                }
                Some(known)
            } else {
                stored
            };
            if let Some(known) = known {
                check_nested_fields(feature.field, &settings, &known, allow_new_field, Given::Feature)?;
            }
            if feature.field == COST_TRACKING {
                notes.extend(keep_stored_cost_settings(&mut settings, surface.get(COST_TRACKING))?);
            }
            fields.insert(feature.field.to_owned(), Value::Object(settings));
        }
        Kind::List { .. } => {
            let added = format!("{}={given}", feature.field);
            let patch = surface_patch::build_patch(&[], &[], &[added], &[], surface)?;
            surface_validate::merge(&mut after, &patch);
            if let Some(switch) = feature.switch {
                if surface.get(switch) == Some(&Value::Bool(false)) {
                    if set_value(surface, feature).is_some() {
                        notes.push(format!(
                            "note: `{switch}` is false, so Agent Stream ignores every item of {}, the new one \
                             included; to turn them all on, run `fabric agent-stream surfaces update {id} --set \
                             {switch}=true`",
                            feature.key
                        ));
                    } else if let Some(fields) = after.as_object_mut() {
                        fields.insert(switch.to_owned(), Value::Bool(true));
                    }
                }
            }
        }
    }
    notes.extend(surface_type_note(feature, surface, id));
    notes.extend(variant_note(feature, &after));
    Ok(Changed { surface: after, notes })
}

/// Fills `given`, the new `cost_tracking`, with the stored `enabled` and
/// prices it leaves out, and refuses it when it still has no `enabled`,
/// which Agent Stream requires. Returns a note naming what was kept.
fn keep_stored_cost_settings(
    given: &mut Map<String, Value>,
    stored: Option<&Value>,
) -> Result<Option<String>> {
    let mut kept = Vec::new();
    for name in COST_TRACKING_KEPT {
        if given.contains_key(name) {
            continue;
        }
        if let Some(value) = stored
            .and_then(|stored| stored.get(name))
            .filter(|value| !value.is_null())
        {
            given.insert(name.to_owned(), value.clone());
            kept.push(format!("`{name}`"));
        }
    }
    if !given
        .get("enabled")
        .is_some_and(Value::is_boolean)
    {
        bail!(
            "cost-tracking needs `enabled` set to true or false, or Agent Stream refuses the surface: true counts \
             spend against the monthly budget, and false keeps only the prices"
        );
    }
    Ok((!kept.is_empty()).then(|| {
        format!(
            "note: kept the stored {} of `{COST_TRACKING}`, which the settings given leave out; give a value, or \
             null to drop a price, to change it",
            kept.join(", ")
        )
    }))
}

/// A note when the surface's type means Agent Stream does not act on
/// `feature`: a `webhook` surface, whose calls it refuses, and an
/// `ide_catalog` surface, which hands each call to a member surface.
fn surface_type_note(
    feature: &Feature,
    surface: &Value,
    id: &str,
) -> Option<String> {
    let key = feature.key;
    match (pipe_type_of(surface), feature.reach) {
        (_, Reach::AnySurface) => None,
        (Some("webhook"), reach) => {
            let mut note = format!(
                "note: surface '{id}' is a `webhook` surface, and Agent Stream serves calls only on `llm` surfaces, \
                 so {key} takes effect only through a variant whose `pipe_type` is `llm`"
            );
            if reach == Reach::PaidModelCalls {
                note.push_str(&format!(
                    "; until then {key} still runs on each call before the call fails, and its own calls can cost \
                     money"
                ));
            }
            Some(note)
        }
        (Some("ide_catalog"), _) => Some(format!(
            "note: surface '{id}' is an `ide_catalog` surface, which hands each call to the member surface serving \
             the model, so Agent Stream does not use its {key}; set it on the member surfaces instead"
        )),
        _ => None,
    }
}

/// A note naming the variants of `surface` that use their own `feature`, so
/// a change to the base surface does not reach calls through them.
fn variant_note(
    feature: &Feature,
    surface: &Value,
) -> Option<String> {
    let variants = overriding_variants(surface, feature);
    (!variants.is_empty()).then(|| {
        format!(
            "note: variants {} use their own `{}`, so calls through them do not see this change; add-feature and \
             remove-feature change only the base surface",
            variants.join(", "),
            feature.field
        )
    })
}

/// Removes the feature, or one item of a list feature, from the surface, and
/// returns the text to print, as `surfaces update` does.
pub async fn remove(
    client: &GatewayClient,
    removal: FeatureRemoval,
    output: Output,
) -> Result<Option<String>> {
    let FeatureRemoval {
        id,
        path,
        feature,
        item,
        dry_run,
    } = removal;
    let before = read_live_surface(client, &path, &id).await?;
    let changed = with_feature_removed(feature, &before, item.as_deref(), &id)?;
    for note in &changed.notes {
        eprintln!("{note}");
    }
    let edit = Edit {
        path: &path,
        id: &id,
        before: &before,
        dry_run,
    };
    save(client, &edit, changed.surface, output).await
}

/// `surface` without its `feature`, or without the one `item` of a list
/// feature, which is named by its `id`, else its `alias`, else some of its
/// fields as JSON. Without `item` the whole field goes. A feature the
/// surface does not have set is refused. A list's switch is left as it is.
fn with_feature_removed(
    feature: &Feature,
    surface: &Value,
    item: Option<&str>,
    id: &str,
) -> Result<Changed> {
    let Some(stored) = set_value(surface, feature) else {
        bail!("surface '{id}' has no {} set, so there is nothing to remove", feature.key);
    };
    let mut after = surface.clone();
    let mut notes = Vec::new();
    match item {
        Some(item) => {
            let removed = format!("{}={item}", feature.field);
            let patch = surface_patch::build_patch(&[], &[], &[], &[removed], surface)?;
            surface_validate::merge(&mut after, &patch);
        }
        None => {
            if let Some(fields) = after.as_object_mut() {
                fields.remove(feature.field);
            }
            if feature.field == COST_TRACKING {
                notes.extend(removed_prices_note(stored, id));
            }
        }
    }
    notes.extend(variant_note(feature, surface));
    Ok(Changed { surface: after, notes })
}

/// A note that removing `stored`, the `cost_tracking` of surface `id`,
/// removes its prices too, with their values so they can be given back, and
/// how to keep them.
fn removed_prices_note(
    stored: &Value,
    id: &str,
) -> Option<String> {
    let prices: Vec<String> = COST_TRACKING_PRICES
        .iter()
        .filter_map(|price| {
            stored
                .get(*price)
                .filter(|value| !value.is_null())
                .map(|value| format!("`{price}` ({})", tables::flatten(&value.to_string())))
        })
        .collect();
    (!prices.is_empty()).then(|| {
        format!(
            "note: this removes the surface's own {} too, so Agent Stream no longer prices its calls with them; to \
             stop only the budget and keep the prices, run `fabric agent-stream surfaces update {id} --set \
             {COST_TRACKING}.enabled=false` instead of remove-feature",
            prices.join(" and ")
        )
    })
}

/// The text `surfaces budget <id>` prints: this month's spend against the
/// budget as a table, or Agent Stream's answer with --output json. A 403
/// that gives no reason of its own adds that the route needs
/// [`BUDGET_PERMISSION`].
pub async fn budget(
    client: &GatewayClient,
    id: &str,
    output: Output,
) -> Result<String> {
    let path = format!("{}/budget", surface_path(id)?);
    let answer = client
        .request(Method::GET, &path, None)
        .await
        .map_err(|error| {
            if is_unexplained_agent_stream_forbidden(&error) {
                error
                    .context(format!("reading the budget of surface '{id}' needs the `{BUDGET_PERMISSION}` permission"))
            } else {
                error
            }
        })?;
    if !answer.is_object() {
        bail!("Agent Stream did not answer with a budget for surface '{id}'");
    }
    match output {
        Output::Json => pretty_json_for_terminal(&answer),
        Output::Table => Ok(budget_lines(id, &answer).join("\n")),
    }
}

/// The table of a budget answer, or what Agent Stream needs before it counts
/// spend when it has none for this month.
fn budget_lines(
    id: &str,
    answer: &Value,
) -> Vec<String> {
    let month = answer
        .get("month")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if month.is_empty() {
        return vec![format!(
            "Agent Stream has no spend for surface '{id}' this month. It counts spend only while `cost_tracking` has \
             `enabled` set to true, a `monthly_budget_usd` above 0, and an `alert_threshold_percent`."
        )];
    }
    let dollars = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_f64)
            .map_or_else(|| "-".to_owned(), |amount| format!("${amount:.2}"))
    };
    let percent = answer
        .get("usage_percentage")
        .and_then(Value::as_f64)
        .map_or_else(|| "-".to_owned(), |percent| format!("{percent:.1}%"));
    let exceeded = match answer
        .get("budget_exceeded")
        .and_then(Value::as_bool)
    {
        Some(true) => "yes",
        Some(false) => "no",
        None => "-",
    };
    format_rows(
        &["MONTH", "SPENT", "LIMIT", "USED", "REMAINING", "EXCEEDED"],
        &[vec![
            tables::table_cell(month),
            dollars("total_spent"),
            dollars("budget_limit"),
            percent,
            dollars("remaining_budget"),
            exceeded.to_owned(),
        ]],
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use clap::{CommandFactory, Parser};

    use super::{
        super::{
            super::{
                AgentStreamCommand,
                test_support::{
                    HANG_UP, Route, UnusedKeyring, json_file, request_body, run_stream, saved_login,
                    scripted_agent_stream, start_lines, stream_args,
                },
            },
            DRY_RUN_UPDATE_NOTE, SURFACE_FIELDS, SurfaceCommand,
        },
        *,
    };
    use crate::{client::response_status, commands::Cli, config::Config};
    use reqwest::StatusCode;

    const ACCESS_TOKEN: &str = "aspat_live-secret";
    const STORED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","rate_limit":{"enabled":true,"requests_per_minute":60,"tokens_per_minute":5000},"usage_limits":[{"id":"tokens","enabled":true,"scope":"cumulative","monthly_token_cap":1000}],"routing_enabled":false,"usage_alerts_enabled":true,"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    const MOVED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"enabled","rate_limit":{"enabled":true,"requests_per_minute":60,"tokens_per_minute":5000},"usage_limits":[{"id":"tokens","enabled":true,"scope":"cumulative","monthly_token_cap":1000}],"routing_enabled":false,"usage_alerts_enabled":true,"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:05:00Z"}"#;
    const BUDGET: &str = r#"{"pipe_id":"s-1","month":"2026-11","total_spent":12.5,"budget_limit":100.0,"usage_percentage":12.5,"remaining_budget":87.5,"alert_threshold_percent":80,"budget_exceeded":false,"last_updated":"2026-11-20T10:00:00+00:00"}"#;
    /// What Agent Stream answers for a surface it has counted no spend for.
    const NO_SPEND: &str = r#"{"pipe_id":"s-1","month":"","total_spent":0.0,"budget_limit":0.0,"usage_percentage":0.0,"remaining_budget":0.0,"alert_threshold_percent":0,"budget_exceeded":false,"last_updated":""}"#;

    /// What Agent Stream answers a user who has not accepted its current
    /// Terms and Conditions, from its session middleware.
    const TERMS_REQUIRED: &str = r#"{"code":"TERMS_ACCEPTANCE_REQUIRED","message":"Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."}"#;

    const GET_STORED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", STORED);
    const GET_MOVED: Route = ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", MOVED);
    const PUT_SAVED: Route = ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", STORED);
    const GET_BUDGET: Route = ("GET /api/v1/pipes/s-1/budget", "HTTP/1.1 200 OK", BUDGET);

    /// A surface Agent Stream has deleted and keeps for its usage history.
    const DELETED: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"webhook","endpoint":"https://hooks.example/in"},"status":"deleted","rate_limit":{"enabled":true,"requests_per_minute":60},"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    /// What the CLI says when Agent Stream gave no answer to the save of `s-1`.
    const MAY_HAVE_BEEN_SAVED: &str = "Agent Stream gave no answer, so surface 's-1' may have been saved anyway; \
                                       check it with `fabric agent-stream surfaces get s-1` or `fabric agent-stream \
                                       surfaces features s-1` before running this again";

    const GET_LINE: &str = "GET /api/v1/pipes/s-1 HTTP/1.1";
    const PUT_LINE: &str = "PUT /api/v1/pipes/s-1 HTTP/1.1";
    const BUDGET_LINE: &str = "GET /api/v1/pipes/s-1/budget HTTP/1.1";

    const RATE_LIMIT: &str = r#"{"enabled":true,"requests_per_minute":120}"#;
    const USAGE_ALERT: &str = r#"{"alert_type":"cost_threshold","threshold":50.0,"notification_channels":[]}"#;
    /// An `llm` surface with a rate limit, a variant that sets its own judge,
    /// a `complete` variant (which Agent Stream only returns with at least one
    /// override field, so it also swaps the provider), and one that only swaps
    /// the provider.
    const WITH_VARIANTS: &str = r#"{"id":"s-1","name":"Sales","pipe_type":{"type":"llm"},"status":"enabled","rate_limit":{"enabled":true,"requests_per_minute":60},"variants":[{"id":"v-1","alias":"strict","name":"Strict","overrides":{"judge":{"enabled":true}}},{"id":"v-2","alias":"frozen","name":"Frozen","overrides":{"complete":true,"pipe_type":{"type":"llm"}}},{"id":"v-3","alias":"cheap","name":"Cheap","overrides":{"pipe_type":{"type":"llm"}}}],"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}"#;
    const ROUTING_RULE: &str =
        r#"{"match":{"kind":"header","name":"x-tier","equals":"gold"},"target":{"variant":"fast"}}"#;

    /// Runs `fabric agent-stream <words>` with a saved access token for `host`.
    async fn run_surfaces(
        host: &str,
        words: &[&str],
    ) -> Result<()> {
        let (saved, credentials) = saved_login(host, ACCESS_TOKEN);
        run_stream(words, saved, &credentials).await
    }

    /// The `surfaces` command of `fabric agent-stream <words>`.
    fn surface_command(words: &[&str]) -> SurfaceCommand {
        match stream_args(words).command {
            AgentStreamCommand::Surfaces { command } => command,
            other => panic!("{words:?} is not a surfaces command: {other:?}"),
        }
    }

    /// What `add-feature` or `remove-feature` returns to print for `fabric
    /// agent-stream <words>`, against the Agent Stream at `host`.
    async fn printed_change(
        host: &str,
        words: &[&str],
        output: Output,
    ) -> Result<Option<String>> {
        let client = GatewayClient::for_agent_stream(host, ACCESS_TOKEN)?;
        match surface_command(words) {
            SurfaceCommand::AddFeature(args) => add(&client, args.checked()?, output).await,
            SurfaceCommand::RemoveFeature(args) => remove(&client, args.checked()?, output).await,
            other => panic!("{words:?} is not a feature change: {other:?}"),
        }
    }

    /// The JSON body of the recorded request at `index`.
    fn sent_json(
        requests: &Arc<Mutex<Vec<String>>>,
        index: usize,
    ) -> Value {
        let requests = requests.lock().unwrap();
        serde_json::from_str(request_body(&requests[index])).expect("a JSON body")
    }

    fn stored() -> Value {
        serde_json::from_str(STORED).unwrap()
    }

    #[tokio::test]
    async fn add_feature_replaces_a_setting_whole_after_reading_twice() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let printed = printed_change(
            &host,
            &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT],
            Output::Table,
        )
        .await
        .expect("add-feature");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        let mut expected = stored();
        expected["rate_limit"] = serde_json::from_str(RATE_LIMIT).unwrap();
        assert_eq!(sent_json(&requests, 2), expected, "tokens_per_minute is gone, so the field was replaced");
        assert_eq!(
            printed.as_deref(),
            Some(
                "Changes:\n  rate_limit.requests_per_minute: 60 -> 120\n  rate_limit.tokens_per_minute: 5000 -> \
                 (absent)\nUpdated surface 's-1'"
            )
        );
    }

    #[tokio::test]
    async fn add_feature_appends_a_list_item_and_turns_on_its_switch() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "routing-rules", "--json", ROUTING_RULE])
            .await
            .expect("add-feature routing-rules");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        let sent = sent_json(&requests, 2);
        assert_eq!(sent["routing_rules"], json!([serde_json::from_str::<Value>(ROUTING_RULE).unwrap()]));
        assert_eq!(sent["routing_enabled"], true);
    }

    #[tokio::test]
    async fn add_feature_appends_after_the_items_already_there() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(
            &host,
            &["surfaces", "add-feature", "s-1", "usage-limits", "--json", r#"{"id":"spend","monthly_budget_usd":50}"#],
        )
        .await
        .expect("a second usage limit");

        let ids: Vec<Value> = sent_json(&requests, 2)["usage_limits"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|item| item["id"].clone())
            .collect();
        assert_eq!(ids, [json!("tokens"), json!("spend")]);
    }

    #[tokio::test]
    async fn add_feature_refuses_an_item_whose_id_is_already_in_the_list() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(
            &host,
            &["surfaces", "add-feature", "s-1", "usage-limits", "--json", r#"{"id":"tokens","monthly_token_cap":5}"#],
        )
        .await
        .expect_err("the id is taken");

        assert_eq!(
            error.to_string(),
            "'usage_limits' already has an item with id 'tokens': remove it first to replace it"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn add_feature_stops_when_the_surface_was_saved_meanwhile() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, GET_MOVED, PUT_SAVED]).await;

        let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT])
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
    async fn add_feature_dry_run_sends_no_put() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let printed = printed_change(
            &host,
            &[
                "surfaces",
                "add-feature",
                "s-1",
                "budget",
                "--json",
                r#"{"enabled":true,"monthly_budget_usd":100}"#,
                "--dry-run",
            ],
            Output::Table,
        )
        .await
        .expect("a dry run");

        assert_eq!(
            printed.as_deref(),
            Some(
                format!(
                    "Changes:\n  cost_tracking: (absent) -> {{\"enabled\":true,\"monthly_budget_usd\":100}}\n{DRY_RUN_UPDATE_NOTE}"
                )
                .as_str()
            )
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn add_feature_refuses_a_new_name_in_a_setting_the_surface_has_unless_allowed() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let typo = r#"{"enabled":true,"requests_per_minte":120}"#;

        let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", typo])
            .await
            .expect_err("requests_per_minte is a typo");
        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", typo, "--allow-new-field"])
            .await
            .expect("--allow-new-field lets it through");

        assert_eq!(
            error.to_string(),
            "`rate_limit.requests_per_minte` in the feature settings is not in the surface as read; pass \
             --allow-new-field to add it as a new field; did you mean `rate_limit.requests_per_minute`?"
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, GET_LINE, PUT_LINE]);
    }

    #[tokio::test]
    async fn add_feature_does_not_check_names_in_a_setting_the_surface_lacks() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let file = json_file(
            r#"{"enabled":true,"targets":[{"llm":{"provider_type":"openai","model":"m-2","endpoint_url":"https://llm.example/v1"}}]}"#,
        );

        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "failover", "--file", file.path().to_str().unwrap()])
            .await
            .expect("failover is a known field the surface does not have yet");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["failover"]["targets"][0]["llm"]["model"], "m-2");
    }

    #[tokio::test]
    async fn the_pii_alias_adds_the_prompt_guard() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "pii", "--json", r#"{"enabled":true}"#])
            .await
            .expect("pii names prompt-guard");
        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "PII", "--json", r#"{"enabled":false}"#])
            .await
            .expect("names match in any case");

        assert_eq!(sent_json(&requests, 2)["prompt_guard"], json!({"enabled": true}));
        assert_eq!(sent_json(&requests, 5)["prompt_guard"], json!({"enabled": false}));
    }

    #[tokio::test]
    async fn an_unknown_feature_is_refused_before_any_connection() {
        for (name, expected) in [
            ("rate-limt", "unknown feature `rate-limt`; did you mean `rate-limit`?"),
            ("rate_limit", "unknown feature `rate_limit`; did you mean `rate-limit`?"),
            ("tool-gating", "unknown feature `tool-gating`; run `fabric agent-stream surfaces features` to list them"),
        ] {
            let error = run_stream(
                &["surfaces", "add-feature", "s-1", name, "--json", "{}"],
                Config::default(),
                &UnusedKeyring,
            )
            .await
            .expect_err("not an Agent Stream feature");
            assert_eq!(error.to_string(), expected);
        }
        let error = run_stream(&["surfaces", "remove-feature", "s-1", "jurry"], Config::default(), &UnusedKeyring)
            .await
            .expect_err("a typo of jury");
        assert_eq!(error.to_string(), "unknown feature `jurry`; did you mean `jury`?");
    }

    #[tokio::test]
    async fn add_feature_refuses_settings_of_the_wrong_shape_before_any_connection() {
        for (feature, given, expected) in [
            ("rate-limit", "60", "rate-limit takes a JSON object of settings, such as {\"enabled\":true}"),
            (
                "usage-limits",
                r#"[{"id":"a","monthly_token_cap":1}]"#,
                "usage-limits adds one item at a time: give one JSON object, and run add-feature again for the next",
            ),
            ("usage-alerts", "\"cost\"", "usage-alerts takes one item as a JSON object"),
        ] {
            let error = run_stream(
                &["surfaces", "add-feature", "s-1", feature, "--json", given],
                Config::default(),
                &UnusedKeyring,
            )
            .await
            .expect_err("the wrong shape");
            assert_eq!(error.to_string(), expected);
        }
        let error = run_stream(
            &["surfaces", "add-feature", "s-1", "retry", "--json", "{not json"],
            Config::default(),
            &UnusedKeyring,
        )
        .await
        .expect_err("not JSON");
        assert_eq!(error.to_string(), "parse --json as JSON");
    }

    #[tokio::test]
    async fn remove_feature_unsets_a_setting() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "rate-limit"])
            .await
            .expect("remove-feature rate-limit");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE]);
        let mut expected = stored();
        expected
            .as_object_mut()
            .unwrap()
            .remove("rate_limit");
        assert_eq!(sent_json(&requests, 2), expected);
    }

    #[tokio::test]
    async fn remove_feature_removes_one_item_by_id_or_the_whole_list_with_all() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "usage-limits", "--item", "tokens"])
            .await
            .expect("remove one item");
        run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "usage-limits", "--all"])
            .await
            .expect("remove the list");

        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE, GET_LINE, GET_LINE, PUT_LINE]);
        assert_eq!(sent_json(&requests, 2)["usage_limits"], json!([]));
        assert!(
            sent_json(&requests, 5)
                .get("usage_limits")
                .is_none()
        );
    }

    #[test]
    fn remove_feature_names_an_item_without_an_id_by_its_fields() {
        let feature = lookup("routing-rules").unwrap();
        let mut surface = stored();
        surface["routing_rules"] = json!([
            {"match": {"kind": "header", "name": "x-tier", "equals": "gold"}, "target": {"variant": "fast"}},
            {"match": {"kind": "modality", "has": "image"}, "target": {"variant": "vision"}},
        ]);

        let after = with_feature_removed(feature, &surface, Some(r#"{"target":{"variant":"vision"}}"#), "s-1")
            .expect("one rule matches")
            .surface;

        assert_eq!(after["routing_rules"], json!([surface["routing_rules"][0]]));
        assert_eq!(after["routing_enabled"], false, "the switch is left as it is");
    }

    #[tokio::test]
    async fn remove_feature_refuses_a_feature_or_item_the_surface_does_not_have() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let missing = run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "judge"])
            .await
            .expect_err("the surface has no judge");
        let no_item = run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "usage-limits", "--item", "spend"])
            .await
            .expect_err("no usage limit has that id");

        assert_eq!(missing.to_string(), "surface 's-1' has no judge set, so there is nothing to remove");
        assert_eq!(no_item.to_string(), "'usage_limits' has no item 'spend'");
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn remove_feature_refuses_item_or_all_on_a_setting_before_any_connection() {
        for flag in [["--item", "x"].as_slice(), ["--all"].as_slice()] {
            let mut words = vec!["surfaces", "remove-feature", "s-1", "rate-limit"];
            words.extend(flag);
            let error = run_stream(&words, Config::default(), &UnusedKeyring)
                .await
                .expect_err("a setting has no items");

            assert_eq!(
                error.to_string(),
                "rate-limit is one group of settings, not a list, so --item and --all do not apply; leave them out to \
                 remove the feature"
            );
        }
    }

    #[tokio::test]
    async fn remove_feature_on_a_list_needs_item_or_all_before_any_connection() {
        for (feature, expected) in [
            (
                "usage-limits",
                "usage-limits is a list: give --item <id> to remove one item, or --all to remove the whole list",
            ),
            (
                "routing-rules",
                "routing-rules is a list: give --item '<fields as JSON>' to remove one item, or --all to remove the \
                 whole list",
            ),
        ] {
            let error = run_stream(&["surfaces", "remove-feature", "s-1", feature], Config::default(), &UnusedKeyring)
                .await
                .expect_err("neither --item nor --all");
            assert_eq!(error.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn remove_feature_dry_run_sends_no_put() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        run_surfaces(&host, &["surfaces", "remove-feature", "s-1", "rate-limit", "--dry-run"])
            .await
            .expect("a dry run");

        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[tokio::test]
    async fn feature_commands_refuse_a_bad_id_before_any_connection() {
        for words in [
            vec!["surfaces", "add-feature", "../s-1", "rate-limit", "--json", "{}"],
            vec!["surfaces", "remove-feature", "s 1", "rate-limit"],
        ] {
            let error = run_stream(&words, Config::default(), &UnusedKeyring)
                .await
                .expect_err("the id breaks Agent Stream's rules");
            assert!(
                error
                    .to_string()
                    .starts_with("a surface id"),
                "{words:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn the_feature_list_needs_no_saved_connection() {
        run_stream(&["surfaces", "features"], Config::default(), &UnusedKeyring)
            .await
            .expect("the list is built on this machine");
    }

    #[test]
    fn the_feature_list_shows_each_feature_with_its_alias_and_field() {
        let table = catalog(Output::Table).expect("a table");
        let lines: Vec<&str> = table.lines().collect();

        assert_eq!(lines.len(), FEATURES.len() + 1);
        assert!(lines[0].starts_with("FEATURE"), "{table}");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("prompt-guard") && line.contains("pii") && line.contains("prompt_guard")),
            "{table}"
        );
        let json: Value = serde_json::from_str(&catalog(Output::Json).expect("JSON")).expect("JSON");
        assert_eq!(json[3]["feature"], "usage-alerts");
        assert_eq!(json[3]["kind"], "list");
        assert_eq!(json[3]["switch"], "usage_alerts_enabled");
    }

    #[test]
    fn every_feature_is_a_surface_field_and_every_name_is_used_once() {
        let mut names = Vec::new();
        for feature in &FEATURES {
            assert!(SURFACE_FIELDS.contains(&feature.field), "{}", feature.field);
            if let Some(switch) = feature.switch {
                assert!(SURFACE_FIELDS.contains(&switch), "{switch}");
            }
            names.push(feature.key);
            names.extend(feature.alias);
        }
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        for field in VARIANT_FIELDS {
            assert!(
                FEATURES
                    .iter()
                    .any(|feature| feature.field == field),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn features_of_a_surface_shows_the_set_ones_and_how_to_remove_each() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let table = on_surface(&client, "s-1", Output::Table)
            .await
            .expect("features s-1");
        let json: Value = serde_json::from_str(
            &on_surface(&client, "s-1", Output::Json)
                .await
                .expect("features s-1 --output json"),
        )
        .expect("JSON");

        assert_eq!(
            table
                .lines()
                .collect::<Vec<_>>(),
            [
                "FEATURE       FIELD         STATE   VARIANTS  REMOVE WITH",
                "rate-limit    rate_limit    on      -         fabric agent-stream surfaces remove-feature s-1 rate-limit",
                "usage-limits  usage_limits  1 item  -         fabric agent-stream surfaces remove-feature s-1 usage-limits (--item <id> | --all)",
            ]
        );
        assert_eq!(
            json[0],
            json!({
                "feature": "rate-limit",
                "field": "rate_limit",
                "state": "on",
                "value": stored()["rate_limit"],
                "overridden_by": [],
            })
        );
        assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE]);
    }

    #[tokio::test]
    async fn a_save_with_no_answer_or_a_proxy_502_or_504_says_it_may_have_been_saved() {
        for put in [
            ("PUT /api/v1/pipes/s-1", HANG_UP, ""),
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 502 Bad Gateway", ""),
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 504 Gateway Timeout", "upstream timed out"),
        ] {
            let (host, requests) = scripted_agent_stream(vec![GET_STORED, put]).await;

            let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT])
                .await
                .expect_err("the save got no answer");

            let text = format!("{error:#}");
            assert!(text.starts_with(MAY_HAVE_BEEN_SAVED), "{put:?}: {text}");
            assert!(!text.contains(ACCESS_TOKEN), "{text}");
            assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE], "{put:?}");
        }
    }

    #[tokio::test]
    async fn a_save_answered_with_a_server_error_says_it_may_have_been_saved() {
        for put in [
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 500 Internal Server Error", "Failed to update surface: timeout"),
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 503 Service Unavailable", ""),
        ] {
            let (host, requests) = scripted_agent_stream(vec![GET_STORED, put]).await;

            let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT])
                .await
                .expect_err("the save got a server error");

            let text = format!("{error:#}");
            assert!(
                text.starts_with(
                    "Agent Stream answered the save of surface 's-1' with a server error, so it may have been saved \
                     anyway; check it with `fabric agent-stream surfaces get s-1`"
                ),
                "{put:?}: {text}"
            );
            assert!(text.contains(put.2), "{put:?}: {text}");
            assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE], "{put:?}");
        }
    }

    #[tokio::test]
    async fn a_save_agent_stream_refuses_prints_the_refusal_without_the_no_answer_advice() {
        for put in [
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 400 Bad Request", "Invalid LLM configuration: bad canary"),
            ("PUT /api/v1/pipes/s-1", "HTTP/1.1 409 Conflict", "Save blocked: surface 'Sales' has drifted"),
        ] {
            let (host, requests) = scripted_agent_stream(vec![GET_STORED, put]).await;

            let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT])
                .await
                .expect_err("Agent Stream refused the save");

            let text = format!("{error:#}");
            assert!(text.contains(put.2), "{put:?}: {text}");
            assert!(!text.contains("may have been saved"), "{put:?}: {text}");
            assert_eq!(start_lines(&requests), [GET_LINE, GET_LINE, PUT_LINE], "{put:?}");
        }
    }

    #[tokio::test]
    async fn cost_tracking_names_are_checked_on_a_surface_without_cost_tracking() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;
        let typo = r#"{"enabled":true,"monthly_budget":100,"alert_threshold_percent":80}"#;
        let good = r#"{"enabled":true,"monthly_budget_usd":100,"alert_threshold_percent":80}"#;
        assert!(
            stored()
                .get("cost_tracking")
                .is_none()
        );

        let error = run_surfaces(&host, &["surfaces", "add-feature", "s-1", "cost-tracking", "--json", typo])
            .await
            .expect_err("monthly_budget is not a cost-tracking setting");
        let sent_before_good = start_lines(&requests);
        run_surfaces(&host, &["surfaces", "add-feature", "s-1", "cost-tracking", "--json", good])
            .await
            .expect("every name is a cost-tracking setting");

        assert_eq!(
            error.to_string(),
            "`cost_tracking.monthly_budget` in the feature settings is not in the surface as read; pass \
             --allow-new-field to add it as a new field; did you mean `cost_tracking.monthly_budget_usd`?"
        );
        assert_eq!(sent_before_good, [GET_LINE]);
        assert_eq!(sent_json(&requests, 3)["cost_tracking"], serde_json::from_str::<Value>(good).unwrap());
    }

    #[test]
    fn allow_new_field_lets_an_unknown_cost_tracking_name_through_on_a_surface_without_it() {
        let feature = lookup("cost-tracking").unwrap();

        let changed =
            with_feature_added(feature, &stored(), json!({"enabled": true, "monthly_budget": 100}), true, "s-1")
                .expect("--allow-new-field skips the name check");

        assert_eq!(changed.surface["cost_tracking"]["monthly_budget"], 100);
    }

    #[test]
    fn cost_tracking_that_is_off_with_a_price_says_the_prices_are_used() {
        let feature = lookup("cost-tracking").unwrap();
        let surface = stored();
        let state_of = |value: Value| state(&surface, feature, Some(&value));

        assert_eq!(state_of(json!({"enabled": false, "input_price_per_1k": 0.002})), "off (prices used)");
        assert_eq!(state_of(json!({"enabled": false, "output_price_per_1k": 0.006})), "off (prices used)");
        assert_eq!(state_of(json!({"enabled": false, "input_price_per_1k": null})), "off");
        assert_eq!(state_of(json!({"enabled": true, "input_price_per_1k": 0.002})), "on");
        assert_eq!(state(&surface, lookup("rate-limit").unwrap(), Some(&json!({"enabled": false}))), "off");
    }

    #[tokio::test]
    async fn features_of_a_deleted_surface_shows_no_remove_command_and_says_it_is_deleted() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", DELETED)]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let table = on_surface(&client, "s-1", Output::Table)
            .await
            .expect("features s-1");

        assert_eq!(
            table
                .lines()
                .collect::<Vec<_>>(),
            [
                "FEATURE     FIELD       STATE  VARIANTS  REMOVE WITH",
                "rate-limit  rate_limit  on     -         -",
                "",
                "Surface 's-1' is deleted, so its features can't be changed.",
            ]
        );
    }

    #[test]
    fn a_list_whose_switch_is_off_says_so() {
        let feature = lookup("routing-rules").unwrap();
        let mut surface = stored();
        surface["routing_rules"] = json!([serde_json::from_str::<Value>(ROUTING_RULE).unwrap()]);

        let shown = state(&surface, feature, Some(&surface["routing_rules"]));

        assert_eq!(shown, "1 item, off (`routing_enabled` is false)");
    }

    #[tokio::test]
    async fn budget_reads_the_budget_route_and_prints_a_table() {
        let (host, requests) = scripted_agent_stream(vec![GET_BUDGET]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let table = budget(&client, "s-1", Output::Table)
            .await
            .expect("surfaces budget");
        let json = budget(&client, "s-1", Output::Json)
            .await
            .expect("surfaces budget --output json");

        assert_eq!(
            table
                .lines()
                .collect::<Vec<_>>(),
            ["MONTH    SPENT   LIMIT    USED   REMAINING  EXCEEDED", "2026-11  $12.50  $100.00  12.5%  $87.50     no",]
        );
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), serde_json::from_str::<Value>(BUDGET).unwrap());
        assert_eq!(start_lines(&requests), [BUDGET_LINE, BUDGET_LINE]);
    }

    #[tokio::test]
    async fn budget_with_no_spend_this_month_says_what_agent_stream_counts() {
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/pipes/s-1/budget", "HTTP/1.1 200 OK", NO_SPEND)]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let printed = budget(&client, "s-1", Output::Table)
            .await
            .expect("surfaces budget");

        assert_eq!(
            printed,
            "Agent Stream has no spend for surface 's-1' this month. It counts spend only while `cost_tracking` has \
             `enabled` set to true, a `monthly_budget_usd` above 0, and an `alert_threshold_percent`."
        );
    }

    #[tokio::test]
    async fn a_budget_refused_with_no_reason_names_the_permission_it_needs() {
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/pipes/s-1/budget", "HTTP/1.1 403 Forbidden", "")]).await;

        let error = run_surfaces(&host, &["surfaces", "budget", "s-1"])
            .await
            .expect_err("the login lacks metrics.view");

        let shown = format!("{error:#}");
        assert!(
            shown.starts_with(
                "reading the budget of surface 's-1' needs the `metrics.view` permission: Agent Stream answered 403 \
                 Forbidden"
            ),
            "{shown}"
        );
        assert_eq!(response_status(&error), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn a_budget_refused_for_the_terms_says_so_and_does_not_blame_the_permission() {
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/pipes/s-1/budget", "HTTP/1.1 403 Forbidden", TERMS_REQUIRED)])
                .await;

        let error = run_surfaces(&host, &["surfaces", "budget", "s-1"])
            .await
            .expect_err("the terms are not accepted");

        let shown = format!("{error:#}");
        assert!(!shown.contains(BUDGET_PERMISSION), "{shown}");
        assert!(shown.contains("accept the required Terms and Conditions"), "{shown}");
    }

    #[tokio::test]
    async fn budget_and_features_refuse_a_bad_id_before_any_connection() {
        for words in [["surfaces", "budget", "../access-tokens"], ["surfaces", "features", "s 1"]] {
            let error = run_stream(&words, Config::default(), &UnusedKeyring)
                .await
                .expect_err("the id breaks Agent Stream's rules");
            assert!(
                error
                    .to_string()
                    .starts_with("a surface id"),
                "{words:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn budget_refuses_a_bad_id_before_sending() {
        let (host, requests) = scripted_agent_stream(vec![GET_BUDGET]).await;

        run_surfaces(&host, &["surfaces", "budget", "../access-tokens"])
            .await
            .expect_err("the id breaks Agent Stream's rules");

        assert!(start_lines(&requests).is_empty());
    }

    #[test]
    fn adding_the_first_item_of_a_list_turns_on_its_switch() {
        let feature = lookup("usage-alerts").unwrap();
        let mut surface = stored();
        surface["usage_alerts_enabled"] = json!(false);

        let alert: Value = serde_json::from_str(USAGE_ALERT).unwrap();

        let changed = with_feature_added(feature, &surface, alert.clone(), false, "s-1").expect("one alert");

        assert_eq!(changed.surface["usage_alerts"], json!([alert]));
        assert_eq!(changed.surface["usage_alerts_enabled"], true);
        assert!(
            !changed
                .notes
                .iter()
                .any(|note| note.contains("usage_alerts_enabled")),
            "{:?}",
            changed.notes
        );
    }

    #[test]
    fn adding_the_first_item_to_a_surface_without_its_switch_leaves_the_switch_out() {
        let feature = lookup("usage-alerts").unwrap();
        let mut surface = stored();
        surface
            .as_object_mut()
            .unwrap()
            .remove("usage_alerts_enabled");
        let alert: Value = serde_json::from_str(USAGE_ALERT).unwrap();

        let changed = with_feature_added(feature, &surface, alert.clone(), false, "s-1").expect("one alert");

        assert_eq!(changed.surface["usage_alerts"], json!([alert]));
        assert_eq!(
            changed
                .surface
                .get("usage_alerts_enabled"),
            None,
            "Agent Stream reads a missing switch as true"
        );
        assert!(
            !changed
                .notes
                .iter()
                .any(|note| note.contains("usage_alerts_enabled")),
            "{:?}",
            changed.notes
        );
    }

    #[test]
    fn adding_an_item_without_an_id_that_has_the_fields_of_one_in_the_list_is_refused() {
        let rule: Value = serde_json::from_str(ROUTING_RULE).unwrap();
        let alert: Value = serde_json::from_str(USAGE_ALERT).unwrap();
        for (name, field, stored_item, added) in [
            ("routing-rules", "routing_rules", rule.clone(), rule),
            (
                "usage-alerts",
                "usage_alerts",
                alert,
                json!({"threshold": 50.0, "alert_type": "cost_threshold", "notification_channels": []}),
            ),
        ] {
            let mut surface = stored();
            surface[field] = json!([stored_item]);

            let error = with_feature_added(lookup(name).unwrap(), &surface, added, false, "s-1")
                .expect_err("the item is already in the list");

            assert_eq!(
                error.to_string(),
                format!("'{field}' already has {stored_item}: remove it first to replace it"),
                "{name}"
            );
        }
    }

    #[test]
    fn adding_to_a_list_left_off_keeps_it_off_and_says_how_to_turn_it_on() {
        let feature = lookup("routing-rules").unwrap();
        let mut surface = stored();
        surface["routing_rules"] =
            json!([{"match": {"kind": "modality", "has": "image"}, "target": {"variant": "vision"}}]);
        let rule: Value = serde_json::from_str(ROUTING_RULE).unwrap();

        let changed = with_feature_added(feature, &surface, rule, false, "s-1").expect("a second rule");

        assert_eq!(
            changed.surface["routing_rules"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(changed.surface["routing_enabled"], false, "the parked rules stay off");
        assert!(
            changed.notes.contains(
                &"note: `routing_enabled` is false, so Agent Stream ignores every item of routing-rules, the new one \
                  included; to turn them all on, run `fabric agent-stream surfaces update s-1 --set \
                  routing_enabled=true`"
                    .to_owned()
            ),
            "{:?}",
            changed.notes
        );
    }

    #[tokio::test]
    async fn add_and_remove_feature_print_the_saved_surface_with_output_json() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let added = printed_change(
            &host,
            &["surfaces", "add-feature", "s-1", "rate-limit", "--json", RATE_LIMIT],
            Output::Json,
        )
        .await
        .expect("add-feature --output json");
        let removed = printed_change(&host, &["surfaces", "remove-feature", "s-1", "rate-limit"], Output::Json)
            .await
            .expect("remove-feature --output json");

        assert_eq!(
            start_lines(&requests),
            [GET_LINE, GET_LINE, PUT_LINE, GET_LINE, GET_LINE, GET_LINE, PUT_LINE, GET_LINE]
        );
        for printed in [added, removed] {
            let printed: Value = serde_json::from_str(&printed.expect("the saved surface")).expect("JSON");
            assert_eq!(printed, stored(), "the surface read back after the save");
        }
    }

    #[test]
    fn remove_feature_refuses_fields_that_match_more_than_one_item() {
        let feature = lookup("routing-rules").unwrap();
        let mut surface = stored();
        surface["routing_rules"] = json!([
            {"match": {"kind": "header", "name": "x-tier", "equals": "gold"}, "target": {"variant": "fast"}},
            {"match": {"kind": "header", "name": "x-tier", "equals": "silver"}, "target": {"variant": "fast"}},
        ]);

        let error = with_feature_removed(feature, &surface, Some(r#"{"target":{"variant":"fast"}}"#), "s-1")
            .expect_err("both rules go to fast");

        assert!(
            error
                .to_string()
                .contains("matches more than one item"),
            "{error}"
        );
    }

    #[test]
    fn cost_tracking_adds_a_budget_to_a_surface_that_has_only_prices() {
        let feature = lookup("cost-tracking").unwrap();
        let mut surface = stored();
        surface["cost_tracking"] = json!({"enabled": false, "input_price_per_1k": 0.002, "output_price_per_1k": 0.006});

        let changed = with_feature_added(
            feature,
            &surface,
            json!({"enabled": true, "monthly_budget_usd": 100, "alert_threshold_percent": 80}),
            false,
            "s-1",
        )
        .expect("the budget settings Agent Stream left out are known names");

        assert_eq!(
            changed.surface["cost_tracking"],
            json!({
                "enabled": true,
                "input_price_per_1k": 0.002,
                "output_price_per_1k": 0.006,
                "monthly_budget_usd": 100,
                "alert_threshold_percent": 80,
            })
        );
    }

    #[test]
    fn cost_tracking_still_refuses_a_mistyped_setting() {
        let feature = lookup("cost-tracking").unwrap();
        let mut surface = stored();
        surface["cost_tracking"] = json!({"enabled": false, "input_price_per_1k": 0.002});

        let error =
            with_feature_added(feature, &surface, json!({"enabled": true, "monthly_budget": 100}), false, "s-1")
                .expect_err("a name CostTrackingConfig lacks is refused");

        assert!(
            error
                .to_string()
                .contains("monthly_budget"),
            "{error}"
        );
    }

    #[test]
    fn cost_tracking_keeps_the_stored_enabled_and_prices_the_settings_leave_out() {
        let feature = lookup("budget").unwrap();
        let mut surface = stored();
        surface["cost_tracking"] = json!({"enabled": false, "input_price_per_1k": 0.002, "output_price_per_1k": 0.006, "monthly_budget_usd": 50, "alert_threshold_percent": 90});

        let changed = with_feature_added(
            feature,
            &surface,
            json!({"monthly_budget_usd": 100, "alert_threshold_percent": 80}),
            false,
            "s-1",
        )
        .expect("the stored enabled is kept");

        assert_eq!(feature.key, "cost-tracking");
        assert_eq!(
            changed.surface["cost_tracking"],
            json!({
                "enabled": false,
                "input_price_per_1k": 0.002,
                "output_price_per_1k": 0.006,
                "monthly_budget_usd": 100,
                "alert_threshold_percent": 80,
            })
        );
        assert!(
            changed.notes.contains(
                &"note: kept the stored `enabled`, `input_price_per_1k`, `output_price_per_1k` of `cost_tracking`, \
                  which the settings given leave out; give a value, or null to drop a price, to change it"
                    .to_owned()
            ),
            "{:?}",
            changed.notes
        );
    }

    #[test]
    fn cost_tracking_given_its_own_values_keeps_nothing() {
        let feature = lookup("cost-tracking").unwrap();
        let mut surface = stored();
        surface["cost_tracking"] = json!({"enabled": true, "input_price_per_1k": 0.002, "output_price_per_1k": 0.006});
        let given = json!({"enabled": true, "input_price_per_1k": null, "output_price_per_1k": 0.01});

        let changed = with_feature_added(feature, &surface, given.clone(), false, "s-1").expect("all given");

        assert_eq!(changed.surface["cost_tracking"], given);
        assert!(
            !changed
                .notes
                .iter()
                .any(|note| note.contains("kept the stored")),
            "{:?}",
            changed.notes
        );
    }

    #[tokio::test]
    async fn cost_tracking_without_enabled_on_a_surface_that_has_none_is_refused_before_saving() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, PUT_SAVED]).await;

        let error = run_surfaces(
            &host,
            &["surfaces", "add-feature", "s-1", "cost-tracking", "--json", r#"{"monthly_budget_usd":100}"#],
        )
        .await
        .expect_err("Agent Stream needs enabled");

        assert_eq!(
            error.to_string(),
            "cost-tracking needs `enabled` set to true or false, or Agent Stream refuses the surface: true counts \
             spend against the monthly budget, and false keeps only the prices"
        );
        assert_eq!(start_lines(&requests), [GET_LINE]);
    }

    #[test]
    fn removing_cost_tracking_says_its_prices_go_too() {
        let feature = lookup("cost-tracking").unwrap();
        let mut surface = stored();
        surface["cost_tracking"] = json!({"enabled": true, "input_price_per_1k": 0.002, "monthly_budget_usd": 50});

        let changed = with_feature_removed(feature, &surface, None, "s-1").expect("cost tracking is set");

        assert!(
            changed
                .surface
                .get("cost_tracking")
                .is_none()
        );
        assert_eq!(
            changed.notes,
            [
                "note: this removes the surface's own `input_price_per_1k` (0.002) too, so Agent Stream no longer prices \
              its calls with them; to stop only the budget and keep the prices, run `fabric agent-stream surfaces \
              update s-1 --set cost_tracking.enabled=false` instead of remove-feature"
            ]
        );
    }

    #[test]
    fn a_model_feature_on_a_surface_that_serves_no_model_calls_gets_a_note() {
        let mut ide = stored();
        ide["pipe_type"] = json!({"type": "ide_catalog", "config": {}});
        let mut llm = stored();
        llm["pipe_type"] = json!({"type": "llm"});
        let note = |key: &str, surface: &Value| surface_type_note(lookup(key).unwrap(), surface, "s-1");

        assert_eq!(
            note("retry", &stored()).as_deref(),
            Some(
                "note: surface 's-1' is a `webhook` surface, and Agent Stream serves calls only on `llm` surfaces, so \
                 retry takes effect only through a variant whose `pipe_type` is `llm`"
            )
        );
        for paid in ["judge", "decider", "expert-witness"] {
            assert!(
                note(paid, &stored()).is_some_and(|note| note.ends_with(&format!(
                    "; until then {paid} still runs on each call before the call fails, and its own calls can cost \
                     money"
                ))),
                "{paid}"
            );
        }
        assert_eq!(
            note("judge", &ide).as_deref(),
            Some(
                "note: surface 's-1' is an `ide_catalog` surface, which hands each call to the member surface \
                 serving the model, so Agent Stream does not use its judge; set it on the member surfaces instead"
            )
        );
        assert_eq!(note("rate-limit", &stored()), None, "Agent Stream checks the rate limit on every surface");
        assert_eq!(note("rate-limit", &ide), None);
        assert_eq!(note("judge", &llm), None);
    }

    #[test]
    fn a_variant_overrides_a_feature_it_sets_and_a_complete_one_every_feature_the_base_has() {
        let surface: Value = serde_json::from_str(WITH_VARIANTS).unwrap();
        let overriding = |key: &str| overriding_variants(&surface, lookup(key).unwrap());

        assert_eq!(overriding("rate-limit"), ["frozen"]);
        assert_eq!(overriding("judge"), ["strict"]);
        assert!(overriding("jury").is_empty(), "the base has no jury for the complete variant to clear");
        assert!(overriding("failover").is_empty(), "a variant can't override failover");
    }

    #[test]
    fn a_change_to_a_feature_a_variant_overrides_names_the_variant() {
        let surface: Value = serde_json::from_str(WITH_VARIANTS).unwrap();

        let added = with_feature_added(lookup("judge").unwrap(), &surface, json!({"enabled": true}), true, "s-1")
            .expect("add a judge");
        let removed =
            with_feature_removed(lookup("rate-limit").unwrap(), &surface, None, "s-1").expect("remove the rate limit");

        let variant_notes = |notes: &[String]| -> Vec<String> {
            notes
                .iter()
                .filter(|note| note.starts_with("note: variants"))
                .cloned()
                .collect()
        };
        assert_eq!(
            variant_notes(&added.notes),
            ["note: variants strict, frozen use their own `judge`, so calls through them do not see this change; \
              add-feature and remove-feature change only the base surface"]
        );
        assert_eq!(
            variant_notes(&removed.notes),
            ["note: variants frozen use their own `rate_limit`, so calls through them do not see this change; \
              add-feature and remove-feature change only the base surface"]
        );
    }

    #[tokio::test]
    async fn features_of_a_surface_names_the_variants_and_a_feature_only_variants_set() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", WITH_VARIANTS)]).await;
        let client = GatewayClient::for_agent_stream(&host, ACCESS_TOKEN).unwrap();

        let table = on_surface(&client, "s-1", Output::Table)
            .await
            .expect("features s-1");

        assert_eq!(
            table
                .lines()
                .collect::<Vec<_>>(),
            [
                "FEATURE     FIELD       STATE    VARIANTS  REMOVE WITH",
                "rate-limit  rate_limit  on       frozen    fabric agent-stream surfaces remove-feature s-1 rate-limit",
                "judge       judge       not set  strict    -",
            ]
        );
    }

    #[test]
    fn every_surfaces_example_in_the_help_parses() {
        let mut cli = Cli::command();
        cli.build();
        let surfaces = cli
            .find_subcommand("agent-stream")
            .and_then(|stream| stream.find_subcommand("surfaces"))
            .expect("fabric agent-stream surfaces");
        let mut checked = 0;
        for command in surfaces.get_subcommands() {
            let Some(help) = command.get_after_long_help() else {
                continue;
            };
            let mut lines: Vec<String> = Vec::new();
            for line in help.to_string().lines() {
                match lines.last_mut() {
                    Some(last) if last.ends_with('\\') => {
                        last.pop();
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                    _ => lines.push(line.trim().to_owned()),
                }
            }
            for example in lines
                .iter()
                .filter(|line| line.starts_with("fabric agent-stream"))
            {
                let words: Vec<String> = shell_words::split(example)
                    .unwrap_or_else(|error| panic!("cannot split `{example}`: {error}"))
                    .into_iter()
                    .take_while(|word| !matches!(word.as_str(), "|" | ">" | ">>" | "<"))
                    .collect();
                if let Err(error) = Cli::try_parse_from(&words) {
                    panic!("example does not parse: {example}\n{error}");
                }
                checked += 1;
            }
        }
        assert!(checked >= 14, "only {checked} examples were found");
    }

    #[test]
    fn the_feature_help_never_names_agent_gateway() {
        let mut cli = Cli::command();
        cli.build();
        let surfaces = cli
            .find_subcommand("agent-stream")
            .and_then(|stream| stream.find_subcommand("surfaces"))
            .expect("fabric agent-stream surfaces");
        for name in ["features", "add-feature", "remove-feature", "budget"] {
            let command = surfaces
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("surfaces {name}"));
            let mut help: Vec<String> = [command.get_long_about(), command.get_after_long_help()]
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect();
            help.extend(
                command
                    .get_arguments()
                    .filter(|argument| !argument.is_global_set())
                    .filter_map(|argument| {
                        argument
                            .get_long_help()
                            .or(argument.get_help())
                    })
                    .map(ToString::to_string),
            );
            let help = help.join("\n");
            assert!(!help.contains("Agent Gateway"), "surfaces {name}: {help}");
            assert!(!help.contains("agent-gateway"), "surfaces {name}: {help}");
        }
    }

    #[test]
    fn feature_commands_parse_their_flags() {
        assert!(
            Cli::try_parse_from(["fabric", "agent-stream", "surfaces", "add-feature", "s-1", "retry"]).is_err(),
            "settings are required"
        );
        assert!(
            Cli::try_parse_from([
                "fabric",
                "agent-stream",
                "surfaces",
                "add-feature",
                "s-1",
                "retry",
                "--json",
                "{}",
                "--file",
                "x.json"
            ])
            .is_err(),
            "--json and --file conflict"
        );
        assert!(
            Cli::try_parse_from([
                "fabric",
                "agent-stream",
                "surfaces",
                "remove-feature",
                "s-1",
                "usage-limits",
                "--item",
                "tokens",
                "--all"
            ])
            .is_err(),
            "--item and --all conflict"
        );
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "surfaces", "features"]).is_ok());
        assert!(Cli::try_parse_from(["fabric", "agent-stream", "surfaces", "budget"]).is_err(), "budget needs an id");
    }
}
