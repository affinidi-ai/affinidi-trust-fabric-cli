//! Data-driven registry of Agent Surface features, and the merge patches that
//! add or remove them.
//!
//! Each feature maps to one or more placements: an (edge, direction) pair plus
//! the JSON pointer on the surface document where its configuration lives and
//! how a value is written (replace an object, append to a list, or build a
//! policy reference). This mirrors the dashboard surface builder's element to
//! payload-path map so the CLI can add any feature the dashboard can.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::surface_patch::first_null_in_objects;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edge {
    ApMa,
    MaExternal,
    MaTp,
}

impl Edge {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApMa => "ap-ma",
            Self::MaExternal => "ma-external",
            Self::MaTp => "ma-tp",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueKind {
    /// Replace a single object at the pointer.
    Object,
    /// Append to a list at the pointer, creating it if absent.
    List,
    /// Build a `{ policy_definition_id, require_agent_context }` reference.
    PolicyRef,
}

impl ValueKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::List => "list",
            Self::PolicyRef => "policy-ref",
        }
    }
}

/// One valid placement of a feature. `pointer` may contain the `{tp}` token,
/// which is resolved to a transit-point index at apply time.
#[derive(Clone, Copy)]
pub struct Placement {
    pub edge: Edge,
    pub direction: Direction,
    pub pointer: &'static str,
    pub kind: ValueKind,
}

impl Placement {
    /// Whether the pointer needs a transit point alias to be resolved.
    fn has_alias_slot(&self) -> bool {
        self.pointer.contains("{tp}")
    }

    /// Whether both write the same value at the same spot on the surface.
    fn same_place(
        &self,
        other: &Placement,
    ) -> bool {
        self.pointer == other.pointer && self.kind == other.kind
    }

    /// The flags that select this placement.
    fn flags(&self) -> String {
        flags_for(self.edge, self.direction, self.has_alias_slot())
    }
}

pub struct Feature {
    pub key: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
    pub placements: &'static [Placement],
}

impl Feature {
    fn matches(
        &self,
        name: &str,
    ) -> bool {
        self.key
            .eq_ignore_ascii_case(name)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
    }

    pub fn placement(
        &self,
        edge: Edge,
        direction: Direction,
    ) -> Option<&Placement> {
        self.placements
            .iter()
            .find(|placement| placement.edge == edge && placement.direction == direction)
    }

    /// Pick the placement the flags mean. Without `--response` the request
    /// direction is meant (or the feature's response-only place). With no `edge`
    /// and no `transit_point_given`, that leaves one distinct place on the
    /// surface, or an error listing the choices. Two places that write the same
    /// pointer count as one.
    pub fn select_placement(
        &self,
        edge: Option<Edge>,
        transit_point_given: bool,
        response: bool,
    ) -> Result<&Placement> {
        let edge = if transit_point_given {
            Some(Edge::MaTp)
        } else {
            edge
        };
        let direction = if response {
            Direction::Response
        } else {
            Direction::Request
        };
        let Some(edge) = edge else {
            let on_surface = || {
                self.placements
                    .iter()
                    .filter(|placement| placement.edge != Edge::MaTp)
            };
            let mut candidates = distinct_places(on_surface().filter(|placement| placement.direction == direction));
            if candidates.is_empty() && !response {
                candidates = distinct_places(on_surface());
            }
            return match candidates.as_slice() {
                [only] => Ok(only),
                [] => bail!(
                    "feature '{}' has no {}; use one of: {}",
                    self.key,
                    if response {
                        "response place"
                    } else {
                        "place on the whole surface"
                    },
                    self.allowed_flags()
                ),
                _ => bail!(
                    "feature '{}' can go in more than one place; add one of these flags:\n{}",
                    self.key,
                    placement_choices(&candidates, response)
                ),
            };
        };
        let mut on_edge = self
            .placements
            .iter()
            .filter(|placement| placement.edge == edge);
        let chosen = self
            .placement(edge, direction)
            .or_else(|| {
                if response {
                    return None;
                }
                match (on_edge.next(), on_edge.next()) {
                    (Some(only), None) => Some(only),
                    _ => None,
                }
            });
        let no_transit_point_place = !self
            .placements
            .iter()
            .any(|placement| placement.edge == Edge::MaTp && placement.has_alias_slot());
        if transit_point_given && (chosen.is_some_and(|place| !place.has_alias_slot()) || no_transit_point_place) {
            if self
                .placements
                .iter()
                .any(|placement| placement.edge == Edge::MaTp)
            {
                bail!(
                    "feature '{}' has no place per transit point alias, so leave out --transit-point (--edge ma-tp is the target leg); use one of: {}",
                    self.key,
                    self.allowed_flags()
                );
            }
            bail!(
                "feature '{}' cannot go on a transit point, so leave out --transit-point; use one of: {}",
                self.key,
                self.allowed_flags()
            );
        }
        match chosen {
            Some(place) if edge == Edge::MaTp && !transit_point_given && place.has_alias_slot() => bail!(
                "feature '{}' goes on one transit point, so use --transit-point <alias> instead of --edge ma-tp",
                self.key
            ),
            Some(place) => Ok(place),
            None => bail!(
                "feature '{}' cannot use {}; use one of: {}",
                self.key,
                flags_for(edge, direction, transit_point_given),
                self.allowed_flags()
            ),
        }
    }

    /// The flags that pick each place the feature has, for error messages.
    fn allowed_flags(&self) -> String {
        self.placements
            .iter()
            .map(Placement::flags)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The flags that select a place on `edge` in `direction`. A place on the
/// ma-tp edge is picked by alias when its pointer names a transit point, and by
/// `--edge ma-tp` when it does not.
fn flags_for(
    edge: Edge,
    direction: Direction,
    needs_alias: bool,
) -> String {
    let edge = match edge {
        Edge::MaTp if needs_alias => "--transit-point <alias>".to_owned(),
        edge => format!("--edge {}", edge.label()),
    };
    match direction {
        Direction::Request => edge,
        Direction::Response => format!("{edge} --response"),
    }
}

/// One line per place, with the flags that still need adding to pick it.
fn placement_choices(
    places: &[&Placement],
    response_given: bool,
) -> String {
    places
        .iter()
        .map(|placement| {
            let flags = if response_given {
                flags_for(placement.edge, Direction::Request, false)
            } else {
                placement.flags()
            };
            format!("  {}  ({}, on the whole surface: {})", flags, placement.direction.label(), placement.pointer)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Keep the first of any places that write the same value at the same spot.
fn distinct_places<'a>(placements: impl Iterator<Item = &'a Placement>) -> Vec<&'a Placement> {
    let mut distinct: Vec<&Placement> = Vec::new();
    for placement in placements {
        if !distinct
            .iter()
            .any(|seen| seen.same_place(placement))
        {
            distinct.push(placement);
        }
    }
    distinct
}

macro_rules! place {
    ($edge:ident, $direction:ident, $pointer:literal, $kind:ident) => {
        Placement {
            edge: Edge::$edge,
            direction: Direction::$direction,
            pointer: $pointer,
            kind: ValueKind::$kind,
        }
    };
}

pub const FEATURES: &[Feature] = &[
    Feature {
        key: "policy",
        aliases: &["opa"],
        description: "OPA policy reference gating the request or response.",
        placements: &[
            place!(ApMa, Request, "/target/policy", PolicyRef),
            place!(ApMa, Response, "/target/response_policy", PolicyRef),
            place!(MaTp, Request, "/transit/points/{tp}/policy", PolicyRef),
            place!(MaTp, Response, "/transit/points/{tp}/response_policy", PolicyRef),
        ],
    },
    Feature {
        key: "inbound-policy",
        aliases: &["access-point-policy"],
        description: "Access-point OPA policy evaluated before the target pipeline.",
        placements: &[place!(ApMa, Request, "/access_point/inbound_policy", PolicyRef)],
    },
    Feature {
        key: "caller-auth",
        aliases: &["authentication", "source-auth"],
        description: "Caller authentication methods ({ methods: [...] }).",
        placements: &[place!(ApMa, Request, "/access_point/caller_authentication", Object)],
    },
    Feature {
        key: "rate-limit",
        aliases: &["throttling", "network.throttling"],
        description: "Inbound rate limit ({ requests, window_secs, burst? }).",
        placements: &[place!(ApMa, Request, "/access_point/rate_limit", Object)],
    },
    Feature {
        key: "networking",
        aliases: &["timeout", "retry", "circuit-breaker"],
        description: "Target networking (timeout, retry, circuit breaker, mirror).",
        placements: &[
            place!(ApMa, Request, "/target/networking", Object),
            place!(MaExternal, Request, "/target/networking", Object),
            place!(MaTp, Request, "/transit/points/{tp}/networking", Object),
        ],
    },
    Feature {
        key: "payment",
        aliases: &["x402", "mpp"],
        description: "Payment policy (x402 or MPP) on the target.",
        placements: &[place!(ApMa, Request, "/target/payment_policy", Object)],
    },
    Feature {
        key: "extension-validation",
        aliases: &[],
        description: "Schema validation on inbound request payloads.",
        placements: &[place!(ApMa, Request, "/access_point/extension_validation", Object)],
    },
    Feature {
        key: "extension-rules",
        aliases: &[],
        description: "Response extension validation rules on the target.",
        placements: &[place!(ApMa, Request, "/target/extension_rules", Object)],
    },
    Feature {
        key: "custom-metadata",
        aliases: &["metadata-injection"],
        description: "Custom metadata injection (request and/or response).",
        placements: &[
            place!(ApMa, Request, "/target/custom_metadata", Object),
            place!(ApMa, Response, "/target/response_custom_metadata", Object),
        ],
    },
    Feature {
        key: "header-metadata",
        aliases: &["metadata-extraction", "header-mapping"],
        description: "Map inbound HTTP headers into A2A message metadata.",
        placements: &[place!(ApMa, Request, "/access_point/header_metadata_mapping", Object)],
    },
    Feature {
        key: "trust-check",
        aliases: &[],
        description: "Trust Check element list (caller leg on ap-ma, target leg on ma-tp).",
        placements: &[
            place!(ApMa, Request, "/access_point/trust_check_list", List),
            place!(MaTp, Request, "/target/trust_check_list", List),
        ],
    },
    Feature {
        key: "trust-recorder",
        aliases: &[],
        description: "Trust Recorder writing records on the MA->AP response leg.",
        placements: &[place!(ApMa, Response, "/access_point/trust_recorder", Object)],
    },
    Feature {
        key: "identity",
        aliases: &["identity-slot"],
        description: "Managed identity extraction (inbound, protected, external slot).",
        placements: &[
            place!(ApMa, Request, "/identity_slots/inbound", Object),
            place!(ApMa, Response, "/identity_slots/protected", Object),
            place!(MaExternal, Response, "/identity_slots/external", Object),
        ],
    },
    Feature {
        key: "mcp-tool-gating",
        aliases: &["tool-gating"],
        description: "MCP tool gating firewall (surface-wide on ma-external, per-TP on ma-tp).",
        placements: &[
            place!(MaExternal, Response, "/target/mcp_tool_gating", Object),
            place!(MaTp, Response, "/transit/points/{tp}/mcp_tool_gating", Object),
        ],
    },
    Feature {
        key: "credential-delegation",
        aliases: &["outbound-credentials"],
        description: "Outbound credential binding appended to the surface.",
        placements: &[place!(MaExternal, Request, "/outbound_credentials", List)],
    },
    Feature {
        key: "workload-binding",
        aliases: &[],
        description: "Workload Binding VP for the primary MA->EXT forward leg.",
        placements: &[place!(MaExternal, Request, "/target/workload_binding", Object)],
    },
];

/// Find a feature by key or alias (case-insensitive).
pub fn find(name: &str) -> Option<&'static Feature> {
    FEATURES
        .iter()
        .find(|feature| feature.matches(name))
}

/// Build the standard policy reference object.
pub fn policy_ref(policy_id: &str) -> Value {
    json!({ "policy_definition_id": policy_id, "require_agent_context": false })
}

/// Resolve a pointer template against a surface, substituting `{tp}` with the
/// index of the transit point whose `alias` matches `transit_point`.
pub fn resolve_pointer(
    template: &str,
    surface: &Value,
    transit_point: Option<&str>,
) -> Result<String> {
    if !template.contains("{tp}") {
        return Ok(template.to_owned());
    }
    let alias = transit_point.context("this feature requires --transit-point <alias>")?;
    let index = transit_index(surface, alias)?;
    Ok(template.replace("{tp}", &index.to_string()))
}

fn transit_index(
    surface: &Value,
    alias: &str,
) -> Result<usize> {
    let points = surface
        .pointer("/transit/points")
        .and_then(Value::as_array)
        .context("surface has no transit points")?;
    points
        .iter()
        .position(|point| {
            point
                .get("alias")
                .and_then(Value::as_str)
                == Some(alias)
        })
        .with_context(|| format!("transit point '{alias}' not found on surface"))
}

/// Set `value` at `pointer`, creating intermediate objects as needed.
pub fn set_at(
    root: &mut Value,
    pointer: &str,
    value: Value,
) -> Result<()> {
    *entry_mut(root, pointer)? = value;
    Ok(())
}

/// Append `value` to the list at `pointer`, creating the list if absent. When
/// `value` is itself an array its items are appended individually.
pub fn append_at(
    root: &mut Value,
    pointer: &str,
    value: Value,
) -> Result<()> {
    let slot = entry_mut(root, pointer)?;
    if slot.is_null() {
        *slot = Value::Array(Vec::new());
    }
    let array = slot
        .as_array_mut()
        .with_context(|| format!("value at '{pointer}' is not a list"))?;
    match value {
        Value::Array(items) => array.extend(items),
        other => array.push(other),
    }
    Ok(())
}

/// Remove the value at `pointer`. Returns whether something was removed.
pub fn remove_at(
    root: &mut Value,
    pointer: &str,
) -> Result<bool> {
    let (parent, key) = pointer
        .rsplit_once('/')
        .context("invalid JSON pointer")?;
    let Some(parent_value) = root.pointer_mut(parent) else {
        return Ok(false);
    };
    if let Some(object) = parent_value.as_object_mut() {
        return Ok(object.remove(key).is_some());
    }
    if let (Some(array), Ok(index)) = (parent_value.as_array_mut(), key.parse::<usize>())
        && index < array.len()
    {
        array.remove(index);
        return Ok(true);
    }
    Ok(false)
}

/// Navigate to `pointer`, creating intermediate objects, and return a mutable
/// reference to the (possibly newly-created null) leaf.
fn entry_mut<'a>(
    root: &'a mut Value,
    pointer: &str,
) -> Result<&'a mut Value> {
    let mut current = root;
    for token in pointer
        .trim_start_matches('/')
        .split('/')
    {
        if let Ok(index) = token.parse::<usize>() {
            let array = current
                .as_array_mut()
                .with_context(|| format!("expected a list at '{token}' in the surface path"))?;
            current = array
                .get_mut(index)
                .with_context(|| format!("index {index} out of range in the surface path"))?;
        } else {
            if !current.is_object() {
                *current = json!({});
            }
            current = current
                .as_object_mut()
                .expect("just ensured object")
                .entry(token.to_owned())
                .or_insert(Value::Null);
        }
    }
    Ok(current)
}

/// A change to one feature at one placement.
pub enum FeatureEdit {
    /// Put this value at the placement, or append it for a list placement.
    Add(Value),
    /// Take the feature off the placement.
    Remove,
}

/// Build the JSON Merge Patch (https://www.rfc-editor.org/rfc/rfc7396) that
/// makes `edit` on the fetched `surface`, sending only the part it changes.
///
/// A merge patch merges objects, can't address a list item and replaces a list
/// whole. So an object or policy reference is sent at its pointer with keys
/// only the old value had set to `null`, and a value holding `null` in an
/// object is refused, since the merge would read it as a removal. A list is
/// sent whole with the new item appended, and a transit point feature sends
/// the whole `transit.points` list with that one point changed. Removing sends
/// `null` at the pointer, or the edited points list, and is refused when the
/// feature isn't set.
pub fn build_patch(
    feature: &Feature,
    placement: &Placement,
    surface: &Value,
    transit_point: Option<&str>,
    edit: FeatureEdit,
) -> Result<Value> {
    let pointer = resolve_pointer(placement.pointer, surface, transit_point)?;
    if let FeatureEdit::Remove = edit
        && surface
            .pointer(&pointer)
            .is_none_or(Value::is_null)
    {
        bail!("feature '{}' is not set at {}", feature.key, pointer);
    }
    if placement
        .pointer
        .contains("{tp}")
    {
        let mut edited = surface.clone();
        match edit {
            FeatureEdit::Add(value) => {
                if let ValueKind::Object | ValueKind::PolicyRef = placement.kind {
                    reject_nulls(feature, &pointer, &value)?;
                }
                apply_add(&mut edited, &pointer, placement.kind, value)?
            }
            FeatureEdit::Remove => {
                remove_at(&mut edited, &pointer)?;
            }
        }
        let points = edited
            .pointer("/transit/points")
            .cloned()
            .context("surface has no transit points")?;
        return nest("/transit/points", points);
    }
    match (edit, placement.kind) {
        (FeatureEdit::Remove, _) => nest(&pointer, Value::Null),
        (FeatureEdit::Add(value), ValueKind::List) => {
            let mut edited = surface.clone();
            append_at(&mut edited, &pointer, value)?;
            let list = edited
                .pointer(&pointer)
                .cloned()
                .unwrap_or_default();
            nest(&pointer, list)
        }
        (FeatureEdit::Add(value), ValueKind::Object | ValueKind::PolicyRef) => {
            reject_nulls(feature, &pointer, &value)?;
            let old = surface
                .pointer(&pointer)
                .unwrap_or(&Value::Null);
            nest(&pointer, replacement(old, value))
        }
    }
}

fn apply_add(
    root: &mut Value,
    pointer: &str,
    kind: ValueKind,
    value: Value,
) -> Result<()> {
    match kind {
        ValueKind::List => append_at(root, pointer, value),
        ValueKind::Object | ValueKind::PolicyRef => set_at(root, pointer, value),
    }
}

fn reject_nulls(
    feature: &Feature,
    pointer: &str,
    value: &Value,
) -> Result<()> {
    if value.is_null() {
        bail!(
            "feature '{}' needs a value, not null: use `fabric agent-gateway surfaces remove-feature` to remove it",
            feature.key
        );
    }
    let path = pointer
        .trim_start_matches('/')
        .replace('/', ".");
    if let Some(removed) = first_null_in_objects(&path, value) {
        bail!(
            "the value for feature '{}' has null at {removed}, but null means remove in a partial update, so give it a \
             value or leave it out",
            feature.key
        );
    }
    Ok(())
}

/// The merge patch value that turns `old` into exactly `new`: objects merge,
/// so every key only `old` has becomes `null`, at any depth.
fn replacement(
    old: &Value,
    new: Value,
) -> Value {
    match (old, new) {
        (Value::Object(old_fields), Value::Object(mut new_fields)) => {
            for (key, new_child) in new_fields.iter_mut() {
                if let Some(old_child) = old_fields.get(key) {
                    *new_child = replacement(old_child, new_child.take());
                }
            }
            for key in old_fields.keys() {
                if !new_fields.contains_key(key) {
                    new_fields.insert(key.clone(), Value::Null);
                }
            }
            Value::Object(new_fields)
        }
        (_, new) => new,
    }
}

/// Wrap `value` in one object per key of a pointer that names no list items,
/// so `/access_point/rate_limit` becomes `{"access_point":{"rate_limit":..}}`.
fn nest(
    pointer: &str,
    value: Value,
) -> Result<Value> {
    pointer
        .trim_start_matches('/')
        .split('/')
        .rev()
        .try_fold(value, |child, key| {
            if key.is_empty() {
                bail!("invalid JSON pointer '{pointer}'");
            }
            let mut parent = Map::new();
            parent.insert(key.to_owned(), child);
            Ok(Value::Object(parent))
        })
}

/// A JSON description of every feature, for `--output json`.
pub fn describe() -> Value {
    Value::Array(
        FEATURES
            .iter()
            .map(|feature| {
                json!({
                    "feature": feature.key,
                    "aliases": feature.aliases,
                    "description": feature.description,
                    "placements": feature
                        .placements
                        .iter()
                        .map(|placement| json!({
                            "edge": placement.edge.label(),
                            "direction": placement.direction.label(),
                            "pointer": placement.pointer,
                            "kind": placement.kind.label(),
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_feature_by_key_and_alias() {
        assert_eq!(
            find("rate-limit")
                .unwrap()
                .key,
            "rate-limit"
        );
        assert_eq!(
            find("network.throttling")
                .unwrap()
                .key,
            "rate-limit"
        );
        assert_eq!(find("OPA").unwrap().key, "policy");
        assert!(find("nope").is_none());
    }

    #[test]
    fn resolves_placement_per_direction() {
        let policy = find("policy").unwrap();
        assert_eq!(
            policy
                .placement(Edge::ApMa, Direction::Request)
                .unwrap()
                .pointer,
            "/target/policy"
        );
        assert_eq!(
            policy
                .placement(Edge::ApMa, Direction::Response)
                .unwrap()
                .pointer,
            "/target/response_policy"
        );
        assert!(
            find("payment")
                .unwrap()
                .placement(Edge::MaExternal, Direction::Request)
                .is_none()
        );
    }

    fn pointer_for(
        key: &str,
        edge: Option<Edge>,
        per_transit_point: bool,
        response: bool,
    ) -> Result<&'static str> {
        find(key)
            .expect("feature")
            .select_placement(edge, per_transit_point, response)
            .map(|placement| placement.pointer)
    }

    #[test]
    fn places_every_feature_with_no_flags() {
        let expected = [
            ("policy", "/target/policy"),
            ("custom-metadata", "/target/custom_metadata"),
            ("identity", "/identity_slots/inbound"),
            ("inbound-policy", "/access_point/inbound_policy"),
            ("caller-auth", "/access_point/caller_authentication"),
            ("rate-limit", "/access_point/rate_limit"),
            ("networking", "/target/networking"),
            ("payment", "/target/payment_policy"),
            ("extension-validation", "/access_point/extension_validation"),
            ("extension-rules", "/target/extension_rules"),
            ("header-metadata", "/access_point/header_metadata_mapping"),
            ("trust-check", "/access_point/trust_check_list"),
            ("trust-recorder", "/access_point/trust_recorder"),
            ("mcp-tool-gating", "/target/mcp_tool_gating"),
            ("credential-delegation", "/outbound_credentials"),
            ("workload-binding", "/target/workload_binding"),
        ];
        for feature in FEATURES {
            let (_, pointer) = expected
                .iter()
                .find(|(key, _)| *key == feature.key)
                .unwrap_or_else(|| panic!("no expectation for {}", feature.key));
            assert_eq!(pointer_for(feature.key, None, false, false).unwrap(), *pointer, "{}", feature.key);
        }
        assert_eq!(expected.len(), FEATURES.len());
    }

    #[test]
    fn places_tool_gating_on_the_surface_or_one_transit_point() {
        assert_eq!(pointer_for("tool-gating", None, false, false).unwrap(), "/target/mcp_tool_gating");
        assert_eq!(pointer_for("tool-gating", None, true, false).unwrap(), "/transit/points/{tp}/mcp_tool_gating");
        assert_eq!(pointer_for("tool-gating", None, false, true).unwrap(), "/target/mcp_tool_gating");
        assert_eq!(
            pointer_for("tool-gating", Some(Edge::MaExternal), false, false).unwrap(),
            "/target/mcp_tool_gating"
        );
    }

    #[test]
    fn treats_a_missing_response_flag_as_request() {
        assert_eq!(pointer_for("policy", None, false, false).unwrap(), "/target/policy");
        assert_eq!(pointer_for("policy", None, false, true).unwrap(), "/target/response_policy");
        assert_eq!(pointer_for("policy", None, true, false).unwrap(), "/transit/points/{tp}/policy");
        assert_eq!(pointer_for("policy", None, true, true).unwrap(), "/transit/points/{tp}/response_policy");
        assert_eq!(pointer_for("custom-metadata", None, false, false).unwrap(), "/target/custom_metadata");
        assert_eq!(pointer_for("custom-metadata", None, false, true).unwrap(), "/target/response_custom_metadata");
        assert_eq!(pointer_for("identity", None, false, false).unwrap(), "/identity_slots/inbound");
        assert_eq!(pointer_for("identity", Some(Edge::MaExternal), false, false).unwrap(), "/identity_slots/external");
    }

    #[test]
    fn asks_for_the_edge_only_when_it_is_a_real_choice() {
        let error = pointer_for("identity", None, false, true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "feature 'identity' can go in more than one place; add one of these flags:\n  --edge ap-ma  (response, on the whole surface: /identity_slots/protected)\n  --edge ma-external  (response, on the whole surface: /identity_slots/external)"
        );
    }

    #[test]
    fn explicit_flags_still_pick_the_place() {
        assert_eq!(pointer_for("policy", Some(Edge::ApMa), false, false).unwrap(), "/target/policy");
        assert_eq!(pointer_for("policy", Some(Edge::ApMa), false, true).unwrap(), "/target/response_policy");
        assert_eq!(pointer_for("policy", None, true, false).unwrap(), "/transit/points/{tp}/policy");
        assert_eq!(pointer_for("policy", None, true, true).unwrap(), "/transit/points/{tp}/response_policy");
        assert_eq!(pointer_for("networking", Some(Edge::MaExternal), false, false).unwrap(), "/target/networking");
        assert!(pointer_for("identity", None, false, true).is_err());
        assert_eq!(pointer_for("identity", Some(Edge::MaExternal), false, true).unwrap(), "/identity_slots/external");
        assert_eq!(pointer_for("trust-recorder", None, false, true).unwrap(), "/access_point/trust_recorder");
    }

    #[test]
    fn names_a_place_the_feature_does_not_have() {
        let error = pointer_for("payment", Some(Edge::MaExternal), false, false)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "feature 'payment' cannot use --edge ma-external; use one of: --edge ap-ma");
        let error = pointer_for("payment", Some(Edge::ApMa), false, true)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "feature 'payment' cannot use --edge ap-ma --response; use one of: --edge ap-ma");
        let error = pointer_for("rate-limit", None, false, true)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "feature 'rate-limit' has no response place; use one of: --edge ap-ma");
    }

    #[test]
    fn names_a_missing_surface_place_when_response_was_not_asked_for() {
        let transit_only = Feature {
            key: "transit-only",
            aliases: &[],
            description: "",
            placements: &[place!(MaTp, Request, "/transit/points/{tp}/x", Object)],
        };
        let error = transit_only
            .select_placement(None, false, false)
            .map(|placement| placement.pointer)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "feature 'transit-only' has no place on the whole surface; use one of: --transit-point <alias>"
        );
    }

    #[test]
    fn counts_places_that_write_the_same_spot_once() {
        for name in ["networking", "timeout", "retry", "circuit-breaker"] {
            assert_eq!(pointer_for(name, None, false, false).unwrap(), "/target/networking");
        }
        assert_eq!(pointer_for("networking", Some(Edge::MaExternal), false, false).unwrap(), "/target/networking");
        assert_eq!(pointer_for("networking", None, true, false).unwrap(), "/transit/points/{tp}/networking");
    }

    #[test]
    fn every_pointer_with_a_transit_point_slot_is_on_the_ma_tp_edge() {
        for feature in FEATURES {
            for placement in feature.placements {
                if placement
                    .pointer
                    .contains("{tp}")
                {
                    assert_eq!(placement.edge, Edge::MaTp, "{}: {}", feature.key, placement.pointer);
                }
            }
        }
    }

    #[test]
    fn picks_the_trust_check_leg_by_edge_and_refuses_an_alias() {
        assert_eq!(pointer_for("trust-check", None, false, false).unwrap(), "/access_point/trust_check_list");
        assert_eq!(pointer_for("trust-check", Some(Edge::MaTp), false, false).unwrap(), "/target/trust_check_list");
        let error = pointer_for("trust-check", None, true, false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "feature 'trust-check' has no place per transit point alias, so leave out --transit-point (--edge ma-tp is the target leg); use one of: --edge ap-ma, --edge ma-tp"
        );
    }

    #[test]
    fn refuses_edge_ma_tp_where_the_place_needs_an_alias() {
        for name in ["policy", "networking", "tool-gating"] {
            let error = pointer_for(name, Some(Edge::MaTp), false, false)
                .unwrap_err()
                .to_string();
            assert!(error.ends_with("so use --transit-point <alias> instead of --edge ma-tp"), "{name}: {error}");
        }
        let error = pointer_for("rate-limit", Some(Edge::MaTp), false, false)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "feature 'rate-limit' cannot use --edge ma-tp; use one of: --edge ap-ma");
    }

    #[test]
    fn rejects_transit_point_on_a_feature_without_one() {
        let error = pointer_for("rate-limit", None, true, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot go on a transit point, so leave out --transit-point"), "{error}");
    }

    #[test]
    fn sets_nested_object_creating_parents() {
        let mut surface = json!({});
        set_at(&mut surface, "/identity_slots/inbound", json!({"strategy": "from_mtls"})).unwrap();
        assert_eq!(surface.pointer("/identity_slots/inbound/strategy"), Some(&json!("from_mtls")));
    }

    #[test]
    fn appends_to_list_creating_it() {
        let mut surface = json!({"access_point": {}});
        append_at(&mut surface, "/access_point/trust_check_list", json!({"id": "a"})).unwrap();
        append_at(&mut surface, "/access_point/trust_check_list", json!({"id": "b"})).unwrap();
        assert_eq!(surface.pointer("/access_point/trust_check_list"), Some(&json!([{"id": "a"}, {"id": "b"}])));
    }

    #[test]
    fn resolves_transit_pointer_by_alias() {
        let surface = json!({"transit": {"points": [{"alias": "gh"}, {"alias": "pay"}]}});
        let pointer = resolve_pointer("/transit/points/{tp}/policy", &surface, Some("pay")).unwrap();
        assert_eq!(pointer, "/transit/points/1/policy");
        assert!(resolve_pointer("/transit/points/{tp}/policy", &surface, Some("missing")).is_err());
    }

    #[test]
    fn removes_object_key() {
        let mut surface = json!({"target": {"policy": {"policy_definition_id": "p"}}});
        assert!(remove_at(&mut surface, "/target/policy").unwrap());
        assert_eq!(surface.pointer("/target/policy"), None);
        assert!(!remove_at(&mut surface, "/target/policy").unwrap());
    }

    fn patch_for(
        key: &str,
        edge: Edge,
        direction: Direction,
        surface: &Value,
        transit_point: Option<&str>,
        edit: FeatureEdit,
    ) -> Result<Value> {
        let feature = find(key).expect("feature");
        let placement = feature
            .placement(edge, direction)
            .expect("placement");
        build_patch(feature, placement, surface, transit_point, edit)
    }

    fn transit_surface() -> Value {
        json!({
            "name": "Sales",
            "transit": {"points": [
                {"alias": "gh", "endpoint": "http://gh"},
                {"alias": "pay", "endpoint": "http://pay", "policy": {"policy_definition_id": "old"}},
            ]},
        })
    }

    #[test]
    fn an_object_feature_on_an_empty_spot_is_nested_at_its_pointer() {
        let surface = json!({"name": "Sales", "access_point": {"route": "/sales"}});
        let patch = patch_for(
            "rate-limit",
            Edge::ApMa,
            Direction::Request,
            &surface,
            None,
            FeatureEdit::Add(json!({"requests": 100, "window_secs": 60})),
        )
        .expect("patch");
        assert_eq!(patch, json!({"access_point": {"rate_limit": {"requests": 100, "window_secs": 60}}}));
    }

    #[test]
    fn adding_over_an_existing_object_sends_null_for_its_stale_keys() {
        let surface = json!({"target": {"networking": {
            "timeout_secs": 5,
            "retry": {"attempts": 3, "backoff_ms": 100},
            "mirror": {"endpoint": "http://mirror"},
        }}});
        let patch = patch_for(
            "networking",
            Edge::ApMa,
            Direction::Request,
            &surface,
            None,
            FeatureEdit::Add(json!({"timeout_secs": 10, "retry": {"attempts": 5}})),
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"target": {"networking": {
                "timeout_secs": 10,
                "retry": {"attempts": 5, "backoff_ms": null},
                "mirror": null,
            }}})
        );
    }

    #[test]
    fn a_policy_reference_is_nested_at_the_policy_pointer() {
        let patch = patch_for(
            "policy",
            Edge::ApMa,
            Direction::Response,
            &json!({"target": {}}),
            None,
            FeatureEdit::Add(policy_ref("allow-sales")),
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"target": {"response_policy": {"policy_definition_id": "allow-sales", "require_agent_context": false}}})
        );
    }

    #[test]
    fn a_null_inside_an_object_value_is_refused() {
        let error = patch_for(
            "rate-limit",
            Edge::ApMa,
            Direction::Request,
            &json!({}),
            None,
            FeatureEdit::Add(json!({"requests": 100, "window_secs": 60, "burst": null})),
        )
        .expect_err("a nested null should be refused")
        .to_string();
        assert!(error.contains("access_point.rate_limit.burst"), "{error}");

        let error =
            patch_for("rate-limit", Edge::ApMa, Direction::Request, &json!({}), None, FeatureEdit::Add(Value::Null))
                .expect_err("a null value should be refused")
                .to_string();
        assert!(error.contains("remove-feature"), "{error}");
    }

    #[test]
    fn a_list_feature_sends_the_whole_new_list_and_nothing_else() {
        let surface = json!({
            "name": "Sales",
            "access_point": {"route": "/sales", "trust_check_list": [{"id": "a"}]},
        });
        let patch = patch_for(
            "trust-check",
            Edge::ApMa,
            Direction::Request,
            &surface,
            None,
            FeatureEdit::Add(json!({"id": "b"})),
        )
        .expect("patch");
        assert_eq!(patch, json!({"access_point": {"trust_check_list": [{"id": "a"}, {"id": "b"}]}}));
    }

    #[test]
    fn a_transit_point_feature_sends_the_whole_points_list_with_one_point_changed() {
        let patch = patch_for(
            "policy",
            Edge::MaTp,
            Direction::Request,
            &transit_surface(),
            Some("gh"),
            FeatureEdit::Add(policy_ref("allow-gh")),
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"transit": {"points": [
                {"alias": "gh", "endpoint": "http://gh", "policy": {"policy_definition_id": "allow-gh", "require_agent_context": false}},
                {"alias": "pay", "endpoint": "http://pay", "policy": {"policy_definition_id": "old"}},
            ]}})
        );
    }

    #[test]
    fn adding_over_an_existing_transit_point_object_sends_exactly_the_new_value() {
        let surface = json!({
            "name": "Sales",
            "transit": {"points": [
                {"alias": "gh", "endpoint": "http://gh", "networking": {"timeout_secs": 5, "retry": {"attempts": 3}}},
                {"alias": "pay", "endpoint": "http://pay", "networking": {"timeout_secs": 1}},
            ]},
        });
        let patch = patch_for(
            "networking",
            Edge::MaTp,
            Direction::Request,
            &surface,
            Some("gh"),
            FeatureEdit::Add(json!({"timeout_secs": 10})),
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"transit": {"points": [
                {"alias": "gh", "endpoint": "http://gh", "networking": {"timeout_secs": 10}},
                {"alias": "pay", "endpoint": "http://pay", "networking": {"timeout_secs": 1}},
            ]}})
        );
    }

    #[test]
    fn a_null_inside_a_transit_point_object_value_is_refused() {
        let error = patch_for(
            "mcp-tool-gating",
            Edge::MaTp,
            Direction::Response,
            &transit_surface(),
            Some("gh"),
            FeatureEdit::Add(json!({"allow": ["a"], "deny": null})),
        )
        .expect_err("a nested null should be refused")
        .to_string();
        assert!(error.contains("transit.points.0.mcp_tool_gating.deny"), "{error}");
    }

    #[test]
    fn an_unknown_transit_point_is_refused() {
        let error = patch_for(
            "policy",
            Edge::MaTp,
            Direction::Request,
            &transit_surface(),
            Some("missing"),
            FeatureEdit::Add(policy_ref("allow")),
        )
        .expect_err("an unknown alias should be refused")
        .to_string();
        assert!(error.contains("transit point 'missing' not found"), "{error}");
    }

    #[test]
    fn removing_sends_null_at_the_pointer() {
        let surface = json!({"access_point": {"route": "/sales", "rate_limit": {"requests": 100, "window_secs": 60}}});
        let patch = patch_for("rate-limit", Edge::ApMa, Direction::Request, &surface, None, FeatureEdit::Remove)
            .expect("patch");
        assert_eq!(patch, json!({"access_point": {"rate_limit": null}}));
    }

    #[test]
    fn removing_a_feature_that_is_not_set_is_refused() {
        for surface in [json!({"access_point": {}}), json!({"access_point": {"rate_limit": null}})] {
            let error = patch_for("rate-limit", Edge::ApMa, Direction::Request, &surface, None, FeatureEdit::Remove)
                .expect_err("nothing to remove")
                .to_string();
            assert_eq!(error, "feature 'rate-limit' is not set at /access_point/rate_limit");
        }
        let error =
            patch_for("policy", Edge::MaTp, Direction::Request, &transit_surface(), Some("gh"), FeatureEdit::Remove)
                .expect_err("nothing to remove")
                .to_string();
        assert_eq!(error, "feature 'policy' is not set at /transit/points/0/policy");
    }

    #[test]
    fn removing_a_transit_point_feature_sends_the_points_without_it() {
        let patch =
            patch_for("policy", Edge::MaTp, Direction::Request, &transit_surface(), Some("pay"), FeatureEdit::Remove)
                .expect("patch");
        assert_eq!(
            patch,
            json!({"transit": {"points": [
                {"alias": "gh", "endpoint": "http://gh"},
                {"alias": "pay", "endpoint": "http://pay"},
            ]}})
        );
    }

    #[test]
    fn policy_ref_has_expected_shape() {
        assert_eq!(
            policy_ref("allow-sales"),
            json!({"policy_definition_id": "allow-sales", "require_agent_context": false})
        );
    }
}
