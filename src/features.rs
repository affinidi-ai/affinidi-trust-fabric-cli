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

    /// Human-readable list of valid placements, for error messages.
    pub fn placement_summary(&self) -> String {
        self.placements
            .iter()
            .map(|placement| format!("{}/{}", placement.edge.label(), placement.direction.label()))
            .collect::<Vec<_>>()
            .join(", ")
    }
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
