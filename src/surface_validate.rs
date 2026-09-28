//! Checks a surface edit on this machine before it is sent, so a bad edit
//! fails with a clear message instead of an error from the gateway.
//!
//! [`merge`] applies a JSON Merge Patch (https://www.rfc-editor.org/rfc/rfc7396)
//! the way the gateway's `PATCH /v1/surfaces/{id}` does, and [`check_surface`]
//! runs the gateway's shape check for the fields every surface needs: `name`,
//! `access_point.listen_address`, `access_point.route` and `target.endpoint`
//! must be present and not empty. Like the gateway, a route missing its
//! leading `/` is accepted, because the gateway adds it.
//!
//! Every other check only runs on the gateway: whether referenced policies,
//! secrets, credential providers and other entities exist, route and listen
//! path collisions with other surfaces, variants, transit point aliases,
//! payment policies, trust checks and caller authentication. A dry run sends
//! the patch to the gateway with `?dry_run=true` to run those too.

use anyhow::{Result, bail};
use serde_json::{Map, Value};

/// The fields [`check_surface`] requires, as the dot paths the gateway names
/// in its errors.
const REQUIRED_FIELDS: [&[&str]; 4] =
    [&["name"], &["access_point", "listen_address"], &["access_point", "route"], &["target", "endpoint"]];

/// Apply `patch` to `target` as a JSON Merge Patch: a `null` removes the
/// field, an object merges into the object already there, and anything else,
/// a list included, replaces the value whole. A patch that is not an object
/// replaces `target`.
pub fn merge(
    target: &mut Value,
    patch: &Value,
) {
    let Value::Object(fields) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    let Value::Object(existing) = target else {
        return;
    };
    for (key, value) in fields {
        if value.is_null() {
            existing.remove(key);
        } else {
            merge(
                existing
                    .entry(key.clone())
                    .or_insert(Value::Null),
                value,
            );
        }
    }
}

/// Refuse a surface missing a field every surface needs, with the gateway's
/// own message. A field holding something other than text is left for the
/// gateway to report.
pub fn check_surface(surface: &Value) -> Result<()> {
    for keys in REQUIRED_FIELDS {
        let value = keys
            .iter()
            .try_fold(surface, |value, key| value.get(key));
        let missing = match value {
            None | Some(Value::Null) => true,
            Some(Value::String(text)) => text.is_empty(),
            Some(_) => false,
        };
        if missing {
            bail!("{} is required", keys.join("."));
        }
    }
    Ok(())
}

/// One field a dry run changes: its dot path and its value before and after,
/// `None` where the field is absent.
#[derive(Debug, PartialEq)]
pub struct Change {
    pub path: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

/// Every field that differs between `before` and `after`, in path order.
/// Objects are compared field by field and anything else, a list included, as
/// one value, the same way a merge patch replaces it.
pub fn changes(
    before: &Value,
    after: &Value,
) -> Vec<Change> {
    let mut found = Vec::new();
    collect_changes("", Some(before), Some(after), &mut found);
    found
}

fn collect_changes(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    found: &mut Vec<Change>,
) {
    if let (Some(Value::Object(old)), Some(Value::Object(new))) = (before, after) {
        let mut keys: Vec<&String> = old
            .keys()
            .chain(new.keys())
            .collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            collect_changes(&child, old.get(key), new.get(key), found);
        }
    } else if before != after {
        found.push(Change {
            path: path.to_owned(),
            before: before.cloned(),
            after: after.cloned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_surface() -> Value {
        json!({
            "surface_id": "s-1",
            "name": "Sales",
            "access_point": {"listen_address": "0.0.0.0:8080", "route": "/sales"},
            "target": {"endpoint": "http://127.0.0.1:3000"},
            "tags": ["prod"]
        })
    }

    #[test]
    fn merge_removes_a_field_set_to_null() {
        let mut surface = json!({"name": "Sales", "description": "old"});

        merge(&mut surface, &json!({"description": null}));

        assert_eq!(surface, json!({"name": "Sales"}));
    }

    #[test]
    fn merge_merges_nested_objects() {
        let mut surface =
            json!({"access_point": {"route": "/sales", "rate_limit": {"requests": 10, "window_secs": 60}}});

        merge(&mut surface, &json!({"access_point": {"rate_limit": {"requests": 100}}}));

        assert_eq!(
            surface,
            json!({"access_point": {"route": "/sales", "rate_limit": {"requests": 100, "window_secs": 60}}})
        );
    }

    #[test]
    fn merge_replaces_a_list_whole() {
        let mut surface = json!({"tags": ["prod", "beta"]});

        merge(&mut surface, &json!({"tags": ["canary"]}));

        assert_eq!(surface, json!({"tags": ["canary"]}));
    }

    #[test]
    fn merge_creates_an_object_under_a_field_that_was_not_one() {
        let mut surface = json!({"access_point": "legacy"});

        merge(&mut surface, &json!({"access_point": {"route": "/sales", "name": null}}));

        assert_eq!(surface, json!({"access_point": {"route": "/sales"}}));
    }

    #[test]
    fn merge_with_a_patch_that_is_not_an_object_replaces_the_target() {
        let mut surface = json!({"name": "Sales"});

        merge(&mut surface, &json!(["not", "an", "object"]));

        assert_eq!(surface, json!(["not", "an", "object"]));
    }

    #[test]
    fn check_surface_accepts_a_complete_surface() {
        check_surface(&valid_surface()).expect("a complete surface passes");
    }

    #[test]
    fn check_surface_accepts_a_route_without_a_leading_slash() {
        let mut surface = valid_surface();
        surface["access_point"]["route"] = json!("sales");

        check_surface(&surface).expect("the gateway adds the missing '/'");
    }

    #[test]
    fn check_surface_names_each_missing_required_field() {
        for (patch, expected) in [
            (json!({"name": ""}), "name is required"),
            (json!({"name": null}), "name is required"),
            (json!({"access_point": {"listen_address": ""}}), "access_point.listen_address is required"),
            (json!({"access_point": {"route": ""}}), "access_point.route is required"),
            (json!({"access_point": {"route": null}}), "access_point.route is required"),
            (json!({"target": {"endpoint": ""}}), "target.endpoint is required"),
            (json!({"target": null}), "target.endpoint is required"),
        ] {
            let mut surface = valid_surface();
            merge(&mut surface, &patch);
            let error = check_surface(&surface).expect_err("the edit should be refused");
            assert_eq!(error.to_string(), expected, "for patch {patch}");
        }
    }

    #[test]
    fn check_surface_leaves_a_field_of_the_wrong_type_to_the_gateway() {
        let mut surface = valid_surface();
        surface["name"] = json!(5);

        check_surface(&surface).expect("the gateway reports a wrong type itself");
    }

    #[test]
    fn changes_lists_each_changed_field_by_path() {
        let before = valid_surface();
        let after = json!({
            "surface_id": "s-1",
            "name": "Sales",
            "description": "new",
            "access_point": {"listen_address": "0.0.0.0:8080", "route": "/sales", "rate_limit": {"requests": 100}},
            "target": {"endpoint": "http://127.0.0.1:3000"},
            "tags": ["prod", "beta"]
        });

        assert_eq!(
            changes(&before, &after),
            [
                Change {
                    path: "access_point.rate_limit".to_owned(),
                    before: None,
                    after: Some(json!({"requests": 100})),
                },
                Change {
                    path: "description".to_owned(),
                    before: None,
                    after: Some(json!("new")),
                },
                Change {
                    path: "tags".to_owned(),
                    before: Some(json!(["prod"])),
                    after: Some(json!(["prod", "beta"])),
                },
            ]
        );
    }

    #[test]
    fn changes_reports_a_removed_field() {
        let after = json!({
            "surface_id": "s-1",
            "name": "Sales",
            "access_point": {"listen_address": "0.0.0.0:8080", "route": "/sales"},
            "target": {"endpoint": "http://127.0.0.1:3000"}
        });

        assert_eq!(
            changes(&valid_surface(), &after),
            [Change {
                path: "tags".to_owned(),
                before: Some(json!(["prod"])),
                after: None,
            }]
        );
    }

    #[test]
    fn changes_is_empty_for_the_same_surface() {
        assert!(changes(&valid_surface(), &valid_surface()).is_empty());
    }
}
