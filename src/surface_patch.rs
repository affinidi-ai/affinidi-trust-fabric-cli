//! Turns the `--set`, `--unset`, `--add` and `--remove` flags of `surfaces
//! update` into the JSON Merge Patch document the gateway's
//! `PATCH /v1/surfaces/{id}` applies (https://www.rfc-editor.org/rfc/rfc7396).
//! Nothing here talks to the gateway, so the patch can be checked before it is
//! sent.

use anyhow::{Result, bail};
use serde_json::{Map, Value};

/// One field a flag edits: the dot path as the user wrote it, split into its
/// keys, and the value the patch gives it (`null` for `--unset`).
struct Edit<'a> {
    path: &'a str,
    keys: Vec<&'a str>,
    value: Value,
}

/// Build one merge patch from every `--set PATH=VALUE`, `--unset PATH`,
/// `--add PATH=VALUE` and `--remove PATH=VALUE`.
///
/// A path is dot-separated object keys (`access_point.rate_limit.requests`).
/// A value is read as JSON when it parses as JSON with no surrounding spaces
/// and as a plain string otherwise, so `100` is a number, `"100"` and ` 100`
/// are strings and `hello` is the string `hello`. `--unset` sends `null`,
/// which the merge removes, so a `--set` value that is or holds `null` in an
/// object is refused. A merge patch replaces a list whole, so `--add` and
/// `--remove` edit the list read from `surface` and send all of it, with
/// removes applied before adds so removing an item and adding it back
/// replaces it. Paths that repeat or overlap each other are refused, because
/// one would silently undo the other.
pub fn build_patch(
    sets: &[String],
    unsets: &[String],
    adds: &[String],
    removes: &[String],
    surface: &Value,
) -> Result<Value> {
    let mut edits = Vec::with_capacity(sets.len() + unsets.len());
    for set in sets {
        let Some((path, raw)) = set.split_once('=') else {
            bail!("--set '{set}' needs a value: use --set <path>=<value>");
        };
        let value = parse_value(raw);
        reject_nulls(path, &value)?;
        edits.push(Edit {
            path,
            keys: parse_path(path, "--set")?,
            value,
        });
    }
    for path in unsets {
        edits.push(Edit {
            path,
            keys: parse_path(path, "--unset")?,
            value: Value::Null,
        });
    }
    if !adds.is_empty() || !removes.is_empty() {
        edits.extend(list_edits(adds, removes, surface)?);
    }
    reject_overlaps(&edits)?;
    let mut patch = Map::new();
    for edit in edits {
        insert(&mut patch, &edit.keys, edit.value)?;
    }
    Ok(Value::Object(patch))
}

fn parse_value(raw: &str) -> Value {
    if raw != raw.trim() {
        return Value::String(raw.to_owned());
    }
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

/// Refuse a `--set` value whose `null`s the merge would read as removals.
/// Lists are sent whole, so a `null` inside one is kept as a list item.
fn reject_nulls(
    path: &str,
    value: &Value,
) -> Result<()> {
    if value.is_null() {
        bail!("--set {path}=null would remove the field: use --unset {path} instead");
    }
    if let Some(removed) = first_null_in_objects(path, value) {
        bail!("--set {path}={{...}} would remove {removed}: use --unset {removed} instead");
    }
    Ok(())
}

/// The dot path, starting at `path`, of the first `null` inside `value`'s
/// objects. A `null` inside a list is not counted.
pub fn first_null_in_objects(
    path: &str,
    value: &Value,
) -> Option<String> {
    let Value::Object(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find_map(|(key, child)| {
            let child_path = format!("{path}.{key}");
            if child.is_null() {
                Some(child_path)
            } else {
                first_null_in_objects(&child_path, child)
            }
        })
}

fn parse_path<'a>(
    path: &'a str,
    flag: &str,
) -> Result<Vec<&'a str>> {
    if path.is_empty() {
        bail!("{flag} needs a field path, such as target.endpoint");
    }
    let keys: Vec<&str> = path.split('.').collect();
    if keys
        .iter()
        .any(|key| key.is_empty())
    {
        bail!("{flag} path '{path}' has an empty part: separate field names with a single '.'");
    }
    if keys.iter().any(|key| {
        key.chars()
            .all(|c| c.is_ascii_digit())
    }) {
        bail!(
            "{flag} path '{path}' points at a list item by position, which can shift before the change lands: give \
             the list's own path to --add or --remove instead, such as --remove transit.points=<id>"
        );
    }
    Ok(keys)
}

/// One `--add` or `--remove` flag: the value as the user wrote it and as it
/// is read.
struct ListItem<'a> {
    raw: &'a str,
    value: Value,
}

/// The items added to and removed from one list path.
struct ListChange<'a> {
    path: &'a str,
    keys: Vec<&'a str>,
    removes: Vec<ListItem<'a>>,
    adds: Vec<ListItem<'a>>,
}

/// One edit per list path named by `--add` or `--remove`, holding the whole
/// list as it is after the change.
fn list_edits<'a>(
    adds: &'a [String],
    removes: &'a [String],
    surface: &Value,
) -> Result<Vec<Edit<'a>>> {
    let mut changes: Vec<ListChange<'a>> = Vec::new();
    for (flags, flag, is_add) in [(removes, "--remove", false), (adds, "--add", true)] {
        for given in flags {
            let Some((path, raw)) = given.split_once('=') else {
                bail!("{flag} '{given}' needs an item: use {flag} <path>=<item>");
            };
            let keys = parse_path(path, flag)?;
            let item = ListItem { raw, value: parse_value(raw) };
            let change = match changes
                .iter_mut()
                .position(|change| change.keys == keys)
            {
                Some(index) => &mut changes[index],
                None => {
                    changes.push(ListChange {
                        path,
                        keys,
                        removes: Vec::new(),
                        adds: Vec::new(),
                    });
                    changes
                        .last_mut()
                        .expect("just pushed")
                }
            };
            let items = if is_add {
                &mut change.adds
            } else {
                &mut change.removes
            };
            if items
                .iter()
                .any(|seen| seen.raw == raw || seen.value == item.value)
            {
                bail!("{flag} {path}={raw} is given more than once");
            }
            items.push(item);
        }
    }
    changes
        .into_iter()
        .map(|change| {
            let list = edited_list(&change, surface)?;
            Ok(Edit {
                path: change.path,
                keys: change.keys,
                value: Value::Array(list),
            })
        })
        .collect()
}

/// The list at `change.path` on `surface` with its removes and then its adds
/// applied. A missing list starts empty, and an added item must be the same
/// kind as the list as read, when all of it is objects or all of it is text.
/// An added item that is the same item as a removed one, or that holds every
/// field the `--remove` gave, takes its place and, when it has no `id` of its
/// own, the removed item's `id`, so replacing an item keeps its order and
/// identity.
fn edited_list(
    change: &ListChange<'_>,
    surface: &Value,
) -> Result<Vec<Value>> {
    let path = change.path;
    let Some((first, rest)) = change.keys.split_first() else {
        bail!("a field path must not be empty");
    };
    let mut current = surface.get(*first);
    for (depth, key) in rest.iter().enumerate() {
        current = match current {
            None | Some(Value::Null) => break,
            Some(Value::Object(fields)) => fields.get(*key),
            Some(Value::Array(_)) => {
                let ancestor = change.keys[..=depth].join(".");
                bail!("'{ancestor}' is a list: give the list's own path, such as --remove {ancestor}=<id>")
            }
            Some(_) => {
                let ancestor = change.keys[..=depth].join(".");
                bail!("'{ancestor}' is not an object, so '{path}' can't be a list")
            }
        };
    }
    let list = match current {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => bail!("'{path}' is not a list: use --set {path}=<value> to change it"),
    };
    let holds_objects = !list.is_empty()
        && list
            .iter()
            .all(Value::is_object);
    let holds_text = !list.is_empty()
        && list
            .iter()
            .all(Value::is_string);
    let mut slots: Vec<Option<Value>> = list
        .iter()
        .cloned()
        .map(Some)
        .collect();
    let mut removed_as: Vec<Option<&Value>> = vec![None; list.len()];
    for item in &change.removes {
        if let Some(index) = find_item(&slots, item, path)? {
            slots[index] = None;
            removed_as[index] = Some(&item.value);
            continue;
        }
        let removed: Vec<Option<Value>> = list
            .iter()
            .zip(&slots)
            .map(|(old, slot)| {
                slot.is_none()
                    .then(|| old.clone())
            })
            .collect();
        if !matches!(find_item(&removed, item, path), Ok(None)) {
            bail!("--remove {path}={} names the same item as another --remove", item.raw);
        }
        bail!("'{path}' has no item '{}'", item.raw);
    }
    for item in &change.adds {
        match &item.value {
            Value::Null => bail!("--add {path}=null adds nothing: give the item to add"),
            Value::Array(_) => {
                bail!("--add {path}={} is a list: add one item per --add, repeating the flag", item.raw)
            }
            _ => {}
        }
        if holds_objects && !item.value.is_object() {
            bail!("'{path}' holds objects: give the item as JSON, such as --add {path}='{{\"id\":\"...\"}}'");
        }
        if holds_text && !item.value.is_string() {
            bail!(
                "'{path}' holds text: give the item as plain text, such as --add {path}=beta, quoting a number as --add {path}='\"100\"'"
            );
        }
        if let Some(existing) = slots
            .iter()
            .flatten()
            .find(|existing| same_item(existing, &item.value))
        {
            bail!("'{path}' already has {}: remove it first to replace it", describe(existing));
        }
        let replaced = list
            .iter()
            .enumerate()
            .position(|(index, old)| {
                slots[index].is_none()
                    && (same_item(old, &item.value)
                        || (!has_id_or_alias(&item.value)
                            && removed_as[index].is_some_and(|given| holds_fields(&item.value, given))))
            });
        match replaced {
            Some(index) => slots[index] = Some(with_old_id(item.value.clone(), &list[index])),
            None => slots.push(Some(item.value.clone())),
        }
    }
    Ok(slots
        .into_iter()
        .flatten()
        .collect())
}

/// `new` with `old`'s string `id` copied in, when `new` is an object without
/// an `id` of its own.
fn with_old_id(
    mut new: Value,
    old: &Value,
) -> Value {
    if let (Value::Object(fields), Some(id)) = (
        &mut new,
        old.get("id")
            .filter(|id| id.is_string()),
    ) {
        fields
            .entry("id")
            .or_insert_with(|| id.clone());
    }
    new
}

/// The index of the one item still in `slots` that `item` names: an item equal
/// to it, else an object whose `id` is it, else an object whose `alias` is it,
/// else an object holding every field of an object `item`, since the gateway
/// fills in defaults the user never typed. More than one match at the first
/// level that has any is refused.
fn find_item(
    slots: &[Option<Value>],
    item: &ListItem<'_>,
    path: &str,
) -> Result<Option<usize>> {
    let matching = |matches: &dyn Fn(&Value) -> bool| -> Vec<usize> {
        slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.as_ref()
                    .filter(|candidate| matches(candidate))
                    .map(|_| index)
            })
            .collect()
    };
    let field_is = |field: &'static str| {
        move |candidate: &Value| {
            candidate
                .get(field)
                .and_then(Value::as_str)
                == Some(item.raw)
        }
    };
    let levels: [Vec<usize>; 4] = [
        matching(&|candidate| *candidate == item.value || candidate.as_str() == Some(item.raw)),
        matching(&field_is("id")),
        matching(&field_is("alias")),
        matching(&|candidate| holds_fields(candidate, &item.value)),
    ];
    for found in levels {
        match found.as_slice() {
            [] => continue,
            [index] => return Ok(Some(*index)),
            _ => bail!("'{}' matches more than one item in '{path}': give its id, or more of its fields", item.raw),
        }
    }
    Ok(None)
}

/// Whether `stored` is an object holding every field of `given`, a non-empty
/// object.
fn holds_fields(
    stored: &Value,
    given: &Value,
) -> bool {
    match (given, stored) {
        (Value::Object(given), Value::Object(stored)) if !given.is_empty() => given
            .iter()
            .all(|(key, value)| stored.get(key) == Some(value)),
        _ => false,
    }
}

fn has_id_or_alias(item: &Value) -> bool {
    ["id", "alias"]
        .iter()
        .any(|field| item.get(*field).is_some())
}

/// Whether `new` is already in the list as `existing`: equal, an object with
/// the same `id` or `alias`, or, for an object with neither, an object holding
/// every field it gives, since the gateway fills in defaults on stored items.
fn same_item(
    existing: &Value,
    new: &Value,
) -> bool {
    existing == new
        || (!has_id_or_alias(new) && holds_fields(existing, new))
        || ["id", "alias"]
            .iter()
            .any(|field| {
                let key = |value: &Value| {
                    value
                        .get(*field)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                key(existing).is_some() && key(existing) == key(new)
            })
}

fn describe(item: &Value) -> String {
    match item {
        Value::String(text) => format!("'{text}'"),
        _ => match item
            .get("id")
            .and_then(Value::as_str)
        {
            Some(id) => format!("an item with id '{id}'"),
            None => match item
                .get("alias")
                .and_then(Value::as_str)
            {
                Some(alias) => format!("an item with alias '{alias}'"),
                None => format!("{item}"),
            },
        },
    }
}

fn reject_overlaps(edits: &[Edit<'_>]) -> Result<()> {
    for (index, first) in edits.iter().enumerate() {
        for second in &edits[index + 1..] {
            if first.keys == second.keys {
                bail!("'{}' is given more than once", first.path);
            }
            if first
                .keys
                .starts_with(&second.keys)
                || second
                    .keys
                    .starts_with(&first.keys)
            {
                bail!(
                    "'{}' and '{}' overlap, because one is inside the other: change the parent as one value or \
                     change only the fields inside it",
                    first.path,
                    second.path
                );
            }
        }
    }
    Ok(())
}

fn insert(
    patch: &mut Map<String, Value>,
    keys: &[&str],
    value: Value,
) -> Result<()> {
    let Some((last, parents)) = keys.split_last() else {
        bail!("a field path must not be empty");
    };
    let mut node = patch;
    for key in parents {
        node = match node
            .entry(*key)
            .or_insert_with(|| Value::Object(Map::new()))
        {
            Value::Object(child) => child,
            _ => bail!("'{}' overlaps another field being changed", keys.join(".")),
        };
    }
    node.insert((*last).to_owned(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    }

    fn patch(
        sets: &[&str],
        unsets: &[&str],
    ) -> Result<Value> {
        build_patch(&strings(sets), &strings(unsets), &[], &[], &json!({}))
    }

    fn surface() -> Value {
        json!({
            "tags": ["prod", "beta"],
            "description": "Sales",
            "access_point": {"trust_check_list": [
                {"id": "tc-1", "trust_registry_id": "tr-1"},
                {"id": "tc-2", "trust_registry_id": "tr-2"}
            ]},
            "transit": {"points": [
                {"id": "tp-1", "alias": "billing"},
                {"id": "tp-2", "alias": "github"}
            ]},
            "outbound_credentials": [{"credential_provider_id": "cp-1"}]
        })
    }

    fn list_patch(
        sets: &[&str],
        adds: &[&str],
        removes: &[&str],
    ) -> Result<Value> {
        build_patch(&strings(sets), &[], &strings(adds), &strings(removes), &surface())
    }

    fn list_error(
        adds: &[&str],
        removes: &[&str],
    ) -> String {
        list_patch(&[], adds, removes)
            .expect_err("the flags should be refused")
            .to_string()
    }

    fn error_of(
        sets: &[&str],
        unsets: &[&str],
    ) -> String {
        patch(sets, unsets)
            .expect_err("the flags should be refused")
            .to_string()
    }

    #[test]
    fn a_nested_set_builds_the_nested_objects() {
        assert_eq!(
            patch(&["access_point.rate_limit.requests=100"], &[]).expect("patch"),
            json!({"access_point": {"rate_limit": {"requests": 100}}})
        );
    }

    #[test]
    fn sets_sharing_a_parent_merge_into_one_object() {
        assert_eq!(
            patch(&["target.endpoint=http://sales:3000", "target.timeout_secs=30", "name=Sales"], &[]).expect("patch"),
            json!({"name": "Sales", "target": {"endpoint": "http://sales:3000", "timeout_secs": 30}})
        );
    }

    #[test]
    fn unset_sends_null() {
        assert_eq!(
            patch(&["name=Sales"], &["access_point.rate_limit"]).expect("patch"),
            json!({"name": "Sales", "access_point": {"rate_limit": null}})
        );
    }

    #[test]
    fn values_are_read_as_json_when_they_parse() {
        assert_eq!(
            patch(&["a=100", "b=true", "c=\"100\"", "d={\"rpm\":100}", "e=hello", "f=[\"x\",\"y\"]"], &[])
                .expect("patch"),
            json!({"a": 100, "b": true, "c": "100", "d": {"rpm": 100}, "e": "hello", "f": ["x", "y"]})
        );
    }

    #[test]
    fn set_splits_on_the_first_equals_sign() {
        assert_eq!(
            patch(&["target.endpoint=http://sales:3000/?a=b"], &[]).expect("patch"),
            json!({"target": {"endpoint": "http://sales:3000/?a=b"}})
        );
    }

    #[test]
    fn set_without_equals_is_refused() {
        assert!(error_of(&["target.endpoint"], &[]).contains("needs a value"));
    }

    #[test]
    fn empty_paths_and_empty_parts_are_refused() {
        assert!(error_of(&["=1"], &[]).contains("needs a field path"));
        assert!(error_of(&[], &[""]).contains("needs a field path"));
        for path in ["a..b", ".a", "a."] {
            assert!(error_of(&[&format!("{path}=1")], &[]).contains("empty part"), "{path}");
            assert!(error_of(&[], &[path]).contains("empty part"), "{path}");
        }
    }

    #[test]
    fn list_indexes_are_refused_with_a_pointer_to_add_and_remove() {
        let error = error_of(&["transit.points.0.policy=allow"], &[]);
        assert!(error.contains("list item by position"), "{error}");
        assert!(error.contains("--remove transit.points=<id>"), "{error}");
        assert!(error_of(&[], &["transit.points.0"]).contains("list item by position"));
        assert!(list_error(&[], &["transit.points.0=tp-1"]).contains("list item by position"));
    }

    #[test]
    fn set_to_null_points_at_unset() {
        let error = error_of(&["access_point.rate_limit=null"], &[]);
        assert!(error.contains("--unset access_point.rate_limit"), "{error}");
    }

    #[test]
    fn a_null_inside_an_object_points_at_unset() {
        let error = error_of(&["a={\"b\":null}"], &[]);
        assert!(error.contains("would remove a.b"), "{error}");
        assert!(error.contains("--unset a.b"), "{error}");
    }

    #[test]
    fn a_deeper_null_inside_an_object_names_the_full_path() {
        let error = error_of(&["a={\"b\":{\"c\":null}}"], &[]);
        assert!(error.contains("--unset a.b.c"), "{error}");
    }

    #[test]
    fn a_null_inside_a_list_is_kept_as_an_item() {
        assert_eq!(patch(&["a=[1,null]"], &[]).expect("patch"), json!({"a": [1, null]}));
    }

    #[test]
    fn values_with_surrounding_spaces_stay_strings() {
        assert_eq!(patch(&["x= 100", "y=100 "], &[]).expect("patch"), json!({"x": " 100", "y": "100 "}));
    }

    #[test]
    fn the_same_path_twice_is_refused() {
        assert!(error_of(&["a.b=1", "a.b=2"], &[]).contains("more than once"));
        assert!(error_of(&["a.b=1"], &["a.b"]).contains("more than once"));
        assert!(error_of(&[], &["a.b", "a.b"]).contains("more than once"));
    }

    #[test]
    fn a_parent_and_its_child_are_refused_across_flags() {
        assert!(error_of(&["a.b=1"], &["a"]).contains("overlap"));
        assert!(error_of(&["a=1", "a.b=2"], &[]).contains("overlap"));
        assert!(error_of(&["a.b.c=1"], &["a.b"]).contains("overlap"));
    }

    #[test]
    fn siblings_with_a_shared_prefix_do_not_overlap() {
        assert_eq!(patch(&["ab=1", "a.b=2"], &[]).expect("patch"), json!({"ab": 1, "a": {"b": 2}}));
    }

    #[test]
    fn add_sends_the_whole_string_list_with_the_item_appended() {
        assert_eq!(list_patch(&[], &["tags=canary"], &[]).expect("patch"), json!({"tags": ["prod", "beta", "canary"]}));
    }

    #[test]
    fn remove_matches_a_string_item_by_value() {
        assert_eq!(list_patch(&[], &[], &["tags=prod"]).expect("patch"), json!({"tags": ["beta"]}));
    }

    #[test]
    fn a_string_item_that_looks_like_a_number_still_matches() {
        let surface = json!({"tags": ["100", "prod"]});
        let patch = build_patch(&[], &[], &[], &strings(&["tags=100"]), &surface).expect("patch");
        assert_eq!(patch, json!({"tags": ["prod"]}));
    }

    #[test]
    fn removing_the_last_item_sends_an_empty_list_not_null() {
        assert_eq!(list_patch(&[], &[], &["tags=prod", "tags=beta"]).expect("patch"), json!({"tags": []}));
    }

    #[test]
    fn remove_matches_an_object_item_by_id() {
        assert_eq!(
            list_patch(&[], &[], &["access_point.trust_check_list=tc-1"]).expect("patch"),
            json!({"access_point": {"trust_check_list": [{"id": "tc-2", "trust_registry_id": "tr-2"}]}})
        );
    }

    #[test]
    fn remove_matches_a_transit_point_by_alias_or_id() {
        let expected = json!({"transit": {"points": [{"id": "tp-2", "alias": "github"}]}});
        assert_eq!(list_patch(&[], &[], &["transit.points=billing"]).expect("patch"), expected);
        assert_eq!(list_patch(&[], &[], &["transit.points=tp-1"]).expect("patch"), expected);
    }

    #[test]
    fn an_id_wins_over_another_items_alias() {
        let surface = json!({"transit": {"points": [{"id": "a", "alias": "x"}, {"id": "b", "alias": "a"}]}});
        let patch = build_patch(&[], &[], &[], &strings(&["transit.points=a"]), &surface).expect("patch");
        assert_eq!(patch, json!({"transit": {"points": [{"id": "b", "alias": "a"}]}}));
    }

    #[test]
    fn an_item_without_an_id_is_removed_by_its_whole_value() {
        assert_eq!(
            list_patch(&[], &[], &["outbound_credentials={\"credential_provider_id\":\"cp-1\"}"]).expect("patch"),
            json!({"outbound_credentials": []})
        );
    }

    #[test]
    fn an_item_without_an_id_is_removed_by_the_fields_given() {
        let surface = json!({"outbound_credentials": [
            {"credential_provider_id": "cp-1", "scopes": [], "consent_mode": "silent"},
            {"credential_provider_id": "cp-2", "scopes": [], "consent_mode": "silent"}
        ]});
        let patch = build_patch(
            &[],
            &[],
            &[],
            &strings(&["outbound_credentials={\"credential_provider_id\":\"cp-1\"}"]),
            &surface,
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"outbound_credentials": [{"credential_provider_id": "cp-2", "scopes": [], "consent_mode": "silent"}]})
        );
    }

    #[test]
    fn fields_shared_by_two_items_are_refused() {
        let surface = json!({"outbound_credentials": [
            {"credential_provider_id": "cp-1", "consent_mode": "silent"},
            {"credential_provider_id": "cp-2", "consent_mode": "silent"}
        ]});
        let error =
            build_patch(&[], &[], &[], &strings(&["outbound_credentials={\"consent_mode\":\"silent\"}"]), &surface)
                .expect_err("both items hold the field")
                .to_string();
        assert!(error.contains("matches more than one item"), "{error}");
        assert!(list_error(&[], &["outbound_credentials={}"]).contains("has no item"));
    }

    #[test]
    fn remove_then_add_with_the_same_id_replaces_the_item_in_place() {
        assert_eq!(
            list_patch(
                &[],
                &["access_point.trust_check_list={\"id\":\"tc-1\",\"trust_registry_id\":\"tr-9\"}"],
                &["access_point.trust_check_list=tc-1"]
            )
            .expect("patch"),
            json!({"access_point": {"trust_check_list": [
                {"id": "tc-1", "trust_registry_id": "tr-9"},
                {"id": "tc-2", "trust_registry_id": "tr-2"}
            ]}})
        );
    }

    #[test]
    fn replacing_an_item_by_alias_keeps_its_id() {
        let surface = json!({"transit": {"points": [
            {"id": "tp-1", "alias": "billing", "target_endpoint": "a"},
            {"id": "tp-2", "alias": "github"}
        ]}});
        let patch = build_patch(
            &[],
            &[],
            &strings(&["transit.points={\"alias\":\"billing\",\"target_endpoint\":\"b\"}"]),
            &strings(&["transit.points=billing"]),
            &surface,
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"transit": {"points": [
                {"id": "tp-1", "alias": "billing", "target_endpoint": "b"},
                {"id": "tp-2", "alias": "github"}
            ]}})
        );
    }

    #[test]
    fn a_replacing_item_with_its_own_id_keeps_that_id() {
        assert_eq!(
            list_patch(&[], &["transit.points={\"id\":\"tp-9\",\"alias\":\"billing\"}"], &["transit.points=billing"])
                .expect("patch"),
            json!({"transit": {"points": [
                {"id": "tp-9", "alias": "billing"},
                {"id": "tp-2", "alias": "github"}
            ]}})
        );
    }

    #[test]
    fn two_names_for_the_same_item_are_refused_the_second_time() {
        let error = list_error(&[], &["transit.points=billing", "transit.points=tp-1"]);
        assert!(error.contains("--remove transit.points=tp-1 names the same item as another --remove"), "{error}");
    }

    #[test]
    fn an_item_already_removed_does_not_make_a_later_remove_ambiguous() {
        let surface = json!({"points": [{"id": "x", "alias": "dup"}, {"id": "y", "alias": "dup"}]});
        let patch = build_patch(&[], &[], &[], &strings(&["points=x", "points=dup"]), &surface).expect("patch");
        assert_eq!(patch, json!({"points": []}));
    }

    #[test]
    fn add_creates_a_list_that_is_not_set_yet() {
        assert_eq!(
            list_patch(&[], &["supported_extensions=https://ext.example/v1"], &[]).expect("patch"),
            json!({"supported_extensions": ["https://ext.example/v1"]})
        );
    }

    #[test]
    fn list_edits_merge_with_sets_into_one_patch() {
        assert_eq!(
            list_patch(&["name=Sales"], &["tags=canary"], &["access_point.trust_check_list=tc-2"]).expect("patch"),
            json!({
                "name": "Sales",
                "tags": ["prod", "beta", "canary"],
                "access_point": {"trust_check_list": [{"id": "tc-1", "trust_registry_id": "tr-1"}]}
            })
        );
    }

    #[test]
    fn a_missing_item_is_refused() {
        let error = list_error(&[], &["tags=staging"]);
        assert!(error.contains("'tags' has no item 'staging'"), "{error}");
        assert!(list_error(&[], &["variants=v-1"]).contains("has no item"));
    }

    #[test]
    fn an_item_without_an_id_holding_a_stored_items_fields_is_a_duplicate() {
        let error = list_error(&["outbound_credentials={\"credential_provider_id\":\"cp-1\"}"], &[]);
        assert!(error.contains("already has {\"credential_provider_id\":\"cp-1\"}"), "{error}");
        let surface = json!({"outbound_credentials": [
            {"credential_provider_id": "cp-1", "scopes": [], "consent_mode": "silent"}
        ]});
        let error = build_patch(
            &[],
            &[],
            &strings(&["outbound_credentials={\"credential_provider_id\":\"cp-1\"}"]),
            &[],
            &surface,
        )
        .expect_err("the gateway already holds the binding with its defaults")
        .to_string();
        assert!(error.contains("already has"), "{error}");
    }

    #[test]
    fn an_item_without_an_id_for_another_binding_is_added() {
        assert_eq!(
            list_patch(&[], &["outbound_credentials={\"credential_provider_id\":\"cp-2\"}"], &[]).expect("patch"),
            json!({"outbound_credentials": [{"credential_provider_id": "cp-1"}, {"credential_provider_id": "cp-2"}]})
        );
    }

    #[test]
    fn replacing_an_item_without_an_id_keeps_its_position() {
        let surface = json!({"outbound_credentials": [
            {"credential_provider_id": "cp-1", "scopes": [], "consent_mode": "silent"},
            {"credential_provider_id": "cp-2", "scopes": [], "consent_mode": "silent"}
        ]});
        let patch = build_patch(
            &[],
            &[],
            &strings(&["outbound_credentials={\"credential_provider_id\":\"cp-1\",\"scopes\":[\"x\"]}"]),
            &strings(&["outbound_credentials={\"credential_provider_id\":\"cp-1\"}"]),
            &surface,
        )
        .expect("patch");
        assert_eq!(
            patch,
            json!({"outbound_credentials": [
                {"credential_provider_id": "cp-1", "scopes": ["x"]},
                {"credential_provider_id": "cp-2", "scopes": [], "consent_mode": "silent"}
            ]})
        );
    }

    #[test]
    fn a_duplicate_item_is_refused() {
        assert!(list_error(&["tags=prod"], &[]).contains("already has 'prod'"));
        let error = list_error(&["access_point.trust_check_list={\"id\":\"tc-1\"}"], &[]);
        assert!(error.contains("already has an item with id 'tc-1'"), "{error}");
        assert!(list_error(&["transit.points={\"id\":\"tp-9\",\"alias\":\"billing\"}"], &[]).contains("already has"));
        let surface = json!({"transit": {"points": [{"alias": "billing"}]}});
        let error = build_patch(&[], &[], &strings(&["transit.points={\"alias\":\"billing\"}"]), &[], &surface)
            .expect_err("the alias is already there")
            .to_string();
        assert!(error.contains("already has an item with alias 'billing'"), "{error}");
    }

    #[test]
    fn the_same_item_twice_in_one_flag_is_refused() {
        assert!(list_error(&["tags=a", "tags=a"], &[]).contains("more than once"));
        assert!(list_error(&[], &["tags=prod", "tags=prod"]).contains("more than once"));
    }

    #[test]
    fn the_same_item_written_two_ways_is_refused() {
        assert!(list_error(&["tags=beta", "tags=\"beta\""], &[]).contains("is given more than once"));
        assert!(list_error(&[], &["tags=prod", "tags=\"prod\""]).contains("is given more than once"));
    }

    #[test]
    fn a_field_that_is_not_a_list_is_refused() {
        let error = list_error(&["description=x"], &[]);
        assert!(error.contains("'description' is not a list"), "{error}");
        assert!(error.contains("--set description="), "{error}");
    }

    #[test]
    fn a_field_inside_something_that_is_not_an_object_is_refused() {
        let error = list_error(&["description.foo=x"], &[]);
        assert!(error.contains("'description' is not an object"), "{error}");
        let error = list_error(&[], &["transit.points.billing=x"]);
        assert!(error.contains("'transit.points' is a list"), "{error}");
        assert!(error.contains("--remove transit.points=<id>"), "{error}");
    }

    #[test]
    fn an_item_of_the_wrong_kind_is_refused() {
        let error = list_error(&["transit.points=billing"], &[]);
        assert!(error.contains("'transit.points' holds objects"), "{error}");
        let error = list_error(&["transit.points=billing"], &["transit.points=billing"]);
        assert!(error.contains("'transit.points' holds objects"), "{error}");
        let error = list_error(&["tags={\"a\":1}"], &[]);
        assert!(error.contains("'tags' holds text"), "{error}");
    }

    #[test]
    fn a_null_or_list_item_is_refused() {
        assert!(list_error(&["tags=null"], &[]).contains("adds nothing"));
        assert!(list_error(&["tags=[\"a\",\"b\"]"], &[]).contains("one item per --add"));
    }

    #[test]
    fn an_item_matching_two_entries_is_refused() {
        let surface = json!({"gates": [{"id": "g", "name": "a"}, {"id": "g", "name": "b"}]});
        let error = build_patch(&[], &[], &[], &strings(&["gates=g"]), &surface)
            .expect_err("two gates share the id")
            .to_string();
        assert!(error.contains("matches more than one item"), "{error}");
    }

    #[test]
    fn a_list_edit_and_a_set_on_the_same_path_are_refused() {
        assert!(list_patch(&["tags=[\"x\"]"], &["tags=y"], &[]).is_err());
        let error = list_patch(&["access_point={\"route\":\"/x\"}"], &[], &["access_point.trust_check_list=tc-1"])
            .expect_err("the parent and the list overlap")
            .to_string();
        assert!(error.contains("overlap"), "{error}");
    }

    #[test]
    fn add_or_remove_without_an_item_is_refused() {
        assert!(list_error(&["tags"], &[]).contains("needs an item"));
        assert!(list_error(&[], &["tags"]).contains("needs an item"));
    }
}
