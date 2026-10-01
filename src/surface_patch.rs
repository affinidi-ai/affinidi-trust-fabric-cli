//! Turns the `--set`, `--unset`, `--add` and `--remove` flags of `surfaces
//! update` into the JSON Merge Patch document the gateway's
//! `PATCH /v1/surfaces/{id}` applies (https://www.rfc-editor.org/rfc/rfc7396).
//! Nothing here talks to the gateway, so the patch can be checked before it is
//! sent.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use crate::{client::sanitize_for_terminal, tool_gate_preview};

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
///
/// A gate's patterns can be edited without resending the gate by naming the
/// gate by its `id`, else its `name`, in square brackets: `--add
/// 'target.mcp_tool_gating.gates[g-1].action.patterns=^fs_'`. A transit point
/// is named the same way, by `id` else `alias`
/// (`transit.points[billing].mcp_tool_gating.gates[g-1].action.patterns`).
/// The pattern is always text, and the patch holds the surrounding list with
/// only that gate's patterns changed.
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
    if path.contains('[') {
        bail!(
            "{flag} can't use brackets in '{path}': brackets only work with --add and --remove on a gate's patterns, \
             such as --add 'target.mcp_tool_gating.gates[g-1].action.patterns=fs_.*'"
        );
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
    let mut pattern_edits: Vec<PatternEdit<'a>> = Vec::new();
    for (flags, flag, is_add) in [(removes, "--remove", false), (adds, "--add", true)] {
        for given in flags {
            let Some((path, raw)) = split_flag(given) else {
                bail!("{flag} '{given}' needs an item: use {flag} <path>=<item>");
            };
            if path.contains('[') {
                pattern_edits.push(parse_pattern_edit(path, raw, flag, is_add)?);
                continue;
            }
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
    let mut edits = changes
        .into_iter()
        .map(|change| {
            let list = edited_list(&change, surface)?;
            Ok(Edit {
                path: change.path,
                keys: change.keys,
                value: Value::Array(list),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    edits.extend(pattern_list_edits(&pattern_edits, surface)?);
    Ok(edits)
}

/// Split an `--add` or `--remove` flag at its first `=` outside square
/// brackets, so an item named as `gates[g=1]` keeps its `=`. A bracket that is
/// never closed splits at the first `=`, and the path is refused later.
fn split_flag(given: &str) -> Option<(&str, &str)> {
    let mut inside = false;
    for (index, c) in given.char_indices() {
        match c {
            '[' => inside = true,
            ']' => inside = false,
            '=' if !inside => return Some((&given[..index], &given[index + 1..])),
            _ => {}
        }
    }
    given.split_once('=')
}

/// Where a gate sits: on the surface itself or on one transit point, named by
/// its `id` or `alias`.
type GateOwner<'a> = Option<&'a str>;

/// One `--add` or `--remove` of one tool pattern on one gate.
struct PatternEdit<'a> {
    owner: GateOwner<'a>,
    gate: &'a str,
    /// The pattern as the gateway keeps it, without surrounding spaces.
    pattern: &'a str,
    is_add: bool,
}

/// The path segments of `path`, each a field name and the item picked in
/// square brackets, as in `gates[g-1]`. `None` where a bracket is not closed,
/// is empty or is not followed by a `.`.
fn split_segments(path: &str) -> Option<Vec<(&str, Option<&str>)>> {
    let mut segments = Vec::new();
    let mut rest = path;
    loop {
        let end = rest
            .find(['.', '['])
            .unwrap_or(rest.len());
        let name = &rest[..end];
        if name.is_empty() {
            return None;
        }
        rest = &rest[end..];
        let mut picked = None;
        if let Some(inner) = rest.strip_prefix('[') {
            let close = inner.find(']')?;
            picked = Some(&inner[..close]).filter(|picked| !picked.is_empty());
            picked?;
            rest = &inner[close + 1..];
        }
        segments.push((name, picked));
        if rest.is_empty() {
            return Some(segments);
        }
        rest = rest.strip_prefix('.')?;
    }
}

/// Read a flag that names one tool pattern, as
/// `target.mcp_tool_gating.gates[<gate id>].action.patterns` or
/// `transit.points[<id or alias>].mcp_tool_gating.gates[<gate id>].action.patterns`.
/// The pattern is always text, and one that is not valid is refused here.
fn parse_pattern_edit<'a>(
    path: &'a str,
    raw: &'a str,
    flag: &str,
    is_add: bool,
) -> Result<PatternEdit<'a>> {
    let named = "use target.mcp_tool_gating.gates[<gate id>].action.patterns, or \
                 transit.points[<id or alias>].mcp_tool_gating.gates[<gate id>].action.patterns for a transit point";
    let Some(segments) = split_segments(path) else {
        bail!("{flag} path '{path}' has a bracket that is not closed or is empty: {named}");
    };
    let (owner, gate) = match segments.as_slice() {
        [("target", None), ("mcp_tool_gating", None), ("gates", Some(gate)), ("action", None), ("patterns", None)] => {
            (None, *gate)
        }
        [
            ("transit", None),
            ("points", Some(point)),
            ("mcp_tool_gating", None),
            ("gates", Some(gate)),
            ("action", None),
            ("patterns", None),
        ] => (Some(*point), *gate),
        _ => bail!("{flag} can only pick a tool pattern with brackets, and '{path}' is not one: {named}"),
    };
    let pattern = raw.trim();
    if is_add {
        tool_gate_preview::check_pattern(pattern).with_context(|| format!("{flag} {path}={raw}"))?;
    } else if pattern.is_empty() {
        bail!("{flag} {path}= needs the pattern to remove");
    }
    Ok(PatternEdit { owner, gate, pattern, is_add })
}

/// One edit per list that holds a gate with a pattern change: the surface's
/// own `gates`, and `transit.points` for gates on transit points. Each holds
/// the whole list as it is after the change, since a merge patch replaces a
/// list whole, and only the named gates' patterns differ from `surface`.
fn pattern_list_edits<'a>(
    edits: &[PatternEdit<'a>],
    surface: &Value,
) -> Result<Vec<Edit<'a>>> {
    let mut found = Vec::new();
    let own: Vec<&PatternEdit<'a>> = edits
        .iter()
        .filter(|edit| edit.owner.is_none())
        .collect();
    if !own.is_empty() {
        let keys = vec!["target", "mcp_tool_gating", "gates"];
        let mut gates = list_at(surface, &keys)?;
        change_gates(&mut gates, &own, "the surface")?;
        found.push(Edit {
            path: "target.mcp_tool_gating.gates",
            keys,
            value: Value::Array(gates),
        });
    }
    if edits
        .iter()
        .any(|edit| edit.owner.is_some())
    {
        let keys = vec!["transit", "points"];
        let mut points = list_at(surface, &keys)?;
        let resolved = edits
            .iter()
            .filter_map(|edit| {
                edit.owner
                    .map(|owner| (owner, edit))
            })
            .map(|(owner, edit)| Ok((find_point(&points, owner)?, owner, edit)))
            .collect::<Result<Vec<_>>>()?;
        let mut done: Vec<usize> = Vec::new();
        for &(index, owner, _) in &resolved {
            if done.contains(&index) {
                continue;
            }
            done.push(index);
            let point_edits: Vec<&PatternEdit<'a>> = resolved
                .iter()
                .filter(|(other, ..)| *other == index)
                .map(|(.., edit)| *edit)
                .collect();
            let mut gates = list_at(&points[index], &["mcp_tool_gating", "gates"])?;
            change_gates(&mut gates, &point_edits, &format!("transit point '{owner}'"))?;
            let Some(point) = points[index].as_object_mut() else {
                bail!("transit point '{owner}' is not an object");
            };
            let gating = point
                .entry("mcp_tool_gating")
                .or_insert_with(|| Value::Object(Map::new()));
            let Some(gating) = gating.as_object_mut() else {
                bail!("transit point '{owner}' has an mcp_tool_gating that is not an object");
            };
            gating.insert("gates".to_owned(), Value::Array(gates));
        }
        found.push(Edit {
            path: "transit.points",
            keys,
            value: Value::Array(points),
        });
    }
    Ok(found)
}

/// The list found by following `keys` from `value`, empty where it is absent.
fn list_at(
    value: &Value,
    keys: &[&str],
) -> Result<Vec<Value>> {
    let found = keys
        .iter()
        .try_fold(value, |value, key| value.get(key));
    match found {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => bail!("'{}' is not a list", keys.join(".")),
    }
}

/// The index of the transit point named by its `id`, else its `alias`.
fn find_point(
    points: &[Value],
    named: &str,
) -> Result<usize> {
    for field in ["id", "alias"] {
        let mut found = points
            .iter()
            .enumerate()
            .filter(|(_, point)| {
                point
                    .get(field)
                    .and_then(Value::as_str)
                    == Some(named)
            })
            .map(|(index, _)| index);
        match (found.next(), found.next()) {
            (Some(index), None) => return Ok(index),
            (Some(_), Some(_)) => bail!("more than one transit point has the {field} '{named}': use its id"),
            _ => {}
        }
    }
    let known: Vec<String> = points
        .iter()
        .filter_map(|point| {
            point
                .get("alias")
                .or_else(|| point.get("id"))
                .and_then(Value::as_str)
                .map(sanitize_for_terminal)
        })
        .collect();
    if known.is_empty() {
        bail!("this surface has no transit point '{named}': it has no transit points yet");
    }
    bail!("this surface has no transit point '{named}': the transit points are {}", known.join(", "))
}

/// The index of the gate named by its `id`, else its `name`.
fn find_gate(
    gates: &[Value],
    named: &str,
    owner: &str,
) -> Result<usize> {
    for field in ["id", "name"] {
        let mut found = gates
            .iter()
            .enumerate()
            .filter(|(_, gate)| {
                gate.get(field)
                    .and_then(Value::as_str)
                    == Some(named)
            })
            .map(|(index, _)| index);
        match (found.next(), found.next()) {
            (Some(index), None) => return Ok(index),
            (Some(_), Some(_)) => bail!("more than one gate on {owner} has the {field} '{named}': use its id"),
            _ => {}
        }
    }
    let known: Vec<String> = gates
        .iter()
        .filter_map(|gate| {
            gate.get("id")
                .or_else(|| gate.get("name"))
                .and_then(Value::as_str)
                .map(sanitize_for_terminal)
        })
        .collect();
    if known.is_empty() {
        bail!("{owner} has no tool gate '{named}': it has no tool gates yet");
    }
    bail!("{owner} has no tool gate '{named}': the gates are {}", known.join(", "))
}

/// Apply every pattern edit in `edits` to the gate each names in `gates`.
/// Removes run before adds, as for any list. A pattern already in the gate or
/// missing from it is refused, and so is a change that leaves a gate with no
/// pattern, which the gateway does not save.
fn change_gates(
    gates: &mut [Value],
    edits: &[&PatternEdit<'_>],
    owner: &str,
) -> Result<()> {
    let resolved = edits
        .iter()
        .map(|edit| Ok((find_gate(gates, edit.gate, owner)?, *edit)))
        .collect::<Result<Vec<_>>>()?;
    let mut done: Vec<usize> = Vec::new();
    for &(index, first) in &resolved {
        if done.contains(&index) {
            continue;
        }
        done.push(index);
        let named = first.gate;
        let Some(action) = gates[index]
            .get_mut("action")
            .and_then(Value::as_object_mut)
        else {
            bail!("gate '{named}' on {owner} has no action to hold patterns");
        };
        let mut patterns = match action.get("patterns") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => bail!("the patterns of gate '{named}' on {owner} are not a list"),
        };
        for is_add in [false, true] {
            for edit in resolved
                .iter()
                .filter(|(other, edit)| *other == index && edit.is_add == is_add)
                .map(|(_, edit)| edit)
            {
                if resolved
                    .iter()
                    .take_while(|(_, other)| !std::ptr::eq(*other, *edit))
                    .any(|(other_index, other)| {
                        *other_index == index && other.is_add == is_add && other.pattern == edit.pattern
                    })
                {
                    bail!(
                        "{} '{}' is given more than once for gate '{named}' on {owner}",
                        if is_add {
                            "--add"
                        } else {
                            "--remove"
                        },
                        edit.pattern
                    );
                }
                let at = patterns
                    .iter()
                    .position(|existing| {
                        existing
                            .as_str()
                            .map(str::trim)
                            == Some(edit.pattern)
                    });
                match (is_add, at) {
                    (true, Some(_)) => bail!("gate '{named}' on {owner} already has the pattern '{}'", edit.pattern),
                    (true, None) => patterns.push(Value::String(edit.pattern.to_owned())),
                    (false, Some(index)) => {
                        patterns.remove(index);
                    }
                    (false, None) => {
                        bail!("gate '{named}' on {owner} has no pattern '{}'{}", edit.pattern, held(&patterns))
                    }
                }
            }
        }
        let blank = |pattern: &Value| {
            pattern
                .as_str()
                .is_some_and(|text| text.trim().is_empty())
        };
        if patterns.iter().all(blank) {
            bail!(
                "this would leave gate '{named}' on {owner} with no patterns, and the gateway does not save a gate \
                 with none: remove the whole gate instead, such as --remove <path to gates>={named}"
            );
        }
        let texts: Vec<String> = patterns
            .iter()
            .filter_map(|pattern| {
                pattern
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        tool_gate_preview::check_pattern_count(&texts).with_context(|| format!("gate '{named}' on {owner}"))?;
        action.insert("patterns".to_owned(), Value::Array(patterns));
    }
    Ok(())
}

/// ", it has a, b" listing the text in `patterns`, or nothing when it has none.
fn held(patterns: &[Value]) -> String {
    let text: Vec<String> = patterns
        .iter()
        .filter_map(Value::as_str)
        .map(sanitize_for_terminal)
        .collect();
    if text.is_empty() {
        String::new()
    } else {
        format!(": it has {}", text.join(", "))
    }
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

    const OWN: &str = "target.mcp_tool_gating.gates[g-1].action.patterns";
    const POINT: &str = "transit.points[billing].mcp_tool_gating.gates[tg-1].action.patterns";

    fn gated_surface() -> Value {
        json!({
            "name": "Sales",
            "target": {"endpoint": "http://x", "mcp_tool_gating": {"default_effect": "allow", "gates": [
                {"id": "g-1", "name": "files", "action": {"effect": "deny", "patterns": ["fs_.*", "shell_.*"]}},
                {"id": "g-2", "name": "reads", "condition_policy_definition_id": "p-1",
                 "action": {"effect": "allow", "patterns": ["^get_"]}}
            ]}},
            "transit": {"points": [
                {"id": "tp-1", "alias": "billing", "mcp_tool_gating": {"gates": [
                    {"id": "tg-1", "action": {"effect": "deny", "patterns": ["pay_.*"]}}
                ]}},
                {"id": "tp-2", "alias": "github"}
            ]}
        })
    }

    fn pattern_patch(
        adds: &[&str],
        removes: &[&str],
    ) -> Result<Value> {
        build_patch(&[], &[], &strings(adds), &strings(removes), &gated_surface())
    }

    fn pattern_error(
        adds: &[&str],
        removes: &[&str],
    ) -> String {
        pattern_patch(adds, removes)
            .expect_err("the flags should be refused")
            .to_string()
    }

    #[test]
    fn a_pattern_is_added_to_one_surface_wide_gate_and_nothing_else_changes() {
        let patch = pattern_patch(&[&format!("{OWN}=db_.*")], &[]).expect("patch");

        assert_eq!(
            patch,
            json!({"target": {"mcp_tool_gating": {"gates": [
                {"id": "g-1", "name": "files", "action": {"effect": "deny", "patterns": ["fs_.*", "shell_.*", "db_.*"]}},
                {"id": "g-2", "name": "reads", "condition_policy_definition_id": "p-1",
                 "action": {"effect": "allow", "patterns": ["^get_"]}}
            ]}}})
        );
    }

    #[test]
    fn a_pattern_is_added_to_a_transit_point_gate_picked_by_alias_or_id() {
        let by_alias = pattern_patch(&[&format!("{POINT}=refund_.*")], &[]).expect("patch");
        let by_id = pattern_patch(&["transit.points[tp-1].mcp_tool_gating.gates[tg-1].action.patterns=refund_.*"], &[])
            .expect("patch");

        assert_eq!(by_alias, by_id);
        assert_eq!(
            by_alias,
            json!({"transit": {"points": [
                {"id": "tp-1", "alias": "billing", "mcp_tool_gating": {"gates": [
                    {"id": "tg-1", "action": {"effect": "deny", "patterns": ["pay_.*", "refund_.*"]}}
                ]}},
                {"id": "tp-2", "alias": "github"}
            ]}})
        );
    }

    #[test]
    fn a_pattern_is_removed_from_one_gate() {
        let patch = pattern_patch(&[], &[&format!("{OWN}=shell_.*")]).expect("patch");

        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"], json!(["fs_.*"]));
        assert_eq!(
            patch["target"]["mcp_tool_gating"]["gates"][1],
            gated_surface()["target"]["mcp_tool_gating"]["gates"][1]
        );
    }

    #[test]
    fn a_pattern_is_removed_from_a_transit_point_gate() {
        let patch = pattern_patch(&[&format!("{POINT}=x_.*")], &[&format!("{POINT}=pay_.*")]).expect("patch");

        assert_eq!(patch["transit"]["points"][0]["mcp_tool_gating"]["gates"][0]["action"]["patterns"], json!(["x_.*"]));
    }

    #[test]
    fn a_gate_is_picked_by_name_when_no_id_matches() {
        let patch = pattern_patch(&["target.mcp_tool_gating.gates[files].action.patterns=db_.*"], &[]).expect("patch");

        assert_eq!(
            patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"],
            json!(["fs_.*", "shell_.*", "db_.*"])
        );
    }

    #[test]
    fn a_missing_gate_lists_the_gates_that_exist() {
        assert_eq!(
            pattern_error(&["target.mcp_tool_gating.gates[g-9].action.patterns=db_.*"], &[]),
            "the surface has no tool gate 'g-9': the gates are g-1, g-2"
        );
        assert_eq!(
            pattern_error(&["transit.points[billing].mcp_tool_gating.gates[nope].action.patterns=a"], &[]),
            "transit point 'billing' has no tool gate 'nope': the gates are tg-1"
        );
        assert_eq!(
            pattern_error(&["transit.points[github].mcp_tool_gating.gates[g-1].action.patterns=a"], &[]),
            "transit point 'github' has no tool gate 'g-1': it has no tool gates yet"
        );
    }

    #[test]
    fn a_missing_transit_point_lists_the_points_that_exist() {
        assert_eq!(
            pattern_error(&["transit.points[nope].mcp_tool_gating.gates[g-1].action.patterns=a"], &[]),
            "this surface has no transit point 'nope': the transit points are billing, github"
        );
        let error = build_patch(
            &[],
            &[],
            &strings(&["transit.points[a].mcp_tool_gating.gates[g].action.patterns=a"]),
            &[],
            &json!({}),
        )
        .expect_err("no points")
        .to_string();
        assert_eq!(error, "this surface has no transit point 'a': it has no transit points yet");
    }

    #[test]
    fn a_pattern_already_in_the_gate_is_refused_not_duplicated() {
        assert_eq!(
            pattern_error(&[&format!("{OWN}=fs_.*")], &[]),
            "gate 'g-1' on the surface already has the pattern 'fs_.*'"
        );
        assert_eq!(
            pattern_error(&[&format!("{OWN}=  fs_.*  ")], &[]),
            "gate 'g-1' on the surface already has the pattern 'fs_.*'"
        );
    }

    #[test]
    fn a_pattern_missing_from_the_gate_is_refused_with_the_ones_it_has() {
        assert_eq!(
            pattern_error(&[], &[&format!("{OWN}=db_.*")]),
            "gate 'g-1' on the surface has no pattern 'db_.*': it has fs_.*, shell_.*"
        );
    }

    #[test]
    fn a_pattern_that_is_not_valid_is_refused_before_anything_is_built() {
        let error = pattern_error(&[&format!("{OWN}=fs_(")], &[]);

        assert!(error.contains("--add target.mcp_tool_gating.gates[g-1].action.patterns=fs_("), "{error}");
        let error = pattern_patch(&[&format!("{OWN}=fs_(")], &[]).expect_err("refused");
        assert!(format!("{error:#}").contains("is not valid regex"), "{error:#}");
        assert!(
            format!("{:#}", pattern_patch(&[&format!("{OWN}=   ")], &[]).expect_err("blank"))
                .contains("can't be blank")
        );
        let long = "a".repeat(513);
        assert!(
            format!("{:#}", pattern_patch(&[&format!("{OWN}={long}")], &[]).expect_err("long")).contains("513 bytes")
        );
    }

    #[test]
    fn the_pattern_length_limit_counts_the_trimmed_text_that_is_sent() {
        let at_limit = "a".repeat(512);

        let patch = pattern_patch(&[&format!("{OWN}={at_limit} ")], &[]).expect("512 bytes once trimmed");
        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"][2], json!(at_limit));
        let error = pattern_patch(&[&format!("{OWN}={at_limit}a")], &[]).expect_err("513 bytes");
        assert!(format!("{error:#}").contains("513 bytes"), "{error:#}");
    }

    #[test]
    fn a_pattern_with_regex_characters_equals_and_brackets_is_kept_as_written() {
        let patch = pattern_patch(&[&format!("{OWN}=^a=[b]\\.c$")], &[]).expect("patch");

        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"][2], json!("^a=[b]\\.c$"));
    }

    #[test]
    fn a_number_like_pattern_is_text() {
        let patch = pattern_patch(&[&format!("{OWN}=100")], &[]).expect("patch");

        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"][2], json!("100"));
    }

    #[test]
    fn removing_the_last_pattern_is_refused_unless_another_is_added() {
        let error = pattern_error(&[], &["transit.points[billing].mcp_tool_gating.gates[tg-1].action.patterns=pay_.*"]);
        assert!(
            error.starts_with("this would leave gate 'tg-1' on transit point 'billing' with no patterns"),
            "{error}"
        );

        let patch = pattern_patch(&[&format!("{POINT}=a_.*")], &[&format!("{POINT}=pay_.*")]).expect("replaced");
        assert_eq!(patch["transit"]["points"][0]["mcp_tool_gating"]["gates"][0]["action"]["patterns"], json!(["a_.*"]));
    }

    #[test]
    fn one_call_edits_several_gates_and_points() {
        let patch = pattern_patch(
            &[
                &format!("{OWN}=a_.*"),
                "target.mcp_tool_gating.gates[g-2].action.patterns=b_.*",
                &format!("{POINT}=c_.*"),
            ],
            &[],
        )
        .expect("patch");

        assert_eq!(
            patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"],
            json!(["fs_.*", "shell_.*", "a_.*"])
        );
        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][1]["action"]["patterns"], json!(["^get_", "b_.*"]));
        assert_eq!(
            patch["transit"]["points"][0]["mcp_tool_gating"]["gates"][0]["action"]["patterns"],
            json!(["pay_.*", "c_.*"])
        );
    }

    #[test]
    fn a_gate_with_too_many_patterns_is_refused() {
        let mut surface = gated_surface();
        surface["target"]["mcp_tool_gating"]["gates"][1]["action"]["patterns"] = json!(
            (0..64)
                .map(|n| format!("p{n}"))
                .collect::<Vec<_>>()
        );

        let error = build_patch(
            &[],
            &[],
            &strings(&["target.mcp_tool_gating.gates[g-2].action.patterns=one_more"]),
            &[],
            &surface,
        )
        .expect_err("65 patterns");

        assert!(format!("{error:#}").contains("65 patterns"), "{error:#}");
    }

    #[test]
    fn a_path_that_is_not_a_tool_pattern_path_is_refused() {
        for path in [
            "target.mcp_tool_gating.gates[g-1].name",
            "target.mcp_tool_gating.gates[g-1].action",
            "transit.points[billing].tags",
            "target.mcp_tool_gating.gates[g-1.action.patterns",
            "target.mcp_tool_gating.gates[].action.patterns",
            "target.mcp_tool_gating.gates[g-1]action.patterns",
            "target.mcp_tool_gating.gates[g-1].action.patterns[0]",
        ] {
            let error = pattern_error(&[&format!("{path}=x")], &[]);
            assert!(error.contains("gates[<gate id>].action.patterns"), "{path}: {error}");
        }
    }

    #[test]
    fn brackets_are_refused_by_set_and_unset() {
        assert!(
            error_of(&["target.mcp_tool_gating.gates[g-1].name=x"], &[])
                .contains("brackets only work with --add and --remove")
        );
        assert!(
            error_of(&[], &["target.mcp_tool_gating.gates[g-1]"])
                .contains("brackets only work with --add and --remove")
        );
    }

    #[test]
    fn the_same_pattern_given_twice_or_on_a_whole_list_path_too_is_refused() {
        assert!(pattern_error(&[&format!("{OWN}=a"), &format!("{OWN}= a")], &[]).contains("given more than once"));
        assert!(
            pattern_error(
                &[&format!("{OWN}=a"), "target.mcp_tool_gating.gates={\"id\":\"g-3\",\"action\":{\"effect\":\"deny\",\"patterns\":[\"x\"]}}"],
                &[]
            )
            .contains("given more than once")
        );
    }

    #[test]
    fn a_gate_id_holding_an_equals_sign_is_picked() {
        let mut surface = gated_surface();
        surface["target"]["mcp_tool_gating"]["gates"][0]["id"] = json!("a=b");

        let patch =
            build_patch(&[], &[], &strings(&["target.mcp_tool_gating.gates[a=b].action.patterns=z"]), &[], &surface)
                .expect("patch");

        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][0]["action"]["patterns"][2], json!("z"));
    }

    #[test]
    fn removing_the_only_real_pattern_is_refused_even_when_a_blank_one_is_left() {
        let mut surface = gated_surface();
        surface["target"]["mcp_tool_gating"]["gates"][1]["action"]["patterns"] = json!(["", "a_.*"]);

        let error =
            build_patch(&[], &[], &[], &strings(&["target.mcp_tool_gating.gates[g-2].action.patterns=a_.*"]), &surface)
                .expect_err("only a blank would be left")
                .to_string();

        assert!(error.starts_with("this would leave gate 'g-2' on the surface with no patterns"), "{error}");
    }

    #[test]
    fn a_swap_on_the_only_pattern_by_mixed_gate_names_works() {
        let mut surface = gated_surface();
        surface["target"]["mcp_tool_gating"]["gates"][1]["name"] = json!("reads");
        let patch = build_patch(
            &[],
            &[],
            &strings(&["target.mcp_tool_gating.gates[reads].action.patterns=^list_"]),
            &strings(&["target.mcp_tool_gating.gates[g-2].action.patterns=^get_"]),
            &surface,
        )
        .expect("patch");

        assert_eq!(patch["target"]["mcp_tool_gating"]["gates"][1]["action"]["patterns"], json!(["^list_"]));
    }

    #[test]
    fn a_swap_naming_the_transit_point_by_id_and_by_alias_is_one_edit() {
        let patch = pattern_patch(
            &["transit.points[billing].mcp_tool_gating.gates[tg-1].action.patterns=a_.*"],
            &["transit.points[tp-1].mcp_tool_gating.gates[tg-1].action.patterns=pay_.*"],
        )
        .expect("patch");

        assert_eq!(patch["transit"]["points"][0]["mcp_tool_gating"]["gates"][0]["action"]["patterns"], json!(["a_.*"]));
    }

    #[test]
    fn names_and_patterns_from_the_surface_are_cleaned_in_errors() {
        let mut surface = gated_surface();
        surface["target"]["mcp_tool_gating"]["gates"][0]["name"] = json!("fi\u{1b}[2Jles");
        surface["target"]["mcp_tool_gating"]["gates"][0]
            .as_object_mut()
            .expect("a gate")
            .remove("id");
        surface["target"]["mcp_tool_gating"]["gates"][1]["action"]["patterns"] = json!(["\u{1b}]0;pwned\u{7}^get_"]);
        surface["transit"]["points"][0]["alias"] = json!("bil\u{1b}[2Jling");
        let error_of = |flag: &str, path: &str| {
            let (adds, removes) = if flag == "--add" {
                (vec![path], vec![])
            } else {
                (vec![], vec![path])
            };
            build_patch(&[], &[], &strings(&adds), &strings(&removes), &surface)
                .expect_err("refused")
                .to_string()
        };

        let gates = error_of("--add", "target.mcp_tool_gating.gates[nope].action.patterns=a");
        assert!(gates.contains("the gates are fi[2Jles, g-2"), "{gates}");
        assert!(!gates.contains('\u{1b}'), "{gates}");
        let held = error_of("--remove", "target.mcp_tool_gating.gates[g-2].action.patterns=nope");
        assert!(held.contains("it has ]0;pwned^get_"), "{held}");
        assert!(!held.contains('\u{1b}') && !held.contains('\u{7}'), "{held}");
        let points = error_of("--add", "transit.points[nope].mcp_tool_gating.gates[tg-1].action.patterns=a");
        assert!(points.contains("the transit points are bil[2Jling"), "{points}");
        assert!(!points.contains('\u{1b}'), "{points}");
    }

    #[test]
    fn the_same_pattern_added_or_removed_twice_under_two_names_of_one_gate_is_refused() {
        let twice_add = pattern_error(
            &[
                "target.mcp_tool_gating.gates[g-1].action.patterns=a",
                "target.mcp_tool_gating.gates[files].action.patterns= a",
            ],
            &[],
        );
        assert_eq!(twice_add, "--add 'a' is given more than once for gate 'g-1' on the surface");
        let twice_remove = pattern_error(
            &[],
            &[
                "target.mcp_tool_gating.gates[g-1].action.patterns=fs_.*",
                "target.mcp_tool_gating.gates[files].action.patterns=fs_.*",
            ],
        );
        assert_eq!(twice_remove, "--remove 'fs_.*' is given more than once for gate 'g-1' on the surface");
    }

    #[test]
    fn the_same_pattern_added_twice_under_a_transit_point_id_and_alias_is_refused() {
        let error = pattern_error(
            &[
                "transit.points[tp-1].mcp_tool_gating.gates[tg-1].action.patterns=a",
                "transit.points[billing].mcp_tool_gating.gates[tg-1].action.patterns=a",
            ],
            &[],
        );

        assert!(error.contains("is given more than once for gate 'tg-1' on transit point"), "{error}");
    }
}
