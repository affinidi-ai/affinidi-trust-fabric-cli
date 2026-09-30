//! Works out whether a surface's MCP tool gates would allow or block a tool,
//! on this machine, so a gate can be checked before it is saved.
//!
//! The gateway's firewall, which [`decide`] follows: a gate is active when its
//! condition is met, a gate with no condition is always active, and a tool is
//! allowed when no active deny gate matches it and either an active allow gate
//! matches it or `default_effect` is allow. Deny always beats allow, so an
//! allow gate cannot win a tool back from a deny gate that also matches it.
//!
//! A gate's condition is an OPA policy the gateway evaluates per request for
//! the caller, which this machine cannot do. Gates that name the same policy
//! share one answer, so the unit of a condition is the policy id. [`decide`] is
//! told which policies the caller meets, and [`preview`] works through every
//! combination of the policies that were not pinned by the user.
//!
//! What this cannot check is left to the gateway: whether a condition policy
//! exists, and what it decides for a real caller.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

/// Most gates the gateway saves in one surface.
const GATES_MAX: usize = 64;
/// Most patterns the gateway saves in one gate, blank ones not counted.
const PATTERNS_MAX: usize = 64;
/// Longest pattern, in bytes, the gateway saves.
const PATTERN_BYTES_MAX: usize = 512;
/// Most unpinned condition policies [`preview`] works through, since each one
/// doubles the number of cases.
const UNPINNED_POLICIES_MAX: usize = 3;

/// Whether a tool ends up allowed or blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked,
}

/// Which condition policies the caller meets, by policy id: `true` for met. A
/// policy that is not listed counts as not met.
pub type Conditions = BTreeMap<String, bool>;

/// How a gate's condition is settled.
enum Condition<'a> {
    /// No condition, so the gate always applies.
    Always,
    /// A condition policy the caller either meets or does not, looked up by
    /// its id exactly as written.
    Policy(&'a str),
    /// A blank policy id. The gateway finds no policy for it, so it fails
    /// closed: a deny gate stays on and an allow gate is off.
    Unresolved,
}

/// A gate's patterns, compiled once when the gate is read.
#[derive(Debug, Clone)]
struct Patterns {
    /// Each pattern that compiled, trimmed as the gateway trims it, with its
    /// regex.
    matching: Vec<(String, Regex)>,
    /// Trimmed patterns that are not valid regex.
    not_valid: Vec<String>,
    /// Trimmed patterns that are valid but too large to compile.
    too_large: Vec<String>,
}

impl Patterns {
    /// Compile `patterns`. A blank pattern is ignored, as the gateway ignores
    /// it, and so is one over the length the gateway saves, which the gateway
    /// does not compile either.
    fn compile(patterns: &[String]) -> Self {
        let mut compiled = Self {
            matching: Vec::new(),
            not_valid: Vec::new(),
            too_large: Vec::new(),
        };
        for raw in patterns {
            let pattern = raw.trim();
            if pattern.is_empty() || raw.len() > PATTERN_BYTES_MAX {
                continue;
            }
            match Regex::new(pattern) {
                Ok(regex) => compiled
                    .matching
                    .push((pattern.to_owned(), regex)),
                Err(regex::Error::CompiledTooBig(_)) => compiled
                    .too_large
                    .push(pattern.to_owned()),
                Err(_) => compiled
                    .not_valid
                    .push(pattern.to_owned()),
            }
        }
        compiled
    }
}

/// One gate read from a surface, in the order the surface lists it.
#[derive(Debug, Clone)]
pub struct Gate {
    /// The name the surface builder shows for the gate: its own name where it
    /// has one, otherwise `Tool Gate N` for its 1-based position in the list.
    name: String,
    /// `true` where the gate denies, `false` where it allows.
    denies: bool,
    /// The gate's regex patterns as written, matched against a tool name.
    patterns: Vec<String>,
    /// The id of the condition policy that decides whether the gate applies,
    /// or `None` where the gate always applies.
    condition: Option<String>,
    compiled: Patterns,
}

impl PartialEq for Gate {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        self.name == other.name
            && self.denies == other.denies
            && self.patterns == other.patterns
            && self.condition == other.condition
    }
}

impl Gate {
    pub fn new(
        name: String,
        denies: bool,
        patterns: Vec<String>,
        condition: Option<String>,
    ) -> Self {
        let compiled = Patterns::compile(&patterns);
        Self {
            name,
            denies,
            patterns,
            condition,
            compiled,
        }
    }

    fn condition(&self) -> Condition<'_> {
        match self.condition.as_deref() {
            None => Condition::Always,
            Some(id) if id.trim().is_empty() => Condition::Unresolved,
            Some(id) => Condition::Policy(id),
        }
    }

    /// Whether the gate blocks whatever it matches for every caller, because
    /// it is a deny gate with no condition or one that never resolves.
    fn always_blocks(&self) -> bool {
        self.denies && !matches!(self.condition(), Condition::Policy(_))
    }

    /// Whether any of the gate's patterns matches `tool`, the way the gateway
    /// matches it. A gate with no pattern matches no tool, and neither does a
    /// pattern that does not compile, since the gateway refuses to save one.
    fn matches(
        &self,
        tool: &str,
    ) -> bool {
        self.compiled
            .matching
            .iter()
            .any(|(_, regex)| regex.is_match(tool))
    }

    /// Whether the gate applies to a caller who meets `conditions`.
    fn active(
        &self,
        conditions: &Conditions,
    ) -> bool {
        match self.condition() {
            Condition::Always => true,
            Condition::Policy(id) => conditions
                .get(id)
                .copied()
                .unwrap_or(false),
            Condition::Unresolved => self.denies,
        }
    }
}

/// A surface's tool gating: the baseline for a tool no gate matches, plus the
/// gates themselves.
#[derive(Debug, Clone, PartialEq)]
pub struct Gating {
    /// `true` where a tool matching no active gate is blocked.
    pub denies_by_default: bool,
    pub gates: Vec<Gate>,
}

impl Gating {
    /// The distinct condition policy ids the gates name, in order.
    pub fn policy_ids(&self) -> Vec<String> {
        self.gates
            .iter()
            .filter_map(|gate| match gate.condition() {
                Condition::Policy(id) => Some(id.to_owned()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// The outcome for one tool, and what decided it.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub verdict: Verdict,
    /// The name of the gate that decided, or `None` where nothing matched and
    /// the default decided.
    pub decided_by: Option<String>,
}

/// Whether `tool` is allowed, and which gate decided.
///
/// The deciding gate is the first active deny gate that matches, otherwise the
/// first active allow gate that matches, otherwise nothing and the default
/// decides. The gateway's own decision does not depend on the order gates are
/// listed in, so a different matching gate of the same effect would give the
/// same verdict.
pub fn decide(
    gating: &Gating,
    tool: &str,
    conditions: &Conditions,
) -> Decision {
    let mut allowed_by = None;
    for gate in &gating.gates {
        if !gate.active(conditions) || !gate.matches(tool) {
            continue;
        }
        if gate.denies {
            return Decision {
                verdict: Verdict::Blocked,
                decided_by: Some(gate.name.clone()),
            };
        }
        allowed_by.get_or_insert_with(|| gate.name.clone());
    }
    if let Some(name) = allowed_by {
        return Decision {
            verdict: Verdict::Allowed,
            decided_by: Some(name),
        };
    }
    let verdict = if gating.denies_by_default {
        Verdict::Blocked
    } else {
        Verdict::Allowed
    };
    Decision { verdict, decided_by: None }
}

/// The outcome for a tool when the caller meets `conditions`, which lists only
/// the policies the outcome was worked out for.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub conditions: Conditions,
    pub decision: Decision,
}

/// What a tool comes to. One outcome with no conditions where every case
/// gives the same decision, otherwise one outcome per case.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPreview {
    pub tool: String,
    pub outcomes: Vec<Outcome>,
}

impl ToolPreview {
    /// Whether the outcome depends on which conditions the caller meets.
    pub fn depends_on_conditions(&self) -> bool {
        self.outcomes.len() > 1
    }
}

/// The outcome for each tool, with what the user pinned and each tool's cases.
#[derive(Debug, Clone, PartialEq)]
pub struct Preview {
    /// The conditions the user stated, applied to every tool.
    pub assumed: Conditions,
    pub tools: Vec<ToolPreview>,
}

/// Read `POLICY_ID=met` or `POLICY_ID=unmet` for each entry of `pins`. A
/// malformed entry, or a policy given twice, is refused.
pub fn parse_pins(pins: &[String]) -> Result<Conditions> {
    let mut assumed = Conditions::new();
    for pin in pins {
        let (policy, state) = match pin.rsplit_once('=') {
            Some((policy, state)) if !policy.is_empty() => (policy, state.trim()),
            _ => bail!("--condition '{pin}' should be POLICY_ID=met or POLICY_ID=unmet"),
        };
        let met = match state {
            "met" => true,
            "unmet" => false,
            _ => bail!("--condition '{pin}' should end in =met or =unmet"),
        };
        if assumed
            .insert(policy.to_owned(), met)
            .is_some()
        {
            bail!("--condition names '{policy}' more than once");
        }
    }
    Ok(assumed)
}

/// The outcome for each of `tools`, in the order given, for a caller who meets
/// the conditions in `pinned` and, for every other condition policy the gates
/// name, each way of meeting it or not. A policy no gate names, or more than
/// three left unpinned, is refused.
pub fn preview(
    gating: &Gating,
    tools: &[String],
    pinned: &Conditions,
) -> Result<Preview> {
    let policies = gating.policy_ids();
    if let Some(unknown) = pinned
        .keys()
        .find(|policy| !policies.contains(policy))
    {
        if policies.is_empty() {
            bail!("--condition names '{unknown}', but none of the gates has a condition");
        }
        bail!("--condition names '{unknown}', but no gate uses it; the gates use: {}", quoted(&policies));
    }
    let free: Vec<&String> = policies
        .iter()
        .filter(|policy| !pinned.contains_key(*policy))
        .collect();
    if free.len() > UNPINNED_POLICIES_MAX {
        bail!(
            "{} condition policies are not pinned ({}), which is {} cases to compare per tool; pin some with \
             --condition POLICY_ID=met or POLICY_ID=unmet so that {} or fewer are left",
            free.len(),
            free.iter()
                .map(|policy| policy.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            1usize << free.len(),
            UNPINNED_POLICIES_MAX
        );
    }
    let cases: Vec<Conditions> = (0..1usize << free.len())
        .map(|case| {
            free.iter()
                .enumerate()
                .map(|(index, policy)| {
                    let unmet = case >> (free.len() - 1 - index) & 1 == 1;
                    ((*policy).clone(), !unmet)
                })
                .collect()
        })
        .collect();
    let tools = tools
        .iter()
        .map(|tool| {
            let outcomes: Vec<Outcome> = cases
                .iter()
                .map(|case| {
                    let mut conditions = pinned.clone();
                    conditions.extend(case.clone());
                    Outcome {
                        conditions: case.clone(),
                        decision: decide(gating, tool, &conditions),
                    }
                })
                .collect();
            let same = outcomes
                .iter()
                .all(|outcome| outcome.decision == outcomes[0].decision);
            let outcomes = if same {
                vec![Outcome {
                    conditions: Conditions::new(),
                    decision: outcomes[0].decision.clone(),
                }]
            } else {
                outcomes
            };
            ToolPreview { tool: tool.clone(), outcomes }
        })
        .collect();
    Ok(Preview { assumed: pinned.clone(), tools })
}

/// Plain-words notes on gates that will not do what they look like they do,
/// for the gates and the `tools` being previewed. A pattern that does not
/// compile is reported here and matches nothing.
pub fn warnings(
    gating: &Gating,
    tools: &[String],
) -> Vec<String> {
    let mut found = Vec::new();
    if gating.gates.len() > GATES_MAX {
        found.push(format!(
            "This surface has {} gates, and the gateway will refuse to save more than {GATES_MAX}.",
            gating.gates.len()
        ));
    }
    for gate in &gating.gates {
        let name = &gate.name;
        match gate.condition() {
            Condition::Unresolved => found.push(format!(
                "'{name}' has an empty condition policy id, so the gateway can never meet it: a block gate stays on \
                 and an allow gate is off."
            )),
            Condition::Policy(id) if id.trim() != id => found.push(format!(
                "'{name}' has spaces at the start or end of its condition policy id; the gateway looks it up exactly \
                 as written."
            )),
            _ => {}
        }
        let effective = gate
            .patterns
            .iter()
            .filter(|pattern| !pattern.trim().is_empty());
        if effective.clone().count() > PATTERNS_MAX {
            found.push(format!(
                "'{name}' has {} patterns, and the gateway will refuse to save more than {PATTERNS_MAX} in one gate.",
                effective.clone().count()
            ));
        }
        for pattern in effective
            .clone()
            .filter(|pattern| pattern.len() > PATTERN_BYTES_MAX)
        {
            found.push(format!(
                "'{name}' has a pattern of {} bytes, and the gateway will refuse to save one longer than \
                 {PATTERN_BYTES_MAX} bytes. It matches no tool here.",
                pattern.len()
            ));
        }
        for pattern in &gate.compiled.not_valid {
            found.push(format!(
                "'{name}' has a pattern that is not valid regex ({pattern}). It matches no tool, and the gateway will \
                 refuse to save it."
            ));
        }
        for pattern in &gate.compiled.too_large {
            found.push(format!(
                "'{name}' has a pattern that is too large to compile ({pattern}), so the gateway will most likely \
                 refuse to save it. It matches no tool here."
            ));
        }
        if effective.count() == 0 {
            found.push(format!(
                "'{name}' has no patterns, so it matches no tool, and the gateway will refuse to save it."
            ));
        }
        if gate
            .compiled
            .matching
            .is_empty()
        {
            continue;
        }
        let matched: Vec<&String> = tools
            .iter()
            .filter(|tool| gate.matches(tool))
            .collect();
        if !gate.denies && !gating.denies_by_default {
            found.push(format!(
                "'{name}' allows tools, but the default already allows every tool, so it changes nothing."
            ));
        } else if !gate.denies && !matched.is_empty() {
            let blockers: Vec<&str> = gating
                .gates
                .iter()
                .filter(|other| other.always_blocks())
                .filter(|other| {
                    matched
                        .iter()
                        .any(|tool| other.matches(tool))
                })
                .map(|other| other.name.as_str())
                .collect();
            let all_blocked = matched.iter().all(|tool| {
                gating
                    .gates
                    .iter()
                    .any(|other| other.always_blocks() && other.matches(tool))
            });
            if all_blocked {
                found.push(format!(
                    "'{name}' lets none of these tools through: {} {} also blocked by {} with no condition, and a \
                     block always wins.",
                    quoted(&matched),
                    if matched.len() == 1 {
                        "is"
                    } else {
                        "are"
                    },
                    quoted(&blockers)
                ));
            }
        }
        if matched.is_empty() {
            found.push(format!("'{name}' matches none of the tools you gave."));
        }
        for (pattern, regex) in &gate.compiled.matching {
            if ends_anchored(pattern) {
                continue;
            }
            let inside: Vec<&String> = tools
                .iter()
                .filter(|tool| {
                    regex
                        .find(tool)
                        .is_some_and(|hit| hit.start() > 0)
                })
                .collect();
            if !inside.is_empty() {
                let anchor = if pattern.contains('|') {
                    format!(
                        "^(?:{})",
                        pattern
                            .strip_prefix('^')
                            .unwrap_or(pattern)
                    )
                } else {
                    "^".to_owned()
                };
                found.push(format!(
                    "'{name}' pattern {pattern} matches anywhere in the name, so it also catches {}. Add {anchor} if \
                     you only want names that start with it.",
                    quoted(&inside)
                ));
            }
        }
    }
    found
}

/// Whether `pattern` ends with `$` or `\z`, not escaped, optionally followed by
/// closing groups, so a match that starts inside a tool name is what the
/// pattern asks for.
fn ends_anchored(pattern: &str) -> bool {
    let backslashes = |text: &str| {
        text.chars()
            .rev()
            .take_while(|character| *character == '\\')
            .count()
    };
    let mut end = pattern;
    while let Some(rest) = end.strip_suffix(')') {
        if backslashes(rest) % 2 != 0 {
            break;
        }
        end = rest;
    }
    if let Some(rest) = end.strip_suffix('$') {
        return backslashes(rest) % 2 == 0;
    }
    end.strip_suffix('z')
        .is_some_and(|rest| backslashes(rest) % 2 == 1)
}

/// The names as `'a', 'b'`, dropping repeats.
fn quoted<T: AsRef<str>>(names: &[T]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for name in names {
        if !seen.contains(&name.as_ref()) {
            seen.push(name.as_ref());
        }
    }
    seen.iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read the tool gating at `path` in `surface`, as a dot path such as
/// `target.mcp_tool_gating`.
///
/// Gating that is absent reads as no gates and an allow default, which is what
/// the gateway does with a surface that has none.
pub fn read_gating(
    surface: &Value,
    path: &str,
) -> Result<Gating> {
    match path
        .split('.')
        .try_fold(surface, |value, key| value.get(key))
    {
        Some(config) => read_gating_config(config, path),
        None => read_gating_config(&Value::Null, path),
    }
}

/// Read a tool gating object, `{"default_effect": ..., "gates": [...]}`, that
/// was found at `path`, which names it in errors. A gate is named the way the
/// surface builder shows it: its own name where it has one, otherwise
/// `Tool Gate N` for its 1-based position.
pub fn read_gating_config(
    config: &Value,
    path: &str,
) -> Result<Gating> {
    if config.is_null() {
        return Ok(Gating {
            denies_by_default: false,
            gates: Vec::new(),
        });
    }
    if !config.is_object() {
        bail!("{path} should be an object, found {config}");
    }
    let denies_by_default = match config.get("default_effect") {
        None | Some(Value::Null) => false,
        Some(Value::String(effect)) => effect_denies(effect, &format!("{path}.default_effect"))?,
        Some(other) => bail!("{path}.default_effect should be 'allow' or 'deny', found {other}"),
    };
    let gates = match config.get("gates") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(gates)) => gates
            .iter()
            .enumerate()
            .map(|(index, gate)| read_gate(gate, path, index))
            .collect::<Result<Vec<_>>>()?,
        Some(other) => bail!("{path}.gates should be a list, found {other}"),
    };
    Ok(Gating { denies_by_default, gates })
}

/// Read one gate from the list at `path`.
fn read_gate(
    gate: &Value,
    path: &str,
    index: usize,
) -> Result<Gate> {
    let at = format!("{path}.gates.{index}");
    let name = match gate.get("name") {
        Some(Value::String(name)) if !name.trim().is_empty() => name.trim().to_owned(),
        _ => format!("Tool Gate {}", index + 1),
    };
    let action = gate
        .get("action")
        .with_context(|| format!("{at} has no action"))?;
    let effect = match action.get("effect") {
        Some(Value::String(effect)) => effect,
        _ => bail!("{at}.action.effect should be 'allow' or 'deny'"),
    };
    let patterns = match action.get("patterns") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(patterns)) => patterns
            .iter()
            .map(|pattern| match pattern {
                Value::String(pattern) => Ok(pattern.clone()),
                other => bail!("{at}.action.patterns should hold text, found {other}"),
            })
            .collect::<Result<Vec<_>>>()?,
        Some(other) => bail!("{at}.action.patterns should be a list, found {other}"),
    };
    let condition = match gate.get("condition_policy_definition_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(policy)) => Some(policy.clone()),
        Some(other) => bail!("{at}.condition_policy_definition_id should be text, found {other}"),
    };
    Ok(Gate::new(name, effect_denies(effect, &format!("{at}.action.effect"))?, patterns, condition))
}

/// Read an `allow` or `deny` effect, refusing anything else with the field it
/// came from.
fn effect_denies(
    effect: &str,
    at: &str,
) -> Result<bool> {
    match effect {
        "allow" => Ok(false),
        "deny" => Ok(true),
        other => bail!("{at} should be 'allow' or 'deny', found '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate(
        name: &str,
        denies: bool,
        patterns: &[&str],
    ) -> Gate {
        Gate::new(
            name.to_owned(),
            denies,
            patterns
                .iter()
                .map(|p| (*p).to_owned())
                .collect(),
            None,
        )
    }

    /// A gate whose condition policy id is `policy`, kept exactly as given.
    fn with_policy(
        name: &str,
        denies: bool,
        patterns: &[&str],
        policy: &str,
    ) -> Gate {
        Gate {
            condition: Some(policy.to_owned()),
            ..gate(name, denies, patterns)
        }
    }

    fn conditional(
        name: &str,
        denies: bool,
        patterns: &[&str],
    ) -> Gate {
        with_policy(name, denies, patterns, name)
    }

    fn verdict(
        gating: &Gating,
        tool: &str,
    ) -> Verdict {
        decide_all(gating, tool, true).verdict
    }

    #[test]
    fn a_tool_no_gate_matches_falls_back_to_the_default() {
        let allow_by_default = Gating {
            denies_by_default: false,
            gates: vec![gate("g1", true, &["^delete_"])],
        };
        let deny_by_default = Gating {
            denies_by_default: true,
            gates: vec![gate("g1", true, &["^delete_"])],
        };

        assert_eq!(verdict(&allow_by_default, "get_user"), Verdict::Allowed);
        assert_eq!(verdict(&deny_by_default, "get_user"), Verdict::Blocked);
    }

    #[test]
    fn the_default_is_reported_as_deciding_when_no_gate_matches() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("g1", true, &["^delete_"])],
        };

        assert_eq!(
            decide_all(&gating, "get_user", true),
            Decision {
                verdict: Verdict::Allowed,
                decided_by: None
            }
        );
    }

    #[test]
    fn a_deny_gate_blocks_a_tool_it_matches() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("no-delete", true, &["^delete_"])],
        };

        assert_eq!(
            decide_all(&gating, "delete_user", true),
            Decision {
                verdict: Verdict::Blocked,
                decided_by: Some("no-delete".to_owned())
            }
        );
    }

    #[test]
    fn an_allow_gate_is_the_only_way_through_a_deny_default() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![gate("reads", false, &["^get_"])],
        };

        assert_eq!(verdict(&gating, "get_user"), Verdict::Allowed);
        assert_eq!(verdict(&gating, "delete_user"), Verdict::Blocked);
    }

    #[test]
    fn an_allow_gate_does_not_block_a_tool_it_misses_under_an_allow_default() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("reads", false, &["^get_"])],
        };

        assert_eq!(verdict(&gating, "delete_user"), Verdict::Allowed);
    }

    #[test]
    fn a_deny_gate_beats_an_allow_gate_matching_the_same_tool() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("admins", false, &["^delete_"]), gate("no-delete", true, &["^delete_"])],
        };

        assert_eq!(
            decide_all(&gating, "delete_user", true),
            Decision {
                verdict: Verdict::Blocked,
                decided_by: Some("no-delete".to_owned())
            }
        );
    }

    #[test]
    fn a_deny_gate_wins_wherever_it_is_listed() {
        let deny_last = Gating {
            denies_by_default: false,
            gates: vec![gate("admins", false, &["^delete_"]), gate("no-delete", true, &["^delete_"])],
        };
        let deny_first = Gating {
            denies_by_default: false,
            gates: vec![gate("no-delete", true, &["^delete_"]), gate("admins", false, &["^delete_"])],
        };

        assert_eq!(verdict(&deny_last, "delete_user"), Verdict::Blocked);
        assert_eq!(verdict(&deny_first, "delete_user"), Verdict::Blocked);
    }

    #[test]
    fn a_tool_survives_a_deny_default_when_any_allow_gate_matches_it() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![gate("reads", false, &["^read_"]), gate("writes", false, &["^write_"])],
        };

        assert_eq!(verdict(&gating, "read_file"), Verdict::Allowed);
        assert_eq!(verdict(&gating, "write_file"), Verdict::Allowed);
        assert_eq!(verdict(&gating, "delete_file"), Verdict::Blocked);
    }

    #[test]
    fn a_deny_default_still_blocks_when_its_only_allow_gate_is_inactive() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![conditional("reads", false, &["_file$"])],
        };

        assert_eq!(verdict_with(&gating, "read_file", false), Verdict::Blocked);
    }

    #[test]
    fn a_conditional_gate_applies_only_when_its_condition_is_assumed_met() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![conditional("non-admins", true, &["^delete_"])],
        };

        assert_eq!(
            decide_all(&gating, "delete_user", true),
            Decision {
                verdict: Verdict::Blocked,
                decided_by: Some("non-admins".to_owned())
            }
        );
        assert_eq!(
            decide_all(&gating, "delete_user", false),
            Decision {
                verdict: Verdict::Allowed,
                decided_by: None
            }
        );
    }

    /// The decision for a caller who meets every condition policy, or none.
    fn decide_all(
        gating: &Gating,
        tool: &str,
        met: bool,
    ) -> Decision {
        let conditions = gating
            .policy_ids()
            .into_iter()
            .map(|policy| (policy, met))
            .collect();
        decide(gating, tool, &conditions)
    }

    fn verdict_with(
        gating: &Gating,
        tool: &str,
        met: bool,
    ) -> Verdict {
        decide_all(gating, tool, met).verdict
    }

    fn pins(entries: &[(&str, bool)]) -> Conditions {
        entries
            .iter()
            .map(|(policy, met)| ((*policy).to_owned(), *met))
            .collect()
    }

    /// Default deny, an allow gate for admins and a deny gate for contractors,
    /// both matching `delete_user`.
    fn admins_and_contractors() -> Gating {
        Gating {
            denies_by_default: true,
            gates: vec![conditional("admins", false, &["^delete_"]), conditional("contractors", true, &["^delete_"])],
        }
    }

    #[test]
    fn a_gate_with_no_pattern_matches_no_tool() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("empty", true, &[])],
        };

        assert_eq!(verdict(&gating, "delete_user"), Verdict::Allowed);
    }

    #[test]
    fn a_delete_gate_for_non_admins_blocks_deletes_for_non_admins_only() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![conditional("non-admins", true, &["^delete_"])],
        };

        assert_eq!(verdict_with(&gating, "delete_user", true), Verdict::Blocked);
        assert_eq!(verdict_with(&gating, "delete_user", false), Verdict::Allowed);
        assert_eq!(verdict_with(&gating, "get_user", true), Verdict::Allowed);
    }

    #[test]
    fn a_pattern_that_is_not_valid_matches_nothing() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("broken", true, &["^delete_(", "^drop_"])],
        };

        assert_eq!(verdict(&gating, "delete_user"), Verdict::Allowed);
        assert_eq!(verdict(&gating, "drop_table"), Verdict::Blocked);
    }

    #[test]
    fn read_gating_reads_a_surface_the_gateway_would_serialize() {
        let surface = json!({
            "target": {
                "mcp_tool_gating": {
                    "default_effect": "deny",
                    "gates": [{
                        "name": "no-delete",
                        "condition_policy_definition_id": "non-admins",
                        "action": {"effect": "deny", "patterns": ["^delete_"]}
                    }]
                }
            }
        });

        assert_eq!(
            read_gating(&surface, "target.mcp_tool_gating").expect("the surface is readable"),
            Gating {
                denies_by_default: true,
                gates: vec![Gate::new(
                    "no-delete".to_owned(),
                    true,
                    vec!["^delete_".to_owned()],
                    Some("non-admins".to_owned())
                )],
            }
        );
    }

    #[test]
    fn read_gating_treats_absent_gating_as_no_gates_and_an_allow_default() {
        let empty = Gating {
            denies_by_default: false,
            gates: Vec::new(),
        };

        assert_eq!(read_gating(&json!({}), "target.mcp_tool_gating").expect("absent is allowed"), empty);
        assert_eq!(
            read_gating(&json!({"target": {"mcp_tool_gating": null}}), "target.mcp_tool_gating")
                .expect("null is allowed"),
            empty
        );
    }

    #[test]
    fn read_gating_defaults_to_allow_when_the_surface_leaves_the_default_out() {
        let surface = json!({"target": {"mcp_tool_gating": {"gates": []}}});

        assert!(
            !read_gating(&surface, "target.mcp_tool_gating")
                .expect("the surface is readable")
                .denies_by_default
        );
    }

    #[test]
    fn read_gating_names_a_gate_with_no_name_by_its_position_from_one() {
        let surface = json!({
            "target": {"mcp_tool_gating": {"gates": [
                {"id": "abc", "action": {"effect": "deny", "patterns": ["^delete_"]}},
                {"name": "  ", "action": {"effect": "deny", "patterns": ["^drop_"]}},
                {"name": "  Reads  ", "action": {"effect": "allow", "patterns": ["^get_"]}}
            ]}}
        });

        let gating = read_gating(&surface, "target.mcp_tool_gating").expect("the surface is readable");
        let names: Vec<&str> = gating
            .gates
            .iter()
            .map(|gate| gate.name.as_str())
            .collect();

        assert_eq!(names, ["Tool Gate 1", "Tool Gate 2", "Reads"]);
    }

    #[test]
    fn read_gating_config_refuses_gating_that_is_not_an_object() {
        let error = read_gating_config(&json!(["deny"]), "mcp_tool_gating")
            .expect_err("gating is an object")
            .to_string();

        assert_eq!(error, r#"mcp_tool_gating should be an object, found ["deny"]"#);
    }

    #[test]
    fn read_gating_config_refuses_a_default_that_is_not_text() {
        let error = read_gating_config(&json!({"default_effect": 1}), "mcp_tool_gating")
            .expect_err("the default is text")
            .to_string();

        assert_eq!(error, "mcp_tool_gating.default_effect should be 'allow' or 'deny', found 1");
    }

    #[test]
    fn read_gating_config_refuses_gates_that_are_not_a_list() {
        let error = read_gating_config(&json!({"gates": {}}), "mcp_tool_gating")
            .expect_err("gates are a list")
            .to_string();

        assert_eq!(error, "mcp_tool_gating.gates should be a list, found {}");
    }

    #[test]
    fn read_gating_config_refuses_a_gate_with_no_action() {
        let error = read_gating_config(&json!({"gates": [{"name": "g"}]}), "mcp_tool_gating")
            .expect_err("a gate has an action")
            .to_string();

        assert_eq!(error, "mcp_tool_gating.gates.0 has no action");
    }

    #[test]
    fn read_gating_config_refuses_patterns_that_are_not_text() {
        let list = read_gating_config(
            &json!({"gates": [{"action": {"effect": "deny", "patterns": "^a"}}]}),
            "mcp_tool_gating",
        )
        .expect_err("patterns are a list")
        .to_string();
        let item =
            read_gating_config(&json!({"gates": [{"action": {"effect": "deny", "patterns": [1]}}]}), "mcp_tool_gating")
                .expect_err("patterns hold text")
                .to_string();

        assert_eq!(list, r#"mcp_tool_gating.gates.0.action.patterns should be a list, found "^a""#);
        assert_eq!(item, "mcp_tool_gating.gates.0.action.patterns should hold text, found 1");
    }

    #[test]
    fn read_gating_refuses_an_effect_it_does_not_know() {
        let surface = json!({
            "target": {"mcp_tool_gating": {"gates": [{"id": "g1", "action": {"effect": "block"}}]}}
        });

        let error = read_gating(&surface, "target.mcp_tool_gating")
            .expect_err("only allow and deny are effects")
            .to_string();

        assert_eq!(error, "target.mcp_tool_gating.gates.0.action.effect should be 'allow' or 'deny', found 'block'");
    }

    #[test]
    fn an_allow_gate_added_for_admins_does_not_win_the_tool_back() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![conditional("non-admins", true, &["^delete_"]), conditional("admins", false, &["^delete_"])],
        };

        assert_eq!(verdict_with(&gating, "delete_user", true), Verdict::Blocked);
    }

    fn tools(names: &[&str]) -> Vec<String> {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    }

    #[test]
    fn an_admin_who_is_not_a_contractor_is_allowed() {
        let gating = admins_and_contractors();

        let decision = decide(&gating, "delete_user", &pins(&[("admins", true), ("contractors", false)]));

        assert_eq!(
            decision,
            Decision {
                verdict: Verdict::Allowed,
                decided_by: Some("admins".to_owned())
            }
        );
        assert_eq!(verdict_with(&gating, "delete_user", true), Verdict::Blocked);
        assert_eq!(verdict_with(&gating, "delete_user", false), Verdict::Blocked);
    }

    #[test]
    fn preview_works_through_every_combination_of_unpinned_policies_in_order() {
        let previewed = preview(&admins_and_contractors(), &tools(&["delete_user"]), &Conditions::new())
            .expect("two policies are enumerable");

        let cases: Vec<(Conditions, Verdict)> = previewed.tools[0]
            .outcomes
            .iter()
            .map(|outcome| (outcome.conditions.clone(), outcome.decision.verdict))
            .collect();

        assert_eq!(
            cases,
            [
                (pins(&[("admins", true), ("contractors", true)]), Verdict::Blocked),
                (pins(&[("admins", true), ("contractors", false)]), Verdict::Allowed),
                (pins(&[("admins", false), ("contractors", true)]), Verdict::Blocked),
                (pins(&[("admins", false), ("contractors", false)]), Verdict::Blocked),
            ]
        );
        assert!(previewed.assumed.is_empty());
    }

    #[test]
    fn a_pinned_policy_is_applied_to_every_case_and_left_out_of_the_cases() {
        let previewed = preview(&admins_and_contractors(), &tools(&["delete_user"]), &pins(&[("admins", true)]))
            .expect("one policy is left");

        let outcomes = &previewed.tools[0].outcomes;

        assert_eq!(previewed.assumed, pins(&[("admins", true)]));
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].conditions, pins(&[("contractors", true)]));
        assert_eq!(outcomes[0].decision.verdict, Verdict::Blocked);
        assert_eq!(outcomes[1].conditions, pins(&[("contractors", false)]));
        assert_eq!(outcomes[1].decision.verdict, Verdict::Allowed);
    }

    #[test]
    fn a_tool_that_comes_out_the_same_in_every_case_gets_one_outcome() {
        let previewed = preview(&admins_and_contractors(), &tools(&["get_user"]), &Conditions::new())
            .expect("two policies are enumerable");

        assert_eq!(
            previewed.tools[0]
                .outcomes
                .len(),
            1
        );
        assert!(
            previewed.tools[0].outcomes[0]
                .conditions
                .is_empty()
        );
        assert!(!previewed.tools[0].depends_on_conditions());
    }

    #[test]
    fn a_tool_blocked_either_way_by_different_gates_gets_one_outcome_per_case() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![conditional("Tool Gate 1", true, &["^delete_"]), gate("Tool Gate 2", true, &["_user$"])],
        };

        let previewed = preview(&gating, &tools(&["delete_user"]), &Conditions::new()).expect("one policy");

        assert!(previewed.tools[0].depends_on_conditions());
    }

    #[test]
    fn gates_sharing_a_policy_count_as_one_condition() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![
                Gate {
                    condition: Some("admins".to_owned()),
                    ..gate("One", true, &["^a_"])
                },
                Gate {
                    condition: Some("admins".to_owned()),
                    ..gate("Two", true, &["^b_"])
                },
            ],
        };

        let previewed = preview(&gating, &tools(&["a_x", "b_x"]), &Conditions::new()).expect("one policy");

        assert_eq!(gating.policy_ids(), ["admins"]);
        assert_eq!(
            previewed.tools[0]
                .outcomes
                .len(),
            2
        );
    }

    #[test]
    fn more_than_three_unpinned_policies_are_refused_with_the_count() {
        let gating = Gating {
            denies_by_default: false,
            gates: ["a", "b", "c", "d"]
                .iter()
                .map(|policy| conditional(policy, true, &["^x"]))
                .collect(),
        };

        let error = preview(&gating, &tools(&["x"]), &Conditions::new())
            .expect_err("four unpinned policies is too many")
            .to_string();

        assert!(error.starts_with("4 condition policies are not pinned (a, b, c, d), which is 16 cases"), "{error}");
        assert!(error.contains("--condition POLICY_ID=met or POLICY_ID=unmet"), "{error}");
        assert!(preview(&gating, &tools(&["x"]), &pins(&[("a", true)])).is_ok());
    }

    #[test]
    fn a_pin_for_a_policy_no_gate_uses_is_refused_by_name() {
        let error = preview(&admins_and_contractors(), &tools(&["x"]), &pins(&[("admin", true)]))
            .expect_err("admin is a typo")
            .to_string();
        let none = preview(
            &Gating {
                denies_by_default: false,
                gates: vec![gate("g", true, &["^x"])],
            },
            &tools(&["x"]),
            &pins(&[("admin", true)]),
        )
        .expect_err("no gate has a condition")
        .to_string();

        assert_eq!(error, "--condition names 'admin', but no gate uses it; the gates use: 'admins', 'contractors'");
        assert_eq!(none, "--condition names 'admin', but none of the gates has a condition");
    }

    #[test]
    fn parse_pins_reads_met_and_unmet() {
        let parsed = parse_pins(&["admins=met".to_owned(), "contractors=unmet ".to_owned(), "a=b=met".to_owned()])
            .expect("well formed");

        assert_eq!(parsed, pins(&[("admins", true), ("contractors", false), ("a=b", true)]));
    }

    #[test]
    fn parse_pins_refuses_a_malformed_or_repeated_entry() {
        let messages: Vec<String> = ["admins", "=met", "admins=yes", "admins="]
            .iter()
            .map(|pin| {
                parse_pins(&[(*pin).to_owned()])
                    .expect_err("malformed")
                    .to_string()
            })
            .collect();
        let repeated = parse_pins(&["admins=met".to_owned(), "admins=unmet".to_owned()])
            .expect_err("repeated")
            .to_string();

        assert_eq!(messages[0], "--condition 'admins' should be POLICY_ID=met or POLICY_ID=unmet");
        assert_eq!(messages[1], "--condition '=met' should be POLICY_ID=met or POLICY_ID=unmet");
        assert_eq!(messages[2], "--condition 'admins=yes' should end in =met or =unmet");
        assert_eq!(messages[3], "--condition 'admins=' should end in =met or =unmet");
        assert_eq!(repeated, "--condition names 'admins' more than once");
    }

    #[test]
    fn a_pattern_is_trimmed_before_it_is_matched() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Blocker", true, &[" ^delete_ "])],
        };

        assert_eq!(verdict(&gating, "delete_user"), Verdict::Blocked);
        assert!(warnings(&gating, &tools(&["delete_user"])).is_empty());
    }

    #[test]
    fn an_invalid_pattern_is_reported_trimmed() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Blocker", true, &["  ^a(  "])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["a"])),
            [
                "'Blocker' has a pattern that is not valid regex (^a(). It matches no tool, and the gateway will refuse to save it."
            ]
        );
    }

    #[test]
    fn warns_about_more_gates_than_the_gateway_saves() {
        let gating = Gating {
            denies_by_default: false,
            gates: (0..65)
                .map(|index| gate(&format!("Tool Gate {}", index + 1), true, &["^x"]))
                .collect(),
        };

        let found = warnings(&gating, &tools(&["x"]));

        assert_eq!(found[0], "This surface has 65 gates, and the gateway will refuse to save more than 64.");
        assert!(
            warnings(
                &Gating {
                    gates: gating.gates[..64].to_vec(),
                    ..gating
                },
                &tools(&["x"])
            )
            .is_empty()
        );
    }

    #[test]
    fn warns_about_more_patterns_in_one_gate_than_the_gateway_saves() {
        let many: Vec<String> = (0..65)
            .map(|index| format!("^t{index}"))
            .collect();
        let refs: Vec<&str> = many
            .iter()
            .map(String::as_str)
            .collect();
        let mut blanks = refs.clone();
        blanks.truncate(64);
        blanks.extend(["", "  "]);
        let over = Gating {
            denies_by_default: false,
            gates: vec![gate("Wide", true, &refs)],
        };
        let at_the_limit = Gating {
            denies_by_default: false,
            gates: vec![gate("Wide", true, &blanks)],
        };

        assert_eq!(
            warnings(&over, &tools(&["t1"])),
            ["'Wide' has 65 patterns, and the gateway will refuse to save more than 64 in one gate."]
        );
        assert!(warnings(&at_the_limit, &tools(&["t1"])).is_empty());
    }

    #[test]
    fn warns_about_a_pattern_longer_than_the_gateway_saves_counting_bytes() {
        let long = "a".repeat(513);
        let exact = "a".repeat(512);
        let wide = "é".repeat(257);
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Long", true, &[&long]), gate("Exact", true, &[&exact]), gate("Wide", true, &[&wide])],
        };

        assert_eq!(
            warnings(&gating, &tools(&[&long, &exact, &wide])),
            [
                "'Long' has a pattern of 513 bytes, and the gateway will refuse to save one longer than 512 bytes. It matches no tool here.",
                "'Wide' has a pattern of 514 bytes, and the gateway will refuse to save one longer than 512 bytes. It matches no tool here."
            ]
        );
    }

    #[test]
    fn a_gate_that_is_fine_gives_no_warnings() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &["^delete_"])],
        };

        assert!(warnings(&gating, &tools(&["delete_user", "get_user"])).is_empty());
    }

    #[test]
    fn warns_about_a_pattern_that_is_not_valid_regex_and_names_the_gate() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Blocker", true, &["^delete_(", "^drop_"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["drop_table"])),
            [
                "'Blocker' has a pattern that is not valid regex (^delete_(). It matches no tool, and the gateway will refuse to save it."
            ]
        );
    }

    #[test]
    fn warns_about_a_gate_with_no_patterns_once() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &[]), gate("Tool Gate 2", true, &["  "])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["get_user"])),
            [
                "'Tool Gate 1' has no patterns, so it matches no tool, and the gateway will refuse to save it.",
                "'Tool Gate 2' has no patterns, so it matches no tool, and the gateway will refuse to save it."
            ]
        );
    }

    #[test]
    fn a_gate_holding_only_a_pattern_that_is_not_valid_is_not_also_reported_as_matching_nothing() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Broken", true, &["("])],
        };

        assert_eq!(warnings(&gating, &tools(&["get_user"])).len(), 1);
    }

    #[test]
    fn warns_about_an_allow_gate_under_an_allow_default() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Reads", false, &["^get_"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["get_user"])),
            ["'Reads' allows tools, but the default already allows every tool, so it changes nothing."]
        );
    }

    #[test]
    fn warns_about_an_allow_gate_whose_tools_an_unconditional_deny_gate_always_blocks() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![gate("Reads", false, &["^get_"]), gate("Blocker", true, &["^get_secret"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["get_secret", "get_secret_key"])),
            [
                "'Reads' lets none of these tools through: 'get_secret', 'get_secret_key' are also blocked by 'Blocker' with no condition, and a block always wins."
            ]
        );
    }

    #[test]
    fn says_is_for_a_single_tool_an_unconditional_deny_gate_blocks() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![gate("Reads", false, &["^get_"]), gate("Blocker", true, &["^get_secret"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["get_secret"])),
            [
                "'Reads' lets none of these tools through: 'get_secret' is also blocked by 'Blocker' with no condition, and a block always wins."
            ]
        );
    }

    #[test]
    fn does_not_warn_when_the_allow_gate_still_lets_one_tool_through_or_the_blocker_has_a_condition() {
        let one_left = Gating {
            denies_by_default: true,
            gates: vec![gate("Reads", false, &["^get_"]), gate("Blocker", true, &["^get_secret"])],
        };
        let conditional_blocker = Gating {
            denies_by_default: true,
            gates: vec![gate("Reads", false, &["^get_"]), conditional("Blocker", true, &["^get_secret"])],
        };

        assert!(warnings(&one_left, &tools(&["get_secret", "get_user"])).is_empty());
        assert!(warnings(&conditional_blocker, &tools(&["get_secret"])).is_empty());
    }

    #[test]
    fn warns_about_a_gate_that_matches_none_of_the_tools_given() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &["^delete_"])],
        };

        assert_eq!(warnings(&gating, &tools(&["get_user"])), ["'Tool Gate 1' matches none of the tools you gave."]);
    }

    #[test]
    fn warns_about_an_unanchored_pattern_that_matches_in_the_middle_of_a_tool_name() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &["delete_.*"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["delete_user", "undelete_draft", "redelete_x"])),
            [
                "'Tool Gate 1' pattern delete_.* matches anywhere in the name, so it also catches 'undelete_draft', 'redelete_x'. Add ^ if you only want names that start with it."
            ]
        );
    }

    #[test]
    fn does_not_warn_about_an_anchored_pattern_or_one_that_matches_from_the_start() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Anchored", true, &["^delete_"]), gate("Loose", true, &["delete_"])],
        };

        assert!(warnings(&gating, &tools(&["delete_user"])).is_empty());
    }

    #[test]
    fn a_pattern_ending_in_an_end_anchor_gets_no_middle_of_the_name_warning() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Suffix", true, &["_user$"]), gate("Suffix z", true, &["_user\\z"])],
        };

        assert!(warnings(&gating, &tools(&["delete_user"])).is_empty());
    }

    #[test]
    fn an_escaped_dollar_is_not_an_end_anchor() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Price", true, &["cost\\$"])],
        };

        assert_eq!(warnings(&gating, &tools(&["a_cost$"])).len(), 1);
    }

    #[test]
    fn warns_when_only_one_alternative_is_anchored_and_suggests_wrapping_them() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Mixed", true, &["^get_|delete_"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["get_user", "undelete_x"])),
            [
                "'Mixed' pattern ^get_|delete_ matches anywhere in the name, so it also catches 'undelete_x'. Add ^(?:get_|delete_) if you only want names that start with it."
            ]
        );
    }

    #[test]
    fn warns_about_a_mid_name_match_of_a_pattern_without_a_leading_anchor() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &["delete_.*"])],
        };

        assert_eq!(warnings(&gating, &tools(&["undelete_draft"])).len(), 1);
    }

    #[test]
    fn an_anchored_pattern_gets_no_warning() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Tool Gate 1", true, &["^delete_"])],
        };

        assert!(warnings(&gating, &tools(&["delete_user", "undelete_draft"])).is_empty());
    }

    #[test]
    fn a_pattern_over_the_length_the_gateway_saves_matches_nothing() {
        let long = format!("^a{}", "b".repeat(600));
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Long", true, &[&long])],
        };

        assert_eq!(verdict(&gating, &long[1..]), Verdict::Allowed);
        assert!(
            gating.gates[0]
                .compiled
                .matching
                .is_empty()
        );
        assert!(
            gating.gates[0]
                .compiled
                .not_valid
                .is_empty()
        );
    }

    #[test]
    fn a_pattern_is_compiled_when_the_gate_is_read_not_per_tool() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Blocker", true, &["^delete_", "^drop_"])],
        };
        let many: Vec<String> = (0..2000)
            .map(|index| format!("delete_{index}"))
            .collect();

        let previewed = preview(&gating, &many, &Conditions::new()).expect("no conditions");

        assert_eq!(
            gating.gates[0]
                .compiled
                .matching
                .len(),
            2
        );
        assert!(
            previewed
                .tools
                .iter()
                .all(|tool| tool.outcomes[0]
                    .decision
                    .verdict
                    == Verdict::Blocked)
        );
    }

    #[test]
    fn a_valid_pattern_too_big_to_compile_is_told_apart_from_a_syntax_error() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Big", true, &["(?:\\w{100}){100}"]), gate("Broken", true, &["^a("])],
        };

        let found = warnings(&gating, &tools(&["a"]));

        assert_eq!(
            found[0],
            "'Big' has a pattern that is too large to compile ((?:\\w{100}){100}), so the gateway will most likely refuse to save it. It matches no tool here."
        );
        assert!(found.contains(
            &"'Broken' has a pattern that is not valid regex (^a(). It matches no tool, and the gateway will refuse to save it.".to_owned()
        ));
        assert_eq!(
            found
                .iter()
                .filter(|note| note.contains("not valid regex"))
                .count(),
            1
        );
    }

    #[test]
    fn a_blank_condition_policy_id_is_unresolved_so_a_deny_gate_stays_on_and_an_allow_gate_is_off() {
        let deny = Gating {
            denies_by_default: false,
            gates: vec![with_policy("Blocker", true, &["^delete_"], "  ")],
        };
        let allow = Gating {
            denies_by_default: true,
            gates: vec![with_policy("Opener", false, &["^delete_"], "")],
        };

        assert_eq!(verdict_with(&deny, "delete_user", true), Verdict::Blocked);
        assert_eq!(verdict_with(&deny, "delete_user", false), Verdict::Blocked);
        assert_eq!(verdict_with(&allow, "delete_user", true), Verdict::Blocked);
        assert!(deny.policy_ids().is_empty());
        assert!(
            !preview(&deny, &tools(&["delete_user"]), &Conditions::new())
                .expect("nothing to enumerate")
                .tools[0]
                .depends_on_conditions()
        );
        assert_eq!(
            warnings(&deny, &tools(&["delete_user"])),
            [
                "'Blocker' has an empty condition policy id, so the gateway can never meet it: a block gate stays on and an allow gate is off."
            ]
        );
        assert!(warnings(&allow, &tools(&["delete_user"]))[0].starts_with("'Opener' has an empty condition policy id"));
        assert!(preview(&deny, &tools(&["x"]), &pins(&[("", true)])).is_err());
    }

    #[test]
    fn a_condition_policy_id_with_spaces_is_kept_as_written_and_warned_about() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![with_policy("Opener", false, &["^delete_"], "admins ")],
        };

        assert_eq!(gating.policy_ids(), ["admins "]);
        assert_eq!(
            warnings(&gating, &tools(&["delete_user"])),
            [
                "'Opener' has spaces at the start or end of its condition policy id; the gateway looks it up exactly as written."
            ]
        );
        let error = preview(&gating, &tools(&["delete_user"]), &pins(&[("admins", true)]))
            .expect_err("admins is not the id")
            .to_string();
        assert_eq!(error, "--condition names 'admins', but no gate uses it; the gates use: 'admins '");
        let exact = preview(&gating, &tools(&["delete_user"]), &pins(&[("admins ", true)])).expect("exact id pins");
        assert_eq!(
            exact.tools[0].outcomes[0]
                .decision
                .verdict,
            Verdict::Allowed
        );
        assert!(parse_pins(&["admins =met".to_owned()]).expect("kept")["admins "]);
    }

    #[test]
    fn a_deny_gate_with_a_blank_condition_counts_as_always_blocking_in_warnings() {
        let gating = Gating {
            denies_by_default: true,
            gates: vec![gate("Reads", false, &["^get_"]), with_policy("Blocker", true, &["^get_"], " ")],
        };

        assert!(
            warnings(&gating, &tools(&["get_user"]))
                .iter()
                .any(|note| note.starts_with("'Reads' lets none of these tools through"))
        );
    }

    #[test]
    fn suggests_wrapping_alternatives_without_a_leading_anchor_of_their_own() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Plain", true, &["get_|delete_"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["undelete_x"])),
            [
                "'Plain' pattern get_|delete_ matches anywhere in the name, so it also catches 'undelete_x'. Add ^(?:get_|delete_) if you only want names that start with it."
            ]
        );
    }

    #[test]
    fn asks_about_intent_for_a_plain_pattern_meant_to_match_anywhere() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![gate("Bulk", true, &["delete"])],
        };

        assert_eq!(
            warnings(&gating, &tools(&["bulk_delete_user", "delete_user"])),
            [
                "'Bulk' pattern delete matches anywhere in the name, so it also catches 'bulk_delete_user'. Add ^ if you only want names that start with it."
            ]
        );
    }

    #[test]
    fn an_end_anchor_inside_closing_groups_still_counts_as_end_anchored() {
        let gating = Gating {
            denies_by_default: false,
            gates: vec![
                gate("Group", true, &["(?:_user$)"]),
                gate("Capture", true, &["(_user$)"]),
                gate("Nested", true, &["((_user\\z))"]),
            ],
        };

        assert!(warnings(&gating, &tools(&["delete_user"])).is_empty());
    }

    #[test]
    fn an_end_anchor_in_the_middle_or_an_escaped_one_still_warns() {
        let middle = Gating {
            denies_by_default: false,
            gates: vec![gate("Middle", true, &["_user$|_admin"])],
        };
        let escaped_dollar = Gating {
            denies_by_default: false,
            gates: vec![gate("Price", true, &["(cost\\$)"])],
        };
        assert_eq!(warnings(&middle, &tools(&["delete_admin"])).len(), 1);
        assert_eq!(warnings(&escaped_dollar, &tools(&["a_cost$"])).len(), 1);
        assert!(!ends_anchored(r"x$\)"));
        assert!(!ends_anchored(r"x\$)"));
        assert!(ends_anchored(r"(x$)"));
    }
}
