//! Hiding prompt content: the prompts and model answers that governance
//! records and drift runs carry. The CLI shows them only for one record or
//! one run, when asked with `--reveal`, and warns when it does.

use serde_json::{Value, json};

use crate::commands::MASKED_VALUE;

/// Stand-in for prompt content in a list, which has no `--reveal`.
pub const LIST_MASKED_VALUE: &str = "<hidden; shown only by `get --reveal`>";

/// The warning printed on standard error when prompt content is shown.
pub const REVEAL_WARNING: &str = "warning: this output contains prompt content (prompts and model answers, which can \
                                  hold personal data); do not share or log it";

/// Where prompt content sits in a governance record as Agent Stream returns
/// it, the record under `record` beside its `signed_vc`: the record's prompt
/// and completion, each stage's input, output and reason (free text from a
/// guard or judge, which can quote what the caller sent, and is kept even when
/// bodies are not), the attachments' file names, and the signed credential,
/// which wraps the whole record.
const RECORD_FIELDS: &[&[&str]] = &[
    &["record", "prompt"],
    &["record", "completion"],
    &["record", "stages", "*", "input"],
    &["record", "stages", "*", "output"],
    &["record", "stages", "*", "reason"],
    &["record", "attachments", "*", "filename"],
    &[SIGNED_VC],
];

/// The signed credential of a governance record. Agent Stream always sends
/// it, and it only repeats the record, so it is hidden with the rest but does
/// not count as prompt content of its own for the `--reveal` warning.
const SIGNED_VC: &str = "signed_vc";

/// Where prompt content sits in a drift run: each replayed sample's input and
/// output, and its error, which carries the pipeline's error text and can
/// quote the prompt (a guard's rejection, a provider's message).
const RUN_FIELDS: &[&[&str]] = &[&["samples", "*", "input"], &["samples", "*", "output"], &["samples", "*", "error"]];

/// Which kind of item holds the prompt content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    GovernanceRecord,
    DriftRun,
}

impl Item {
    fn fields(self) -> &'static [&'static [&'static str]] {
        match self {
            Self::GovernanceRecord => RECORD_FIELDS,
            Self::DriftRun => RUN_FIELDS,
        }
    }
}

/// Replaces the prompt content of one `item` with `placeholder`. Absent and
/// null fields are left alone, so a record whose surface stores no bodies
/// still shows that it has none. Returns how many fields were replaced.
pub fn mask(
    item: &mut Value,
    kind: Item,
    placeholder: &str,
) -> usize {
    kind.fields()
        .iter()
        .map(|path| mask_path(item, path, placeholder))
        .sum()
}

/// Counts the prompt content fields of one `item` that hold a value, without
/// changing it: what `--reveal` is about to show.
pub fn count(
    item: &Value,
    kind: Item,
) -> usize {
    let mut copy = item.clone();
    kind.fields()
        .iter()
        .filter(|path| **path != [SIGNED_VC])
        .map(|path| mask_path(&mut copy, path, MASKED_VALUE))
        .sum()
}

fn mask_path(
    value: &mut Value,
    path: &[&str],
    placeholder: &str,
) -> usize {
    let Some((first, rest)) = path.split_first() else {
        return 0;
    };
    if *first == "*" {
        return match value {
            Value::Array(items) => items
                .iter_mut()
                .map(|item| mask_path(item, rest, placeholder))
                .sum(),
            _ => 0,
        };
    }
    let Some(child) = value
        .as_object_mut()
        .and_then(|object| object.get_mut(*first))
    else {
        return 0;
    };
    if rest.is_empty() {
        if child.is_null() {
            return 0;
        }
        *child = json!(placeholder);
        return 1;
    }
    mask_path(child, rest, placeholder)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Value {
        json!({
            "record": {
                "record_id": "r1",
                "prompt": "my card is 4111",
                "completion": "noted",
                "stages": [
                    {"stage": "judge", "outcome": "allow", "input": {"messages": ["x"]}, "output": "ok", "input_digest": "sha256:aa"},
                    {"stage": "llm", "outcome": "allow"}
                ],
                "attachments": [{"kind": "image", "filename": "passport.png", "sha256": "bb"}],
                "metrics": {"cost": 0.1}
            },
            "signed_vc": {"credentialSubject": {"prompt": "my card is 4111"}},
            "seq": 7
        })
    }

    #[test]
    fn test_mask_hides_every_prompt_content_field() {
        let mut value = record();
        assert_eq!(mask(&mut value, Item::GovernanceRecord, MASKED_VALUE), 6);
        let text = value.to_string();
        assert!(!text.contains("4111"), "{text}");
        assert!(!text.contains("passport"), "{text}");
        assert!(!text.contains("noted"), "{text}");
        assert_eq!(value["record"]["stages"][0]["input"], json!(MASKED_VALUE));
        assert_eq!(value["record"]["stages"][0]["input_digest"], json!("sha256:aa"));
        assert_eq!(value["record"]["metrics"]["cost"], json!(0.1));
        assert_eq!(value["seq"], json!(7));
    }

    #[test]
    fn test_mask_hides_stage_reasons_and_sample_errors() {
        let mut record = json!({"record": {"stages": [{"stage": "guard", "reason": "rejected: my card is 4111"}]}});
        assert_eq!(mask(&mut record, Item::GovernanceRecord, MASKED_VALUE), 1);
        assert_eq!(record["record"]["stages"][0]["reason"], json!(MASKED_VALUE));
        let mut run =
            json!({"samples": [{"input": null, "output": null, "error": "Prompt guard rejected: my card is 4111"}]});
        assert_eq!(mask(&mut run, Item::DriftRun, LIST_MASKED_VALUE), 1);
        assert_eq!(run["samples"][0]["error"], json!(LIST_MASKED_VALUE));
    }

    #[test]
    fn test_count_ignores_the_signed_credential_agent_stream_always_sends() {
        let record = json!({"record": {"record_id": "r1", "prompt": null, "stages": [{"stage": "llm"}]}, "signed_vc": {"proof": "z..."}});
        assert_eq!(count(&record, Item::GovernanceRecord), 0);
        let mut masked = record.clone();
        assert_eq!(mask(&mut masked, Item::GovernanceRecord, MASKED_VALUE), 1);
        assert_eq!(masked["signed_vc"], json!(MASKED_VALUE));
    }

    #[test]
    fn test_mask_leaves_absent_and_null_fields_alone() {
        let mut value = json!({"record": {"record_id": "r1", "prompt": null, "stages": [{"stage": "llm"}]}});
        assert_eq!(mask(&mut value, Item::GovernanceRecord, MASKED_VALUE), 0);
        assert_eq!(value["record"]["prompt"], Value::Null);
        assert!(
            value
                .get("signed_vc")
                .is_none()
        );
        assert_eq!(count(&value, Item::GovernanceRecord), 0);
    }

    #[test]
    fn test_mask_hides_drift_run_samples() {
        let mut run = json!({"id": "run-1", "samples": [{"input": "hi", "output": "hello", "passed": true}, {"input": "x", "output": null}]});
        assert_eq!(count(&run, Item::DriftRun), 3);
        assert_eq!(mask(&mut run, Item::DriftRun, LIST_MASKED_VALUE), 3);
        assert_eq!(run["samples"][0]["input"], json!(LIST_MASKED_VALUE));
        assert_eq!(run["samples"][1]["output"], Value::Null);
        assert_eq!(run["samples"][0]["passed"], json!(true));
    }
}
