//! What the Agent Stream member and team commands share: checking an id
//! before it goes into a path, checking field names, and the save every
//! change goes through.
//!
//! Agent Stream replaces a whole member or team on each save and has no
//! version check, so a change reads the record, makes the change on this
//! machine, reads the record again to stop if it was saved meanwhile, and
//! sends the whole record back.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::{
    client::{GatewayClient, pretty_json_for_terminal, response_status, sanitize_for_terminal},
    commands::{Output, confirmation_line, entity_path},
    surface_validate::{self, Change},
    tables,
};

/// Longest id the CLI puts in a member or team path. Agent Stream sets no
/// limit of its own on these ids; this one only keeps a mistyped argument out
/// of the path.
const MAX_ID_LEN: usize = 128;

/// The fields of an `update --file` document that are replaced with the
/// stored ones, because Agent Stream sets them and a copy should not change
/// them: `auto_provisioned` marks a member Agent Stream created itself, and
/// `test_fixture` marks a record for the test-mode purge.
const KEPT_FROM_STORED: [&str; 6] =
    ["created_at", "updated_at", "tenant_id", "system", "auto_provisioned", "test_fixture"];

/// One kind of record: where Agent Stream serves it, and how messages name
/// it.
#[derive(Clone, Copy, Debug)]
pub struct Kind {
    /// The API path of the collection, such as `/v1/members`.
    pub path: &'static str,
    /// The record's name in messages, such as `member`.
    pub noun: &'static str,
    /// The command group, such as `members`.
    pub group: &'static str,
    /// The fields these commands never change, such as a member's budget and
    /// limits: `update` keeps them, `update --file` refuses a change to them,
    /// and `create` refuses them.
    pub kept: &'static [&'static str],
}

impl Kind {
    /// The API path of the record `id`, once `id` is one Agent Stream could
    /// have given.
    pub fn record_path(
        self,
        id: &str,
    ) -> Result<String> {
        check_id(self, id)?;
        Ok(entity_path(self.path, id))
    }

    /// Reads the record `id` as Agent Stream has it now.
    pub async fn read(
        self,
        client: &GatewayClient,
        id: &str,
    ) -> Result<Value> {
        let record = client
            .request(Method::GET, &self.record_path(id)?, None)
            .await?;
        if !record.is_object() {
            bail!("Agent Stream did not answer with a {} for '{id}'", self.noun);
        }
        Ok(record)
    }
}

/// Refuses an id that is empty, longer than [`MAX_ID_LEN`], or holds anything
/// but ASCII letters, digits, `-` and `_`, before it is put in a path. These
/// are the CLI's own rules; Agent Stream's ids (UUIDs, and names such as
/// `anonymous`) all pass them.
fn check_id(
    kind: Kind,
    id: &str,
) -> Result<()> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if id.is_empty() || id.len() > MAX_ID_LEN || !id.chars().all(allowed) {
        bail!(
            "{} id '{}' must be 1 to {MAX_ID_LEN} letters, digits, '-', or '_'; see `fabric agent-stream {} list`",
            kind.noun,
            sanitize_for_terminal(id),
            kind.group
        );
    }
    Ok(())
}

/// A field's value, with `null` counted as absent.
pub fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// The field names known at one level: `fields`, and every name the stored
/// `objects` at that level have, for a field a newer Agent Stream added.
pub fn known_names<'a>(
    fields: &[&str],
    objects: impl Iterator<Item = &'a Value>,
) -> BTreeSet<String> {
    let mut known: BTreeSet<String> = fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    for object in objects {
        if let Some(object) = object.as_object() {
            known.extend(object.keys().cloned());
        }
    }
    known
}

/// Refuses a field name outside `known`, naming where it was found: Agent
/// Stream drops a field it does not know without an error, so a mistyped
/// name would be lost.
pub fn check_fields(
    fields: &Map<String, Value>,
    known: &BTreeSet<String>,
    place: &str,
) -> Result<()> {
    if let Some(unknown) = fields
        .keys()
        .find(|name| !known.contains(name.as_str()))
    {
        let names: Vec<&str> = known
            .iter()
            .map(String::as_str)
            .collect();
        bail!(
            "{place} has a field Agent Stream does not know, '{}', which it would drop without an error; known \
             fields are {}",
            sanitize_for_terminal(unknown),
            names.join(", ")
        );
    }
    Ok(())
}

/// The --file document of `update`, refused when it names another record or
/// was read before the stored record was last saved, with the fields Agent
/// Stream keeps set back to the stored ones.
pub fn replacement(
    kind: Kind,
    mut document: Value,
    before: &Value,
    id: &str,
) -> Result<Value> {
    let Some(fields) = document.as_object_mut() else {
        bail!("the --file document must be a JSON object");
    };
    match present(fields.get("id")) {
        None => {
            fields.insert("id".to_owned(), Value::String(id.to_owned()));
        }
        Some(Value::String(given)) if given == id => {}
        Some(other) => {
            bail!("the --file document is for {} {}, not '{id}'", kind.noun, sanitize_for_terminal(&other.to_string()))
        }
    }
    if present(fields.get("updated_at")) != present(before.get("updated_at")) {
        bail!(
            "the --file document's updated_at does not match {noun} '{id}' as stored, so it was read before \
             another save or is not from `{group} get`; start again from `fabric agent-stream {group} get {id}`",
            noun = kind.noun,
            group = kind.group
        );
    }
    for field in KEPT_FROM_STORED {
        if present(fields.get(field)).is_some() && !same_value(fields.get(field), before.get(field)) {
            eprintln!("note: the `{field}` in --file was replaced with the stored one");
        }
        match before.get(field) {
            Some(value) => fields.insert(field.to_owned(), value.clone()),
            None => fields.remove(field),
        };
    }
    for field in kind.kept {
        let given = fields.get(*field);
        if given.is_some() && !same_value(given, before.get(*field)) {
            bail!(
                "update --file can't change the {noun}'s `{field}`; budgets and limits are kept as stored, so set it \
                 back to the value `{group} get` shows",
                noun = kind.noun,
                group = kind.group
            );
        }
        match before.get(*field) {
            Some(stored) => fields.insert((*field).to_owned(), stored.clone()),
            None => fields.remove(*field),
        };
    }
    Ok(document)
}

/// Whether two field values are the same once a `null` counts as absent and
/// numbers are compared by value, so `50` and `50.0` match.
fn same_value(
    given: Option<&Value>,
    stored: Option<&Value>,
) -> bool {
    match (present(given), present(stored)) {
        (Some(Value::Number(given)), Some(Value::Number(stored))) => given.as_f64() == stored.as_f64(),
        (given, stored) => given == stored,
    }
}

/// Refuses a new record that sets a field these commands never change.
pub fn refuse_kept_on_create(
    kind: Kind,
    record: &Value,
) -> Result<()> {
    if let Some(field) = kind
        .kept
        .iter()
        .find(|field| present(record.get(**field)).is_some())
    {
        bail!(
            "`{field}` can't be set when a {} is created; budgets and limits are not set by `fabric agent-stream {}`",
            kind.noun,
            kind.group
        );
    }
    Ok(())
}

/// Refuses a change to a record Agent Stream keeps marked deleted.
pub fn refuse_deleted(
    kind: Kind,
    record: &Value,
    id: &str,
) -> Result<()> {
    if text_field(record, "status") == "deleted" {
        bail!("{} '{id}' is deleted, so it can't be changed", kind.noun);
    }
    Ok(())
}

/// The statuses `update --status` can set on a member or a team.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Status {
    Enabled,
    Disabled,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// Refuses a `status` Agent Stream would refuse, or `deleted`, which only
/// `delete` sets.
pub fn check_status(
    kind: Kind,
    fields: &Map<String, Value>,
) -> Result<()> {
    match present(fields.get("status")) {
        None => Ok(()),
        Some(Value::String(status)) if status == "enabled" || status == "disabled" => Ok(()),
        Some(Value::String(status)) if status == "deleted" => {
            bail!("a {} can't be saved as deleted; use `fabric agent-stream {} delete`", kind.noun, kind.group)
        }
        Some(other) => bail!(
            "the {}'s `status` must be \"enabled\" or \"disabled\", not {}",
            kind.noun,
            sanitize_for_terminal(&other.to_string())
        ),
    }
}

/// The new record `create` sends: `record` with an empty `id`, which Agent
/// Stream replaces with one of its own.
pub fn with_empty_id(
    kind: Kind,
    mut record: Value,
) -> Result<Value> {
    let Some(fields) = record.as_object_mut() else {
        bail!("a {} must be a JSON object", kind.noun);
    };
    fields.insert("id".to_owned(), Value::String(String::new()));
    Ok(record)
}

/// What `create --dry-run` prints: the record, or with --output json the
/// preview `update --dry-run` prints, with a note on standard error in table
/// output.
pub fn print_create_preview(
    record: &Value,
    output: Output,
) -> Result<()> {
    let printed = match output {
        Output::Table => pretty_json_for_terminal(record)?,
        Output::Json => preview(&surface_validate::changes(&json!({}), record), record, output)?,
    };
    println!("{printed}");
    if let Output::Table = output {
        eprintln!("Dry run: nothing was sent.");
    }
    Ok(())
}

/// Saves `after` in place of the record `before`, read as `id`. On a dry run
/// it prints the changes and sends nothing. With no change it sends nothing.
/// Otherwise it reads the record again and stops if it was saved by someone
/// else since `before` was read, then sends the whole record. Agent Stream
/// answers the save with the record as stored, `updated_at` included, so
/// --output json prints that answer.
pub async fn save(
    client: &GatewayClient,
    kind: Kind,
    id: &str,
    before: &Value,
    after: Value,
    dry_run: bool,
    output: Output,
) -> Result<()> {
    if let Some(text) = save_text(client, kind, id, before, after, dry_run, output).await? {
        println!("{text}");
    }
    Ok(())
}

/// [`save`] without the printing: the text it puts on standard output, or
/// `None` when it prints nothing there. Notes still go to standard error.
pub async fn save_text(
    client: &GatewayClient,
    kind: Kind,
    id: &str,
    before: &Value,
    after: Value,
    dry_run: bool,
    output: Output,
) -> Result<Option<String>> {
    let changes = surface_validate::changes(before, &after);
    if dry_run {
        return preview(&changes, &after, output).map(Some);
    }
    if changes.is_empty() {
        eprintln!("{} '{id}' already matches, so nothing was sent.", capitalised(kind.noun));
        return match output {
            Output::Json => pretty_json_for_terminal(before).map(Some),
            Output::Table => Ok(None),
        };
    }
    let current = kind.read(client, id).await?;
    if present(current.get("updated_at")) != present(before.get("updated_at")) {
        bail!(
            "{} '{id}' was saved by someone else after it was read, so nothing was saved; run the command again to \
             change the new version",
            kind.noun
        );
    }
    let path = kind.record_path(id)?;
    let saved = client
        .request(Method::PUT, &path, Some(after))
        .await
        .map_err(|error| {
            unanswered_write(error, || {
                format!(
                    "Agent Stream gave no answer, so {noun} '{id}' may have been saved anyway; check it with \
                     `fabric agent-stream {group} get {id}` before running this again",
                    noun = kind.noun,
                    group = kind.group
                )
            })
        })?;
    match output {
        Output::Table => {
            Ok(Some(format!("{}\n{}", change_summary(&changes), confirmation_line("Updated", kind.noun, id))))
        }
        Output::Json => pretty_json_for_terminal(&saved).map(Some),
    }
}

/// A failed write, with `advice` added when Agent Stream's answer was lost,
/// such as after a timeout, a dropped connection, or a proxy's 502 or 504:
/// the write may then have been applied anyway, and running the command again
/// could repeat it. An answer from Agent Stream, such as a refusal, is
/// returned as it is.
pub fn unanswered_write(
    error: anyhow::Error,
    advice: impl FnOnce() -> String,
) -> anyhow::Error {
    if !answer_lost(&error) {
        return error;
    }
    error.context(advice())
}

/// Whether Agent Stream's answer to a write was lost: no HTTP answer came
/// back, or a proxy in front of Agent Stream answered 502 or 504, which
/// Agent Stream's own routes never do. The write may have been applied.
fn answer_lost(error: &anyhow::Error) -> bool {
    matches!(response_status(error), None | Some(StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT))
}

/// What a dry run prints: the changes, or with --output json the changes and
/// the whole record that would be sent.
pub fn preview(
    changes: &[Change],
    after: &Value,
    output: Output,
) -> Result<String> {
    match output {
        Output::Json => {
            let changes: Vec<Value> = changes
                .iter()
                .map(|change| json!({ "path": change.path, "before": change.before, "after": change.after }))
                .collect();
            pretty_json_for_terminal(&json!({ "dry_run": true, "changes": changes, "after": after }))
        }
        Output::Table => Ok(format!("{}\n\nDry run: nothing was saved.", change_summary(changes))),
    }
}

/// `Changes:` and one line per changed field, as table output prints them
/// after a save.
pub fn change_summary(changes: &[Change]) -> String {
    let mut lines = vec!["Changes:".to_owned()];
    lines.extend(change_lines(changes));
    lines.join("\n")
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
    value.map_or_else(|| "(absent)".to_owned(), |value| tables::flatten_capped(&value.to_string()))
}

fn capitalised(noun: &str) -> String {
    let mut chars = noun.chars();
    chars
        .next()
        .map(|first| {
            first
                .to_uppercase()
                .chain(chars)
                .collect()
        })
        .unwrap_or_default()
}

/// The text of `field`, or "" when it is missing or not text.
pub fn text_field<'a>(
    value: &'a Value,
    field: &str,
) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The records of a list answer, refused when Agent Stream did not answer
/// with a list.
pub fn listed(
    kind: Kind,
    answer: &Value,
) -> Result<&[Value]> {
    answer
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("Agent Stream did not answer with a list of {}", kind.group))
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::{Arc, Mutex};

    use reqwest::StatusCode;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::unanswered_write;

    /// A local server that answers every GET with `read_answer`, and closes the
    /// connection on anything else without answering, as a write looks when it
    /// times out or its connection drops. Returns its base URL and the start
    /// line of each request.
    pub async fn answering_reads_dropping_writes(read_answer: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("local addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 65536];
                let read = socket
                    .read(&mut buf)
                    .await
                    .unwrap_or(0);
                let start = String::from_utf8_lossy(&buf[..read])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                recorded
                    .lock()
                    .unwrap()
                    .push(start.clone());
                if start.starts_with("GET ") {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{read_answer}",
                        read_answer.len()
                    );
                    let _ = socket
                        .write_all(response.as_bytes())
                        .await;
                    let _ = socket.shutdown().await;
                }
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[test]
    fn an_answer_from_agent_stream_is_kept_and_no_answer_gets_the_advice() {
        let refused = crate::client::gateway_error(StatusCode::CONFLICT, b"already exists", &[]);
        let kept = format!("{:#}", unanswered_write(refused, || "check first".to_owned()));
        assert!(kept.contains("already exists") && !kept.contains("check first"), "{kept}");

        let dropped = unanswered_write(anyhow::anyhow!("operation timed out"), || "check first".to_owned());
        assert_eq!(format!("{dropped:#}"), "check first: operation timed out");

        for status in [StatusCode::BAD_GATEWAY, StatusCode::GATEWAY_TIMEOUT] {
            let proxy = crate::client::gateway_error(status, b"<html>Gateway Time-out</html>", &[]);
            let text = format!("{:#}", unanswered_write(proxy, || "check first".to_owned()));
            assert!(text.starts_with("check first: "), "{status}: {text}");
        }
        let server = crate::client::gateway_error(StatusCode::INTERNAL_SERVER_ERROR, b"store failed", &[]);
        let text = format!("{:#}", unanswered_write(server, || "check first".to_owned()));
        assert!(!text.contains("check first"), "{text}");
    }
}
