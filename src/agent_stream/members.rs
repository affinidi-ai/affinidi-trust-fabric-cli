//! `fabric agent-stream members`: the Members of an Agent Stream, the known
//! callers that usage, limits, and spend are counted against.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use reqwest::Method;
use serde_json::{Map, Value, json};

use super::records::{self, Kind, Status, check_fields, known_names, listed, present, text_field};
use crate::{
    client::{GatewayClient, pretty_json_for_terminal, sanitize_for_terminal},
    commands::{Output, confirmation_line, print_list, print_outcome, read_json},
    tables::{self, Scope},
};

/// Where Agent Stream serves its members.
pub const MEMBERS: Kind = Kind {
    path: "/v1/members",
    noun: "member",
    group: "members",
    kept: &[
        "monthly_budget_usd",
        "monthly_token_cap",
        "budget_period_anchor",
        "requests_per_minute",
        "tokens_per_minute",
        "allowed_models",
    ],
};

/// The top-level fields of an Agent Stream member, as Agent Stream stores and
/// returns it. `identifier` is an older spelling of `identifiers` it still
/// reads.
const MEMBER_FIELDS: [&str; 18] = [
    "id",
    "name",
    "description",
    "status",
    "system",
    "tenant_id",
    "test_fixture",
    "auto_provisioned",
    "identifiers",
    "identifier",
    "monthly_budget_usd",
    "monthly_token_cap",
    "budget_period_anchor",
    "requests_per_minute",
    "tokens_per_minute",
    "allowed_models",
    "created_at",
    "updated_at",
];

/// The kinds of identifier a member can have, each with the field that holds
/// its value.
const IDENTIFIER_KINDS: [(&str, &str); 4] =
    [("email", "email"), ("subject", "subject"), ("api_key", "key_name"), ("custom", "value")];

/// How the identifier flags are written, for help and errors.
const IDENTIFIER_FORMS: &str = "email:ADDRESS, subject:JWT_SUBJECT, api_key:KEY_NAME, or custom:VALUE";

#[derive(Debug, Subcommand)]
pub enum MemberCommand {
    /// List members.
    ///
    /// Shows each member's id, name, status, identifiers, and when it was
    /// last saved. Agent Stream leaves deleted members out. Use --output json
    /// for the whole members, limits included.
    #[command(after_long_help = LIST_EXAMPLES)]
    List,
    /// Get a member by id, as the whole JSON document Agent Stream keeps,
    /// limits included.
    ///
    /// A deleted member is still returned, with `status` set to `deleted`,
    /// because Agent Stream keeps it for its usage history.
    #[command(after_long_help = GET_EXAMPLES)]
    Get {
        /// Id of the member (see `fabric agent-stream members list`).
        id: String,
    },
    /// Create a member from flags or a complete JSON document.
    ///
    /// With flags, give at least one --identifier; --name and --description
    /// are optional. With --file, the document is sent as it is, apart from
    /// `id`: Agent Stream gives every new member an id of its own, so the CLI
    /// sends an empty one and any id in the file is replaced.
    ///
    /// Before anything is sent, the CLI checks the member as Agent Stream
    /// would: at least one identifier, each with a kind it knows and a value
    /// that is not blank, an email that looks like one, and only field names
    /// Agent Stream knows. A budget, token cap, rate limit, or allowed models
    /// in --file is refused: these commands don't set them. A document with
    /// both `identifier` and `identifiers` is refused too.
    ///
    /// The CLI then reads the member list and refuses an identifier whose
    /// value another member already has, of any kind: Agent Stream matches a
    /// call by value whatever the kind, so `custom:bob-key` and
    /// `api_key:bob-key` clash, and it checks only a member's first
    /// identifier itself. The list holds only the members this login can see,
    /// so a member in another tenant, or outside a scoped access token's
    /// reach, isn't checked, and Agent Stream may still accept a clash with
    /// it. Reading the list needs `members.view` as well as `members.edit`.
    ///
    /// --dry-run prints the member and sends nothing, so it needs no saved
    /// login, and skips that check against other members; with --output json
    /// it prints the same preview as `update --dry-run`. Table output prints
    /// the new member's id; --output json prints the member Agent Stream
    /// answered with.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Change a member's name, description, status, or identifiers, or replace
    /// it with a JSON document.
    ///
    /// The CLI reads the member, applies the change on this machine, and
    /// checks it as `create` does; when the identifiers change, an identifier
    /// value another member this login can see already has is refused. It
    /// then reads the member
    /// again, stops if
    /// it was saved meanwhile, and otherwise sends the whole member, so its
    /// budget, token cap, rate limits, and allowed models stay as they are.
    /// Agent Stream has no version check, so a save that lands in the short
    /// gap between that last read and the send is still overwritten. A change
    /// that leaves the member as it is sends nothing.
    ///
    /// --file replaces the whole member. It must hold the `updated_at` the
    /// member has now, so start it from `members get`; a copy read before
    /// another save is refused. Its `created_at`, `updated_at`, `tenant_id`,
    /// `system`, `auto_provisioned`, and `test_fixture` are replaced with the
    /// stored ones, with a note for each that differed. Its budget, token cap, budget period, rate limits, and
    /// allowed models must match the stored ones; any it leaves out are kept.
    /// A deleted member can't be changed.
    ///
    /// Table output lists each changed field; --output json prints the member
    /// as Agent Stream answered the save. --dry-run shows the changes, or
    /// with --output json the changes and the whole new member, and saves
    /// nothing.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update(UpdateArgs),
    /// Delete a member.
    ///
    /// Agent Stream keeps it, marked deleted, for its usage history, and no
    /// longer recognises callers by its identifiers. There is no confirmation
    /// prompt. A member still in a team can't be deleted: remove it with
    /// `teams remove-member` first. A built-in member, such as `anonymous`,
    /// can't be deleted; disable it with `members update --status disabled`.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Id of the member (see `fabric agent-stream members list`).
        id: String,
    },
}

/// Examples shown at the bottom of `members list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  List members:
    fabric agent-stream members list

  Find the id of the member with an email address:
    fabric agent-stream members list --output json | jq -r \
      '.[] | select(any(.identifiers[]; .email == "ada@example.com")) | .id'"#;

/// Examples shown at the bottom of `members get --help`.
const GET_EXAMPLES: &str = r#"Examples:
  Show a member, limits included:
    fabric agent-stream members get 6f1c2d3e-0000-4000-8000-000000000001

  Keep a copy to edit:
    fabric agent-stream members get 6f1c2d3e-0000-4000-8000-000000000001 > member.json"#;

/// Examples shown at the bottom of `members create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  A person known by email and JWT subject:
    fabric agent-stream members create --name "Ada Lovelace" \
      --identifier email:ada@example.com --identifier 'subject:auth0|ada'

  A service known by the name of its API key, checked first:
    fabric agent-stream members create --name "Billing job" \
      --identifier api_key:billing-job --dry-run"#;

/// Examples shown at the bottom of `members update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Disable a member, so its calls are refused:
    fabric agent-stream members update 6f1c2d3e-0000-4000-8000-000000000001 \
      --status disabled

  Replace an email address:
    fabric agent-stream members update 6f1c2d3e-0000-4000-8000-000000000001 \
      --remove-identifier email:ada@old.example --add-identifier email:ada@example.com"#;

/// Examples shown at the bottom of `members delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Delete a member that is in no team:
    fabric agent-stream members delete 6f1c2d3e-0000-4000-8000-000000000001"#;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["file", "identifier"])))]
pub struct CreateArgs {
    /// Display name of the member.
    #[arg(long, conflicts_with = "file")]
    name: Option<String>,
    /// What the member is.
    #[arg(long, conflicts_with = "file")]
    description: Option<String>,
    /// An identifier Agent Stream recognises the member's calls by:
    /// email:ADDRESS, subject:JWT_SUBJECT, api_key:KEY_NAME (the name of the
    /// caller's API key), or custom:VALUE. Matched without regard to case or
    /// surrounding spaces. Quote a value that holds a shell character, such
    /// as 'subject:auth0|ada'. Repeat for more; the first one names the
    /// member when it has no name.
    #[arg(long, value_name = "KIND:VALUE", conflicts_with = "file")]
    identifier: Vec<String>,
    /// JSON document of the member, or - for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Print the member that would be sent, or with --output json the
    /// preview `update --dry-run` prints, and send nothing. Needs no saved
    /// login.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").required(true).multiple(true)
    .args(["file", "name", "description", "status", "add_identifier", "remove_identifier"])))]
pub struct UpdateArgs {
    /// Id of the member (see `fabric agent-stream members list`).
    id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// New description.
    #[arg(long)]
    description: Option<String>,
    /// New status. Calls from a disabled member are refused. Use `members
    /// delete` to delete one.
    #[arg(long, value_enum)]
    status: Option<Status>,
    /// Add an identifier, written as for `members create`. One the member
    /// already has is refused, and so is a value another member this login
    /// can see has, of any kind. Repeatable.
    #[arg(long, value_name = "KIND:VALUE")]
    add_identifier: Vec<String>,
    /// Remove an identifier, written as for `members create`. One the member
    /// lacks is refused, and so is removing its last one. Removes run before
    /// adds. Repeatable.
    #[arg(long, value_name = "KIND:VALUE")]
    remove_identifier: Vec<String>,
    /// Complete member JSON that replaces the stored member, or - for
    /// standard input. Start from a fresh `members get`.
    #[arg(short, long, conflicts_with_all = ["name", "description", "status", "add_identifier", "remove_identifier"])]
    file: Option<PathBuf>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Runs one `members` command. `connect` gives the client of the Agent Stream
/// to talk to, and is only called for a command that sends something, so
/// `create --dry-run` needs no saved login.
pub async fn run(
    command: MemberCommand,
    output: Output,
    connect: impl AsyncFnOnce() -> Result<GatewayClient>,
) -> Result<()> {
    let command = match command {
        MemberCommand::Create(args) if args.dry_run => {
            return records::print_create_preview(&create_body(args)?, output);
        }
        command => command,
    };
    let client = connect().await?;
    match command {
        MemberCommand::List => {
            let members = client
                .request(Method::GET, MEMBERS.path, None)
                .await?;
            let shown = match output {
                Output::Table => Value::Array(
                    listed(MEMBERS, &members)?
                        .iter()
                        .map(list_row)
                        .collect(),
                ),
                Output::Json => members,
            };
            print_list(&shown, output, &tables::AGENT_STREAM_MEMBERS, Scope::All)
        }
        MemberCommand::Get { id } => {
            let member = MEMBERS
                .read(&client, &id)
                .await?;
            println!("{}", pretty_json_for_terminal(&member)?);
            Ok(())
        }
        MemberCommand::Create(args) => {
            let member = create_body(args)?;
            refuse_identifiers_in_use(&client, &member, None, &[]).await?;
            let answer = client
                .request(Method::POST, MEMBERS.path, Some(member))
                .await
                .map_err(|error| {
                    records::unanswered_write(error, || {
                        "Agent Stream gave no answer, so the member may have been created anyway; check \
                         `fabric agent-stream members list` before running this again, which would otherwise be \
                         refused because the member's identifiers are already in use"
                            .to_owned()
                    })
                })?;
            let id = text_field(&answer, "id").to_owned();
            print_outcome(&answer, output, &confirmation_line("Created", "member", &id))
        }
        MemberCommand::Update(args) => {
            let before = MEMBERS
                .read(&client, &args.id)
                .await?;
            records::refuse_deleted(MEMBERS, &before, &args.id)?;
            let after = updated(&before, &args)?;
            check_member(&after, Some(&before))?;
            refuse_identifiers_in_use(&client, &after, Some(&args.id), &identifier_values(&before)).await?;
            records::save(&client, MEMBERS, &args.id, &before, after, args.dry_run, output).await
        }
        MemberCommand::Delete { id } => {
            let answer = client
                .request(Method::DELETE, &MEMBERS.record_path(&id)?, None)
                .await?;
            print_outcome(&answer, output, &confirmation_line("Deleted", "member", &id))
        }
    }
}

/// The member `members create` sends: the --file document, or one built from
/// the flags, with an empty `id` for Agent Stream to replace, checked as
/// Agent Stream would check it.
fn create_body(args: CreateArgs) -> Result<Value> {
    let member = match args.file {
        Some(file) => read_json(&file)?,
        None => {
            let identifiers = args
                .identifier
                .iter()
                .map(|text| parse_identifier(text))
                .collect::<Result<Vec<Value>>>()?;
            let mut member = Map::new();
            if let Some(name) = args.name {
                member.insert("name".to_owned(), Value::String(name));
            }
            if let Some(description) = args.description {
                member.insert("description".to_owned(), Value::String(description));
            }
            member.insert("identifiers".to_owned(), Value::Array(identifiers));
            Value::Object(member)
        }
    };
    let member = records::with_empty_id(MEMBERS, member)?;
    records::refuse_kept_on_create(MEMBERS, &member)?;
    check_member(&member, None)?;
    Ok(member)
}

/// The member `members update` would save: `before` with the flags applied,
/// or the --file document with the fields Agent Stream keeps put back.
fn updated(
    before: &Value,
    args: &UpdateArgs,
) -> Result<Value> {
    if let Some(file) = &args.file {
        return records::replacement(MEMBERS, read_json(file)?, before, &args.id);
    }
    let mut after = before.clone();
    if let Some(name) = &args.name {
        after["name"] = Value::String(name.clone());
    }
    if let Some(description) = &args.description {
        after["description"] = Value::String(description.clone());
    }
    if let Some(status) = args.status {
        after["status"] = Value::String(status.as_str().to_owned());
    }
    if args.add_identifier.is_empty()
        && args
            .remove_identifier
            .is_empty()
    {
        return Ok(after);
    }
    let mut identifiers = identifiers_of(before).to_vec();
    for text in &args.remove_identifier {
        let removed = parse_identifier(text)?;
        let count = identifiers.len();
        identifiers.retain(|identifier| !same_identifier(identifier, &removed));
        if identifiers.len() == count {
            bail!("member '{}' has no identifier {}", args.id, sanitize_for_terminal(text));
        }
    }
    for text in &args.add_identifier {
        let added = parse_identifier(text)?;
        if identifiers
            .iter()
            .any(|identifier| same_identifier(identifier, &added))
        {
            bail!("member '{}' already has identifier {}", args.id, sanitize_for_terminal(text));
        }
        identifiers.push(added);
    }
    if identifiers.is_empty() {
        bail!("a member needs at least one identifier; add another before removing the last one");
    }
    if let Some(fields) = after.as_object_mut() {
        fields.remove("identifier");
        fields.insert("identifiers".to_owned(), Value::Array(identifiers));
    }
    Ok(after)
}

/// The identifier `KIND:VALUE`, such as `email:ada@example.com`, as Agent
/// Stream writes it: `{"kind": "email", "email": "ada@example.com"}`.
pub fn parse_identifier(text: &str) -> Result<Value> {
    let Some((kind, value)) = text.split_once(':') else {
        bail!("identifier '{}' must be {IDENTIFIER_FORMS}", sanitize_for_terminal(text));
    };
    let Some((kind, field)) = IDENTIFIER_KINDS
        .iter()
        .find(|(name, _)| *name == kind.trim())
    else {
        bail!("identifier kind '{}' must be email, subject, api_key, or custom", sanitize_for_terminal(kind));
    };
    let identifier = json!({ "kind": kind, *field: value });
    check_identifier(&identifier)?;
    Ok(identifier)
}

/// Whether `text` names a member by identifier (`KIND:VALUE`) rather than by
/// id. An id can't hold a `:`, so any text with one is read as an identifier,
/// and a kind members don't have is refused as one.
pub fn is_identifier(text: &str) -> bool {
    text.contains(':')
}

/// Refuses an identifier Agent Stream would refuse: an unknown kind, a blank
/// value, or an email that does not look like one.
fn check_identifier(identifier: &Value) -> Result<()> {
    let kind = text_field(identifier, "kind");
    let Some((_, field)) = IDENTIFIER_KINDS
        .iter()
        .find(|(name, _)| *name == kind)
    else {
        bail!(
            "each identifier needs a `kind` of email, subject, api_key, or custom, not '{}'",
            sanitize_for_terminal(kind)
        );
    };
    let value = normalised(text_field(identifier, field));
    if value.is_empty() {
        bail!("each {kind} identifier needs a `{field}` that is not blank");
    }
    if kind == "email" && !plausible_email(&value) {
        bail!("identifier '{}' is not a valid email", sanitize_for_terminal(&value));
    }
    Ok(())
}

/// An identifier value as Agent Stream compares it: trimmed, in lower case.
fn normalised(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Agent Stream's test of an email: one `@`, text on both sides, and a `.`
/// after it.
fn plausible_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

/// The values of `member`'s identifiers as Agent Stream compares them:
/// trimmed and in lower case, whatever their kind.
fn identifier_values(member: &Value) -> Vec<String> {
    identifiers_of(member)
        .iter()
        .filter_map(|identifier| {
            let kind = text_field(identifier, "kind");
            IDENTIFIER_KINDS
                .iter()
                .find(|(name, _)| *name == kind)
                .map(|(_, field)| normalised(text_field(identifier, field)))
        })
        .filter(|value| !value.is_empty())
        .collect()
}

/// Refuses `member` when one of its identifier values, other than those in
/// `already` (the ones it had before), is an identifier value of another
/// member, whatever the kind. Agent Stream matches a call to a member by value
/// and checks only a member's first identifier when it saves, so a second
/// identifier that clashes would be saved and attribute another member's
/// calls to this one. `own_id` is the member's own id on an update. The
/// member list must be read, so a failure to read it stops the command. Agent
/// Stream lists only the members the login can see, so a member in another
/// tenant or outside a scoped token's reach is not checked.
async fn refuse_identifiers_in_use(
    client: &GatewayClient,
    member: &Value,
    own_id: Option<&str>,
    already: &[String],
) -> Result<()> {
    let new: Vec<String> = identifier_values(member)
        .into_iter()
        .filter(|value| !already.contains(value))
        .collect();
    if new.is_empty() {
        return Ok(());
    }
    let answer = client
        .request(Method::GET, MEMBERS.path, None)
        .await
        .context("read the member list to check that no other member has these identifiers")?;
    for other in listed(MEMBERS, &answer)? {
        let other_id = text_field(other, "id");
        if Some(other_id) == own_id {
            continue;
        }
        let theirs = identifier_values(other);
        if let Some(value) = new
            .iter()
            .find(|value| theirs.contains(value))
        {
            bail!(
                "member '{}' already has an identifier with the value '{}'; Agent Stream matches identifiers by \
                 value whatever their kind, so each value can belong to one member only",
                sanitize_for_terminal(other_id),
                sanitize_for_terminal(value)
            );
        }
    }
    Ok(())
}

/// The identifiers of `member`, under either spelling Agent Stream reads.
pub fn identifiers_of(member: &Value) -> &[Value] {
    match present(member.get("identifiers")).or_else(|| present(member.get("identifier"))) {
        Some(Value::Array(identifiers)) => identifiers,
        Some(single @ Value::Object(_)) => std::slice::from_ref(single),
        _ => &[],
    }
}

/// Whether `identifier` has the kind and, compared as Agent Stream compares
/// them, the value of `wanted`.
pub fn same_identifier(
    identifier: &Value,
    wanted: &Value,
) -> bool {
    let kind = text_field(wanted, "kind");
    text_field(identifier, "kind") == kind
        && IDENTIFIER_KINDS
            .iter()
            .find(|(name, _)| *name == kind)
            .is_some_and(|(_, field)| {
                normalised(text_field(identifier, field)) == normalised(text_field(wanted, field))
            })
}

/// `identifier` as the flags write it, such as `email:ada@example.com`.
fn identifier_text(identifier: &Value) -> String {
    let kind = text_field(identifier, "kind");
    let value = IDENTIFIER_KINDS
        .iter()
        .find(|(name, _)| *name == kind)
        .map_or("", |(_, field)| text_field(identifier, field));
    format!("{kind}:{value}")
}

/// Refuses a member Agent Stream would refuse, or would save without a field
/// it does not know. A field name the `stored` member already has counts as
/// known, and identifiers left as stored are not checked again, so a stored
/// member a rule here would refuse can still be changed otherwise.
fn check_member(
    member: &Value,
    stored: Option<&Value>,
) -> Result<()> {
    let Some(fields) = member.as_object() else {
        bail!("a member must be a JSON object");
    };
    check_fields(fields, &known_names(&MEMBER_FIELDS, stored.into_iter()), "the member")?;
    records::check_status(MEMBERS, fields)?;
    if present(fields.get("identifiers")).is_some() && present(fields.get("identifier")).is_some() {
        bail!(
            "the member has both `identifiers` and `identifier`, which Agent Stream can't read; keep `identifiers` \
             only"
        );
    }
    if present(fields.get("identifiers")).is_some_and(|identifiers| !identifiers.is_array()) {
        bail!("the member's `identifiers` must be a list");
    }
    let identifiers = identifiers_of(member);
    let stored_identifiers = stored.map_or(&[][..], identifiers_of);
    if stored.is_some() && identifiers == stored_identifiers {
        return Ok(());
    }
    if identifiers.is_empty() {
        bail!("a member needs at least one identifier ({IDENTIFIER_FORMS})");
    }
    for identifier in identifiers {
        let Some(identifier_fields) = identifier.as_object() else {
            bail!("each identifier must be a JSON object");
        };
        let known = known_names(&["kind", "email", "subject", "key_name", "value"], stored_identifiers.iter());
        check_fields(identifier_fields, &known, "an identifier")?;
        check_identifier(identifier)?;
    }
    Ok(())
}

/// The row of `members list` in table output for `member`: its own fields,
/// with its identifiers as one line of text.
pub fn list_row(member: &Value) -> Value {
    let mut row = Map::new();
    for field in ["id", "name", "status", "updated_at"] {
        if let Some(value) = member.get(field) {
            row.insert(field.to_owned(), value.clone());
        }
    }
    let identifiers: Vec<String> = identifiers_of(member)
        .iter()
        .map(identifier_text)
        .collect();
    row.insert("identifier_list".to_owned(), Value::String(identifiers.join(", ")));
    Value::Object(row)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        super::test_support::{
            Route, TEST_ACCESS_TOKEN, UnusedKeyring, json_file, request_body, run_stream, saved_login,
            scripted_agent_stream, sends_bearer, start_lines, stream_args,
        },
        *,
    };
    use clap::Parser;

    use crate::{commands::Cli, config::Config};

    const MEMBER_ID: &str = "6f1c2d3e-0000-4000-8000-000000000001";

    /// A stored member with two identifiers and limits the CLI must keep.
    const STORED: &str = r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada","status":"enabled",
        "system":false,"identifiers":[{"kind":"email","email":"ada@example.com"},{"kind":"api_key","key_name":"ada-key"}],
        "monthly_budget_usd":50.0,"allowed_models":["gpt-4o-mini"],
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z"}"#;

    /// The same member, saved again by someone else.
    const STORED_LATER: &str = r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada","status":"enabled",
        "system":false,"identifiers":[{"kind":"email","email":"ada@example.com"},{"kind":"api_key","key_name":"ada-key"}],
        "monthly_budget_usd":50.0,"allowed_models":["gpt-4o-mini"],
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-03T00:00:00Z"}"#;

    const GET_STORED: Route = ("GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED);
    const PUT_OK: Route = ("PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED);

    /// The member list: this member and Bob, known by the name of his API key.
    const MEMBER_LIST: &str = r#"[
        {"id":"6f1c2d3e-0000-4000-8000-000000000001","identifiers":[{"kind":"email","email":"ada@example.com"},{"kind":"api_key","key_name":"ada-key"}]},
        {"id":"m-bob","identifiers":[{"kind":"api_key","key_name":"bob-key"}]}]"#;
    const LIST_OK: Route = ("GET /api/v1/members", "HTTP/1.1 200 OK", MEMBER_LIST);

    async fn run_members(
        words: &[&str],
        routes: Vec<Route>,
    ) -> (Result<()>, Arc<Mutex<Vec<String>>>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
        let result = run_stream(words, saved, &credentials).await;
        (result, requests)
    }

    fn body_of(
        requests: &Arc<Mutex<Vec<String>>>,
        index: usize,
    ) -> Value {
        let recorded = requests.lock().unwrap();
        serde_json::from_str(request_body(&recorded[index])).unwrap_or_else(|error| panic!("{error}"))
    }

    fn error_text(result: Result<()>) -> String {
        match result {
            Err(error) => format!("{error:#}"),
            Ok(()) => panic!("expected the command to fail"),
        }
    }

    #[tokio::test]
    async fn list_sends_the_token_to_the_members_route() {
        let (result, requests) =
            run_members(&["members", "list"], vec![("GET /api/v1/members", "HTTP/1.1 200 OK", "[]")]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1"]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], TEST_ACCESS_TOKEN));
    }

    #[test]
    fn list_row_writes_identifiers_as_the_flags_do() {
        let stored: Value = serde_json::from_str(STORED).unwrap();
        assert_eq!(
            list_row(&stored),
            json!({"id":MEMBER_ID,"name":"Ada","status":"enabled","updated_at":"2026-11-02T00:00:00Z",
                   "identifier_list":"email:ada@example.com, api_key:ada-key"})
        );
    }

    #[tokio::test]
    async fn create_from_flags_sends_an_empty_id_and_each_identifier_in_order() {
        let (result, requests) = run_members(
            &[
                "members",
                "create",
                "--name",
                "Ada",
                "--identifier",
                "email:Ada@Example.com",
                "--identifier",
                "subject:auth0|ada",
                "--identifier",
                "api_key:ada-key",
                "--identifier",
                "custom:team:x",
            ],
            vec![("GET /api/v1/members", "HTTP/1.1 200 OK", "[]"), ("POST /api/v1/members", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1", "POST /api/v1/members HTTP/1.1"]);
        assert_eq!(
            body_of(&requests, 1),
            json!({"id":"","name":"Ada","identifiers":[
                {"kind":"email","email":"Ada@Example.com"},{"kind":"subject","subject":"auth0|ada"},
                {"kind":"api_key","key_name":"ada-key"},{"kind":"custom","value":"team:x"}]})
        );
    }

    #[tokio::test]
    async fn create_from_a_file_replaces_its_id_with_an_empty_one() {
        let file = json_file(r#"{"id":"mine","name":"Job","identifiers":[{"kind":"custom","value":"x"}]}"#);
        let (result, requests) = run_members(
            &["members", "create", "--file", file.path().to_str().unwrap()],
            vec![LIST_OK, ("POST /api/v1/members", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        result.unwrap();
        assert_eq!(body_of(&requests, 1), json!({"id":"","name":"Job","identifiers":[{"kind":"custom","value":"x"}]}));
    }

    #[tokio::test]
    async fn budgets_and_limits_are_refused_on_create_and_on_a_changed_update_file() {
        let file = json_file(r#"{"identifiers":[{"kind":"custom","value":"x"}],"monthly_budget_usd":5}"#);
        let (result, requests) =
            run_members(&["members", "create", "--file", file.path().to_str().unwrap()], vec![]).await;
        assert!(error_text(result).contains("`monthly_budget_usd` can't be set"));
        assert!(start_lines(&requests).is_empty());

        let mut changed: Value = serde_json::from_str(STORED).unwrap();
        changed["allowed_models"] = json!([]);
        let file = json_file(&changed.to_string());
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("can't change the member's `allowed_models`"));
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn an_update_file_with_a_limit_written_as_another_number_form_is_accepted() {
        let mut document: Value = serde_json::from_str(STORED).unwrap();
        document["monthly_budget_usd"] = json!(50);
        document["name"] = json!("Ada L");
        let file = json_file(&document.to_string());
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["monthly_budget_usd"], json!(50.0));
        assert_eq!(sent["name"], json!("Ada L"));
    }

    #[tokio::test]
    async fn an_update_file_that_leaves_out_limits_keeps_the_stored_ones() {
        let mut document: Value = serde_json::from_str(STORED).unwrap();
        let fields = document
            .as_object_mut()
            .unwrap();
        fields.remove("monthly_budget_usd");
        fields.remove("allowed_models");
        fields.insert("name".to_owned(), json!("Ada L"));
        let file = json_file(&document.to_string());
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["monthly_budget_usd"], json!(50.0));
        assert_eq!(sent["allowed_models"], json!(["gpt-4o-mini"]));
    }

    #[tokio::test]
    async fn the_built_in_member_can_be_disabled_and_a_deleted_member_is_not_changed() {
        let anonymous = r#"{"id":"anonymous","name":"Anonymous","status":"enabled","system":true,
            "identifiers":[{"kind":"custom","value":"anonymous"}],"updated_at":"2026-11-02T00:00:00Z"}"#;
        let (result, requests) = run_members(
            &["members", "update", "anonymous", "--status", "disabled"],
            vec![
                ("GET /api/v1/members/anonymous", "HTTP/1.1 200 OK", anonymous),
                ("PUT /api/v1/members/anonymous", "HTTP/1.1 200 OK", anonymous),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(body_of(&requests, 2)["status"], json!("disabled"));

        let deleted = r#"{"id":"m-gone","status":"deleted","identifiers":[{"kind":"custom","value":"x"}]}"#;
        let (result, requests) = run_members(
            &["members", "update", "m-gone", "--name", "Back"],
            vec![("GET /api/v1/members/m-gone", "HTTP/1.1 200 OK", deleted)],
        )
        .await;
        assert!(error_text(result).contains("is deleted, so it can't be changed"));
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn create_refuses_a_member_agent_stream_would_refuse_before_sending() {
        let cases: [(&[&str], &str); 5] = [
            (&["--identifier", "phone:123"], "email, subject, api_key, or custom"),
            (&["--identifier", "email:not-an-email"], "not a valid email"),
            (&["--identifier", "api_key:  "], "not blank"),
            (&["--identifier", "ada@example.com"], "must be email:ADDRESS"),
            (&["--name", "x"], "--identifier"),
        ];
        for (flags, expected) in cases {
            let mut words = vec!["members", "create"];
            words.extend_from_slice(flags);
            let (host, requests) = scripted_agent_stream(vec![]).await;
            let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
            let result = match Cli::try_parse_from(
                ["fabric", "agent-stream"]
                    .into_iter()
                    .chain(words.iter().copied()),
            ) {
                Ok(_) => run_stream(&words, saved, &credentials).await,
                Err(error) => Err(anyhow::anyhow!(error.to_string())),
            };
            let text = error_text(result);
            assert!(text.contains(expected), "{flags:?}: {text}");
            assert!(start_lines(&requests).is_empty(), "{flags:?}");
        }
        let unknown = json_file(r#"{"identifiers":[{"kind":"custom","value":"x"}],"alowed_models":[]}"#);
        let (result, requests) = run_members(
            &[
                "members",
                "create",
                "--file",
                unknown
                    .path()
                    .to_str()
                    .unwrap(),
            ],
            vec![],
        )
        .await;
        assert!(error_text(result).contains("'alowed_models'"));
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn create_dry_run_needs_no_login_and_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        super::super::dispatch_with(
            stream_args(&["members", "create", "--identifier", "custom:x", "--dry-run"]),
            Config::default(),
            &UnusedKeyring,
            &dir.path()
                .join("agent-stream.toml"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn update_identifiers_keeps_limits_and_sends_the_whole_member() {
        let (result, requests) = run_members(
            &[
                "members",
                "update",
                MEMBER_ID,
                "--remove-identifier",
                "email:ADA@example.com ",
                "--add-identifier",
                "email:ada@new.example",
            ],
            vec![GET_STORED, LIST_OK, PUT_OK],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1",
                "GET /api/v1/members HTTP/1.1",
                "GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1",
                "PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1"
            ]
        );
        let sent = body_of(&requests, 3);
        assert_eq!(
            sent["identifiers"],
            json!([{"kind":"api_key","key_name":"ada-key"},{"kind":"email","email":"ada@new.example"}])
        );
        assert_eq!(sent["monthly_budget_usd"], json!(50.0));
        assert_eq!(sent["allowed_models"], json!(["gpt-4o-mini"]));
    }

    #[tokio::test]
    async fn update_refuses_a_missing_or_duplicate_identifier_and_the_last_one() {
        let cases: [(&[&str], &str); 3] = [
            (&["--remove-identifier", "email:other@example.com"], "has no identifier"),
            (&["--add-identifier", "api_key:ADA-KEY"], "already has identifier"),
            (
                &["--remove-identifier", "email:ada@example.com", "--remove-identifier", "api_key:ada-key"],
                "at least one identifier",
            ),
        ];
        for (flags, expected) in cases {
            let mut words = vec!["members", "update", MEMBER_ID];
            words.extend_from_slice(flags);
            let (result, requests) = run_members(&words, vec![GET_STORED, PUT_OK]).await;
            assert!(error_text(result).contains(expected), "{flags:?}");
            assert_eq!(start_lines(&requests).len(), 1, "{flags:?}");
        }
    }

    #[tokio::test]
    async fn update_stops_when_the_member_was_saved_after_it_was_read() {
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--status", "disabled"],
            vec![
                GET_STORED,
                ("GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED_LATER),
                PUT_OK,
            ],
        )
        .await;
        assert!(error_text(result).contains("saved by someone else"));
        assert!(
            !start_lines(&requests)
                .iter()
                .any(|line| line.starts_with("PUT"))
        );
    }

    #[tokio::test]
    async fn update_with_no_change_or_a_dry_run_sends_nothing() {
        for words in [
            &["members", "update", MEMBER_ID, "--name", "Ada"][..],
            &["members", "update", MEMBER_ID, "--name", "New", "--dry-run"],
        ] {
            let (result, requests) = run_members(words, vec![GET_STORED, PUT_OK]).await;
            result.unwrap();
            assert_eq!(start_lines(&requests).len(), 1, "{words:?}");
        }
    }

    #[tokio::test]
    async fn update_file_read_before_another_save_is_refused_and_a_current_one_keeps_server_fields() {
        let stale = json_file(STORED_LATER);
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--file", stale.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("updated_at does not match"));
        assert_eq!(start_lines(&requests).len(), 1);

        let mut document: Value = serde_json::from_str(STORED).unwrap();
        document["name"] = json!("Ada L");
        document["system"] = json!(true);
        let current = json_file(&document.to_string());
        let (result, requests) = run_members(
            &[
                "members",
                "update",
                MEMBER_ID,
                "--file",
                current
                    .path()
                    .to_str()
                    .unwrap(),
            ],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["name"], json!("Ada L"));
        assert_eq!(sent["system"], json!(false));
    }

    #[tokio::test]
    async fn a_field_a_newer_agent_stream_returns_does_not_block_a_save() {
        let newer = r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada","region":"eu",
            "identifiers":[{"kind":"email","email":"ada@example.com","verified":true}],
            "updated_at":"2026-11-02T00:00:00Z"}"#;
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--name", "New"],
            vec![("GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", newer), PUT_OK],
        )
        .await;
        result.unwrap();
        assert_eq!(body_of(&requests, 2)["region"], json!("eu"));
    }

    #[tokio::test]
    async fn delete_shows_agent_stream_plain_text_refusal() {
        let (result, requests) = run_members(
            &["members", "delete", MEMBER_ID],
            vec![(
                "DELETE /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001",
                "HTTP/1.1 409 Conflict",
                "Member belongs to team(s): Research. Remove them first.",
            )],
        )
        .await;
        let text = error_text(result);
        assert!(text.contains("Member belongs to team(s): Research"), "{text}");
        assert!(!text.contains(TEST_ACCESS_TOKEN), "{text}");
        assert_eq!(start_lines(&requests).len(), 1);

        let (result, requests) = run_members(&["members", "delete", "../teams"], vec![]).await;
        assert!(error_text(result).contains("must be 1 to 128"));
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn create_refuses_a_value_another_member_has_on_any_identifier_of_any_kind() {
        let (result, requests) = run_members(
            &["members", "create", "--identifier", "email:new@example.com", "--identifier", "custom:BOB-KEY "],
            vec![LIST_OK, ("POST /api/v1/members", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        let text = error_text(result);
        assert!(text.contains("member 'm-bob' already has an identifier with the value 'bob-key'"), "{text}");
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1"]);
    }

    #[tokio::test]
    async fn update_refuses_an_added_value_another_member_has_and_ignores_the_member_itself() {
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--add-identifier", "custom:bob-key"],
            vec![GET_STORED, LIST_OK, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("member 'm-bob' already has an identifier"));
        assert!(
            !start_lines(&requests)
                .iter()
                .any(|line| line.starts_with("PUT"))
        );

        // The member's own identifiers are not a clash, and its unchanged ones are not checked again.
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--add-identifier", "custom:ada-key"],
            vec![GET_STORED, LIST_OK, PUT_OK],
        )
        .await;
        result.unwrap();
        assert!(
            start_lines(&requests)
                .iter()
                .any(|line| line.starts_with("PUT"))
        );
    }

    #[tokio::test]
    async fn a_member_list_that_can_not_be_read_stops_the_create() {
        let (result, requests) = run_members(
            &["members", "create", "--identifier", "custom:x"],
            vec![("GET /api/v1/members", "HTTP/1.1 403 Forbidden", "")],
        )
        .await;
        assert!(error_text(result).contains("read the member list to check"));
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_document_with_both_identifier_spellings_is_refused_before_sending() {
        let file =
            json_file(r#"{"identifiers":[{"kind":"custom","value":"x"}],"identifier":{"kind":"custom","value":"y"}}"#);
        let (result, requests) =
            run_members(&["members", "create", "--file", file.path().to_str().unwrap()], vec![LIST_OK]).await;
        assert!(error_text(result).contains("both `identifiers` and `identifier`"));
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn update_with_json_output_prints_the_save_answer_without_reading_again() {
        let (result, requests) =
            run_members(&["-o", "json", "members", "update", MEMBER_ID, "--name", "New"], vec![GET_STORED, PUT_OK])
                .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1",
                "GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1",
                "PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1"
            ]
        );

        let (result, requests) =
            run_members(&["-o", "json", "members", "update", MEMBER_ID, "--name", "Ada"], vec![GET_STORED, PUT_OK])
                .await;
        result.unwrap();
        assert_eq!(start_lines(&requests).len(), 1, "a no-op with --output json sends nothing");
    }

    #[tokio::test]
    async fn an_update_file_keeps_the_stored_auto_provisioned_and_test_fixture() {
        let stored = r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada","auto_provisioned":true,
            "identifiers":[{"kind":"email","email":"ada@example.com"}],"updated_at":"2026-11-02T00:00:00Z"}"#;
        let file = json_file(
            r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada L","test_fixture":true,
            "identifiers":[{"kind":"email","email":"ada@example.com"}],"updated_at":"2026-11-02T00:00:00Z"}"#,
        );
        let (result, requests) = run_members(
            &["members", "update", MEMBER_ID, "--file", file.path().to_str().unwrap()],
            vec![("GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", stored), PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["auto_provisioned"], json!(true));
        assert!(
            sent.get("test_fixture")
                .is_none(),
            "{sent}"
        );
        assert_eq!(sent["name"], json!("Ada L"));
    }

    #[tokio::test]
    async fn get_reads_the_member_and_delete_sends_one_delete() {
        let (result, requests) = run_members(&["members", "get", MEMBER_ID], vec![GET_STORED]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1"]);

        let (result, requests) = run_members(
            &["members", "delete", MEMBER_ID],
            vec![("DELETE /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 204 No Content", "")],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn json_output_after_an_update_is_agent_streams_answer_to_the_save_not_the_earlier_read() {
        let answer = r#"{"id":"6f1c2d3e-0000-4000-8000-000000000001","name":"Ada","status":"disabled",
            "identifiers":[{"kind":"email","email":"ada@example.com"}],"updated_at":"2026-11-09T09:09:09Z"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            GET_STORED,
            ("PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", answer),
        ])
        .await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let before: Value = serde_json::from_str(STORED).unwrap();
        let mut after = before.clone();
        after["status"] = json!("disabled");
        let text = records::save_text(&client, MEMBERS, MEMBER_ID, &before, after, false, Output::Json)
            .await
            .unwrap()
            .expect("--output json prints the saved member");
        let printed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(printed["updated_at"], json!("2026-11-09T09:09:09Z"), "{text}");
        assert_eq!(printed["status"], json!("disabled"), "{text}");
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1",
                "PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn table_output_after_an_update_lists_each_change_then_names_the_member() {
        let (host, _) = scripted_agent_stream(vec![GET_STORED, PUT_OK]).await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let before: Value = serde_json::from_str(STORED).unwrap();
        let mut after = before.clone();
        after["status"] = json!("disabled");
        after["name"] = json!("Ada L");
        let text = records::save_text(&client, MEMBERS, MEMBER_ID, &before, after, false, Output::Table)
            .await
            .unwrap()
            .expect("table output prints the changes");
        assert_eq!(
            text,
            format!(
                "Changes:\n  name: \"Ada\" -> \"Ada L\"\n  status: \"enabled\" -> \"disabled\"\nUpdated member '{MEMBER_ID}'"
            )
        );
    }

    #[tokio::test]
    async fn a_no_op_prints_nothing_in_table_output_and_the_stored_member_in_json() {
        let before: Value = serde_json::from_str(STORED).unwrap();
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let table = records::save_text(&client, MEMBERS, MEMBER_ID, &before, before.clone(), false, Output::Table)
            .await
            .unwrap();
        assert_eq!(table, None);
        let json_text = records::save_text(&client, MEMBERS, MEMBER_ID, &before, before.clone(), false, Output::Json)
            .await
            .unwrap()
            .expect("--output json prints the member as it is");
        assert_eq!(serde_json::from_str::<Value>(&json_text).unwrap(), before);
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn a_create_agent_stream_never_answers_says_the_member_may_exist_and_what_to_check() {
        let (host, requests) = super::super::records::tests::answering_reads_dropping_writes("[]").await;
        let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
        let result = run_stream(&["members", "create", "--identifier", "custom:x"], saved, &credentials).await;
        let text = error_text(result);
        assert!(
            text.starts_with(
                "Agent Stream gave no answer, so the member may have been created anyway; check `fabric \
                 agent-stream members list` before running this again, which would otherwise be refused because \
                 the member's identifiers are already in use: "
            ),
            "{text}"
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .as_slice(),
            ["GET /api/v1/members HTTP/1.1", "POST /api/v1/members HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn an_update_agent_stream_never_answers_says_it_may_be_saved_and_how_to_check() {
        let (host, requests) = super::super::records::tests::answering_reads_dropping_writes(STORED).await;
        let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
        let result = run_stream(&["members", "update", MEMBER_ID, "--name", "Ada L"], saved, &credentials).await;
        let text = error_text(result);
        assert!(
            text.starts_with(&format!(
                "Agent Stream gave no answer, so member '{MEMBER_ID}' may have been saved anyway; check it with \
                 `fabric agent-stream members get {MEMBER_ID}` before running this again: "
            )),
            "{text}"
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .last()
                .map(String::as_str),
            Some("PUT /api/v1/members/6f1c2d3e-0000-4000-8000-000000000001 HTTP/1.1")
        );
    }
}
