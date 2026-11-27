//! `fabric agent-stream teams`: the Teams of an Agent Stream, which group
//! Members under a shared budget.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use reqwest::Method;
use serde_json::{Map, Value, json};

use super::{
    members::{self, MEMBERS, identifiers_of, is_identifier, parse_identifier, same_identifier},
    records::{self, Kind, Status, check_fields, known_names, listed, present, text_field},
};
use crate::{
    client::{GatewayClient, pretty_json_for_terminal, sanitize_for_terminal},
    commands::{Output, confirmation_line, entity_path, print_list, print_outcome, read_json},
    surface_validate::Change,
    tables::{self, Scope},
};

/// Where Agent Stream serves its teams.
const TEAMS: Kind = Kind {
    path: "/v1/teams",
    noun: "team",
    group: "teams",
    kept: &["monthly_budget_usd", "monthly_token_cap"],
};

/// The top-level fields of an Agent Stream team, as Agent Stream stores and
/// returns it.
const TEAM_FIELDS: [&str; 12] = [
    "id",
    "name",
    "description",
    "status",
    "system",
    "tenant_id",
    "test_fixture",
    "monthly_budget_usd",
    "monthly_token_cap",
    "members",
    "created_at",
    "updated_at",
];

/// How a member is named on the command line, for help and errors.
const MEMBER_REF_HELP: &str = "Member: its id, or one of its identifiers written as for `members create`, such as \
                               email:ada@example.com or api_key:billing-job";

#[derive(Debug, Subcommand)]
pub enum TeamCommand {
    /// List teams.
    ///
    /// Shows each team's id, name, status, number of members, and when it was
    /// last saved. Agent Stream leaves deleted teams out. Use --output json
    /// for the whole teams, member ids and caps included.
    #[command(after_long_help = LIST_EXAMPLES)]
    List,
    /// Get a team by id: the whole JSON document Agent Stream keeps, then, in
    /// table output, a table of its members.
    ///
    /// Agent Stream keeps only member ids on a team, so the members table
    /// comes from `members list`: it shows each member's name, status, and
    /// identifiers, and "(not listed)" for a member that is deleted or not
    /// visible to you. When the members can't be read, a warning says why and
    /// the table shows only each member's id. --output json prints the team
    /// document only. A deleted team is still returned, with `status` set to
    /// `deleted`.
    #[command(after_long_help = GET_EXAMPLES)]
    Get {
        /// Id of the team (see `fabric agent-stream teams list`).
        id: String,
    },
    /// Create a team from flags or a complete JSON document.
    ///
    /// With flags, --name is required, and each --member adds one member. A
    /// member named by an identifier is looked up in `members list`, and the
    /// command stops, sending nothing, when the identifier matches no member
    /// or more than one. With --file, the document is sent as it is, apart
    /// from `id`: Agent Stream gives every new team an id of its own, so the
    /// CLI sends an empty one and any id in the file is replaced.
    ///
    /// Before anything is sent, the CLI checks the team as Agent Stream
    /// would: a name, no member twice, and only field names Agent Stream
    /// knows. A budget or token cap in --file is refused: these commands don't
    /// set them. Agent Stream refuses a member that is deleted or not visible
    /// to you.
    ///
    /// --dry-run prints the team and sends nothing; it needs a saved login
    /// only to look up members named by identifier. With --output json it
    /// prints the same preview as `update --dry-run`. Table output prints the
    /// new team's id; --output json prints the team Agent Stream answered
    /// with.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Change a team's name, description, or status, or replace it with a
    /// JSON document.
    ///
    /// The CLI reads the team, applies the change on this machine, and checks
    /// it as `create` does. It then reads the team again, stops if it was
    /// saved meanwhile, and otherwise sends the whole team, so its members,
    /// budget, and token cap stay as they are. Agent Stream has no version
    /// check, so a save that lands in the short gap between that last read
    /// and the send is still overwritten. A change that leaves the team as it
    /// is sends nothing. Use `add-member` and `remove-member` for members.
    ///
    /// --file replaces the whole team, its member list included. It must hold
    /// the `updated_at` the team has now, so start it from `teams get`; a
    /// copy read before another save is refused. Its `created_at`,
    /// `updated_at`, `tenant_id`, `system`, and `test_fixture` are replaced
    /// with the stored ones, with a note for each that differed. Its budget and token cap must
    /// match the stored ones; any it leaves out are kept. A deleted team
    /// can't be changed.
    ///
    /// Table output lists each changed field; --output json prints the team as
    /// Agent Stream answered the save. --dry-run shows the changes, or
    /// with --output json the changes and the whole new team, and saves
    /// nothing.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update(UpdateArgs),
    /// Delete a team.
    ///
    /// Its members stay, and only lose this team; its usage history is
    /// dropped. Agent Stream keeps the team, marked deleted. There is no
    /// confirmation prompt. A built-in team, such as `anonymous`, can't be
    /// deleted; disable it with `teams update --status disabled`.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Id of the team (see `fabric agent-stream teams list`).
        id: String,
    },
    /// Add a member to a team.
    ///
    /// The member is named by id or by identifier; an identifier that matches
    /// no member, or more than one, is refused before anything is sent. A
    /// member already in the team sends nothing. Agent Stream adds the member
    /// to the team as it is stored, so nothing else in the team is changed.
    /// A deleted team is refused, as `teams update` refuses it. Table output
    /// lists the team's members before and after. --dry-run shows the change
    /// and sends nothing.
    #[command(after_long_help = ADD_MEMBER_EXAMPLES)]
    AddMember(MemberChangeArgs),
    /// Remove a member from a team.
    ///
    /// The member is named as for `add-member`. A member not in the team
    /// sends nothing. The member itself is kept; delete it with `members
    /// delete` once it is in no team. A deleted team is refused. Table output
    /// lists the team's members before and after. --dry-run shows the change
    /// and sends nothing.
    #[command(after_long_help = REMOVE_MEMBER_EXAMPLES)]
    RemoveMember(MemberChangeArgs),
}

/// Examples shown at the bottom of `teams list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  List teams:
    fabric agent-stream teams list

  Print each team's id and name for a script:
    fabric agent-stream teams list --output json | jq -r '.[] | "\(.id) \(.name)"'"#;

/// Examples shown at the bottom of `teams get --help`.
const GET_EXAMPLES: &str = r#"Examples:
  Show a team and its members:
    fabric agent-stream teams get 0b7e4a52-0000-4000-8000-000000000001"#;

/// Examples shown at the bottom of `teams create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a team with two members, one named by email:
    fabric agent-stream teams create --name Research \
      --member email:ada@example.com \
      --member 6f1c2d3e-0000-4000-8000-000000000002

  Check a JSON document without sending it, then create it:
    fabric agent-stream teams create --file team.json --dry-run
    fabric agent-stream teams create --file team.json"#;

/// Examples shown at the bottom of `teams update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Rename a team:
    fabric agent-stream teams update 0b7e4a52-0000-4000-8000-000000000001 --name "Applied research"

  Disable a team, after a dry run:
    fabric agent-stream teams update 0b7e4a52-0000-4000-8000-000000000001 \
      --status disabled --dry-run"#;

/// Examples shown at the bottom of `teams delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Delete a team:
    fabric agent-stream teams delete 0b7e4a52-0000-4000-8000-000000000001"#;

/// Examples shown at the bottom of `teams add-member --help`.
const ADD_MEMBER_EXAMPLES: &str = r#"Examples:
  Add the member with an email address:
    fabric agent-stream teams add-member 0b7e4a52-0000-4000-8000-000000000001 \
      email:ada@example.com

  Add a member by id:
    fabric agent-stream teams add-member 0b7e4a52-0000-4000-8000-000000000001 \
      6f1c2d3e-0000-4000-8000-000000000002"#;

/// Examples shown at the bottom of `teams remove-member --help`.
const REMOVE_MEMBER_EXAMPLES: &str = r#"Examples:
  Remove the member whose API key is named billing-job:
    fabric agent-stream teams remove-member 0b7e4a52-0000-4000-8000-000000000001 \
      api_key:billing-job --dry-run"#;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["file", "name"])))]
pub struct CreateArgs {
    /// Display name of the team.
    #[arg(long, conflicts_with = "file")]
    name: Option<String>,
    /// What the team is for.
    #[arg(long, conflicts_with = "file")]
    description: Option<String>,
    /// A member of the new team: its id, or one of its identifiers written as
    /// for `members create`, such as email:ada@example.com. Repeatable.
    #[arg(long, value_name = "MEMBER", conflicts_with = "file")]
    member: Vec<String>,
    /// JSON document of the team, or - for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Print the team that would be sent, or with --output json the preview
    /// `update --dry-run` prints, and send nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args(["file", "name", "description", "status"])))]
pub struct UpdateArgs {
    /// Id of the team (see `fabric agent-stream teams list`).
    id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// New description.
    #[arg(long)]
    description: Option<String>,
    /// New status. A disabled team no longer counts its members' calls. Use
    /// `teams delete` to delete one.
    #[arg(long, value_enum)]
    status: Option<Status>,
    /// Complete team JSON that replaces the stored team, or - for standard
    /// input. Start from a fresh `teams get`.
    #[arg(short, long, conflicts_with_all = ["name", "description", "status"])]
    file: Option<PathBuf>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct MemberChangeArgs {
    /// Id of the team (see `fabric agent-stream teams list`).
    team: String,
    #[arg(help = MEMBER_REF_HELP)]
    member: String,
    /// Show the change, and send nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Runs one `teams` command. `connect` gives the client of the Agent Stream
/// to talk to, and is only called for a command that sends something, so
/// `create --dry-run` with no member named by identifier needs no saved
/// login.
pub async fn run(
    command: TeamCommand,
    output: Output,
    connect: impl AsyncFnOnce() -> Result<GatewayClient>,
) -> Result<()> {
    let command = match command {
        TeamCommand::Create(args)
            if args.dry_run
                && !args
                    .member
                    .iter()
                    .any(|member| is_identifier(member)) =>
        {
            return records::print_create_preview(&create_body(None, args).await?, output);
        }
        command => command,
    };
    let client = connect().await?;
    match command {
        TeamCommand::List => {
            let teams = client
                .request(Method::GET, TEAMS.path, None)
                .await?;
            let shown = match output {
                Output::Table => Value::Array(
                    listed(TEAMS, &teams)?
                        .iter()
                        .map(list_row)
                        .collect(),
                ),
                Output::Json => teams,
            };
            print_list(&shown, output, &tables::AGENT_STREAM_TEAMS, Scope::All)
        }
        TeamCommand::Get { id } => get(&client, &id, output).await,
        TeamCommand::Create(args) => {
            let dry_run = args.dry_run;
            let team = create_body(Some(&client), args).await?;
            if dry_run {
                return records::print_create_preview(&team, output);
            }
            let answer = client
                .request(Method::POST, TEAMS.path, Some(team))
                .await
                .map_err(|error| {
                    records::unanswered_write(error, || {
                        "Agent Stream gave no answer, so the team may have been created anyway; Agent Stream \
                         allows two teams with one name, so check `fabric agent-stream teams list` before running \
                         this again"
                            .to_owned()
                    })
                })?;
            let id = text_field(&answer, "id").to_owned();
            print_outcome(&answer, output, &confirmation_line("Created", "team", &id))
        }
        TeamCommand::Update(args) => {
            let before = TEAMS
                .read(&client, &args.id)
                .await?;
            records::refuse_deleted(TEAMS, &before, &args.id)?;
            let after = updated(&before, &args)?;
            check_team(&after, Some(&before))?;
            records::save(&client, TEAMS, &args.id, &before, after, args.dry_run, output).await
        }
        TeamCommand::Delete { id } => {
            let answer = client
                .request(Method::DELETE, &TEAMS.record_path(&id)?, None)
                .await?;
            print_outcome(&answer, output, &confirmation_line("Deleted", "team", &id))
        }
        TeamCommand::AddMember(args) => change_member(&client, args, Membership::Add, output).await,
        TeamCommand::RemoveMember(args) => change_member(&client, args, Membership::Remove, output).await,
    }
}

/// `teams get`: the team document, then in table output a table of its
/// members.
async fn get(
    client: &GatewayClient,
    id: &str,
    output: Output,
) -> Result<()> {
    let report = get_report(client, id, output).await?;
    if let Some(warning) = &report.warning {
        eprintln!("{warning}");
    }
    println!("{}", report.stdout);
    Ok(())
}

/// What `teams get` prints: the text for standard output and, when the
/// members can't be read, the warning for standard error.
#[derive(Debug)]
struct GetReport {
    stdout: String,
    warning: Option<String>,
}

/// [`get`] without the printing.
async fn get_report(
    client: &GatewayClient,
    id: &str,
    output: Output,
) -> Result<GetReport> {
    let team = TEAMS.read(client, id).await?;
    let document = pretty_json_for_terminal(&team)?;
    if let Output::Json = output {
        return Ok(GetReport {
            stdout: document,
            warning: None,
        });
    }
    let ids = member_ids(&team);
    let (members, warning) = match client
        .request(Method::GET, MEMBERS.path, None)
        .await
        .and_then(|answer| listed(MEMBERS, &answer).map(<[Value]>::to_vec))
    {
        Ok(members) => (Some(members), None),
        // The team was read, so show it with the ids it holds rather than
        // fail: reading members needs its own permission.
        Err(error) => {
            (None, Some(format!("warning: could not read the members, so only their ids are shown: {error:#}")))
        }
    };
    let table =
        tables::render_scoped(&tables::AGENT_STREAM_MEMBERS, &member_rows(&ids, members.as_deref()), Scope::All);
    Ok(GetReport {
        stdout: format!("{document}\n\nMembers:\n{}", table.join("\n")),
        warning,
    })
}

/// The rows of the members table of `teams get`: each id of the team with the
/// member `members list` gave for it, or "(not listed)" when the list has
/// none. With no list (`None`, it could not be read), each row is the id
/// alone.
fn member_rows(
    ids: &[String],
    members: Option<&[Value]>,
) -> Vec<Value> {
    ids.iter()
        .map(|member_id| match members {
            None => json!({ "id": member_id }),
            Some(members) => members
                .iter()
                .find(|member| text_field(member, "id") == member_id)
                .map_or_else(|| json!({ "id": member_id, "status": "(not listed)" }), members::list_row),
        })
        .collect()
}

/// The team `teams create` sends: the --file document, or one built from the
/// flags with each member named by identifier looked up through `client`,
/// with an empty `id` for Agent Stream to replace, checked as Agent Stream
/// would check it.
async fn create_body(
    client: Option<&GatewayClient>,
    args: CreateArgs,
) -> Result<Value> {
    let team = match args.file {
        Some(file) => read_json(&file)?,
        None => {
            let name = args.name.unwrap_or_default();
            let mut members = Vec::new();
            for reference in &args.member {
                members.push(Value::String(resolve_member(client, reference).await?));
            }
            let mut team = json!({ "name": name, "members": members });
            if let Some(description) = args.description {
                team["description"] = Value::String(description);
            }
            team
        }
    };
    let team = records::with_empty_id(TEAMS, team)?;
    records::refuse_kept_on_create(TEAMS, &team)?;
    check_team(&team, None)?;
    Ok(team)
}

/// The team `teams update` would save: `before` with the flags applied, or
/// the --file document with the fields Agent Stream keeps put back.
fn updated(
    before: &Value,
    args: &UpdateArgs,
) -> Result<Value> {
    if let Some(file) = &args.file {
        return records::replacement(TEAMS, read_json(file)?, before, &args.id);
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
    Ok(after)
}

/// Whether `teams add-member` or `teams remove-member` is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Membership {
    Add,
    Remove,
}

/// `teams add-member` and `teams remove-member`: reads the team, finds the
/// member, and asks Agent Stream to add or remove it unless the team already
/// is as asked or this is a dry run.
async fn change_member(
    client: &GatewayClient,
    args: MemberChangeArgs,
    membership: Membership,
    output: Output,
) -> Result<()> {
    let team = TEAMS
        .read(client, &args.team)
        .await?;
    records::refuse_deleted(TEAMS, &team, &args.team)?;
    let member_id = resolve_member(Some(client), &args.member).await?;
    let ids = member_ids(&team);
    let present_now = ids.contains(&member_id);
    if present_now == (membership == Membership::Add) {
        let state = if present_now {
            "already in"
        } else {
            "not in"
        };
        eprintln!(
            "Member '{}' is {state} team '{}', so nothing was sent.",
            sanitize_for_terminal(&member_id),
            args.team
        );
        if let Output::Json = output {
            println!("{}", pretty_json_for_terminal(&team)?);
        }
        return Ok(());
    }
    let mut after = team.clone();
    let mut new_ids: Vec<Value> = ids
        .iter()
        .filter(|id| **id != member_id)
        .map(|id| Value::String(id.clone()))
        .collect();
    if membership == Membership::Add {
        new_ids.push(Value::String(member_id.clone()));
    }
    after["members"] = Value::Array(new_ids);
    let change = Change {
        path: "members".to_owned(),
        before: team.get("members").cloned(),
        after: after.get("members").cloned(),
    };
    if args.dry_run {
        println!("{}", records::preview(&[change], &after, output)?);
        return Ok(());
    }
    let team_path = TEAMS.record_path(&args.team)?;
    let (answer, verb, preposition) = match membership {
        Membership::Add => (
            client
                .request(Method::POST, &format!("{team_path}/members"), Some(json!({ "member_id": member_id })))
                .await?,
            "Added",
            "to",
        ),
        Membership::Remove => (
            client
                .request(Method::DELETE, &entity_path(&format!("{team_path}/members"), &member_id), None)
                .await?,
            "Removed",
            "from",
        ),
    };
    let confirmation = format!(
        "{} {preposition} team '{}'",
        confirmation_line(verb, "member", &member_id),
        sanitize_for_terminal(&args.team)
    );
    match output {
        Output::Table => {
            println!("{}\n{confirmation}", records::change_summary(&[change]));
            Ok(())
        }
        Output::Json => print_outcome(&answer, output, &confirmation),
    }
}

/// The id of the member `reference` names: an identifier is looked up in
/// `members list` through `client` and must match exactly one member; any
/// other text is taken as an id.
async fn resolve_member(
    client: Option<&GatewayClient>,
    reference: &str,
) -> Result<String> {
    if !is_identifier(reference) {
        MEMBERS.record_path(reference)?;
        return Ok(reference.to_owned());
    }
    let wanted = parse_identifier(reference)?;
    let client = client.context("a member named by identifier needs a saved login to look it up")?;
    let answer = client
        .request(Method::GET, MEMBERS.path, None)
        .await
        .context("look up the member by identifier")?;
    let matches: Vec<&str> = listed(MEMBERS, &answer)?
        .iter()
        .filter(|member| {
            identifiers_of(member)
                .iter()
                .any(|identifier| same_identifier(identifier, &wanted))
        })
        .map(|member| text_field(member, "id"))
        .collect();
    match matches.as_slice() {
        [id] if !id.is_empty() => Ok((*id).to_owned()),
        [_] => {
            bail!("Agent Stream listed the member with identifier {} without an id", sanitize_for_terminal(reference))
        }
        [] => bail!(
            "no member has identifier {}; see `fabric agent-stream members list`",
            sanitize_for_terminal(reference)
        ),
        _ => bail!("more than one member has identifier {}; name the member by id", sanitize_for_terminal(reference)),
    }
}

/// The member ids of `team`.
fn member_ids(team: &Value) -> Vec<String> {
    team.get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Refuses a team Agent Stream would refuse, or would save without a field it
/// does not know. A field name the `stored` team already has counts as known.
fn check_team(
    team: &Value,
    stored: Option<&Value>,
) -> Result<()> {
    let Some(fields) = team.as_object() else {
        bail!("a team must be a JSON object");
    };
    check_fields(fields, &known_names(&TEAM_FIELDS, stored.into_iter()), "the team")?;
    if text_field(team, "name")
        .trim()
        .is_empty()
    {
        bail!("the team needs a `name` that is not blank");
    }
    records::check_status(TEAMS, fields)?;
    match present(fields.get("members")) {
        None => {}
        Some(Value::Array(members)) => {
            let mut seen = std::collections::BTreeSet::new();
            for member in members {
                let id = member
                    .as_str()
                    .filter(|id| !id.trim().is_empty())
                    .context("each of the team's `members` must be a member id that is not blank")?;
                if !seen.insert(id) {
                    bail!("the team has member '{}' twice", sanitize_for_terminal(id));
                }
            }
        }
        Some(_) => bail!("the team's `members` must be a list of member ids"),
    }
    Ok(())
}

/// The row of `teams list` in table output for `team`: its own fields, with
/// the number of its members in place of their ids.
fn list_row(team: &Value) -> Value {
    let mut row = Map::new();
    for field in ["id", "name", "status", "updated_at"] {
        if let Some(value) = team.get(field) {
            row.insert(field.to_owned(), value.clone());
        }
    }
    row.insert("member_count".to_owned(), json!(member_ids(team).len()));
    Value::Object(row)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        super::test_support::{
            Route, TEST_ACCESS_TOKEN, UnusedKeyring, json_file, request_body, run_stream, saved_login,
            scripted_agent_stream, start_lines, stream_args,
        },
        *,
    };
    use crate::config::Config;

    const TEAM_ID: &str = "0b7e4a52-0000-4000-8000-000000000001";

    const STORED: &str = r#"{"id":"0b7e4a52-0000-4000-8000-000000000001","name":"Research","status":"enabled",
        "system":false,"members":["m-ada"],"monthly_budget_usd":100.0,"monthly_token_cap":5000,
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z"}"#;
    const STORED_LATER: &str = r#"{"id":"0b7e4a52-0000-4000-8000-000000000001","name":"Research","status":"enabled",
        "system":false,"members":["m-ada"],"monthly_budget_usd":100.0,"monthly_token_cap":5000,
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-03T00:00:00Z"}"#;
    const MEMBER_LIST: &str = r#"[
        {"id":"m-ada","name":"Ada","status":"enabled","identifiers":[{"kind":"email","email":"ada@example.com"}]},
        {"id":"m-bob","name":"Bob","status":"enabled","identifiers":[{"kind":"api_key","key_name":"bob-key"}]}]"#;

    const GET_STORED: Route = ("GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED);
    const PUT_OK: Route = ("PUT /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED);
    const MEMBERS_OK: Route = ("GET /api/v1/members", "HTTP/1.1 200 OK", MEMBER_LIST);

    async fn run_teams(
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

    #[test]
    fn member_rows_mark_an_unlisted_member_only_when_the_list_was_read() {
        let ids = vec!["m-ada".to_owned(), "m-gone".to_owned()];
        let listed: Vec<Value> = serde_json::from_str(MEMBER_LIST).unwrap();
        let rows = member_rows(&ids, Some(&listed));
        assert_eq!(rows[0]["identifier_list"], json!("email:ada@example.com"));
        assert_eq!(rows[1], json!({"id":"m-gone","status":"(not listed)"}));
        assert_eq!(member_rows(&ids, None), [json!({"id":"m-ada"}), json!({"id":"m-gone"})]);
    }

    #[test]
    fn list_row_counts_members_instead_of_listing_ids() {
        let stored: Value = serde_json::from_str(STORED).unwrap();
        assert_eq!(
            list_row(&stored),
            json!({"id":TEAM_ID,"name":"Research","status":"enabled","updated_at":"2026-11-02T00:00:00Z",
                   "member_count":1})
        );
    }

    #[tokio::test]
    async fn create_resolves_members_named_by_identifier_and_sends_an_empty_id() {
        let (result, requests) = run_teams(
            &["teams", "create", "--name", "Research", "--member", "email:ADA@example.com", "--member", "m-carol"],
            vec![MEMBERS_OK, ("POST /api/v1/teams", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1", "POST /api/v1/teams HTTP/1.1"]);
        assert_eq!(body_of(&requests, 1), json!({"id":"","name":"Research","members":["m-ada","m-carol"]}));
    }

    #[tokio::test]
    async fn create_stops_when_an_identifier_matches_no_member_and_refuses_a_bad_team() {
        let (result, requests) = run_teams(
            &["teams", "create", "--name", "Research", "--member", "email:nobody@example.com"],
            vec![MEMBERS_OK],
        )
        .await;
        assert!(error_text(result).contains("no member has identifier"));
        assert_eq!(start_lines(&requests), ["GET /api/v1/members HTTP/1.1"]);

        for (document, expected) in [
            (r#"{"name":" "}"#, "`name` that is not blank"),
            (r#"{"name":"R","members":["m-ada","m-ada"]}"#, "twice"),
            (r#"{"name":"R","monthly_budget_usd":10}"#, "can't be set when a team is created"),
            (r#"{"name":"R","membres":[]}"#, "'membres'"),
        ] {
            let file = json_file(document);
            let (result, requests) =
                run_teams(&["teams", "create", "--file", file.path().to_str().unwrap()], vec![]).await;
            assert!(error_text(result).contains(expected), "{document}");
            assert!(start_lines(&requests).is_empty(), "{document}");
        }
    }

    #[tokio::test]
    async fn create_dry_run_with_member_ids_only_needs_no_login() {
        let dir = tempfile::tempdir().unwrap();
        super::super::dispatch_with(
            stream_args(&["teams", "create", "--name", "Research", "--member", "m-ada", "--dry-run"]),
            Config::default(),
            &UnusedKeyring,
            &dir.path()
                .join("agent-stream.toml"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn more_than_one_member_with_the_identifier_is_refused() {
        let twice = r#"[{"id":"m-1","identifiers":[{"kind":"custom","value":"x"}]},
                        {"id":"m-2","identifiers":[{"kind":"custom","value":"X "}]}]"#;
        let (result, requests) = run_teams(
            &["teams", "add-member", TEAM_ID, "custom:x"],
            vec![GET_STORED, ("GET /api/v1/members", "HTTP/1.1 200 OK", twice)],
        )
        .await;
        assert!(error_text(result).contains("more than one member"));
        assert!(
            !start_lines(&requests)
                .iter()
                .any(|line| line.starts_with("POST"))
        );
    }

    #[tokio::test]
    async fn add_member_posts_the_resolved_id_and_skips_a_member_already_in_the_team() {
        let (result, requests) = run_teams(
            &["teams", "add-member", TEAM_ID, "api_key:bob-key"],
            vec![
                GET_STORED,
                MEMBERS_OK,
                ("POST /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members", "HTTP/1.1 200 OK", STORED),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests)[2],
            "POST /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members HTTP/1.1"
        );
        assert_eq!(body_of(&requests, 2), json!({"member_id":"m-bob"}));

        let (result, requests) = run_teams(&["teams", "add-member", TEAM_ID, "m-ada"], vec![GET_STORED]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn remove_member_deletes_by_id_and_a_dry_run_sends_nothing() {
        let (result, requests) = run_teams(
            &["teams", "remove-member", TEAM_ID, "m-ada"],
            vec![
                GET_STORED,
                ("DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members/m-ada", "HTTP/1.1 200 OK", STORED),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests)[1],
            "DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members/m-ada HTTP/1.1"
        );

        let (result, requests) =
            run_teams(&["teams", "remove-member", TEAM_ID, "m-ada", "--dry-run"], vec![GET_STORED]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn remove_member_by_identifier_and_an_unknown_kind_is_refused() {
        let (result, requests) = run_teams(
            &["teams", "remove-member", TEAM_ID, "email:ada@example.com"],
            vec![
                GET_STORED,
                MEMBERS_OK,
                ("DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members/m-ada", "HTTP/1.1 200 OK", STORED),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests)[2],
            "DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members/m-ada HTTP/1.1"
        );

        let (result, requests) =
            run_teams(&["teams", "add-member", TEAM_ID, "emial:ada@example.com"], vec![GET_STORED]).await;
        assert!(error_text(result).contains("must be email, subject, api_key, or custom"));
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn a_team_update_file_can_t_change_its_budget_and_a_stale_one_is_refused() {
        let mut changed: Value = serde_json::from_str(STORED).unwrap();
        changed["monthly_token_cap"] = json!(1);
        let file = json_file(&changed.to_string());
        let (result, requests) =
            run_teams(&["teams", "update", TEAM_ID, "--file", file.path().to_str().unwrap()], vec![GET_STORED, PUT_OK])
                .await;
        assert!(error_text(result).contains("can't change the team's `monthly_token_cap`"));
        assert_eq!(start_lines(&requests).len(), 1);

        let stale = json_file(STORED_LATER);
        let (result, requests) = run_teams(
            &["teams", "update", TEAM_ID, "--file", stale.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("updated_at does not match"));
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn update_keeps_members_and_caps_and_stops_on_a_later_save() {
        let (result, requests) =
            run_teams(&["teams", "update", TEAM_ID, "--name", "Applied"], vec![GET_STORED, PUT_OK]).await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["name"], json!("Applied"));
        assert_eq!(sent["members"], json!(["m-ada"]));
        assert_eq!(sent["monthly_token_cap"], json!(5000));

        let (result, requests) = run_teams(
            &["teams", "update", TEAM_ID, "--status", "disabled"],
            vec![
                GET_STORED,
                ("GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001", "HTTP/1.1 200 OK", STORED_LATER),
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
    async fn get_reads_the_team_then_the_members_and_still_succeeds_when_members_are_refused() {
        let (result, requests) = run_teams(&["teams", "get", TEAM_ID], vec![GET_STORED, MEMBERS_OK]).await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001 HTTP/1.1", "GET /api/v1/members HTTP/1.1"]
        );

        let (result, _) = run_teams(
            &["teams", "get", TEAM_ID],
            vec![GET_STORED, ("GET /api/v1/members", "HTTP/1.1 403 Forbidden", "")],
        )
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn delete_shows_the_built_in_team_refusal() {
        let (result, _) = run_teams(
            &["teams", "delete", "anonymous"],
            vec![(
                "DELETE /api/v1/teams/anonymous",
                "HTTP/1.1 400 Bad Request",
                "This is a built-in system team and cannot be deleted. Disable it instead.",
            )],
        )
        .await;
        assert!(error_text(result).contains("Disable it instead"));
    }

    #[tokio::test]
    async fn update_file_replaces_the_team_and_a_dry_run_sends_nothing() {
        let mut document: Value = serde_json::from_str(STORED).unwrap();
        document["description"] = json!("Applied research");
        let file = json_file(&document.to_string());
        let (result, requests) =
            run_teams(&["teams", "update", TEAM_ID, "--file", file.path().to_str().unwrap()], vec![GET_STORED, PUT_OK])
                .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["description"], json!("Applied research"));
        assert_eq!(sent["members"], json!(["m-ada"]));

        let (result, requests) =
            run_teams(&["teams", "update", TEAM_ID, "--name", "Applied", "--dry-run"], vec![GET_STORED, PUT_OK]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn add_member_with_json_output_and_a_successful_delete() {
        let (result, requests) = run_teams(
            &["-o", "json", "teams", "add-member", TEAM_ID, "m-bob"],
            vec![
                GET_STORED,
                ("POST /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members", "HTTP/1.1 200 OK", STORED),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001 HTTP/1.1",
                "POST /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001/members HTTP/1.1"
            ]
        );

        let (result, requests) = run_teams(
            &["teams", "delete", TEAM_ID],
            vec![("DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001", "HTTP/1.1 204 No Content", "")],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn get_prints_the_team_then_a_table_of_its_members_with_their_identifiers() {
        let (host, _) = scripted_agent_stream(vec![GET_STORED, MEMBERS_OK]).await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let report = get_report(&client, TEAM_ID, Output::Table)
            .await
            .unwrap();
        assert_eq!(report.warning, None);
        assert!(
            report
                .stdout
                .contains("\"name\": \"Research\""),
            "{}",
            report.stdout
        );
        let table = report
            .stdout
            .split("\n\nMembers:\n")
            .nth(1)
            .unwrap_or_else(|| panic!("no members table:\n{}", report.stdout));
        assert!(table.starts_with("ID") && table.contains("IDENTIFIERS"), "{table}");
        let row = table
            .lines()
            .find(|line| line.starts_with("m-ada"))
            .unwrap_or_else(|| panic!("no m-ada row:\n{table}"));
        assert!(row.contains("Ada") && row.contains("email:ada@example.com") && row.contains("enabled"), "{row}");
        assert!(!table.contains("m-bob"), "a member of no team is shown:\n{table}");
    }

    #[tokio::test]
    async fn get_warns_and_shows_only_member_ids_when_the_member_list_is_refused() {
        let (host, _) = scripted_agent_stream(vec![
            GET_STORED,
            ("GET /api/v1/members", "HTTP/1.1 403 Forbidden", "Insufficient permissions"),
        ])
        .await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let report = get_report(&client, TEAM_ID, Output::Table)
            .await
            .unwrap();
        let warning = report
            .warning
            .expect("a warning on standard error");
        assert!(warning.starts_with("warning: could not read the members, so only their ids are shown: "), "{warning}");
        assert!(warning.contains("Insufficient permissions"), "{warning}");
        assert!(!warning.contains(TEST_ACCESS_TOKEN), "{warning}");
        let table = report
            .stdout
            .split("\n\nMembers:\n")
            .nth(1)
            .unwrap();
        let row = table
            .lines()
            .find(|line| line.starts_with("m-ada"))
            .unwrap_or_else(|| panic!("{table}"));
        assert!(!row.contains("(not listed)") && !row.contains("email:"), "{row}");
    }

    #[tokio::test]
    async fn get_with_json_output_prints_the_team_only_and_reads_no_members() {
        let (host, requests) = scripted_agent_stream(vec![GET_STORED, MEMBERS_OK]).await;
        let client = GatewayClient::for_agent_stream(host, TEST_ACCESS_TOKEN).unwrap();
        let report = get_report(&client, TEAM_ID, Output::Json)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&report.stdout).unwrap(),
            serde_json::from_str::<Value>(STORED).unwrap()
        );
        assert_eq!(start_lines(&requests), ["GET /api/v1/teams/0b7e4a52-0000-4000-8000-000000000001 HTTP/1.1"]);
    }

    const DELETED_TEAM: &str =
        r#"{"id":"t-gone","name":"Gone","status":"deleted","members":["m-ada"],"updated_at":"2026-11-02T00:00:00Z"}"#;

    #[tokio::test]
    async fn add_member_and_remove_member_refuse_a_deleted_team_after_reading_it() {
        for words in [&["teams", "add-member", "t-gone", "m-bob"][..], &["teams", "remove-member", "t-gone", "m-ada"]] {
            let (result, requests) =
                run_teams(words, vec![("GET /api/v1/teams/t-gone", "HTTP/1.1 200 OK", DELETED_TEAM)]).await;
            assert!(error_text(result).contains("team 't-gone' is deleted, so it can't be changed"), "{words:?}");
            assert_eq!(start_lines(&requests), ["GET /api/v1/teams/t-gone HTTP/1.1"], "{words:?}");
        }
    }

    #[tokio::test]
    async fn a_create_agent_stream_never_answers_says_the_team_may_exist_and_what_to_check() {
        let (host, requests) = super::super::records::tests::answering_reads_dropping_writes("[]").await;
        let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
        let result =
            run_stream(&["teams", "create", "--name", "Research", "--member", "m-ada"], saved, &credentials).await;
        let text = error_text(result);
        assert!(
            text.starts_with(
                "Agent Stream gave no answer, so the team may have been created anyway; Agent Stream allows two \
                 teams with one name, so check `fabric agent-stream teams list` before running this again: "
            ),
            "{text}"
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .as_slice(),
            ["POST /api/v1/teams HTTP/1.1"]
        );
    }
}
