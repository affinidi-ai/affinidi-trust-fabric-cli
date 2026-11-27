//! `fabric agent-stream governance`: reading governance records and checking
//! that each surface's record chain is intact.
//!
//! A governance record carries the caller's prompt and the model's answer, so
//! the commands hide that content (see [`prompt_content`]) and offer no way to
//! read records in bulk: a list is one page of at most [`MAX_LIMIT`] records,
//! as in the Agent Stream dashboard, which has no download either.

use anyhow::{Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use reqwest::Method;
use serde_json::{Value, json};

use super::{
    prompt_content::{self, Item, LIST_MASKED_VALUE, REVEAL_WARNING},
    request::{Permission, name_missing_surface, name_permission, path_id, with_query},
    when::parse_moment,
};
use crate::{
    client::GatewayClient,
    commands::{MASKED_VALUE, Output, print_list, print_value, unix_now},
    tables::{self, Scope, flatten},
};

const RECORDS_PATH: &str = "/v1/governance/records";
const VERIFY_PATH: &str = "/v1/governance/verify";
const SURFACES_PATH: &str = "/v1/governance/surfaces";
const COVERAGE_PATH: &str = "/v1/governance/coverage";

/// The header Agent Stream names the next page's cursor in, present only when
/// another matching record exists.
const NEXT_CURSOR_HEADER: &str = "x-next-cursor";

/// Records a list shows when --limit is not given.
const DEFAULT_LIMIT: u32 = 50;
/// The most records one list shows. Agent Stream itself has no maximum and
/// returns every record when no limit is sent, which would be a download.
pub const MAX_LIMIT: u32 = 500;

/// Longest record id Agent Stream accepts.
const MAX_RECORD_ID: usize = 64;

/// The chain problems that are security findings rather than faults to
/// repair, each with what it means. `index_mismatch` is also one Agent Stream
/// repairs during the same check, by rebuilding the index, so the next
/// `verify` shows the surface as valid and only this run shows the finding.
const SECURITY_PROBLEMS: &[(&str, &str)] = &[
    ("broken", "a record was changed or removed"),
    ("truncated", "the newest records are missing from the log"),
    (
        "index_mismatch",
        "the record index no longer matched the log. Agent Stream rebuilt the index during this check, so the next \
         verify will show the surface as valid and only this output records the finding",
    ),
];

/// The problem shown for a surface whose chain check could not be run, such
/// as one Agent Stream refused or could not find.
const NOT_CHECKED: &str = "not_checked";

#[derive(Debug, Subcommand)]
pub enum GovernanceCommand {
    /// List and view governance records.
    ///
    /// Agent Stream keeps one signed record per model call on a surface that
    /// records them, chained to the record before it so a change shows.
    Records {
        #[command(subcommand)]
        command: RecordCommand,
    },
    /// Check that governance record chains are intact.
    ///
    /// Agent Stream checks a surface's whole chain: every record's hash and
    /// signature, the link to the record before it, and that the chain reaches
    /// its last record. Without --surface, every surface in `governance
    /// surfaces` is checked. Prints, for each surface, whether its chain is
    /// valid, how many records were checked, and the problem found: `broken` (a
    /// record changed or is missing), `unknown_key`, `truncated` (the newest
    /// records are missing), or `index_mismatch`, or `not_checked` when the
    /// check could not be run for that surface (its error is shown, and the
    /// other surfaces are still checked). A `broken`, `truncated` or
    /// `index_mismatch` chain is reported as a security finding on standard
    /// error. The CLI repairs nothing, but Agent Stream rebuilds the index
    /// during a check that finds `index_mismatch`, so only that run shows it:
    /// keep its output.
    ///
    /// With --surface, an error checking that surface, such as a refusal, is
    /// shown as it is. A surface with no records, a mistyped ID included,
    /// verifies as valid with 0 records, since Agent Stream does not check that
    /// it exists.
    ///
    /// The command exits 1 when any chain is not valid or not checked.
    #[command(after_long_help = VERIFY_EXAMPLES)]
    Verify(VerifyArgs),
    /// Show which LLM Surfaces record governance records and export them.
    ///
    /// RECORDING is whether the surface records governance records, EXPORT
    /// whether it sends them to an integration or OpenTelemetry, and PIPE
    /// EVENTS whether it sends surface events.
    #[command(after_long_help = COVERAGE_EXAMPLES)]
    Coverage {
        /// Only surfaces that do not record or do not export.
        #[arg(long)]
        gaps_only: bool,
    },
    /// List the surfaces that have governance records.
    ///
    /// Includes deleted surfaces, whose records Agent Stream keeps, named as
    /// their latest record names them.
    #[command(after_long_help = SURFACES_EXAMPLES)]
    Surfaces,
}

#[derive(Debug, Subcommand)]
pub enum RecordCommand {
    /// List one page of a surface's governance records, newest first.
    ///
    /// Shows the time, record id, outcome (`ok`, `blocked`, or `failed`),
    /// model, tokens, cost, and position in the chain (SEQ). Prompts, answers
    /// and stage bodies are never shown in a list, even with --output json,
    /// where they are replaced with a placeholder.
    ///
    /// A page has at most 500 records and there is no way to read every
    /// record at once. When more records match, the cursor of the next page is
    /// printed on standard error (in `next_cursor` with --output json); pass
    /// it to --cursor with the same filters.
    #[command(after_long_help = LIST_EXAMPLES)]
    List(RecordListArgs),
    /// Get one governance record, with its prompt content hidden.
    ///
    /// Shows the record's stages, metrics, attribution and hashes. The
    /// caller's prompt, the model's answer, each stage's input, output and
    /// reason, the attachments' file names and the signed credential (which holds the
    /// whole record) are replaced with a placeholder unless --reveal is given.
    #[command(after_long_help = GET_EXAMPLES)]
    Get(RecordGetArgs),
}

#[derive(Debug, Args)]
pub struct RecordListArgs {
    /// ID of the surface whose records to list (see `fabric agent-stream
    /// governance surfaces`).
    #[arg(long)]
    surface: String,
    /// Records on this page, from 1 to 500.
    #[arg(long, default_value_t = DEFAULT_LIMIT, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_LIMIT)))]
    limit: u32,
    /// Cursor of the page to read, as printed by the previous page.
    #[arg(long)]
    cursor: Option<u64>,
    /// Only records with these outcomes, comma-separated.
    #[arg(long, value_enum, value_delimiter = ',')]
    outcome: Vec<Outcome>,
    /// Only records blocked or failed at these stages, comma-separated, such
    /// as judge,jury,policy.
    #[arg(long, value_delimiter = ',')]
    stage: Vec<String>,
    /// Only records at or after this time: an RFC 3339 time
    /// (2026-11-20T09:00:00Z), unix seconds, or a duration before now (30m,
    /// 24h, 7d).
    #[arg(long)]
    since: Option<String>,
    /// Only records before this time, in the forms --since takes.
    #[arg(long)]
    until: Option<String>,
    /// Order of the records: newest first (desc) or oldest first (asc).
    #[arg(long, value_enum, default_value_t = Order::Desc)]
    order: Order,
}

#[derive(Debug, Args)]
pub struct RecordGetArgs {
    /// ID of the record (`record_id`, see `governance records list`).
    record_id: String,
    /// ID of the surface the record belongs to.
    #[arg(long)]
    surface: String,
    /// Show the prompt, the answer, stage inputs, outputs and reasons,
    /// attachment file names and the signed credential. When there are any, a warning is
    /// printed on standard error, since they can hold personal data.
    #[arg(long)]
    reveal: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Check only this surface's chain.
    #[arg(long)]
    surface: Option<String>,
}

/// How a governance record's interaction ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Outcome {
    /// No stage blocked or failed it.
    Ok,
    /// A stage blocked it.
    Blocked,
    /// A stage failed, and none blocked it.
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }
}

/// The order a list of records is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Order {
    /// Newest first.
    Desc,
    /// Oldest first.
    Asc,
}

impl Order {
    fn as_str(self) -> &'static str {
        match self {
            Self::Desc => "desc",
            Self::Asc => "asc",
        }
    }
}

/// Examples shown at the bottom of `records list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  The 50 newest records of a surface:
    fabric agent-stream governance records list --surface support-bot

  Blocked records from the last day, then the next page:
    fabric agent-stream governance records list --surface support-bot \
      --outcome blocked --since 24h
    fabric agent-stream governance records list --surface support-bot \
      --outcome blocked --since 24h --cursor 4182"#;

/// Examples shown at the bottom of `records get --help`.
const GET_EXAMPLES: &str = r#"Examples:
  View a record's stages and metrics:
    fabric agent-stream governance records get 6f1c2a9e-5b7d-4c1e-9a3f-2d8b7e6c5a41 \
      --surface support-bot

  Show its prompt and answer too (prints a warning):
    fabric agent-stream governance records get 6f1c2a9e-5b7d-4c1e-9a3f-2d8b7e6c5a41 \
      --surface support-bot --reveal"#;

/// Examples shown at the bottom of `verify --help`.
const VERIFY_EXAMPLES: &str = r#"Examples:
  Check every surface's chain, and fail a script when one is not intact:
    fabric agent-stream governance verify

  Check one surface:
    fabric agent-stream governance verify --surface support-bot"#;

/// Examples shown at the bottom of `coverage --help`.
const COVERAGE_EXAMPLES: &str = r#"Examples:
  Find the LLM Surfaces that do not record or do not export:
    fabric agent-stream governance coverage --gaps-only"#;

/// Examples shown at the bottom of `surfaces --help`.
const SURFACES_EXAMPLES: &str = r#"Examples:
  Find a surface's id before listing its records:
    fabric agent-stream governance surfaces
    fabric agent-stream governance records list --surface support-bot"#;

/// Runs one `governance` command.
pub async fn run(
    client: &GatewayClient,
    command: GovernanceCommand,
    output: Output,
) -> Result<()> {
    match command {
        GovernanceCommand::Records {
            command: RecordCommand::List(args),
        } => list_records(client, args, output).await,
        GovernanceCommand::Records {
            command: RecordCommand::Get(args),
        } => get_record(client, args, output).await,
        GovernanceCommand::Verify(args) => verify(client, args, output).await,
        GovernanceCommand::Coverage { gaps_only } => {
            let path = with_query(COVERAGE_PATH, &[("gaps_only", gaps_only.then(|| "true".to_owned()))]);
            let value = read(client, &path).await?;
            let scope = if gaps_only {
                Scope::Filtered
            } else {
                Scope::All
            };
            print_list(&value, output, &tables::GOVERNANCE_COVERAGE, scope)
        }
        GovernanceCommand::Surfaces => {
            let value = read(client, SURFACES_PATH).await?;
            print_list(&value, output, &tables::GOVERNANCE_SURFACES, Scope::All)
        }
    }
}

/// A `GET` that needs `governance.view`.
async fn read(
    client: &GatewayClient,
    path: &str,
) -> Result<Value> {
    name_permission(
        client
            .request(Method::GET, path, None)
            .await,
        Permission::GovernanceView,
    )
}

/// The query of a `records list`, with each time read as unix seconds.
fn list_query(
    args: &RecordListArgs,
    now: u64,
) -> Result<String> {
    for stage in &args.stage {
        path_id("--stage", stage, 64)?;
    }
    let since = args
        .since
        .as_deref()
        .map(|text| parse_moment("--since", text, now))
        .transpose()?;
    let until = args
        .until
        .as_deref()
        .map(|text| parse_moment("--until", text, now))
        .transpose()?;
    if let (Some(since), Some(until)) = (since, until)
        && since >= until
    {
        bail!("--since must be before --until");
    }
    let join = |items: Vec<&str>| (!items.is_empty()).then(|| items.join(","));
    Ok(with_query(
        RECORDS_PATH,
        &[
            ("surface_id", Some(args.surface.clone())),
            ("limit", Some(args.limit.to_string())),
            ("order", Some(args.order.as_str().to_owned())),
            // Oldest first with no cursor would get the newest page in
            // ascending order from Agent Stream, with no next page; starting
            // from position 0 reads from the first record forward.
            (
                "cursor",
                args.cursor
                    .or_else(|| (args.order == Order::Asc).then_some(0))
                    .map(|cursor| cursor.to_string()),
            ),
            (
                "outcome",
                join(
                    args.outcome
                        .iter()
                        .map(|outcome| outcome.as_str())
                        .collect(),
                ),
            ),
            (
                "stage",
                join(
                    args.stage
                        .iter()
                        .map(String::as_str)
                        .collect(),
                ),
            ),
            ("since", since.map(|seconds| seconds.to_string())),
            ("until", until.map(|seconds| seconds.to_string())),
        ],
    ))
}

async fn list_records(
    client: &GatewayClient,
    args: RecordListArgs,
    output: Output,
) -> Result<()> {
    let (records, next_cursor) = fetch_page(client, &args).await?;
    match output {
        Output::Json => print_value(&list_json(records, next_cursor), output)?,
        Output::Table => {
            let rows: Vec<Value> = records
                .iter()
                .map(summary_row)
                .collect();
            let filtered = !args.outcome.is_empty()
                || !args.stage.is_empty()
                || args.since.is_some()
                || args.until.is_some()
                || args.cursor.is_some();
            let scope = if filtered {
                Scope::Filtered
            } else {
                Scope::All
            };
            print_list(&Value::Array(rows), output, &tables::GOVERNANCE_RECORDS, scope)?;
            if let Some(cursor) = &next_cursor {
                eprintln!("{}", next_page_hint(cursor));
            }
        }
    }
    Ok(())
}

/// What `records list --output json` prints: the page's records and the
/// cursor of the next page, or null on the last page.
fn list_json(
    records: Vec<Value>,
    next_cursor: Option<String>,
) -> Value {
    json!({ "records": records, "next_cursor": next_cursor })
}

/// The line table output prints on standard error when more records match.
fn next_page_hint(cursor: &str) -> String {
    format!("More records match; pass --cursor {cursor} with the same options for the next page.")
}

/// One page of records, with their prompt content masked, and the cursor of
/// the next page from Agent Stream's `x-next-cursor` header.
async fn fetch_page(
    client: &GatewayClient,
    args: &RecordListArgs,
) -> Result<(Vec<Value>, Option<String>)> {
    let path = list_query(args, unix_now())?;
    let (value, headers) = name_missing_surface(
        name_permission(
            client
                .get_with_headers(&path)
                .await,
            Permission::GovernanceView,
        ),
        &args.surface,
    )?;
    let Value::Array(mut records) = value else {
        bail!("Agent Stream answered the records list with something other than a list");
    };
    // A page is never longer than asked for, so a list can never turn into a
    // download. A server that ignored the limit is refused rather than cut
    // short, since cutting would skip records between pages.
    if records.len() > args.limit as usize {
        bail!(
            "Agent Stream answered with {} records, more than the {} asked for; nothing was printed",
            records.len(),
            args.limit
        );
    }
    for record in &records {
        require_stored_record(record)?;
    }
    let next_cursor = next_cursor(&headers);
    for record in &mut records {
        prompt_content::mask(record, Item::GovernanceRecord, LIST_MASKED_VALUE);
    }
    Ok((records, next_cursor))
}

/// The cursor of the next page, from the `x-next-cursor` header, when it is a
/// record position (digits only) as Agent Stream writes it.
fn next_cursor(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(NEXT_CURSOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|cursor| {
            !cursor.is_empty()
                && cursor
                    .chars()
                    .all(|c| c.is_ascii_digit())
        })
        .map(str::to_owned)
}

/// The row a record gets in the table of `records list`: its time, id,
/// outcome, model, tokens, cost and chain position, and nothing else.
fn summary_row(stored: &Value) -> Value {
    let record = &stored["record"];
    let metrics = record
        .get("metrics")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "timestamp": record.get("timestamp"),
        "record_id": record.get("record_id"),
        "outcome": outcome_of(record),
        "model": metrics.get("model"),
        "total_tokens": metrics.get("total_tokens"),
        "cost": metrics.get("cost"),
        "seq": stored.get("seq"),
    })
}

/// Refuses a record that is not in the shape Agent Stream stores it in, an
/// object with the record under `record`, since the prompt content could then
/// sit where [`prompt_content::mask`] does not look for it.
fn require_stored_record(stored: &Value) -> Result<()> {
    if !stored
        .get("record")
        .is_some_and(Value::is_object)
    {
        bail!("Agent Stream answered with a governance record in a shape this CLI does not know; nothing was printed");
    }
    Ok(())
}

/// How a record's interaction ended, read off its stages the way Agent Stream
/// reads it: `blocked` when any stage blocked it, else `failed` when any stage
/// failed, else `ok`.
fn outcome_of(record: &Value) -> &'static str {
    let outcomes: Vec<&str> = record
        .get("stages")
        .and_then(Value::as_array)
        .map(|stages| {
            stages
                .iter()
                .filter_map(|stage| {
                    stage
                        .get("outcome")
                        .and_then(Value::as_str)
                })
                .collect()
        })
        .unwrap_or_default();
    if outcomes.contains(&"block") {
        "blocked"
    } else if outcomes.contains(&"error") {
        "failed"
    } else {
        "ok"
    }
}

async fn get_record(
    client: &GatewayClient,
    args: RecordGetArgs,
    output: Output,
) -> Result<()> {
    let id = path_id("record id", &args.record_id, MAX_RECORD_ID)?;
    let path = with_query(&format!("{RECORDS_PATH}/{id}"), &[("surface_id", Some(args.surface.clone()))]);
    let mut record = name_missing_surface(read(client, &path).await, &args.surface)?;
    require_stored_record(&record)?;
    if args.reveal {
        if prompt_content::count(&record, Item::GovernanceRecord) > 0 {
            eprintln!("{REVEAL_WARNING}");
        }
    } else {
        prompt_content::mask(&mut record, Item::GovernanceRecord, MASKED_VALUE);
    }
    print_value(&record, output)
}

async fn verify(
    client: &GatewayClient,
    args: VerifyArgs,
    output: Output,
) -> Result<()> {
    let (surfaces, single) = match args.surface {
        Some(surface) => (vec![surface], true),
        None => {
            // A list this CLI can't read fails the command, so it never
            // reports success for surfaces it did not check.
            let listed = read(client, SURFACES_PATH).await?;
            let Some(listed) = listed.as_array() else {
                bail!("Agent Stream answered the governance surfaces list with something other than a list");
            };
            let listed = listed
                .iter()
                .map(|surface| {
                    surface
                        .get("surface_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("Agent Stream listed a governance surface without a surface_id"))
                })
                .collect::<Result<Vec<_>>>()?;
            (listed, false)
        }
    };
    let mut verdicts = Vec::with_capacity(surfaces.len());
    for surface in &surfaces {
        let path = with_query(VERIFY_PATH, &[("surface_id", Some(surface.clone()))]);
        // A surface whose check fails to run is shown as not valid and the
        // others are still checked, so one error never hides another
        // surface's finding.
        let verdict = match name_missing_surface(read(client, &path).await, surface) {
            Ok(verdict) => verdict,
            // With one --surface, its error is the answer: shown as it is.
            Err(error) if single => return Err(error),
            Err(error) => json!({
                "surface_id": surface,
                "valid": false,
                "problem": NOT_CHECKED,
                "error": format!("{error:#}"),
            }),
        };
        verdicts.push(verdict);
    }
    match output {
        Output::Json => print_value(&Value::Array(verdicts.clone()), output)?,
        Output::Table => print_list(&Value::Array(verdicts.clone()), output, &tables::GOVERNANCE_VERIFY, Scope::All)?,
    }
    let failed: Vec<&Value> = verdicts
        .iter()
        .filter(|verdict| {
            verdict
                .get("valid")
                .and_then(Value::as_bool)
                != Some(true)
        })
        .collect();
    for verdict in &failed {
        let problem = verdict
            .get("problem")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Some((_, meaning)) = SECURITY_PROBLEMS
            .iter()
            .find(|(name, _)| *name == problem)
        {
            let surface = verdict
                .get("surface_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            eprintln!(
                "security finding: the governance record chain of surface '{}' is {}: {meaning}. Don't try to repair \
                 anything; keep the records as they are and investigate.",
                flatten(surface),
                flatten(problem)
            );
        }
    }
    if !failed.is_empty() {
        let not_checked = failed
            .iter()
            .filter(|verdict| {
                verdict
                    .get("problem")
                    .and_then(Value::as_str)
                    == Some(NOT_CHECKED)
            })
            .count();
        bail!("{}", verify_summary(failed.len() - not_checked, not_checked, verdicts.len()));
    }
    Ok(())
}

/// The error a `verify` with failures ends with, counting chains that are not
/// valid apart from those that could not be checked.
fn verify_summary(
    not_valid: usize,
    not_checked: usize,
    total: usize,
) -> String {
    match (not_valid, not_checked) {
        (n, 0) => format!("{n} of {total} governance record chains are not valid"),
        (0, m) => format!("{m} of {total} governance record chains could not be checked"),
        (n, m) => format!("{n} of {total} governance record chains are not valid and {m} could not be checked"),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::agent_stream::test_support::{Route, scripted_agent_stream, start_lines};

    const TOKEN: &str = "aspat_governance";

    /// The `governance` subcommand alone, parsed as clap parses it under
    /// `fabric agent-stream`.
    #[derive(Debug, Parser)]
    struct Governance {
        #[command(subcommand)]
        command: GovernanceCommand,
    }

    fn try_parse(args: &[&str]) -> Result<GovernanceCommand, clap::Error> {
        let mut argv = vec!["governance"];
        argv.extend_from_slice(args);
        Governance::try_parse_from(argv).map(|parsed| parsed.command)
    }

    fn parse(args: &[&str]) -> GovernanceCommand {
        try_parse(args).expect("parse")
    }

    async fn run_with(
        routes: Vec<Route>,
        args: &[&str],
        output: Output,
    ) -> (Result<()>, Vec<String>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let client = GatewayClient::for_agent_stream(host, TOKEN.to_owned()).expect("client");
        let result = run(&client, parse(args), output).await;
        (result, start_lines(&requests))
    }

    const RECORD: &str = r#"[{"record":{"record_id":"r1","timestamp":"2026-11-20T09:00:00Z","prompt":"card 4111","completion":"ok","stages":[{"stage":"judge","outcome":"block","input":"card 4111"}],"metrics":{"model":"gpt-4o","total_tokens":12,"cost":0.01}},"signed_vc":{"credentialSubject":{"prompt":"card 4111"}},"seq":41}]"#;

    #[tokio::test]
    async fn test_records_list_sends_one_page_newest_first() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/governance/records?surface_id=s1&limit=50&order=desc",
                "HTTP/1.1 200 OK\r\nx-next-cursor: 40",
                RECORD,
            )],
            &["records", "list", "--surface", "s1"],
            Output::Table,
        )
        .await;
        result.expect("list");
        assert_eq!(requests, ["GET /api/v1/governance/records?surface_id=s1&limit=50&order=desc HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_records_page_carries_the_next_cursor_into_the_output() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/v1/governance/records?surface_id=s1&limit=50&order=desc",
            "HTTP/1.1 200 OK\r\nx-next-cursor: 40",
            RECORD,
        )])
        .await;
        let client = GatewayClient::for_agent_stream(host, TOKEN.to_owned()).expect("client");
        let GovernanceCommand::Records {
            command: RecordCommand::List(args),
        } = parse(&["records", "list", "--surface", "s1"])
        else {
            panic!("expected records list");
        };
        let (records, next_cursor) = fetch_page(&client, &args)
            .await
            .expect("page");
        assert_eq!(next_cursor.as_deref(), Some("40"));
        let output = list_json(records, next_cursor);
        assert_eq!(output["next_cursor"], json!("40"));
        assert_eq!(output["records"][0]["record"]["prompt"], json!(LIST_MASKED_VALUE));
        assert_eq!(
            next_page_hint("40"),
            "More records match; pass --cursor 40 with the same options for the next page."
        );
        assert_eq!(list_json(Vec::new(), None)["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn test_records_list_oldest_first_starts_from_the_first_record() {
        let (result, requests) = run_with(
            vec![("GET /api/v1/governance/records?surface_id=s1&limit=50&order=asc&cursor=0", "HTTP/1.1 200 OK", "[]")],
            &["records", "list", "--surface", "s1", "--order", "asc"],
            Output::Json,
        )
        .await;
        result.expect("list");
        assert_eq!(requests, ["GET /api/v1/governance/records?surface_id=s1&limit=50&order=asc&cursor=0 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_verify_one_surface_shows_its_error_as_it_is() {
        let (result, _) = run_with(
            vec![("GET /api/v1/governance/verify?surface_id=s1", "HTTP/1.1 403 Forbidden", "Insufficient permissions")],
            &["verify", "--surface", "s1"],
            Output::Table,
        )
        .await;
        let error = result
            .expect_err("refused")
            .to_string();
        assert!(error.starts_with("Insufficient permissions; this needs the `governance.view` permission"), "{error}");
        assert!(!error.contains("not valid"), "{error}");
    }

    #[test]
    fn test_verify_summary_counts_not_valid_apart_from_not_checked() {
        assert_eq!(verify_summary(2, 0, 5), "2 of 5 governance record chains are not valid");
        assert_eq!(verify_summary(0, 1, 5), "1 of 5 governance record chains could not be checked");
        assert_eq!(verify_summary(1, 2, 5), "1 of 5 governance record chains are not valid and 2 could not be checked");
    }

    #[test]
    fn test_security_problems_include_truncated_and_index_mismatch() {
        let names: Vec<&str> = SECURITY_PROBLEMS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(names, ["broken", "truncated", "index_mismatch"]);
        assert!(
            SECURITY_PROBLEMS[2]
                .1
                .contains("rebuilt the index")
        );
    }

    #[tokio::test]
    async fn test_records_list_sends_filters_and_cursor() {
        let (result, requests) = run_with(
            vec![("GET /api/v1/governance/records?surface_id=s1&limit=10&order=asc&cursor=40&outcome=blocked%2Cfailed&stage=judge%2Cjury&since=1700000000&until=1700006400", "HTTP/1.1 200 OK", "[]")],
            &[
                "records",
                "list",
                "--surface",
                "s1",
                "--limit",
                "10",
                "--cursor",
                "40",
                "--outcome",
                "blocked,failed",
                "--stage",
                "judge,jury",
                "--since",
                "1700000000",
                "--until",
                "2023-11-15T00:00:00Z",
                "--order",
                "asc",
            ],
            Output::Json,
        )
        .await;
        result.expect("list");
        assert_eq!(
            requests,
            [
                "GET /api/v1/governance/records?surface_id=s1&limit=10&order=asc&cursor=40&outcome=blocked%2Cfailed&stage=judge%2Cjury&since=1700000000&until=1700006400 HTTP/1.1"
            ]
        );
    }

    #[test]
    fn test_records_list_refuses_a_limit_over_the_maximum() {
        let error = try_parse(&["records", "list", "--surface", "s1", "--limit", "501"]).expect_err("over the maximum");
        assert!(
            error
                .to_string()
                .contains("501"),
            "{error}"
        );
        assert!(try_parse(&["records", "list", "--surface", "s1", "--all"]).is_err());
    }

    #[test]
    fn test_list_query_refuses_a_bad_window_before_sending() {
        let RecordCommand::List(args) =
            (match parse(&["records", "list", "--surface", "s1", "--since", "1h", "--until", "2h"]) {
                GovernanceCommand::Records { command } => command,
                other => panic!("expected records, got {other:?}"),
            })
        else {
            panic!("expected list");
        };
        let error = list_query(&args, 1_764_000_000).expect_err("since after until");
        assert_eq!(error.to_string(), "--since must be before --until");
    }

    #[test]
    fn test_summary_row_has_no_prompt_content() {
        let records: Value = serde_json::from_str(RECORD).expect("json");
        let row = summary_row(&records[0]);
        assert_eq!(
            row,
            json!({"timestamp": "2026-11-20T09:00:00Z", "record_id": "r1", "outcome": "blocked", "model": "gpt-4o", "total_tokens": 12, "cost": 0.01, "seq": 41})
        );
    }

    #[test]
    fn test_help_text_states_the_page_limit_and_the_hidden_content() {
        use clap::CommandFactory;

        let mut command = Governance::command();
        let list = command
            .find_subcommand_mut("records")
            .and_then(|records| records.find_subcommand_mut("list"))
            .expect("records list")
            .render_long_help()
            .to_string();
        assert!(list.contains("at most 500 records"), "{list}");
        assert!(list.contains("--cursor"), "{list}");
        assert!(!list.contains("--all"), "{list}");
        let get = command
            .find_subcommand_mut("records")
            .and_then(|records| records.find_subcommand_mut("get"))
            .expect("records get")
            .render_long_help()
            .to_string();
        assert!(get.contains("--reveal"), "{get}");
        assert!(get.contains("replaced with a placeholder"), "{get}");
        assert!(get.contains("Examples:"), "{get}");
    }

    #[test]
    fn test_next_cursor_reads_only_a_record_position() {
        use reqwest::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        assert_eq!(next_cursor(&headers), None);
        headers.insert(NEXT_CURSOR_HEADER, HeaderValue::from_static("40"));
        assert_eq!(next_cursor(&headers), Some("40".to_owned()));
        for bad in ["", "4a", "-1", "\u{1b}"] {
            if let Ok(value) = HeaderValue::from_str(bad) {
                headers.insert(NEXT_CURSOR_HEADER, value);
                assert_eq!(next_cursor(&headers), None, "{bad:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_records_list_refuses_a_page_longer_than_asked_for() {
        let (result, _) = run_with(
            vec![(
                "GET /api/v1/governance/records?surface_id=s1&limit=1&order=desc",
                "HTTP/1.1 200 OK",
                r#"[{"record":{"record_id":"a"}},{"record":{"record_id":"b"}}]"#,
            )],
            &["records", "list", "--surface", "s1", "--limit", "1"],
            Output::Json,
        )
        .await;
        let error = result
            .expect_err("too many")
            .to_string();
        assert_eq!(error, "Agent Stream answered with 2 records, more than the 1 asked for; nothing was printed");
    }

    #[tokio::test]
    async fn test_records_get_refuses_an_unknown_shape() {
        let (result, _) = run_with(
            vec![(
                "GET /api/v1/governance/records/r1?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"{"record_id":"r1","prompt":"secret"}"#,
            )],
            &["records", "get", "r1", "--surface", "s1"],
            Output::Json,
        )
        .await;
        assert!(
            result
                .expect_err("unwrapped record")
                .to_string()
                .contains("shape this CLI does not know")
        );
    }

    #[tokio::test]
    async fn test_verify_fails_when_the_surfaces_list_is_unreadable() {
        let (result, requests) = run_with(
            vec![("GET /api/v1/governance/surfaces", "HTTP/1.1 200 OK", r#"{"surfaces":[]}"#)],
            &["verify"],
            Output::Json,
        )
        .await;
        assert!(
            result
                .expect_err("not a list")
                .to_string()
                .contains("something other than a list")
        );
        assert_eq!(requests, ["GET /api/v1/governance/surfaces HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_verify_checks_the_other_surfaces_after_one_fails_to_run() {
        let (result, requests) = run_with(
            vec![
                (
                    "GET /api/v1/governance/surfaces",
                    "HTTP/1.1 200 OK",
                    r#"[{"surface_id":"gone"},{"surface_id":"s1"}]"#,
                ),
                (
                    "GET /api/v1/governance/verify?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"{"surface_id":"s1","valid":true,"count":3}"#,
                ),
            ],
            &["verify"],
            Output::Json,
        )
        .await;
        assert_eq!(
            result
                .expect_err("one not checked")
                .to_string(),
            "1 of 2 governance record chains could not be checked"
        );
        assert_eq!(requests.len(), 3);
    }

    #[test]
    fn test_outcome_of_follows_agent_stream() {
        assert_eq!(outcome_of(&json!({"stages": [{"outcome": "error"}, {"outcome": "block"}]})), "blocked");
        assert_eq!(outcome_of(&json!({"stages": [{"outcome": "allow"}, {"outcome": "error"}]})), "failed");
        assert_eq!(outcome_of(&json!({"stages": [{"outcome": "flag"}]})), "ok");
        assert_eq!(outcome_of(&json!({})), "ok");
    }

    #[tokio::test]
    async fn test_records_get_requests_the_record_of_the_surface() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/governance/records/r1?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"{"record":{"record_id":"r1"}}"#,
            )],
            &["records", "get", "r1", "--surface", "s1"],
            Output::Json,
        )
        .await;
        result.expect("get");
        assert_eq!(requests, ["GET /api/v1/governance/records/r1?surface_id=s1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_records_get_refuses_a_path_in_the_id_before_sending() {
        let (result, requests) =
            run_with(vec![], &["records", "get", "../verify", "--surface", "s1"], Output::Json).await;
        assert!(
            result
                .expect_err("bad id")
                .to_string()
                .contains("is not valid")
        );
        assert!(requests.is_empty());
    }

    #[tokio::test]
    async fn test_verify_without_surface_checks_every_surface_and_fails_on_a_broken_chain() {
        let (result, requests) = run_with(
            vec![
                ("GET /api/v1/governance/surfaces", "HTTP/1.1 200 OK", r#"[{"surface_id":"s1"},{"surface_id":"s2"}]"#),
                ("GET /api/v1/governance/verify?surface_id=s1", "HTTP/1.1 200 OK", r#"{"surface_id":"s1","valid":true,"count":3}"#),
                (
                    "GET /api/v1/governance/verify?surface_id=s2",
                    "HTTP/1.1 200 OK",
                    r#"{"surface_id":"s2","valid":false,"count":0,"problem":"broken","error":"hash mismatch at seq 2"}"#,
                ),
            ],
            &["verify"],
            Output::Table,
        )
        .await;
        assert_eq!(
            result
                .expect_err("broken chain")
                .to_string(),
            "1 of 2 governance record chains are not valid"
        );
        assert_eq!(
            requests,
            [
                "GET /api/v1/governance/surfaces HTTP/1.1",
                "GET /api/v1/governance/verify?surface_id=s1 HTTP/1.1",
                "GET /api/v1/governance/verify?surface_id=s2 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_verify_one_intact_surface_succeeds() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/governance/verify?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"{"surface_id":"s1","valid":true,"count":3}"#,
            )],
            &["verify", "--surface", "s1"],
            Output::Json,
        )
        .await;
        result.expect("intact");
        assert_eq!(requests, ["GET /api/v1/governance/verify?surface_id=s1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_a_refusal_names_the_governance_view_permission() {
        let (result, _) = run_with(
            vec![("GET /api/v1/governance/surfaces", "HTTP/1.1 403 Forbidden", "Insufficient permissions")],
            &["surfaces"],
            Output::Json,
        )
        .await;
        let error = result
            .expect_err("403")
            .to_string();
        assert!(error.contains("`governance.view` permission"), "{error}");
    }

    #[tokio::test]
    async fn test_coverage_gaps_only_asks_for_gaps() {
        let (result, requests) = run_with(
            vec![("GET /api/v1/governance/coverage?gaps_only=true", "HTTP/1.1 200 OK", "[]")],
            &["coverage", "--gaps-only"],
            Output::Table,
        )
        .await;
        result.expect("coverage");
        assert_eq!(requests, ["GET /api/v1/governance/coverage?gaps_only=true HTTP/1.1"]);
    }
}
