//! `fabric agent-stream drift`: a surface's drift verdict, its baseline, and
//! the replay runs that measure it.
//!
//! A replay sends a surface's captured sessions to its model again, which is
//! real spend, so `drift run` shows the surface's caps and asks first, and
//! refuses while another run of the surface is in progress. A run's samples
//! hold the replayed prompts and answers, which are hidden unless one run is
//! asked for with `--reveal` (see [`prompt_content`]).

use std::{future::Future, time::Duration};

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use reqwest::Method;
use serde_json::Value;

use super::{
    prompt_content::{self, Item, LIST_MASKED_VALUE, REVEAL_WARNING},
    request::{Permission, name_missing_surface, name_permission, path_id, with_query},
    when::{parse_duration, parse_moment},
};
use crate::{
    client::{GatewayClient, response_status},
    commands::{MASKED_VALUE, Output, confirm_action, print_list, print_value, refuse_without_terminal, unix_now},
    tables::{self, Scope, flatten},
};

const VERDICT_PATH: &str = "/v1/drift/verdict";
const BASELINE_PATH: &str = "/v1/drift/baseline";
const RUNS_PATH: &str = "/v1/drift/runs";
const RUN_PATH: &str = "/v1/drift/eval/run";
const CANCEL_PATH: &str = "/v1/drift/eval/cancel";
const SURFACES_PATH: &str = "/v1/pipes";

/// Longest surface or run id Agent Stream accepts.
const MAX_ID: usize = 128;

/// How far before --until (or now) `drift status` reads when --since is not
/// given: 24 hours.
const DEFAULT_STATUS_WINDOW_SECS: u64 = 86_400;

/// The baseline window Agent Stream uses when none is sent, and the shortest
/// and longest it accepts: five minutes and thirty days.
const DEFAULT_BASELINE_WINDOW: &str = "24h";
const MIN_BASELINE_WINDOW: u64 = 300;
const MAX_BASELINE_WINDOW: u64 = 2_592_000;

/// Sessions one replay sends when the surface sets no `drift.eval.max_sessions`,
/// and the fewest and most Agent Stream replays whatever the surface sets.
const DEFAULT_MAX_SESSIONS: u64 = 50;
const MIN_MAX_SESSIONS: u64 = 1;
const MAX_MAX_SESSIONS: u64 = 200;

/// Most runs `drift runs list` shows without --surface; Agent Stream clamps
/// the limit to 1-200.
const DEFAULT_RUNS_LIMIT: u32 = 25;
const MAX_RUNS_LIMIT: u32 = 200;

/// How often `drift run --wait` reads the run again.
#[cfg(not(test))]
const POLL_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// The run statuses that mean a run has not finished.
const IN_PROGRESS: &[&str] = &["pending", "running"];

/// Reads of the run in a row that `drift run --wait` lets fail with a server
/// error or no answer before it stops waiting.
const WAIT_ATTEMPTS: u32 = 5;

/// The longest `drift run --wait --timeout` accepts: thirty days.
const MAX_WAIT_TIMEOUT: u64 = 2_592_000;

#[derive(Debug, Subcommand)]
pub enum DriftCommand {
    /// Show a surface's drift verdict against its baseline.
    ///
    /// Compares each dimension's mean over the window with the surface's
    /// pinned baseline: STATUS is `stable`, `warn`, `drift`, or `unknown` (no
    /// baseline, or no samples), and CHANGE is the relative change from the
    /// baseline. The window ends at --until (now by default) and starts at
    /// --since (24 hours before its end by default). Table output starts with
    /// the overall status and when the baseline was pinned.
    #[command(after_long_help = STATUS_EXAMPLES)]
    Status(StatusArgs),
    /// Read or re-pin a surface's drift baseline.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// List and view drift replay runs.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Start a drift replay run on a surface.
    ///
    /// Replays the surface's captured sessions against a model and scores the
    /// answers. The calls are real and billed. Before starting, the command
    /// shows the run's session cap (`drift.eval.max_sessions`, 50 when unset,
    /// and never fewer than 1 or more than 200 whatever the surface sets) and
    /// cost cap (`drift.eval.max_run_cost_usd`), which Agent Stream takes
    /// from the surface whose sessions are replayed even for an experiment, or
    /// `unknown` when that surface can't be read. Then it asks you to confirm;
    /// only `y` or `yes` starts the run. Without a terminal it refuses unless
    /// --yes is given.
    ///
    /// It also refuses while a run that replays or targets the surface (or,
    /// for an experiment, the target) is pending or running, unless --force is
    /// given. That check reads the runs of the surface and the target, and
    /// the 200 most recent runs this login can see for runs from other
    /// surfaces that target them. When the command asked you to confirm, it
    /// checks again after you answer. Unless --force is given, the command
    /// needs `drift.view` for that check as well as the `drift.manage` the
    /// run needs. Agent Stream itself doesn't stop two
    /// runs at once, so the check narrows the window for one but can't close
    /// it.
    ///
    /// With --variant, or a --target other than the surface itself, the run
    /// is an experiment: it replays the surface's sessions against another
    /// surface or a variant, and never feeds the surface's drift series or
    /// verdict.
    ///
    /// Prints the new run's id. With --wait, progress goes to standard error
    /// until the run ends, then the run is printed; the command exits 1 when
    /// the run failed, was cancelled, or was stopped. A read of the run that
    /// fails with a server error or no answer is tried again, up to 5 times in
    /// a row; then the command stops waiting and says how to check or cancel
    /// the run. With --timeout, it also stops waiting when the run is still
    /// in progress after that long (at most 30 days), however slowly Agent
    /// Stream answers, and exits 1 with the same advice. Ctrl-C
    /// stops waiting without cancelling the run; the command to cancel it is
    /// printed when the waiting starts.
    #[command(after_long_help = RUN_EXAMPLES)]
    Run(RunArgs),
    /// Cancel a drift run in progress.
    ///
    /// Agent Stream stops the run after the session in progress. The run is
    /// recorded as `cancelled` with its partial results and cost, and never
    /// feeds the drift series. This can't be undone, and there is no
    /// confirmation prompt.
    #[command(after_long_help = CANCEL_EXAMPLES)]
    Cancel {
        /// ID of the run (see `fabric agent-stream drift runs list`).
        run_id: String,
    },
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// ID of the surface.
    #[arg(long)]
    surface: String,
    /// Start of the window: an RFC 3339 time (2026-11-20T09:00:00Z), unix
    /// seconds, or a duration before now (30m, 24h, 7d). Defaults to 24 hours
    /// before the end of the window.
    #[arg(long)]
    since: Option<String>,
    /// End of the window, in the forms --since takes. Defaults to now.
    #[arg(long)]
    until: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    /// Show a surface's pinned drift baseline.
    ///
    /// Shows when it was pinned, the window it covers, and each dimension's
    /// mean over that window. Prints a line saying there is none (`null` with
    /// --output json) when no baseline is pinned.
    #[command(after_long_help = BASELINE_GET_EXAMPLES)]
    Get {
        /// ID of the surface.
        #[arg(long)]
        surface: String,
    },
    /// Re-pin a surface's drift baseline from its recent data.
    ///
    /// Replaces the surface's only baseline with each dimension's mean over
    /// the last --window. This changes the surface's drift verdict and, when
    /// its drift settings have `gate_on_regression` on, whether the surface
    /// can be saved. The current baseline and the window are shown and you
    /// are asked to confirm; only `y` or `yes` re-pins. Without a terminal the
    /// command refuses unless --yes is given. Reading the current baseline
    /// needs `drift.view` as well as the `drift.manage` the re-pin needs.
    #[command(after_long_help = BASELINE_SET_EXAMPLES)]
    Set {
        /// ID of the surface.
        #[arg(long)]
        surface: String,
        /// How far back the new baseline reaches: a duration from 5m to 30d,
        /// such as 24h or 7d.
        #[arg(long, default_value = DEFAULT_BASELINE_WINDOW)]
        window: String,
        /// Re-pin without asking.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RunsCommand {
    /// List drift runs, newest first.
    ///
    /// With --surface, every run of that surface: runs in progress first,
    /// then its whole history. Without it, runs in progress and the most
    /// recent ones across all surfaces, up to --limit. PASSED and TOTAL count
    /// the sessions replayed. Replayed prompts and answers are never shown in
    /// a list, even with --output json.
    #[command(after_long_help = RUNS_LIST_EXAMPLES)]
    List {
        /// Only runs of this surface.
        #[arg(long)]
        surface: Option<String>,
        /// Most runs to show when --surface is not given, from 1 to 200.
        #[arg(long, default_value_t = DEFAULT_RUNS_LIMIT, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_RUNS_LIMIT)), conflicts_with = "surface")]
        limit: u32,
    },
    /// Get one drift run, with its replayed prompts and answers hidden.
    ///
    /// Shows the run's status, progress, scores, cost and each dimension's
    /// verdict. Each sample's input, output and error are replaced with a
    /// placeholder unless --reveal is given.
    #[command(after_long_help = RUNS_GET_EXAMPLES)]
    Get {
        /// ID of the run (see `fabric agent-stream drift runs list`).
        run_id: String,
        /// Show each sample's replayed prompt, answer and error. When there are any, a
        /// warning is printed on standard error, since they can hold personal
        /// data.
        #[arg(long)]
        reveal: bool,
    },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// ID of the surface whose captured sessions are replayed.
    #[arg(long)]
    surface: String,
    /// Replay against this surface instead, as an experiment. Naming the
    /// surface itself is the same as leaving it out.
    #[arg(long)]
    target: Option<String>,
    /// Replay against this variant (by its alias) of the target, or of the
    /// surface when --target is not given, as an experiment.
    #[arg(long)]
    variant: Option<String>,
    /// Wait until the run ends, showing progress on standard error.
    #[arg(long)]
    wait: bool,
    /// Start without asking.
    #[arg(long)]
    yes: bool,
    /// Start even though a run of the surface is already in progress.
    #[arg(long)]
    force: bool,
    /// With --wait, stop waiting when the run is still in progress after this
    /// long, such as 30m or 2h, and at most 30d. The run goes on. Without it,
    /// the command waits until the run ends.
    #[arg(long, requires = "wait")]
    timeout: Option<String>,
}

/// Examples shown at the bottom of `drift status --help`.
const STATUS_EXAMPLES: &str = r#"Examples:
  Drift over the last 24 hours:
    fabric agent-stream drift status --surface support-bot

  Drift over the last week:
    fabric agent-stream drift status --surface support-bot --since 7d"#;

/// Examples shown at the bottom of `drift baseline get --help`.
const BASELINE_GET_EXAMPLES: &str = r#"Examples:
  Show the pinned baseline:
    fabric agent-stream drift baseline get --surface support-bot"#;

/// Examples shown at the bottom of `drift runs list --help`.
const RUNS_LIST_EXAMPLES: &str = r#"Examples:
  Every run of one surface:
    fabric agent-stream drift runs list --surface support-bot

  The 10 most recent runs across all surfaces:
    fabric agent-stream drift runs list --limit 10"#;

/// Examples shown at the bottom of `drift runs get --help`.
const RUNS_GET_EXAMPLES: &str = r#"Examples:
  Show a run's scores and verdicts:
    fabric agent-stream drift runs get 0b6c1f7e-3d2a-4e8b-9c51-7a4f2e9d6b10

  Show its replayed prompts and answers too (prints a warning):
    fabric agent-stream drift runs get 0b6c1f7e-3d2a-4e8b-9c51-7a4f2e9d6b10 --reveal"#;

/// Examples shown at the bottom of `drift cancel --help`.
const CANCEL_EXAMPLES: &str = r#"Examples:
  Find the run in progress, then cancel it:
    fabric agent-stream drift runs list --surface support-bot
    fabric agent-stream drift cancel 0b6c1f7e-3d2a-4e8b-9c51-7a4f2e9d6b10"#;

/// Examples shown at the bottom of `drift baseline set --help`.
const BASELINE_SET_EXAMPLES: &str = r#"Examples:
  Re-pin the baseline from the last 7 days, after confirming:
    fabric agent-stream drift baseline set --surface support-bot --window 7d"#;

/// Examples shown at the bottom of `drift run --help`.
const RUN_EXAMPLES: &str = r#"Examples:
  Start a replay after confirming, and wait for it:
    fabric agent-stream drift run --surface support-bot --wait

  Try the surface's sessions against a variant, from a script, waiting at most
  two hours:
    fabric agent-stream drift run --surface support-bot --variant cheaper-model \
      --yes --wait --timeout 2h --output json"#;

impl DriftCommand {
    /// Fails, before anything is sent, for a command that would ask for a
    /// confirmation nobody can give.
    pub fn refuse_without_terminal(&self) -> Result<()> {
        match self {
            Self::Run(args) => refuse_without_terminal("start a drift run on", &args.surface, args.yes),
            Self::Baseline {
                command: BaselineCommand::Set { surface, yes, .. },
            } => refuse_without_terminal("replace the drift baseline of", surface, *yes),
            _ => Ok(()),
        }
    }
}

/// Runs one `drift` command.
pub async fn run(
    client: &GatewayClient,
    command: DriftCommand,
    output: Output,
) -> Result<()> {
    match command {
        DriftCommand::Status(args) => status(client, args, output).await,
        DriftCommand::Baseline {
            command: BaselineCommand::Get { surface },
        } => {
            path_id("surface id", &surface, MAX_ID)?;
            let baseline = read_baseline(client, &surface).await?;
            if baseline.is_null() && matches!(output, Output::Table) {
                println!("No drift baseline is pinned for surface '{}'.", flatten(&surface));
                return Ok(());
            }
            print_value(&baseline, output)
        }
        DriftCommand::Baseline {
            command: BaselineCommand::Set { surface, window, yes },
        } => set_baseline(client, &surface, &window, yes, output).await,
        DriftCommand::Runs {
            command: RunsCommand::List { surface, limit },
        } => list_runs(client, surface.as_deref(), limit, output).await,
        DriftCommand::Runs {
            command: RunsCommand::Get { run_id, reveal },
        } => {
            let mut run = read_run(client, &run_id).await?;
            if reveal {
                if prompt_content::count(&run, Item::DriftRun) > 0 {
                    eprintln!("{REVEAL_WARNING}");
                }
            } else {
                prompt_content::mask(&mut run, Item::DriftRun, MASKED_VALUE);
            }
            print_value(&run, output)
        }
        DriftCommand::Run(args) => {
            let surface = args.surface.clone();
            start_run(client, args, output, move |prompt| async move {
                confirm_action("start a drift run on", &surface, async { prompt }).await
            })
            .await
        }
        DriftCommand::Cancel { run_id } => {
            let id = path_id("run id", &run_id, MAX_ID)?;
            let path = with_query(CANCEL_PATH, &[("run_id", Some(id.to_owned()))]);
            let answer = name_permission(
                client
                    .request(Method::POST, &path, None)
                    .await,
                Permission::DriftManage,
            )?;
            match output {
                Output::Json => print_value(&answer, output),
                Output::Table => {
                    println!(
                        "Cancelling drift run '{}': it stops after the session in progress and keeps its partial \
                         results.",
                        flatten(id)
                    );
                    Ok(())
                }
            }
        }
    }
}

/// A `GET` that needs `drift.view`.
async fn read(
    client: &GatewayClient,
    path: &str,
) -> Result<Value> {
    name_permission(
        client
            .request(Method::GET, path, None)
            .await,
        Permission::DriftView,
    )
}

async fn status(
    client: &GatewayClient,
    args: StatusArgs,
    output: Output,
) -> Result<()> {
    path_id("surface id", &args.surface, MAX_ID)?;
    let now = unix_now();
    let until = args
        .until
        .as_deref()
        .map(|text| parse_moment("--until", text, now))
        .transpose()?
        .unwrap_or(now);
    // Without --since, the window is the 24 hours before --until (or now).
    let since = match args.since.as_deref() {
        Some(text) => parse_moment("--since", text, now)?,
        None => until.saturating_sub(DEFAULT_STATUS_WINDOW_SECS),
    };
    if since >= until {
        bail!("--since must be before --until");
    }
    let path = with_query(
        VERDICT_PATH,
        &[
            ("surface_id", Some(args.surface.clone())),
            ("from", Some(since.to_string())),
            ("to", Some(until.to_string())),
        ],
    );
    let verdict = name_missing_surface(read(client, &path).await, &args.surface)?;
    match output {
        Output::Json => print_value(&verdict, output),
        Output::Table => {
            let overall = verdict
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let pinned = verdict
                .get("baseline_captured_at")
                .and_then(Value::as_str)
                .map_or_else(|| "no baseline pinned".to_owned(), |at| format!("baseline pinned {}", flatten(at)));
            println!("Surface '{}': {} ({pinned})", flatten(&args.surface), flatten(overall));
            let dimensions = verdict
                .get("dimensions")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            print_list(&dimensions, output, &tables::DRIFT_DIMENSIONS, Scope::All)
        }
    }
}

async fn read_baseline(
    client: &GatewayClient,
    surface: &str,
) -> Result<Value> {
    let path = with_query(BASELINE_PATH, &[("surface_id", Some(surface.to_owned()))]);
    name_missing_surface(read(client, &path).await, surface)
}

async fn set_baseline(
    client: &GatewayClient,
    surface: &str,
    window: &str,
    yes: bool,
    output: Output,
) -> Result<()> {
    path_id("surface id", surface, MAX_ID)?;
    let seconds = parse_duration("--window", window)?;
    if !(MIN_BASELINE_WINDOW..=MAX_BASELINE_WINDOW).contains(&seconds) {
        bail!("--window must be from 5m to 30d, not '{}'", flatten(window));
    }
    if !yes {
        let current = read_baseline(client, surface).await?;
        let current = match current
            .get("captured_at")
            .and_then(Value::as_str)
        {
            Some(at) => format!(
                "the baseline pinned {} over {}",
                flatten(at),
                current
                    .get("window_secs")
                    .and_then(Value::as_u64)
                    .map_or_else(|| "an unknown window".to_owned(), describe_seconds)
            ),
            None => "no baseline (none is pinned yet)".to_owned(),
        };
        let prompt = format!(
            "Replace {current} of surface '{}' with one over the last {}? This changes its drift verdict and, with \
             gate_on_regression on, whether the surface can be saved.",
            flatten(surface),
            describe_seconds(seconds)
        );
        if !confirm_action("replace the drift baseline of", surface, async { prompt }).await? {
            bail!("baseline not changed");
        }
    }
    let path = with_query(
        BASELINE_PATH,
        &[("surface_id", Some(surface.to_owned())), ("window_secs", Some(seconds.to_string()))],
    );
    let baseline = name_missing_surface(
        name_permission(
            client
                .request(Method::POST, &path, None)
                .await,
            Permission::DriftManage,
        ),
        surface,
    )?;
    if matches!(output, Output::Table) {
        println!("Pinned a new drift baseline for surface '{}'.", flatten(surface));
    }
    print_value(&baseline, output)
}

/// A count of seconds as the largest whole unit it fits: `7d`, `24h`, `90m`.
fn describe_seconds(seconds: u64) -> String {
    for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        if seconds >= size && seconds % size == 0 {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

async fn list_runs(
    client: &GatewayClient,
    surface: Option<&str>,
    limit: u32,
    output: Output,
) -> Result<()> {
    let runs = fetch_runs(client, surface, limit).await?;
    let scope = if surface.is_some() {
        Scope::Filtered
    } else {
        Scope::All
    };
    print_list(&runs, output, &tables::DRIFT_RUNS, scope)
}

/// The runs `drift runs list` shows, with their replayed content masked.
async fn fetch_runs(
    client: &GatewayClient,
    surface: Option<&str>,
    limit: u32,
) -> Result<Value> {
    let mut runs = read_runs(client, surface, limit).await?;
    let Value::Array(items) = &mut runs else {
        bail!("Agent Stream answered the drift runs list with something other than a list");
    };
    for run in items {
        prompt_content::mask(run, Item::DriftRun, LIST_MASKED_VALUE);
    }
    Ok(runs)
}

async fn read_runs(
    client: &GatewayClient,
    surface: Option<&str>,
    limit: u32,
) -> Result<Value> {
    let path = match surface {
        Some(surface) => {
            path_id("surface id", surface, MAX_ID)?;
            with_query(RUNS_PATH, &[("surface_id", Some(surface.to_owned()))])
        }
        None => with_query(RUNS_PATH, &[("limit", Some(limit.to_string()))]),
    };
    match surface {
        Some(surface) => name_missing_surface(read(client, &path).await, surface),
        None => read(client, &path).await,
    }
}

async fn read_run(
    client: &GatewayClient,
    run_id: &str,
) -> Result<Value> {
    let id = path_id("run id", run_id, MAX_ID)?;
    read(client, &format!("{RUNS_PATH}/{id}")).await
}

/// The first run that is pending or running and replays or targets one of
/// `surfaces`, as the surface it touches and the run's id.
///
/// A surface's own list holds every run in progress that replays it, with no
/// cap, but leaves out runs from other surfaces that only target it. Those
/// are looked for in the list without a surface, which keeps only the 200
/// most recent runs by `ran_at`: a run in progress counts from its start, so
/// a long one can fall out of it, which is why it is not used for the
/// surfaces' own runs.
async fn run_in_progress(
    client: &GatewayClient,
    surfaces: &[&str],
) -> Result<Option<(String, String)>> {
    for surface in surfaces {
        let runs = read_runs(client, Some(surface), MAX_RUNS_LIMIT).await?;
        if let Some(found) = first_in_progress(&runs, "surface_id", surfaces)? {
            return Ok(Some(found));
        }
    }
    let runs = read_runs(client, None, MAX_RUNS_LIMIT).await?;
    first_in_progress(&runs, "target_surface_id", surfaces)
}

/// The first pending or running run in `runs` whose `field` is one of
/// `surfaces`, as that surface and the run's id.
fn first_in_progress(
    runs: &Value,
    field: &str,
    surfaces: &[&str],
) -> Result<Option<(String, String)>> {
    let Some(runs) = runs.as_array() else {
        bail!("Agent Stream answered the drift runs list with something other than a list");
    };
    Ok(runs
        .iter()
        .filter(|run| {
            run.get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| IN_PROGRESS.contains(&status))
        })
        .find_map(|run| {
            let id = run
                .get("id")
                .and_then(Value::as_str)?;
            let surface = run
                .get(field)
                .and_then(Value::as_str)
                .filter(|surface| surfaces.contains(surface))?;
            Some((surface.to_owned(), id.to_owned()))
        }))
}

/// The session cap Agent Stream applies when the surface sets `max_sessions`
/// (or nothing), as shown before a run starts.
fn describe_session_cap(max_sessions: Option<u64>) -> String {
    match max_sessions {
        None => format!("{DEFAULT_MAX_SESSIONS} (Agent Stream's default)"),
        Some(set) => {
            let applied = set.clamp(MIN_MAX_SESSIONS, MAX_MAX_SESSIONS);
            if applied == set {
                set.to_string()
            } else {
                format!(
                    "{applied} (the surface sets {set}; Agent Stream replays {MIN_MAX_SESSIONS} to {MAX_MAX_SESSIONS})"
                )
            }
        }
    }
}

/// The session cap and cost cap of a run, as shown before it starts. Agent
/// Stream takes both from the `drift.eval` of the surface whose sessions are
/// replayed, even for an experiment against another surface. Best effort: the
/// read needs permission to read surfaces, and a surface that can't be read
/// gives `unknown` for both rather than stopping the command, since the caps
/// are shown for information and the user still confirms.
async fn spend_caps(
    client: &GatewayClient,
    surface: &str,
) -> (String, String) {
    let unknown = || ("unknown".to_owned(), "unknown".to_owned());
    let Ok(surface) = path_id("surface id", surface, MAX_ID) else {
        return unknown();
    };
    let Ok(document) = client
        .request(Method::GET, &format!("{SURFACES_PATH}/{surface}"), None)
        .await
    else {
        return unknown();
    };
    let eval = document
        .get("drift")
        .and_then(|drift| drift.get("eval"));
    let sessions = describe_session_cap(
        eval.and_then(|eval| eval.get("max_sessions"))
            .and_then(Value::as_u64),
    );
    let cost = match eval
        .and_then(|eval| eval.get("max_run_cost_usd"))
        .and_then(Value::as_f64)
    {
        Some(cost) if cost > 0.0 => format!("USD {cost:.2}"),
        Some(_) => "none (turned off for this surface)".to_owned(),
        None => "the Agent Stream default, if one is set".to_owned(),
    };
    (sessions, cost)
}

/// Starts a drift run. `confirm` asks the question it is given and says
/// whether the answer was yes; it is only called without --yes.
async fn start_run<C, F>(
    client: &GatewayClient,
    args: RunArgs,
    output: Output,
    confirm: C,
) -> Result<()>
where
    C: FnOnce(String) -> F,
    F: Future<Output = Result<bool>>,
{
    let mut args = args;
    path_id("surface id", &args.surface, MAX_ID)?;
    if let Some(target) = &args.target {
        path_id("--target", target, MAX_ID)?;
    }
    if let Some(variant) = &args.variant {
        path_id("--variant", variant, MAX_ID)?;
    }
    // Agent Stream runs a target equal to the surface as a plain run, which
    // feeds the drift series, so it is not called an experiment.
    if args.target.as_deref() == Some(args.surface.as_str()) {
        args.target = None;
    }
    let experiment = args.target.is_some() || args.variant.is_some();
    let timeout = args
        .timeout
        .as_deref()
        .map(|timeout| parse_duration("--timeout", timeout))
        .transpose()?;
    if timeout.is_some_and(|seconds| seconds > MAX_WAIT_TIMEOUT) {
        bail!("--timeout can be at most 30d");
    }
    let timeout = timeout.map(Duration::from_secs);

    if !args.force {
        refuse_if_busy(client, &args).await?;
    }

    if !args.yes {
        let (sessions, cost) = spend_caps(client, &args.surface).await;
        let against = match (&args.target, &args.variant) {
            (Some(target), Some(variant)) => {
                format!(" against variant '{}' of surface '{}'", flatten(variant), flatten(target))
            }
            (Some(target), None) => format!(" against surface '{}'", flatten(target)),
            (None, Some(variant)) => format!(" against its variant '{}'", flatten(variant)),
            (None, None) => String::new(),
        };
        let kind = if experiment {
            " This is an experiment: it does not feed the surface's drift series."
        } else {
            ""
        };
        let prompt = format!(
            "Replay the captured sessions of surface '{}'{against}? Each session is a real, billed model call. \
             Session cap: {sessions}. Cost cap: {cost}.{kind} Start the run?",
            flatten(&args.surface)
        );
        if !confirm(prompt).await? {
            bail!("drift run not started");
        }
        // The prompt can stay open for minutes, long enough for someone else
        // to start a run, so the check is made again before starting.
        if !args.force {
            refuse_if_busy(client, &args).await?;
        }
    }

    let path = with_query(
        RUN_PATH,
        &[
            ("surface_id", Some(args.surface.clone())),
            ("target_surface_id", args.target.clone()),
            ("variant", args.variant.clone()),
        ],
    );
    let mut started = name_missing_surface(
        name_permission(
            client
                .request(Method::POST, &path, None)
                .await,
            Permission::DriftManage,
        ),
        &args.surface,
    )?;
    let Some(run_id) = started
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        bail!("Agent Stream started a drift run but did not say its id; see `fabric agent-stream drift runs list`");
    };
    path_id("run id", &run_id, MAX_ID)?;

    if !args.wait {
        return match output {
            Output::Json => {
                prompt_content::mask(&mut started, Item::DriftRun, LIST_MASKED_VALUE);
                print_value(&started, output)
            }
            Output::Table => {
                println!("Started drift run '{}' on surface '{}'.", flatten(&run_id), flatten(&args.surface));
                Ok(())
            }
        };
    }
    // Ctrl-C ends the CLI as it always does, which stops the waiting and
    // leaves the run going, so the way to cancel it is printed up front.
    eprintln!(
        "Started drift run '{id}'; waiting for it to end. Ctrl-C stops waiting and leaves the run going; cancel it \
         with `fabric agent-stream drift cancel {id}`.",
        id = flatten(&run_id)
    );
    let finished = wait_at_most(client, &run_id, timeout).await?;
    let mut shown = finished.clone();
    prompt_content::mask(&mut shown, Item::DriftRun, LIST_MASKED_VALUE);
    print_value(&shown, output)?;
    let status = finished
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if status != "completed" {
        let reason = finished
            .get("failure_reason")
            .and_then(Value::as_str)
            .map(|reason| format!(": {}", flatten(reason)))
            .unwrap_or_default();
        bail!("drift run '{}' ended {}{reason}", flatten(&run_id), flatten(status));
    }
    Ok(())
}

/// Refuses when a run that replays or targets the surface, or the target,
/// is pending or running.
async fn refuse_if_busy(
    client: &GatewayClient,
    args: &RunArgs,
) -> Result<()> {
    let mut checked = vec![args.surface.as_str()];
    checked.extend(args.target.as_deref());
    if let Some((surface, run_id)) = run_in_progress(client, &checked).await? {
        bail!(
            "drift run '{}' on surface '{}' is in progress; wait for it, cancel it with `fabric agent-stream drift \
             cancel {}`, or pass --force to start another",
            flatten(&run_id),
            flatten(&surface),
            flatten(&run_id)
        );
    }
    Ok(())
}

/// How to check or cancel a run the CLI stopped waiting for.
fn still_going(run_id: &str) -> String {
    let id = flatten(run_id);
    format!(
        "drift run '{id}' may still be going: check it with `fabric agent-stream drift runs get {id}` or cancel it \
         with `fabric agent-stream drift cancel {id}`"
    )
}

/// Waits for the run to end, for at most `timeout` when given. The limit
/// holds over the whole wait, a read that hangs included.
async fn wait_at_most(
    client: &GatewayClient,
    run_id: &str,
    timeout: Option<Duration>,
) -> Result<Value> {
    let Some(limit) = timeout else {
        return wait_for(client, run_id).await;
    };
    match tokio::time::timeout(limit, wait_for(client, run_id)).await {
        Ok(finished) => finished,
        Err(_) => {
            bail!("stopped waiting after {} (--timeout); {}", describe_seconds(limit.as_secs()), still_going(run_id))
        }
    }
}

/// Reads the run until it is neither pending nor running, printing its
/// progress on standard error whenever it changes.
async fn wait_for(
    client: &GatewayClient,
    run_id: &str,
) -> Result<Value> {
    let mut last = None;
    loop {
        let run = read_run_retrying(client, run_id).await?;
        let status = run
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        if !IN_PROGRESS.contains(&status.as_str()) {
            return Ok(run);
        }
        let done = run
            .get("progress_done")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let progress = (status.clone(), done);
        if last.as_ref() != Some(&progress) {
            let total = run
                .get("total")
                .and_then(Value::as_u64)
                .filter(|total| *total > 0)
                .map(|total| format!(" of {total}"))
                .unwrap_or_default();
            eprintln!("drift run '{}': {}, {done}{total} sessions done", flatten(run_id), flatten(&status));
            last = Some(progress);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Reads the run, trying again after a server error or no answer, up to
/// [`WAIT_ATTEMPTS`] times in a row. Any other failure, or the last one, stops
/// the waiting with a note that the run may still be going.
async fn read_run_retrying(
    client: &GatewayClient,
    run_id: &str,
) -> Result<Value> {
    let mut attempt = 1;
    loop {
        match read_run(client, run_id).await {
            Ok(run) => return Ok(run),
            Err(error) => {
                let transient = response_status(&error).is_none_or(|status| status.is_server_error());
                if transient && attempt < WAIT_ATTEMPTS {
                    attempt += 1;
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
                bail!("{error}; stopped waiting: {}", still_going(run_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::agent_stream::test_support::{
        Route, scripted_agent_stream, scripted_agent_stream_in_order, start_lines,
    };

    const TOKEN: &str = "aspat_drift";

    /// The `drift` subcommand alone, parsed as clap parses it under
    /// `fabric agent-stream`.
    #[derive(Debug, Parser)]
    struct Drift {
        #[command(subcommand)]
        command: DriftCommand,
    }

    fn parse(args: &[&str]) -> DriftCommand {
        let mut argv = vec!["drift"];
        argv.extend_from_slice(args);
        Drift::try_parse_from(argv)
            .expect("parse")
            .command
    }

    async fn client_for(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN.to_owned()).expect("client")
    }

    async fn run_with(
        routes: Vec<Route>,
        args: &[&str],
    ) -> (Result<()>, Vec<String>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let result = run(&client_for(host).await, parse(args), Output::Json).await;
        (result, start_lines(&requests))
    }

    #[tokio::test]
    async fn test_status_asks_for_the_verdict_over_a_window() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/drift/verdict?surface_id=s1&from=1700000000&to=1700086400",
                "HTTP/1.1 200 OK",
                r#"{"surface_id":"s1","status":"stable","dimensions":[]}"#,
            )],
            &["status", "--surface", "s1", "--since", "1700000000", "--until", "1700086400"],
        )
        .await;
        result.expect("status");
        assert_eq!(requests, ["GET /api/v1/drift/verdict?surface_id=s1&from=1700000000&to=1700086400 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_run_with_yes_checks_runs_then_starts() {
        let (result, requests) = run_with(
            vec![
                (
                    "GET /api/v1/drift/runs?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"[{"id":"old","surface_id":"s1","status":"completed"}]"#,
                ),
                ("GET /api/v1/drift/runs?limit=200", "HTTP/1.1 200 OK", "[]"),
                (
                    "POST /api/v1/drift/eval/run?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"{"id":"run-1","status":"running","samples":[]}"#,
                ),
            ],
            &["run", "--surface", "s1", "--yes"],
        )
        .await;
        result.expect("run");
        assert_eq!(
            requests,
            [
                "GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1",
                "GET /api/v1/drift/runs?limit=200 HTTP/1.1",
                "POST /api/v1/drift/eval/run?surface_id=s1 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn test_run_refuses_while_a_run_is_in_progress() {
        // The run is only in the surface's own list, as a long run that has
        // fallen out of the 200 most recent would be.
        let (result, requests) = run_with(
            vec![
                (
                    "GET /api/v1/drift/runs?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"[{"id":"busy-1","surface_id":"s1","status":"running"}]"#,
                ),
                ("GET /api/v1/drift/runs?limit=200", "HTTP/1.1 200 OK", "[]"),
            ],
            &["run", "--surface", "s1", "--yes"],
        )
        .await;
        let error = result
            .expect_err("busy")
            .to_string();
        assert!(error.contains("drift run 'busy-1' on surface 's1' is in progress"), "{error}");
        assert_eq!(requests, ["GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_run_refuses_while_another_run_targets_the_surface() {
        let (result, requests) = run_with(
            vec![
                (
                    "GET /api/v1/drift/runs?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"[{"id":"done","surface_id":"s1","status":"completed"}]"#,
                ),
                ("GET /api/v1/drift/runs?surface_id=s2", "HTTP/1.1 200 OK", "[]"),
                (
                    "GET /api/v1/drift/runs?limit=200",
                    "HTTP/1.1 200 OK",
                    r#"[{"id":"own","surface_id":"s2","status":"completed"},
                        {"id":"other","surface_id":"s9","target_surface_id":"s2","status":"pending"}]"#,
                ),
            ],
            &["run", "--surface", "s1", "--target", "s2", "--yes"],
        )
        .await;
        let error = result
            .expect_err("busy target")
            .to_string();
        assert!(error.contains("drift run 'other' on surface 's2' is in progress"), "{error}");
        assert_eq!(
            requests,
            [
                "GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1",
                "GET /api/v1/drift/runs?surface_id=s2 HTTP/1.1",
                "GET /api/v1/drift/runs?limit=200 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn test_run_with_the_surface_as_target_is_a_plain_run() {
        let (result, requests) = run_with(
            vec![
                ("GET /api/v1/drift/runs?surface_id=s1", "HTTP/1.1 200 OK", "[]"),
                ("GET /api/v1/drift/runs?limit=200", "HTTP/1.1 200 OK", "[]"),
                (
                    "POST /api/v1/drift/eval/run?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"{"id":"run-5","status":"running"}"#,
                ),
            ],
            &["run", "--surface", "s1", "--target", "s1", "--yes"],
        )
        .await;
        result.expect("plain run");
        assert_eq!(
            requests,
            [
                "GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1",
                "GET /api/v1/drift/runs?limit=200 HTTP/1.1",
                "POST /api/v1/drift/eval/run?surface_id=s1 HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn test_run_with_force_skips_the_check() {
        let (result, requests) = run_with(
            vec![(
                "POST /api/v1/drift/eval/run?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"{"id":"run-2","status":"running"}"#,
            )],
            &["run", "--surface", "s1", "--yes", "--force"],
        )
        .await;
        result.expect("forced");
        assert_eq!(requests, ["POST /api/v1/drift/eval/run?surface_id=s1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_experiment_checks_the_target_and_sends_it() {
        let (result, requests) = run_with(
            vec![
                ("GET /api/v1/drift/runs?surface_id=s1", "HTTP/1.1 200 OK", "[]"),
                ("GET /api/v1/drift/runs?surface_id=s2", "HTTP/1.1 200 OK", "[]"),
                ("GET /api/v1/drift/runs?limit=200", "HTTP/1.1 200 OK", "[]"),
                (
                    "POST /api/v1/drift/eval/run?surface_id=s1&target_surface_id=s2&variant=cheap",
                    "HTTP/1.1 200 OK",
                    r#"{"id":"run-3","status":"running"}"#,
                ),
            ],
            &["run", "--surface", "s1", "--target", "s2", "--variant", "cheap", "--yes"],
        )
        .await;
        result.expect("experiment");
        assert_eq!(
            requests,
            [
                "GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1",
                "GET /api/v1/drift/runs?surface_id=s2 HTTP/1.1",
                "GET /api/v1/drift/runs?limit=200 HTTP/1.1",
                "POST /api/v1/drift/eval/run?surface_id=s1&target_surface_id=s2&variant=cheap HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_run_wait_polls_until_the_run_ends_and_fails_when_cancelled() {
        let (host, requests) = scripted_agent_stream_in_order(vec![
            ("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 200 OK", r#"{"id":"run-4","status":"running"}"#),
            (
                "GET /api/v1/drift/runs/run-4",
                "HTTP/1.1 200 OK",
                r#"{"id":"run-4","status":"running","progress_done":1,"total":3}"#,
            ),
            (
                "GET /api/v1/drift/runs/run-4",
                "HTTP/1.1 200 OK",
                r#"{"id":"run-4","status":"running","progress_done":2,"total":3}"#,
            ),
            (
                "GET /api/v1/drift/runs/run-4",
                "HTTP/1.1 200 OK",
                r#"{"id":"run-4","status":"cancelled","samples":[{"input":"secret prompt","output":"answer"}]}"#,
            ),
        ])
        .await;
        let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
        let error = run(&client_for(host).await, command, Output::Json)
            .await
            .expect_err("cancelled");
        assert_eq!(error.to_string(), "drift run 'run-4' ended cancelled");
        assert_eq!(start_lines(&requests).len(), 4);
    }

    #[tokio::test]
    async fn test_run_wait_fails_when_the_run_fails_or_stops() {
        for (status, expected) in [
            (
                r#"{"id":"run-6","status":"failed","failure_reason":"provider down"}"#,
                "drift run 'run-6' ended failed: provider down",
            ),
            (r#"{"id":"run-6","status":"stopped"}"#, "drift run 'run-6' ended stopped"),
        ] {
            let (host, _) = scripted_agent_stream_in_order(vec![
                (
                    "POST /api/v1/drift/eval/run?surface_id=s1",
                    "HTTP/1.1 200 OK",
                    r#"{"id":"run-6","status":"running"}"#,
                ),
                ("GET /api/v1/drift/runs/run-6", "HTTP/1.1 200 OK", status),
            ])
            .await;
            let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
            let error = run(&client_for(host).await, command, Output::Json)
                .await
                .expect_err(expected);
            assert_eq!(error.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn test_status_with_only_until_reads_the_24_hours_before_it() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/drift/verdict?surface_id=s1&from=1699913600&to=1700000000",
                "HTTP/1.1 200 OK",
                r#"{"status":"stable"}"#,
            )],
            &["status", "--surface", "s1", "--until", "1700000000"],
        )
        .await;
        result.expect("status");
        assert_eq!(requests, ["GET /api/v1/drift/verdict?surface_id=s1&from=1699913600&to=1700000000 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_runs_list_and_the_run_check_refuse_an_unknown_shape() {
        let (result, _) = run_with(
            vec![(
                "GET /api/v1/drift/runs?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"{"runs":[{"samples":[{"input":"secret"}]}]}"#,
            )],
            &["runs", "list", "--surface", "s1"],
        )
        .await;
        assert!(
            result
                .expect_err("list")
                .to_string()
                .contains("something other than a list")
        );
        let (result, requests) = run_with(
            vec![("GET /api/v1/drift/runs?surface_id=s1", "HTTP/1.1 200 OK", r#"{"runs":[]}"#)],
            &["run", "--surface", "s1", "--yes"],
        )
        .await;
        assert!(
            result
                .expect_err("check")
                .to_string()
                .contains("something other than a list")
        );
        assert_eq!(requests, ["GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_run_wait_succeeds_when_the_run_completes() {
        let (host, _) = scripted_agent_stream_in_order(vec![
            ("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 200 OK", r#"{"id":"run-5","status":"pending"}"#),
            ("GET /api/v1/drift/runs/run-5", "HTTP/1.1 200 OK", r#"{"id":"run-5","status":"completed"}"#),
        ])
        .await;
        let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
        run(&client_for(host).await, command, Output::Json)
            .await
            .expect("completed");
    }

    #[tokio::test]
    async fn test_cancel_posts_the_run_id() {
        let (result, requests) = run_with(
            vec![("POST /api/v1/drift/eval/cancel?run_id=run-1", "HTTP/1.1 202 Accepted", "")],
            &["cancel", "run-1"],
        )
        .await;
        result.expect("cancel");
        assert_eq!(requests, ["POST /api/v1/drift/eval/cancel?run_id=run-1 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_baseline_set_with_yes_sends_the_window() {
        let (result, requests) = run_with(
            vec![(
                "POST /api/v1/drift/baseline?surface_id=s1&window_secs=604800",
                "HTTP/1.1 200 OK",
                r#"{"surface_id":"s1","window_secs":604800}"#,
            )],
            &["baseline", "set", "--surface", "s1", "--window", "7d", "--yes"],
        )
        .await;
        result.expect("set");
        assert_eq!(requests, ["POST /api/v1/drift/baseline?surface_id=s1&window_secs=604800 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_baseline_set_refuses_a_window_out_of_range_before_sending() {
        let (result, requests) =
            run_with(vec![], &["baseline", "set", "--surface", "s1", "--window", "31d", "--yes"]).await;
        assert!(
            result
                .expect_err("too long")
                .to_string()
                .contains("from 5m to 30d")
        );
        assert!(requests.is_empty());
    }

    #[tokio::test]
    async fn test_runs_list_sends_the_limit_without_surface() {
        let (result, requests) = run_with(
            vec![("GET /api/v1/drift/runs?limit=5", "HTTP/1.1 200 OK", "[]")],
            &["runs", "list", "--limit", "5"],
        )
        .await;
        result.expect("list");
        assert_eq!(requests, ["GET /api/v1/drift/runs?limit=5 HTTP/1.1"]);
    }

    #[tokio::test]
    async fn test_a_refused_start_names_the_drift_manage_permission() {
        let (result, _) = run_with(
            vec![("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 403 Forbidden", "Insufficient permissions")],
            &["run", "--surface", "s1", "--yes", "--force"],
        )
        .await;
        let error = result
            .expect_err("403")
            .to_string();
        assert!(error.contains("`drift.manage` permission"), "{error}");
    }

    #[tokio::test]
    async fn test_a_disabled_surface_is_not_called_a_permission_problem() {
        let (result, _) = run_with(
            vec![("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 403 Forbidden", "Pipe is disabled: s1")],
            &["run", "--surface", "s1", "--yes", "--force"],
        )
        .await;
        let error = result
            .expect_err("disabled")
            .to_string();
        assert_eq!(error, "Pipe is disabled: s1");
    }

    #[tokio::test]
    async fn test_run_wait_reads_again_after_a_server_error() {
        let (host, requests) = scripted_agent_stream_in_order(vec![
            ("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 200 OK", r#"{"id":"run-6","status":"running"}"#),
            ("GET /api/v1/drift/runs/run-6", "HTTP/1.1 503 Service Unavailable", "busy"),
            ("GET /api/v1/drift/runs/run-6", "HTTP/1.1 200 OK", r#"{"id":"run-6","status":"completed"}"#),
        ])
        .await;
        let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
        run(&client_for(host).await, command, Output::Json)
            .await
            .expect("completed after a retry");
        assert_eq!(start_lines(&requests).len(), 3);
    }

    #[tokio::test]
    async fn test_run_wait_gives_up_saying_the_run_may_still_be_going() {
        let mut routes: Vec<Route> = vec![(
            "POST /api/v1/drift/eval/run?surface_id=s1",
            "HTTP/1.1 200 OK",
            r#"{"id":"run-7","status":"running"}"#,
        )];
        routes.extend(std::iter::repeat_n(
            ("GET /api/v1/drift/runs/run-7", "HTTP/1.1 502 Bad Gateway", "down"),
            WAIT_ATTEMPTS as usize,
        ));
        let (host, requests) = scripted_agent_stream_in_order(routes).await;
        let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
        let error = run(&client_for(host).await, command, Output::Json)
            .await
            .expect_err("gave up")
            .to_string();
        assert!(error.contains("stopped waiting: drift run 'run-7' may still be going"), "{error}");
        assert!(error.contains("`fabric agent-stream drift runs get run-7`"), "{error}");
        assert!(error.contains("`fabric agent-stream drift cancel run-7`"), "{error}");
        assert_eq!(start_lines(&requests).len(), 1 + WAIT_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn test_run_wait_does_not_retry_a_refusal() {
        let (host, requests) = scripted_agent_stream_in_order(vec![
            ("POST /api/v1/drift/eval/run?surface_id=s1", "HTTP/1.1 200 OK", r#"{"id":"run-8","status":"running"}"#),
            ("GET /api/v1/drift/runs/run-8", "HTTP/1.1 403 Forbidden", "Insufficient permissions"),
        ])
        .await;
        let command = parse(&["run", "--surface", "s1", "--yes", "--force", "--wait"]);
        let error = run(&client_for(host).await, command, Output::Json)
            .await
            .expect_err("refused")
            .to_string();
        assert!(error.contains("may still be going"), "{error}");
        assert_eq!(start_lines(&requests).len(), 2);
    }

    async fn caps_for(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, String) {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/pipes/s1", status_line, body)]).await;
        spend_caps(&client_for(host).await, "s1").await
    }

    #[tokio::test]
    async fn test_spend_caps_read_the_surface_drift_eval() {
        assert_eq!(
            caps_for("HTTP/1.1 200 OK", r#"{"drift":{"eval":{"max_sessions":10,"max_run_cost_usd":2.5}}}"#).await,
            ("10".to_owned(), "USD 2.50".to_owned())
        );
        assert_eq!(
            caps_for("HTTP/1.1 200 OK", r#"{"drift":{"eval":{"max_run_cost_usd":0}}}"#).await,
            ("50 (Agent Stream's default)".to_owned(), "none (turned off for this surface)".to_owned())
        );
        assert_eq!(
            caps_for("HTTP/1.1 200 OK", "{}").await,
            ("50 (Agent Stream's default)".to_owned(), "the Agent Stream default, if one is set".to_owned())
        );
        assert_eq!(
            caps_for("HTTP/1.1 403 Forbidden", "Insufficient permissions").await,
            ("unknown".to_owned(), "unknown".to_owned())
        );
    }

    #[tokio::test]
    async fn test_run_wait_stops_at_the_timeout_saying_the_run_may_still_be_going() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/v1/drift/runs/run-9",
            "HTTP/1.1 200 OK",
            r#"{"id":"run-9","status":"running","progress_done":1,"total":3}"#,
        )])
        .await;
        let error = wait_at_most(&client_for(host).await, "run-9", Some(Duration::from_millis(20)))
            .await
            .expect_err("timed out")
            .to_string();
        assert!(
            error.starts_with("stopped waiting after 0s (--timeout); drift run 'run-9' may still be going"),
            "{error}"
        );
        assert!(error.contains("`fabric agent-stream drift cancel run-9`"), "{error}");
    }

    #[tokio::test]
    async fn test_run_wait_timeout_holds_while_a_read_hangs() {
        // A host that accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let host = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("addr")
        );
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let started = std::time::Instant::now();
        let error = wait_at_most(&client_for(host).await, "run-10", Some(Duration::from_millis(50)))
            .await
            .expect_err("timed out")
            .to_string();
        assert!(started.elapsed() < Duration::from_secs(5), "waited {:?}", started.elapsed());
        assert!(error.contains("drift run 'run-10' may still be going"), "{error}");
    }

    #[tokio::test]
    async fn test_run_refuses_a_timeout_over_30_days_before_starting() {
        let (result, requests) = run_with(
            vec![],
            &["run", "--surface", "s1", "--yes", "--force", "--wait", "--timeout", "10000000000000000000s"],
        )
        .await;
        let error = result
            .expect_err("too long")
            .to_string();
        assert!(error.contains("--timeout"), "{error}");
        assert!(requests.is_empty());
        let (result, requests) =
            run_with(vec![], &["run", "--surface", "s1", "--yes", "--force", "--wait", "--timeout", "31d"]).await;
        assert_eq!(
            result
                .expect_err("over the maximum")
                .to_string(),
            "--timeout can be at most 30d"
        );
        assert!(requests.is_empty());
    }

    #[tokio::test]
    async fn test_run_checks_again_after_confirming_and_sends_nothing_when_busy() {
        let (host, requests) = scripted_agent_stream_in_order(vec![
            ("GET /api/v1/drift/runs?surface_id=s1", "HTTP/1.1 200 OK", "[]"),
            ("GET /api/v1/drift/runs?limit=200", "HTTP/1.1 200 OK", "[]"),
            ("GET /api/v1/pipes/s1", "HTTP/1.1 200 OK", "{}"),
            (
                "GET /api/v1/drift/runs?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"[{"id":"late","surface_id":"s1","status":"running"}]"#,
            ),
        ])
        .await;
        let Drift {
            command: DriftCommand::Run(args),
        } = Drift::parse_from(["drift", "run", "--surface", "s1"])
        else {
            panic!("expected run");
        };
        let error = start_run(&client_for(host).await, args, Output::Json, |_| async { Ok(true) })
            .await
            .expect_err("busy after confirming")
            .to_string();
        assert!(error.contains("drift run 'late' on surface 's1' is in progress"), "{error}");
        let sent = start_lines(&requests);
        assert_eq!(sent.len(), 4, "{sent:?}");
        assert!(
            !sent
                .iter()
                .any(|line| line.starts_with("POST")),
            "{sent:?}"
        );
    }

    #[tokio::test]
    async fn test_run_refuses_a_bad_timeout_before_starting() {
        let (result, requests) =
            run_with(vec![], &["run", "--surface", "s1", "--yes", "--force", "--wait", "--timeout", "soon"]).await;
        let error = result
            .expect_err("bad timeout")
            .to_string();
        assert!(error.contains("--timeout 'soon' is not a duration"), "{error}");
        assert!(requests.is_empty());
    }

    #[test]
    fn test_run_timeout_needs_wait() {
        let parsed = Drift::try_parse_from(["drift", "run", "--surface", "s1", "--timeout", "30m"]);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_session_cap_shows_what_agent_stream_applies() {
        assert_eq!(describe_session_cap(Some(500)), "200 (the surface sets 500; Agent Stream replays 1 to 200)");
        assert_eq!(describe_session_cap(Some(0)), "1 (the surface sets 0; Agent Stream replays 1 to 200)");
        assert_eq!(describe_session_cap(Some(200)), "200");
    }

    #[tokio::test]
    async fn test_spend_caps_refuse_an_unsafe_surface_id_without_a_request() {
        let (host, requests) = scripted_agent_stream(vec![]).await;
        let caps = spend_caps(&client_for(host).await, "../admin").await;
        assert_eq!(caps, ("unknown".to_owned(), "unknown".to_owned()));
        assert!(start_lines(&requests).is_empty());
    }

    #[tokio::test]
    async fn test_runs_list_json_hides_replayed_content() {
        let (host, _) = scripted_agent_stream(vec![(
            "GET /api/v1/drift/runs?limit=25",
            "HTTP/1.1 200 OK",
            r#"[{"id":"r1","samples":[{"input":"secret prompt","output":"answer","error":"echoed secret"}]}]"#,
        )])
        .await;
        let runs = fetch_runs(&client_for(host).await, None, 25)
            .await
            .expect("runs");
        let text = runs.to_string();
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(runs[0]["samples"][0]["error"], Value::from(LIST_MASKED_VALUE));
    }

    #[test]
    fn test_run_help_states_the_spend_and_the_guards() {
        use clap::CommandFactory;

        let help = Drift::command()
            .find_subcommand_mut("run")
            .expect("run")
            .render_long_help()
            .to_string();
        for expected in ["billed", "--yes", "--force", "experiment", "Ctrl-C", "Examples:"] {
            assert!(help.contains(expected), "missing {expected}: {help}");
        }
    }

    #[test]
    fn test_describe_seconds_uses_the_largest_whole_unit() {
        assert_eq!(describe_seconds(604_800), "7d");
        assert_eq!(describe_seconds(86_400), "1d");
        assert_eq!(describe_seconds(5_400), "90m");
        assert_eq!(describe_seconds(300), "5m");
        assert_eq!(describe_seconds(301), "301s");
    }

    #[test]
    fn test_runs_list_refuses_limit_with_surface() {
        let parsed = Drift::try_parse_from(["drift", "runs", "list", "--surface", "s1", "--limit", "3"]);
        assert!(parsed.is_err());
    }
}
