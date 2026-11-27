//! `fabric agent-stream drift`: a surface's drift verdict, its baseline, and
//! the replay runs that measure it.
//!
//! A replay sends a surface's captured sessions to its model again, which is
//! real spend, so `drift run` shows the surface's caps and asks first, and
//! refuses while another run of the surface is in progress. A run's samples
//! hold the replayed prompts and answers, which are hidden unless one run is
//! asked for with `--reveal` (see [`prompt_content`]).

use std::time::Duration;

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
    client::GatewayClient,
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

/// Sessions one replay sends when the surface sets no `drift.eval.max_sessions`.
const DEFAULT_MAX_SESSIONS: u64 = 50;

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
    /// shows the run's session cap (`drift.eval.max_sessions`, 50 when unset)
    /// and cost cap (`drift.eval.max_run_cost_usd`), which Agent Stream takes
    /// from the surface whose sessions are replayed even for an experiment, or
    /// `unknown` when that surface can't be read. Then it asks you to confirm;
    /// only `y` or `yes` starts the run. Without a terminal it refuses unless
    /// --yes is given.
    ///
    /// It also refuses while the surface (or, for an experiment, the target)
    /// already has a run pending or running, unless --force is given. That
    /// check needs `drift.view` as well as the `drift.manage` the run needs.
    ///
    /// With --target or --variant the run is an experiment: it replays the
    /// surface's sessions against another surface or a variant, and never
    /// feeds the surface's drift series or verdict.
    ///
    /// Prints the new run's id. With --wait, progress goes to standard error
    /// until the run ends, then the run is printed; the command exits 1 when
    /// the run failed, was cancelled, or was stopped. Ctrl-C stops waiting
    /// without cancelling the run; the command to cancel it is printed when
    /// the waiting starts.
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
    /// verdict. Each sample's input and output are replaced with a
    /// placeholder unless --reveal is given.
    #[command(after_long_help = RUNS_GET_EXAMPLES)]
    Get {
        /// ID of the run (see `fabric agent-stream drift runs list`).
        run_id: String,
        /// Show each sample's replayed prompt and answer. When there are any, a
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
    /// Replay against this surface instead, as an experiment.
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

  Try the surface's sessions against a variant, from a script:
    fabric agent-stream drift run --surface support-bot --variant cheaper-model \
      --yes --wait --output json"#;

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
        DriftCommand::Run(args) => start_run(client, args, output).await,
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
    let mut runs = read_runs(client, surface, limit).await?;
    let Value::Array(items) = &mut runs else {
        bail!("Agent Stream answered the drift runs list with something other than a list");
    };
    for run in items {
        prompt_content::mask(run, Item::DriftRun, LIST_MASKED_VALUE);
    }
    let scope = if surface.is_some() {
        Scope::Filtered
    } else {
        Scope::All
    };
    print_list(&runs, output, &tables::DRIFT_RUNS, scope)
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

/// The ids of the runs of `surface` that are pending or running.
async fn runs_in_progress(
    client: &GatewayClient,
    surface: &str,
) -> Result<Vec<String>> {
    let runs = read_runs(client, Some(surface), DEFAULT_RUNS_LIMIT).await?;
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
        .filter_map(|run| {
            run.get("id")
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
        .collect())
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
    let Ok(document) = client
        .request(Method::GET, &format!("{SURFACES_PATH}/{surface}"), None)
        .await
    else {
        return ("unknown".to_owned(), "unknown".to_owned());
    };
    let eval = document
        .get("drift")
        .and_then(|drift| drift.get("eval"));
    let sessions = match eval
        .and_then(|eval| eval.get("max_sessions"))
        .and_then(Value::as_u64)
    {
        Some(sessions) => sessions.to_string(),
        None => format!("{DEFAULT_MAX_SESSIONS} (Agent Stream's default)"),
    };
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

async fn start_run(
    client: &GatewayClient,
    args: RunArgs,
    output: Output,
) -> Result<()> {
    path_id("surface id", &args.surface, MAX_ID)?;
    if let Some(target) = &args.target {
        path_id("--target", target, MAX_ID)?;
    }
    if let Some(variant) = &args.variant {
        path_id("--variant", variant, MAX_ID)?;
    }
    let called = args
        .target
        .clone()
        .unwrap_or_else(|| args.surface.clone());
    let experiment = args.target.is_some() || args.variant.is_some();

    if !args.force {
        let mut checked = vec![args.surface.clone()];
        if called != args.surface {
            checked.push(called.clone());
        }
        for surface in &checked {
            let busy = name_missing_surface(runs_in_progress(client, surface).await, surface)?;
            if let Some(run_id) = busy.first() {
                bail!(
                    "surface '{}' already has drift run '{}' in progress; wait for it, cancel it with `fabric \
                     agent-stream drift cancel {}`, or pass --force to start another",
                    flatten(surface),
                    flatten(run_id),
                    flatten(run_id)
                );
            }
        }
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
        if !confirm_action("start a drift run on", &args.surface, async { prompt }).await? {
            bail!("drift run not started");
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
                prompt_content::mask(&mut started, Item::DriftRun, MASKED_VALUE);
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
    let finished = wait_for(client, &run_id).await?;
    let mut shown = finished.clone();
    prompt_content::mask(&mut shown, Item::DriftRun, MASKED_VALUE);
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

/// Reads the run until it is neither pending nor running, printing its
/// progress on standard error whenever it changes.
async fn wait_for(
    client: &GatewayClient,
    run_id: &str,
) -> Result<Value> {
    let mut last = None;
    loop {
        let run = read_run(client, run_id).await?;
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
                ("GET /api/v1/drift/runs?surface_id=s1", "HTTP/1.1 200 OK", r#"[{"id":"old","status":"completed"}]"#),
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
            ["GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1", "POST /api/v1/drift/eval/run?surface_id=s1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn test_run_refuses_while_a_run_is_in_progress() {
        let (result, requests) = run_with(
            vec![(
                "GET /api/v1/drift/runs?surface_id=s1",
                "HTTP/1.1 200 OK",
                r#"[{"id":"busy-1","status":"running"}]"#,
            )],
            &["run", "--surface", "s1", "--yes"],
        )
        .await;
        let error = result
            .expect_err("busy")
            .to_string();
        assert!(error.contains("already has drift run 'busy-1' in progress"), "{error}");
        assert_eq!(requests, ["GET /api/v1/drift/runs?surface_id=s1 HTTP/1.1"]);
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
            vec![(
                "POST /api/v1/drift/eval/run?surface_id=s1",
                "HTTP/1.1 403 Forbidden",
                r#"{"error":"Insufficient permissions"}"#,
            )],
            &["run", "--surface", "s1", "--yes", "--force"],
        )
        .await;
        let error = result
            .expect_err("403")
            .to_string();
        assert!(error.contains("`drift.manage` permission"), "{error}");
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
