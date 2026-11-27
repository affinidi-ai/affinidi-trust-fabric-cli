# Agent Stream Governance and Drift

Audit an Agent Stream from a terminal: read its governance records, check that they are intact, and watch each surface's drift.

These commands exist only in builds with the `agent-stream` Cargo feature, which releases leave out. All of them start with `fabric agent-stream`.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`governance records list --surface <id>`](#list-governance-records) | List one page of a surface's records, newest first |
| [`governance records get <record-id> --surface <id>`](#view-one-record) | Show one record, with its prompt content hidden |
| [`governance records get ... --reveal`](#show-prompt-content) | Show that record's prompt content too, with a warning |
| [`governance verify [--surface <id>]`](#check-that-records-are-intact) | Check that record chains are intact; exits 1 if one is not |
| [`governance coverage [--gaps-only]`](#see-which-surfaces-record) | Show which LLM Surfaces record and export records |
| [`governance surfaces`](#see-which-surfaces-record) | List the surfaces that have records |
| [`drift status --surface <id>`](#see-a-surfaces-drift) | Show the drift verdict of each dimension against the baseline |
| [`drift baseline get` / `set`](#read-or-re-pin-the-baseline) | Read the baseline, or re-pin it after confirming |
| [`drift runs list` / `get`](#list-and-view-runs) | List replay runs, or show one with its samples hidden |
| [`drift run --surface <id>`](#start-a-replay-run) | Start a replay run after confirming |
| [`drift cancel <run-id>`](#cancel-a-run) | Cancel a run in progress |

## Who can run them

| Permission | Commands | Default |
| --- | --- | --- |
| `governance.view` | every `governance` command | administrators only |
| `drift.view` | `drift status`, `drift baseline get`, `drift runs` | administrators only |
| `drift.manage` | `drift run`, `drift cancel`, `drift baseline set` | administrators only |

`drift run` also needs `drift.view` for its check for a run in progress, unless `--force` is given, and `drift baseline set` needs it to read the current baseline, unless `--yes` is given. An access token must list each permission in its scopes too. When Agent Stream refuses a request with 403, the error names the permission the command needed.

A token limited to a tenant or to some resources gets `404` for a surface outside its scope, and the error says there is `no surface '<id>' that this login can read`. Agent Stream does not otherwise check that a surface exists, so for an administrator a mistyped surface ID is not an error: `records list` finds no records, `verify` reports a valid chain of 0 records, and `drift status` shows every dimension as `unknown`. Check the ID with `governance surfaces` when a result looks empty.

## Prompt content stays hidden

Governance records hold the caller's prompt and the model's answer. Drift runs hold the prompts and answers they replayed. Both can hold personal data, so the CLI hides them:

| Item | Hidden fields |
| --- | --- |
| Governance record | `record.prompt`, `record.completion`, each stage's `input` and `output`, each attachment's `filename`, and `signed_vc` (the signed credential, which holds the whole record) |
| Drift run | each sample's `input` and `output` |

Each hidden field is replaced with a placeholder, in table and JSON output alike. A field that is absent or null stays as it is, so a record from a surface that stores no bodies still shows that it has none.

Only `get` of one record or one run shows them, with `--reveal`. It then prints this warning on standard error, unless the item holds no prompt content:

```text
warning: this output contains prompt content (prompts and model answers, which can hold personal data); do not share or log it
```

Lists never show prompt content and have no `--reveal`.

## Governance records

Agent Stream keeps one signed record per model call on a surface that records them. Each record is chained to the one before it on the same surface, so a changed or missing record shows when the chain is checked.

### List governance records

```sh
fabric agent-stream governance records list --surface support-bot
```

| Column | Record field |
| --- | --- |
| `TIMESTAMP` | `record.timestamp` |
| `ID` | `record.record_id` |
| `OUTCOME` | `blocked` when a stage blocked the call, else `failed` when a stage failed, else `ok`, as Agent Stream reads it |
| `MODEL` | `record.metrics.model` |
| `TOKENS` | `record.metrics.total_tokens` |
| `COST` | `record.metrics.cost` |
| `SEQ` | `seq`, the record's place in the surface's chain |

| Flag | Meaning |
| --- | --- |
| `--surface` | The surface whose records to list. Required |
| `--limit` | Records on the page, from 1 to 500. Defaults to 50 |
| `--cursor` | The cursor of the page to read, as the previous page printed it |
| `--outcome` | Only `ok`, `blocked` or `failed` records, comma-separated |
| `--stage` | Only records blocked or failed at these stages, comma-separated, such as `judge,jury` |
| `--since` / `--until` | Only records at or after, or before, a time. See [Times](#times) |
| `--order` | `desc` (newest first, the default) or `asc` (oldest first) |

There is no way to read every record at once, as in the Agent Stream dashboard, which has no download either. A page has at most 500 records, and the CLI never sends a request without a limit, which Agent Stream would answer with every record.

When more records match, the next page's cursor is printed on standard error:

```text
More records match; pass --cursor 4182 with the same options for the next page.
```

With `--output json`, standard output is `{"records": [...], "next_cursor": "4182"}`, with `next_cursor` set to `null` on the last page. Each record is the whole stored record, with its prompt content replaced.

If Agent Stream answers with more records than asked for, the command prints nothing and fails, rather than cutting the page short and skipping records. A record in a shape the CLI does not know is refused the same way, so its prompt content can't slip past the masking.

With no records, the table reads `No governance records yet.`, or `No matching governance records.` when a filter or `--cursor` was given.

### View one record

```sh
fabric agent-stream governance records get 6f1c2a9e-5b7d-4c1e-9a3f-2d8b7e6c5a41 --surface support-bot
```

Prints the record as JSON: its stages (each with its outcome, reason, policy and digests), metrics, attribution and hashes, with its prompt content replaced. The record ID holds letters, digits, `-` and `_`, at most 64 characters; any other ID is refused before anything is sent.

### Show prompt content

```sh
fabric agent-stream governance records get 6f1c2a9e-5b7d-4c1e-9a3f-2d8b7e6c5a41 --surface support-bot --reveal
```

Prints the whole record as Agent Stream returned it, and the warning on standard error. See [Prompt content stays hidden](#prompt-content-stays-hidden).

### Check that records are intact

```sh
fabric agent-stream governance verify
fabric agent-stream governance verify --surface support-bot
```

Agent Stream checks a surface's whole chain: every record's hash and signature, the link to the record before it, and that the chain reaches its last record. Without `--surface`, the CLI checks every surface that `governance surfaces` lists, one after another.

| Column | Meaning |
| --- | --- |
| `ID` | The surface |
| `VALID` | `yes` when the chain is intact |
| `RECORDS` | How many records were checked |
| `PROBLEM` | `none`, or `broken` (a record changed or is missing), `unknown_key` (signed with a key Agent Stream does not know), `truncated`, or `index_mismatch`. `not_checked` when the check could not be run for that surface, such as a refusal or a `404`; the other surfaces are still checked |
| `ERROR` | Agent Stream's note on the first problem |

A `broken` or `index_mismatch` chain is a security finding. The CLI says so on standard error and repairs nothing:

```text
security finding: the governance record chain of surface 'support-bot' is broken: a record was changed or removed, or the index no longer matches the log. Do not try to repair it; keep the records as they are and investigate.
```

A surface with no records, a mistyped ID included, verifies as valid with 0 records. If the list of surfaces can't be read, the command fails without checking any. It exits 1 when any chain is not valid or not checked, with `error: N of M governance record chains did not verify`, so a script can rely on the exit status. With `--output json`, standard output is the list of Agent Stream's verdicts, one per surface, even for a single `--surface`.

### See which surfaces record

```sh
fabric agent-stream governance coverage --gaps-only
fabric agent-stream governance surfaces
```

`coverage` lists the LLM Surfaces with `RECORDING` (records governance records), `EXPORT` (sends them to an integration or OpenTelemetry) and `PIPE EVENTS`. `--gaps-only` keeps the surfaces that do not record or do not export.

`surfaces` lists the surfaces that have records, deleted ones included, named as their latest record names them.

## Drift

Drift monitoring compares a surface's recent answers with a pinned baseline, dimension by dimension: quality, refusal rate, safety flags, length, tokens, cost, latency, schema validity and semantic distance. Turning drift on, and its thresholds and caps, are surface settings (`drift` on the surface document), not part of these commands.

### See a surface's drift

```sh
fabric agent-stream drift status --surface support-bot --since 7d
```

The first line gives the overall status and when the baseline was pinned, then one row per dimension:

| Column | Meaning |
| --- | --- |
| `DIMENSION` | The dimension |
| `STATUS` | `stable`, `warn`, `drift`, or `unknown` (no baseline, or no samples) |
| `BASELINE` | The dimension's mean in the baseline |
| `CURRENT` | Its mean over the window |
| `CHANGE` | The relative change from the baseline |
| `SAMPLES` | The samples in the window |

The window ends at `--until`, now by default, and starts at `--since`, 24 hours before its end by default. See [Times](#times). `--output json` prints Agent Stream's verdict as it is.

### Read or re-pin the baseline

```sh
fabric agent-stream drift baseline get --surface support-bot
fabric agent-stream drift baseline set --surface support-bot --window 7d
```

`get` prints the baseline: when it was pinned, its window, and each dimension's mean. With none pinned, it prints `No drift baseline is pinned for surface '<id>'.` (`null` with `--output json`).

`set` replaces the surface's only baseline with each dimension's mean over the last `--window`: a duration from `5m` to `30d`, `24h` by default. This changes the surface's drift verdict and, when its drift settings have `gate_on_regression` on, whether the surface can be saved. So the command reads the current baseline, shows it with the new window, and asks you to confirm; only `y` or `yes` re-pins. Without a terminal it refuses before sending anything, unless `--yes` is given, which also skips the question.

### List and view runs

```sh
fabric agent-stream drift runs list --surface support-bot
fabric agent-stream drift runs get 0b6c1f7e-3d2a-4e8b-9c51-7a4f2e9d6b10
```

With `--surface`, `runs list` shows every run of that surface: runs in progress first, then its history. Without it, runs in progress and the most recent ones across all surfaces, up to `--limit` (25 by default, at most 200). `--limit` can't be combined with `--surface`.

| Column | Run field |
| --- | --- |
| `ID` | `id` |
| `SURFACE` | `surface_id`, whose captured sessions were replayed |
| `TARGET` | `target_surface_id`, for an experiment against another surface |
| `STATUS` | `pending`, `running`, `completed`, `failed`, `cancelled` or `stopped` |
| `TRIGGER` | `manual` or `scheduled` |
| `RAN AT` | `ran_at` |
| `PASSED` / `TOTAL` | Sessions that passed, and sessions replayed |
| `COST USD` | `cost_usd`, what the replay cost |

`runs get` prints one run: status, progress, scores, cost and each dimension's verdict, with each sample's input and output replaced unless `--reveal` is given.

### Start a replay run

```sh
fabric agent-stream drift run --surface support-bot --wait
```

A replay sends the surface's captured sessions to a model again and scores the answers. The calls are real and billed, so before starting:

1. Unless `--force` is given, the CLI lists the surface's runs, and the target's for an experiment, and refuses if one is `pending` or `running`. Agent Stream itself would start runs side by side.
2. Unless `--yes` is given, the CLI reads the surface whose sessions are replayed and shows its session cap (`drift.eval.max_sessions`, 50 when unset) and cost cap (`drift.eval.max_run_cost_usd`). Agent Stream takes both caps from that surface even for an experiment against another surface. When the CLI can't read the surface, both show `unknown`. Then it asks you to confirm; only `y` or `yes` starts the run.

Without a terminal and without `--yes`, the command refuses before sending anything.

| Flag | Meaning |
| --- | --- |
| `--surface` | The surface whose captured sessions are replayed. Required |
| `--target` | Replay against this surface instead |
| `--variant` | Replay against this variant (by its alias) of the target, or of the surface |
| `--wait` | Wait until the run ends |
| `--yes` | Start without asking |
| `--force` | Start even though a run is already in progress |

With `--target` or `--variant`, the run is an experiment: it never feeds the surface's drift series or verdict.

Without `--wait`, the command prints `Started drift run '<id>' on surface '<id>'.` (with `--output json`, the run as Agent Stream answered, its samples hidden) and exits.

With `--wait`, progress goes to standard error whenever it changes, such as `drift run '<id>': running, 12 of 50 sessions done`. When the run ends, it is printed with its samples hidden, and the command exits 1 if the run did not complete: `error: drift run '<id>' ended cancelled`. When the waiting starts, the `drift cancel` command for the run is printed on standard error; Ctrl-C then stops waiting without cancelling the run.

### Cancel a run

```sh
fabric agent-stream drift cancel 0b6c1f7e-3d2a-4e8b-9c51-7a4f2e9d6b10
```

Agent Stream stops the run after the session in progress. The run is recorded as `cancelled`, with its partial results and cost, and never feeds the drift series. This can't be undone, and there is no confirmation prompt. A run that is not in progress gets `404`.

## Times

`--since` and `--until` take any of:

| Form | Example |
| --- | --- |
| RFC 3339 time, with `Z` or an offset | `2026-11-20T09:00:00Z`, `2026-11-20T17:00:00+08:00` |
| Unix seconds | `1763629200` |
| A duration before now | `30m`, `24h`, `7d`, `2w` (units `s`, `m`, `h`, `d`, `w`) |

The CLI turns each into unix seconds before sending it. `--since` must be before `--until`. `drift baseline set --window` takes a duration only.

## Not covered

- **Downloading records.** There is no export, on purpose.
- **Drift sessions, series and dimensions.** Captured sessions hold raw prompts with no metadata-only view, and the series are chart data the dashboard shows better. `fabric agent-stream api` can still reach `/v1/drift/series` and `/v1/drift/dimensions`.
- **Recording and drift settings.** Turning governance recording or drift on, and changing their settings, are surface edits.
