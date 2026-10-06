# Observability

Read what the gateway recorded: the audit log, payment records, metrics, and log files.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`audit list`](#read-the-audit-log) | List audit events, newest first, one page at a time |
| [`audit list --all`](#export-the-whole-audit-log) | Read every page of the audit log |
| [`audit list --category` / `--filter` / `--flow` / `--scope` / `--decision`](#filter-audit-events) | Narrow the audit events you read |
| [`payments list`](#list-payment-records) | List x402 and MPP payment records in one merged table |
| [`payments get <transaction-id>`](#get-one-payment-record) | Show one full payment record |
| [`payments stats [--sync]`](#show-settlement-counters) | Show x402 settlement counters |
| [`payments delete <transaction-id> --yes`](#delete-an-x402-transaction) | Delete a finalised x402 transaction |
| [`metrics status`](#check-metrics-export-health) | Report OpenTelemetry export health |
| [`metrics config show` / `set`](#update-the-metrics-configuration) | Read or replace the metrics configuration |
| [`metrics scrape`](#scrape-metrics) | Fetch the Prometheus exposition |
| [`metrics test-endpoint <url>`](#test-an-otlp-endpoint) | Check whether the gateway can reach an OTLP endpoint |
| [`metrics truncate --yes`](#delete-old-metrics) | Delete metrics older than the retention period |
| [`logs download`](#download-logs) | Download every log file as one ZIP archive |
| [`logs truncate --yes`](#delete-rotated-log-files) | Delete every rotated log file |

All commands start with `fabric agent-gateway`. Several commands share rules for redaction, table cells, and confirmation: see [How observability output behaves](#how-observability-output-behaves). Some read-only endpoints have no command at all: see [Left to `fabric agent-gateway api`](#left-to-fabric-agent-gateway-api).

These four groups are aggregates and verbs rather than collections. Their value is in the query filters and in what the CLI merges locally, not in CRUD.

## Audit log

### Read the audit log

```sh
fabric agent-gateway audit list --limit 50
```

`audit list` prints one page of events, newest first, in this table:

| Column | Event field |
| --- | --- |
| `TIMESTAMP` | `timestamp` |
| `EVENT` | `event`, the event type, such as `policy_decision` or `token_revoked`. It matches the `--category` name, except that payment events show `payment_event` and are selected with `payment` |
| `SURFACE` | `surface_id` |
| `DECISION` | `decision` |
| `DETAIL` | `detail`, the gateway's own note on the event, such as `0 tokens revoked` on a `user_tokens_revoked` event |

| Flag | Meaning |
| --- | --- |
| `--limit` | Events per page. Defaults to 100; the gateway clamps it to 1–500 |
| `--page` | Page to read, counting from 1. Can't be combined with `--all` |
| `--reveal` | Show the caller's email and name and the full VP JWT. See [Sensitive fields are redacted by default](#sensitive-fields-are-redacted-by-default) |

Good to know:

- Audit events carry no `id`, `name`, or `description`, so this table has its own columns.
- A field the event lacks shows as `-`.
- A long `detail` ends in `...`, and every cell stays on one row. See [Table cells stay on one line](#table-cells-stay-on-one-line).
- With no events, the table reads `No audit events yet.`, or `No matching audit events.` when a filter or `--page` was given.

The audit log records gateway traffic, not administration: delegation consent and tokens, policy decisions, trust checks, VP injection, payments, and trace terminations.

> [!NOTE]
>
> - **Admin API calls are not audited.** Creating an identity, for example, never appears here. The one exception is revoking delegation tokens, which records `token_revoked` or `user_tokens_revoked`.
> - **Gateway settings gate three kinds of event.** Each is recorded only when `audit_enabled` is on and its own category setting is on. Turning `audit_enabled` off stops all three. Every other event is recorded whatever those settings say.

| Setting | Records |
| --- | --- |
| `audit_categories.policies` | Policy decisions |
| `audit_categories.trust_checks` | Trust checks |
| `audit_categories.identity` | VP-injection events, not changes to identities |

> [!IMPORTANT]
> **An empty result is ambiguous.** The gateway answers HTTP 200 with no events when the audit log is genuinely empty, when its audit subsystem failed to start, and when it cannot read the audit file or the file is not valid UTF-8. It also silently drops any line of the file it cannot parse, so a listing can be short as well as empty.

When the table is empty, the CLI explains this on standard error, with each line starting with `note:`. The note also says what the log records, and that admin API calls are not audited.

### Export the whole audit log

```sh
fabric agent-gateway audit list --all --output json > audit.json
```

`--all` pages through the whole log rather than reading one page. This is the main thing the dashboard view cannot do.

Events are redacted in the export unless you pass `--reveal`, so writing it to a file or a CI log does not leak a credential by default. See [Sensitive fields are redacted by default](#sensitive-fields-are-redacted-by-default).

> [!NOTE]
> Events written during a long `--all` run can shift rows across page boundaries. If the export has to be exact, take it when the gateway is quiet.

<details>
<summary>How <code>--all</code> pages, and why rows can shift</summary>

`--all` reads the page count from the first page, then requests each remaining page. The gateway clamps a page past the end back into range instead of returning an empty page, so the CLI also stops as soon as a response comes back with a different page number or no events.

Paging is by offset over a newest-first list. Events written while the run is in progress shift the offsets, and can push rows past a page boundary the run has already passed.

</details>

### Filter audit events

```sh
fabric agent-gateway audit list --category policy_decision,trust_check
fabric agent-gateway audit list --flow access_point --decision deny
```

| Flag | Meaning |
| --- | --- |
| `--category` | Comma-separated event categories, such as `policy_decision,trust_check,consent_granted,token_injected,payment`. An OR set: an event matching any of them is kept |
| `--filter` | Case-insensitive substring, matched by the gateway against each event re-serialised as JSON, including policy evidence the gateway adds from signed VPs |
| `--flow` | Policy decisions from this request flow: `access_point`, `transit_point`, or `fabric` |
| `--scope` | Policy decisions at this scope: `gateway`, `surface`, `mcp_tool`, or `response` |
| `--decision` | Policy decisions with this outcome: `allow` or `deny` |

> [!WARNING]
>
> - **`--flow`, `--scope`, and `--decision` restrict the view to policy decisions.** Setting any of them drops every other kind of event, rather than narrowing the policy decisions within a wider set.
> - **`--filter` matches more than a row displays.** It also matches field names and the base64 body of an embedded JWT.

Good to know:

- There is no separate delegation-audit command. Delegation events are a subset of the audit log, so select them with `--category`.

<details>
<summary>Reproduce the gateway's delegation-audit view</summary>

`/v1/audit` and `/v1/delegation-audit` read the same append-only file. In which events they return, they differ by one filter. The delegation view drops policy decisions, trust checks, and trace terminations, and keeps every other category.

Because `--category` is an OR set, reproducing that view means naming the sixteen categories it keeps:

```sh
fabric agent-gateway audit list --category consent_granted,consent_required,token_injected,token_refreshed,token_revoked,token_not_found,refresh_failed,user_tokens_revoked,vp_injected,pre_authorize_blocked,payment,elicitation_sent,elicitation_accepted,elicitation_declined,elicitation_cancelled,elicitation_timed_out
```

A shorter list is a narrower view, not the same one, and it fails quietly. Asking only for the consent and token-injection categories, for example, hides `refresh_failed`, `consent_required`, `token_revoked`, and the whole `elicitation_*` family.

</details>

## Payments

The gateway keeps payment records in two independent stores, x402 and MPP, behind separate endpoints. The `payments` commands read both, which `fabric agent-gateway api` cannot do in one call.

> [!NOTE]
> On a gateway with no payment stores configured, these routes do not exist at all. The CLI reports this as "payments are not enabled on this gateway".

### List payment records

```sh
fabric agent-gateway payments list
fabric agent-gateway payments list --store x402 --surface <surface-id> --status verified
```

`payments list` reads both stores by default and merges them into one table, newest first:

| Column | Record field |
| --- | --- |
| `ID` | `id`, the transaction ID |
| `STORE` | Which store the record came from: `x402` or `mpp` |
| `SURFACE` | `surface_id` |
| `STATUS` | `status`. For x402, this is the verification status |
| `AMOUNT` | `amount` |
| `CURRENCY` | `currency` for MPP; `asset` for x402 (empty for a native asset) |
| `CREATED` | `created_at`, as an ISO 8601 UTC time. See [Table times are ISO 8601 UTC](#table-times-are-iso-8601-utc) |

| Flag | Meaning |
| --- | --- |
| `--store` | `x402`, `mpp`, or `all`. Defaults to `all`, which reads both and merges them |
| `--surface` | Only records for the Agent Surface with this ID. A surface name is not accepted |
| `--status` | Only records with this status. Matching ignores case |
| `--limit` | Maximum records to read from each store. Defaults to 100 |

Good to know:

- One `--status` value can select from both stores, because they share `verified` and `failed` and differ only in case.
- Settlement is a separate x402 field that the merged row drops, so no `--status` value selects on it. Read it from [`payments get`](#get-one-payment-record).
- Every cell is cleaned like an audit row. See [Table cells stay on one line](#table-cells-stay-on-one-line).
- With no records, the table reads `No payments yet.` (`No matching payments.` when filtered).
- Only the MPP footer reports a real "N of total", and only when `--status` is not set. The x402 total can only ever equal the number of rows returned.

> [!IMPORTANT]
> **Both stores require the `payments.view` permission.** If one store rejects the request, `list` still prints the rows it did read and names the store it could not read on standard error. It fails only when no store could be read at all.

<details>
<summary>How <code>--status</code> and totals differ between x402 and MPP</summary>

`--status` is a query parameter on x402 but not on MPP, so the CLI filters MPP records after they are fetched.

| Store | Filterable status values |
| --- | --- |
| x402 | The verification status: `Pending`, `Verified`, `Failed`, `Timeout` |
| MPP | `verified`, `failed`, `challengeissued` |

x402 computes its record total after applying the limit, so its total always equals the number of rows returned. MPP reports the real total.

</details>

### Get one payment record

```sh
fabric agent-gateway payments get <transaction-id>
```

| Flag | Meaning |
| --- | --- |
| `--store` | `x402`, `mpp`, or `all`. The default tries x402 and then MPP, because record IDs do not say which store they belong to |
| `--reveal` | Show the signed payment credentials and the payer signature |

A full record carries the signed `PaymentReceiptCredential` and `PaymentRejectionCredential` JWTs and, for x402, the payer's signature. These are redacted unless you pass `--reveal`. The `sha256:` fingerprint beside each JWT is kept, so a redacted record is still verifiable. See [Sensitive fields are redacted by default](#sensitive-fields-are-redacted-by-default).

### Show settlement counters

```sh
fabric agent-gateway payments stats --sync
```

`payments stats` shows the x402 settlement counters. `--sync` also reports cross-gateway synchronisation health.

### Delete an x402 transaction

```sh
fabric agent-gateway payments delete <transaction-id> --yes
```

`payments delete` deletes a finalised x402 transaction. It requires `--yes`. See [Destructive commands require `--yes`](#destructive-commands-require---yes).

Good to know:

- `delete` is x402 only. MPP records cannot be deleted.

> [!NOTE]
> **x402 reports every error its handlers raise as HTTP 500**, such as an unknown ID or a transaction whose verification or settlement is still pending, so only the message tells them apart. MPP answers 404 for an unknown ID and 500 for other failures. For both stores, the CLI prints the gateway's message without the status code.

## Metrics

### Check metrics export health

```sh
fabric agent-gateway metrics status
```

`metrics status` reports OpenTelemetry export health.

### Update the metrics configuration

```sh
fabric agent-gateway metrics config show --output json > metrics.json
fabric agent-gateway metrics config set --file metrics.json
```

Always start from `config show --output json`, edit that file, then pass it to `config set`.

| Flag | Meaning |
| --- | --- |
| `--file`, `-f` | The replacement JSON document. `-` reads standard input |
| `--force` | Submit the document even though the CLI's check refuses it |

> [!CAUTION]
> **`config set` removes or resets any setting the document leaves out.** It replaces the whole document rather than patching it. Leaving out `opentelemetry.auth` removes it. Leaving out `retention`, `advanced`, or `opentelemetry.protocol` resets it to the gateway default (`protocol` falls back to `grpc`), which discards any custom values. The live exporter is re-applied immediately, so omitting `opentelemetry.auth` silently switches collector export to unauthenticated.

To guard against this, the CLI reads the live document first and refuses any submission that would drop a stored setting, listing each one. Replacing a stored section with `null` or any other non-object value is refused by name too. For `opentelemetry.auth`, `null` removes the section exactly as leaving the key out does. Pass `--force` to submit anyway.

> [!WARNING]
> **Read the message, not the success flag.** The gateway reports success as soon as the file is written, even when re-applying it to the running collector failed. `config set` therefore prints the response's `message` rather than reading `success`.

### Scrape metrics

```sh
fabric agent-gateway metrics scrape | promtool check metrics
fabric agent-gateway metrics scrape --username prometheus --output-file metrics.txt
```

`scrape` returns a Prometheus exposition, not JSON.

| Flag | Meaning |
| --- | --- |
| `--username` | Prometheus Basic-auth user configured in the gateway's admin settings. Falls back to `FABRIC_METRICS_USERNAME` |
| `--password` | Password for `--username`. Falls back to `FABRIC_METRICS_PASSWORD`; prefer the variable, since a command-line value lands in shell history |
| `--output-file` | Where to write the exposition. Defaults to `-`, standard output. See [File output and display format are separate](#file-output-and-display-format-are-separate) |

Good to know:

- When the gateway has Prometheus authentication enabled, this route needs HTTP Basic credentials in the same header the bearer token would occupy. So `--username` and `--password` are sent *instead of* the token.
- Set both or neither. The two options require each other, and a value supplied through the environment counts as supplied.

### Test an OTLP endpoint

```sh
fabric agent-gateway metrics test-endpoint http://otel-collector:4317
```

`test-endpoint` checks whether the gateway can reach an OTLP endpoint. Give the URL including the scheme.

Good to know:

- The test only opens a TCP connection.
- The gateway answers HTTP 200 for every connection outcome, including a refused connection and a timeout. It answers 400 only when it rejects the URL itself (for example, a non-http(s) scheme or a loopback address). The CLI takes its verdict from the response's `success` field, so a failed test exits non-zero.

### Delete old metrics

```sh
fabric agent-gateway metrics truncate --yes
```

`metrics truncate` deletes metrics older than the configured retention period. It cannot be undone, and requires `--yes`. See [Destructive commands require `--yes`](#destructive-commands-require---yes).

## Logs

### Download logs

```sh
fabric agent-gateway logs download --output-file logs.zip
```

`download` retrieves every log file as one ZIP archive. `--output-file` defaults to `logs.zip`; `-` writes to standard output. See [File output and display format are separate](#file-output-and-display-format-are-separate).

> [!NOTE]
> The gateway builds the whole archive in memory before sending it, so this is expensive on a large log directory.

### Delete rotated log files

```sh
fabric agent-gateway logs truncate --yes
```

`truncate` deletes every rotated log file and keeps the current one.

> [!CAUTION]
> **This is irreversible, and there is no prompt**, so the CLI requires `--yes`.

## How observability output behaves

These rules apply across the `audit`, `payments`, `metrics`, and `logs` commands.

### Sensitive fields are redacted by default

Some records carry credentials or personal data. These fields are replaced with `[redacted]` unless you pass `--reveal`:

| Command | Redacted fields |
| --- | --- |
| `audit list` | The caller's raw email and display name, and the `vp_jwt` field of any event that carries one: the complete VP for VP injections and delegation events, or the payment credential for payment events |
| `payments get` | The signed `PaymentReceiptCredential` and `PaymentRejectionCredential` JWTs and, for x402, the payer's signature |

Redaction means writing output to a file or a CI log does not leak a credential by default. In payment records, the `sha256:` fingerprint beside each JWT is kept, so a redacted record is still verifiable.

### Table cells stay on one line

In the `audit list` and `payments list` tables, every cell is stripped of control characters, and its line breaks and tabs become spaces. Each record stays on one row with its columns in place.

### Table times are ISO 8601 UTC

Table output shows times as ISO 8601 UTC, like the tokens and audit tables. In `payments list`, `--output json` keeps the Unix seconds both payment stores return in `created_at`. Full records from `payments get` already carry RFC 3339 times.

### Destructive commands require `--yes`

`payments delete`, `metrics truncate`, and `logs truncate` refuse to run without `--yes`. There is no confirmation prompt: with `--yes` they run at once.

### File output and display format are separate

`metrics scrape` and `logs download` name their destination with `--output-file`, where `-` means standard output. The global `--output` still selects the display format.

## Left to `fabric agent-gateway api`

These endpoints are deliberately not wrapped, because a command would add nothing over a raw call:

| Endpoint | Why it has no command |
| --- | --- |
| `GET /v1/dashboard/stats`, `/v1/dashboard/delta`, `/v1/dashboard/surface/{id}/metrics`, `/v1/dashboard/surface/{id}/ucp-operations`, `/v1/dashboard/system-metrics` | Aggregates whose value is a rendered dashboard, not a table. `/v1/dashboard/delta` is also deprecated in the gateway source |
| `GET /v1/dashboard/metrics/hierarchical` | A nested map four levels deep (surface, source, identity, destination) with no useful flat projection |
| `GET /api/admin/x402/payments/all` | Its extra content over `payments list` is a separate row per settlement and `chart_data`, for a graph the CLI does not draw |
| The x402 `verifications` and `settlements` paths | Deprecated aliases of `transactions`, bound to the same handlers |
| `/api/ws`, `/api/ws/dashboard` | Websockets, which a request/response CLI cannot wrap |

```sh
fabric agent-gateway api get /v1/dashboard/stats --output json
fabric agent-gateway api get /v1/dashboard/metrics/hierarchical --output json
```

## Related

- [Gateway configuration](GATEWAY_CONFIGURATION.md): audit and Prometheus settings
- [Scripting and output](SCRIPTING_AND_OUTPUT.md): tables, JSON, and the raw api command
