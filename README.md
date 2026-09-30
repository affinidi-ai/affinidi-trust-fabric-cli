# Fabric CLI

`fabric` is the scriptable command-line client for Affinidi appliance management APIs.

Commands take the shape `fabric <appliance> <command>`. Agent Gateway commands live under `agent-gateway`, for example `fabric agent-gateway surfaces list`, and more appliances will be added later. Run `fabric` on its own to list the available appliances.

## Build

```sh
make cli-build
```

On macOS this also codesigns the binary with a stable identifier so the Keychain "Always Allow" prompt (for reading stored credentials) survives rebuilds — a plain `cargo build` produces an ad-hoc/unsigned binary whose Keychain code requirement is pinned to its content hash, so the prompt reappears on every rebuild. The binary is written to `cli/target/debug/fabric`.

For a release build: `make cli-build-release` (writes to `cli/target/release/fabric`).

## Interactive shell

Run `fabric agent-gateway shell` to open the interactive shell. Commands typed in the shell are Agent Gateway commands, without the `fabric agent-gateway` prefix, and use the same parser and behavior as one-shot invocations:

```text
$ fabric agent-gateway shell
Fabric Agent Gateway interactive shell. Type `help` for commands; `exit` or `quit` to leave.
fabric agent-gateway> surfaces list
fabric agent-gateway> surfaces create --name "Sales Agent" --description "Routes sales traffic"
fabric agent-gateway> help
fabric agent-gateway> exit
```

Running `fabric agent-gateway` with no command prints its help instead of opening the shell.

The shell supports quoted arguments, command history for the current session, Ctrl-C to cancel the current line, and Ctrl-D to exit. Global options supplied at startup become shell defaults and can be overridden per command:

```sh
fabric agent-gateway --connection production --output json shell
```

## Login

By default, `fabric agent-gateway login` opens your browser to complete the gateway's normal passkey or SAML SSO login and captures the session token automatically over a loopback redirect — no manual copy-paste.

```sh
fabric agent-gateway login --host https://gateway.example.com
```

The `https://` scheme may be omitted; bare gateway hostnames default to HTTPS. The flow is:

1. The CLI starts a temporary listener on `127.0.0.1` and opens `/auth/cli/authorize` in your browser.
2. You sign in with passkey or SSO (or, if already signed in, the browser continues immediately).
3. The gateway redirects back to `http://127.0.0.1:<port>/callback` with a single-use code.
4. The CLI exchanges the code plus a PKCE verifier for the session token over a direct back channel (the token never appears in a browser URL or history).

The captured token is validated with `/api/auth/check` and stored in the operating system credential store: macOS Keychain, Windows Credential Manager, or Linux Secret Service. Bearer tokens are never written to the CLI configuration file. Credentials use the `affinidi-fabric-cli` service name and the connection profile name as their account key.

Non-secret connection metadata such as profile names, hosts, and the current profile remains in the user configuration directory. On macOS the file is `~/Library/Application Support/fabric/config.toml`; on Linux it is normally `~/.config/fabric/config.toml`. Existing plaintext-token configurations are migrated to the OS credential store and scrubbed automatically on the next CLI invocation.

For automation or headless environments, supply the token manually instead of using the browser:

```sh
fabric agent-gateway login --host https://gateway.example.com --paste          # prompt to paste a token
printf '%s' "$TOKEN" | fabric agent-gateway login --host https://gateway.example.com --token-stdin
FABRIC_TOKEN="$TOKEN" fabric agent-gateway login --host https://gateway.example.com
```

Login saves the host and token under the connection named by `--connection` (or `FABRIC_CONNECTION`), or `default` when neither is set, and makes it current. The same flag selects a saved connection on the commands that talk to a gateway. Per-resource `--name` flags always name the resource being created, never a connection.

Logging in under a connection name that already exists replaces its saved token and host; this is also how an expired session is refreshed. The CLI says so on standard error, naming both the old and the new host when the host changed, so a stale `FABRIC_CONNECTION` or a pasted command cannot repoint a connection unnoticed. A login the gateway rejects changes nothing.

Subsequent commands use the current connection automatically, so the host and token do not need to be repeated:

```sh
fabric agent-gateway surfaces list
fabric agent-gateway policies list
```

Global `--host` and `--token` options are temporary overrides for a single command. Use `fabric agent-gateway login` when the settings should be remembered.

`fabric agent-gateway logout` and `fabric agent-gateway config remove <name>` remove both the local profile and its OS credential-store entry.

Inspect the active session at any time:

```sh
fabric agent-gateway whoami
fabric agent-gateway whoami --output json
```

`whoami` shows the current connection and host, whether a token is stored, and, checked live against the gateway, whether that token is still accepted plus the signed-in username, role, email, user ID and name. For a personal access token it also lists the scopes the token was granted; a session login holds its whole role and shows no scopes.

### Session lifetime

Gateway sessions use a **sliding expiration**: every authenticated CLI call extends the session by the gateway's idle-timeout window, so an actively used connection keeps working without re-authenticating. There is no separate refresh token — once the session has been idle past the timeout, run `fabric agent-gateway login` again under the same connection name. Use `fabric agent-gateway whoami` to check whether the stored token is still valid.

Automation should use standard input or the environment rather than command history:

```sh
printf '%s' "$TOKEN" | fabric agent-gateway login --host https://gateway.example.com --token-stdin
FABRIC_TOKEN="$TOKEN" fabric agent-gateway --host https://gateway.example.com surfaces list --output json
```

Multiple gateways can be saved and selected:

```sh
fabric agent-gateway --connection production login --host https://gateway.example.com
fabric agent-gateway config list
fabric agent-gateway config use production
fabric agent-gateway --connection production surfaces list
```

### Personal access tokens

A personal access token is a long-lived bearer token that starts with `agpat_`, for scripts and CI jobs that cannot complete a browser login. Pass `--pat` to log in with one. The token can follow the flag, come from `FABRIC_PAT`, or come from standard input with `--token-stdin` (piped input is read even without it); with none of those, the CLI prompts for it without echoing:

```sh
fabric agent-gateway login --host https://gateway.example.com --pat              # prompt for the token
printf '%s' "$PAT" | fabric agent-gateway login --host https://gateway.example.com --pat --token-stdin
FABRIC_PAT="$PAT" fabric agent-gateway login --host https://gateway.example.com --pat
```

`FABRIC_PAT` is only read once `--pat` is given; on its own it does not select PAT login, and a plain `fabric agent-gateway login` still opens the browser. `--pat` cannot be combined with `--token` or `--paste`, and a `FABRIC_TOKEN` set in the environment counts as `--token`, so unset it first. A value without the `agpat_` prefix is refused before anything is sent. The CLI then checks the token against the gateway before storing it: a token the gateway does not accept, such as a revoked one, saves nothing, while a token that is accepted but lacks the permission the check reads still counts as valid. A token that passes is saved to the OS credential store under the connection, the same way a session login is.

`fabric agent-gateway tokens` manages the tokens themselves:

```sh
fabric agent-gateway tokens list
fabric agent-gateway tokens get <token-id>
fabric agent-gateway tokens scopes
fabric agent-gateway tokens create --name ci-deploy --scope surfaces.view --scope surfaces.edit --expires-at 2027-01-01T00:00:00Z
fabric agent-gateway tokens create --file token.json
fabric agent-gateway tokens revoke <token-id>
fabric agent-gateway tokens revoke <token-id> --yes
```

`list` prints `NAME  ID  STATUS  SCOPES  CREATED  EXPIRES`, one row per token. `STATUS` is `REVOKED` once the token has been revoked and `ACTIVE` otherwise. The `SCOPES` cell joins scope names with commas up to 40 characters and ends with `+N more` for the ones that did not fit, without cutting a name in half; `get` and `--output json` show the full list. `get` prints the token's whole record as JSON.

`scopes` lists the scopes you can grant a new token, one per line. It is based on your own role and, when you are logged in with a scoped personal access token, narrowed to that token's scopes.

`create` takes `--name` (required unless `--file` is given), `--description`, `--scope` (repeat it for each scope) and `--expires-at`, an RFC 3339 timestamp such as `2027-01-01T00:00:00Z`; omit `--expires-at` for a token that never expires. A token created without any `--scope` carries your whole role. `--file` takes a complete creation document instead, with `-` reading standard input; the other creation flags are ignored when it is given. The gateway keeps only a hash of the secret, so this is the one time it is shown: in table mode `create` prints the secret on its own line so it can be captured (`PAT=$(fabric agent-gateway tokens create ...)`) and says so on standard error, and `--output json` prints the whole response, secret included.

Two more flags narrow where a token works. `--required-header name=pattern` names a header the caller must send and a regex its whole value must match, and can be repeated; a value that is not `name=pattern` with both parts non-empty is refused before anything is sent. `--resource-pattern` limits the token to the resources it matches; omit it for an appliance-wide token. It has to take the form `TENANT:${header}:<resource-kind>:<resource-id-pattern>`, where `${header}` names one of the token's required headers and the resource kind is a path family such as `surfaces`, `gateways` or `secrets`. Anything else is refused with a 400. The caller picks that header's value on each request, so it decides the tenant, and the gateway therefore refuses a header pattern that could match more than one value unless the deployment sets `tenancy.trusted_tenant_header` for a proxy that overwrites the header:

```sh
fabric agent-gateway tokens create --name acme-surfaces --scope surfaces.view \
  --required-header x-tenant-id=acme --resource-pattern 'TENANT:${x-tenant-id}:surfaces:.*'
```

The gateway refuses a scope your own role does not hold with a 403, which the CLI shows as `access-token scopes must not exceed the caller's own role`, and creates nothing; `fabric agent-gateway tokens scopes` shows what you can grant. When you create a token while logged in with a scoped personal access token, the new token must also ask for at least one scope, all of them held by the token you are using, and a token carrying a resource pattern or required headers cannot create tokens at all. A scope name the gateway does not recognise is refused as `unknown scope: <name>`, and the CLI adds a pointer to `fabric agent-gateway tokens scopes`.

`revoke` asks `Revoke access token <id>? [y/N]` and revokes only on `y` or `yes`; any other answer leaves the token alone and exits successfully. Pass `--yes` or `-y` to skip the prompt. When standard input is not a terminal the prompt could never be answered, so `revoke` without `--yes` fails there and sends nothing.

## Observability

Four command groups read what the gateway recorded: the audit log, payment records, metrics, and log files. These are aggregates and verbs rather than collections, so the value is in the query filters and in what the CLI merges locally, not in CRUD.

### Audit log

```sh
fabric agent-gateway audit list --limit 50
fabric agent-gateway audit list --category policy_decision,trust_check
fabric agent-gateway audit list --flow access_point --decision deny
fabric agent-gateway audit list --all --output json > audit.json
```

Rows are `timestamp  event  surface_id  decision  detail`, with `-` for a field the event lacks. Audit events carry no `id`, `name`, or `description`, so they use their own row format instead of the shared `id  name  description` summary. `detail` is the gateway's own note on the event, such as `0 tokens revoked` on a `user_tokens_revoked` event. Every cell is stripped of control characters, and its line breaks and tabs become spaces, so each event stays on one row with its columns in place. `--all` pages through the whole log rather than one page, which is the main thing the dashboard view cannot do.

The audit log records gateway traffic, not administration: delegation consent and tokens, policy decisions, trust checks, VP injection, payments, and trace terminations. Admin API calls, such as creating an identity, are not audited and never appear here; the one exception is revoking delegation tokens, which records `token_revoked` or `user_tokens_revoked`. The gateway settings gate three kinds of event, and only while `audit_enabled` is on: `audit_categories.policies` records policy decisions, `audit_categories.trust_checks` records trust checks, and `audit_categories.identity` records VP-injection events, not changes to identities. Every other event is recorded whatever those settings say. An empty table result says what the log records, and that admin API calls are not audited, on standard error.

There is no separate delegation-audit command. `/v1/audit` and `/v1/delegation-audit` read the same append-only file and differ by one filter: the delegation view drops policy decisions, trust checks, and trace terminations, and keeps every other category. `--category` is an OR set, so reproducing that view means naming the sixteen it keeps:

```sh
fabric agent-gateway audit list --category consent_granted,consent_required,token_injected,token_refreshed,token_revoked,token_not_found,refresh_failed,user_tokens_revoked,vp_injected,pre_authorize_blocked,payment,elicitation_sent,elicitation_accepted,elicitation_declined,elicitation_cancelled,elicitation_timed_out
```

A shorter list is a narrower view, not the same one, and it fails quietly — asking only for the consent and token-injection categories hides `refresh_failed`, `consent_required`, `token_revoked`, and the whole `elicitation_*` family.

Three things to know about the filters:

- `--filter` is matched by the gateway against the raw JSON of each event, so it also matches field names and the base64 body of an embedded JWT, not only the values a row displays.
- `--flow`, `--scope`, and `--decision` restrict the view to policy decisions. Setting any of them drops every other kind of event rather than narrowing the policy decisions within a wider set.
- An empty result is ambiguous. The gateway answers HTTP 200 with no events when the audit log is genuinely empty, when its audit subsystem failed to start, and when it cannot read the audit file or the file is not valid UTF-8. It also drops any line of the file it cannot parse without saying so, so a listing can be short as well as empty.

`--all` walks pages until the gateway repeats one, because it clamps a page past the end back into range instead of returning an empty page. Paging is by offset over a newest-first list, so events written while a long `--all` run is in progress shift the offsets and can push rows past the page boundary the run already passed; take the export when the gateway is quiet if it has to be exact.

Audit events carry the caller's raw email and display name and, for a VP injection, a complete Verifiable Presentation JWT. All three are replaced with `[redacted]` unless `--reveal` is passed, so writing audit output to a file or a CI log does not leak a credential by default.

### Payments

The gateway keeps payment records in two independent stores, x402 and MPP, behind separate endpoints. `fabric agent-gateway payments list` reads both by default and merges them into one table of `id  store  surface_id  status  amount  currency  created_at`, newest first — the one thing `fabric agent-gateway api` cannot do here, because it takes two calls.

```sh
fabric agent-gateway payments list
fabric agent-gateway payments list --store x402 --surface <surface-id> --status verified
fabric agent-gateway payments get <transaction-id>
fabric agent-gateway payments stats --sync
fabric agent-gateway payments delete <transaction-id> --yes
```

- `delete` is x402 only; MPP records cannot be deleted.
- Every x402 admin-API failure is reported as HTTP 500 — an unknown ID, a transaction whose settlement is still pending, an unconfigured store — so the CLI shows the message and drops the status code. MPP sets a meaningful status and keeps it.
- `--status` is a query parameter on x402 but not on MPP, so MPP records are filtered after they are fetched. Matching ignores case on both, which is what lets one value select from both: the two stores share `verified` and `failed` and differ only in case. x402's filterable status is the verification status — `Pending`, `Verified`, `Failed`, `Timeout` — and MPP's is `verified`, `failed`, or `challengeissued`. Settlement is a separate x402 field that the merged `list` row drops, so no `--status` value selects on it; read it from `payments get`.
- A full record from `get` carries the signed `PaymentReceiptCredential` and `PaymentRejectionCredential` JWTs and, for x402, the payer's signature. Those are replaced with `[redacted]` unless `--reveal` is passed; the `sha256:` fingerprint beside each JWT is kept, so a redacted record is still verifiable.
- x402 computes its record total after applying the limit, so it can only ever equal the number of rows returned. Only the MPP footer reports a real "N of total".
- Timestamps are Unix seconds, exactly as both stores return them.
- Every cell of the merged table is cleaned like an audit row: control characters stripped, line breaks and tabs turned into spaces.
- On a gateway with no payment stores configured these routes do not exist at all, which the CLI reports as "payments are not enabled on this gateway".
- The two stores are authorised differently: x402 needs only a session, while MPP additionally requires the `payments.view` permission, because its records carry the payer, amount, and method. An operator without it gets x402's rows and a rejection from MPP. `list` prints the rows it did read and names the store it could not on standard error; it fails only when no store could be read at all.

### Metrics

```sh
fabric agent-gateway metrics status
fabric agent-gateway metrics config show --output json > metrics.json
fabric agent-gateway metrics config set --file metrics.json
fabric agent-gateway metrics scrape | promtool check metrics
fabric agent-gateway metrics scrape --username prometheus --output-file metrics.txt
fabric agent-gateway metrics test-endpoint http://otel-collector:4317
fabric agent-gateway metrics truncate --yes
```

`config set` replaces the whole document rather than patching it, and the gateway treats several settings as optional — `opentelemetry.auth` above all. A document that omits one **removes** it instead of defaulting it, and the live exporter is re-applied immediately, so omitting `auth` silently switches collector export to unauthenticated; `retention`, `advanced` and `opentelemetry.protocol` drop the same way. The CLI therefore reads the live document first and refuses any submission that would drop a stored setting, listing each one. Setting a stored section to `null` removes it exactly as leaving the key out does, so that is refused by the same name. Start from `config show --output json`, or pass `--force` to submit anyway.

The gateway reports the update as a success as soon as the file is written, including when re-applying it to the running collector failed, so `config set` prints the response's `message` rather than reading `success`. Read it.

`scrape` returns a Prometheus exposition, not JSON. When the gateway has Prometheus authentication enabled that route requires HTTP Basic credentials in the same header the bearer token would occupy, so `--username` and `--password` are sent *instead of* the token. Both accept an environment fallback, `FABRIC_METRICS_USERNAME` and `FABRIC_METRICS_PASSWORD`; set both or neither, since the two options require each other and an env-supplied value counts as supplied. `--output-file` names the destination (`-` for standard output); the global `--output` still selects the display format.

`test-endpoint` only opens a TCP connection, and the gateway answers HTTP 200 for every outcome including a refused connection and a timeout. The CLI takes its verdict from the response's `success` field, so a failed test exits non-zero.

### Logs

```sh
fabric agent-gateway logs download --output-file logs.zip
fabric agent-gateway logs truncate --yes
```

`download` retrieves every log file as one ZIP archive. The gateway builds the whole archive in memory before sending it, so this is expensive on a large log directory. `truncate` deletes every rotated log file and keeps the current one; it is irreversible and has no server-side role check, so `--yes` is required and there is no prompt.

### Left to `fabric agent-gateway api`

These endpoints are deliberately not wrapped, because a command would add nothing over a raw call:

- `GET /v1/dashboard/stats`, `/v1/dashboard/delta`, `/v1/dashboard/surface/{id}/metrics`, `/v1/dashboard/surface/{id}/ucp-operations`, and `/v1/dashboard/system-metrics` — aggregates whose value is a rendered dashboard, not a table. `/v1/dashboard/delta` is additionally deprecated in the gateway source.
- `GET /v1/dashboard/metrics/hierarchical` — a three-level nested map with no useful flat projection.
- `GET /api/admin/x402/payments/all` — its extra content over `payments list` is `chart_data` for a graph the CLI does not draw.
- The `verifications` and `settlements` x402 paths — deprecated aliases of `transactions`, bound to the same handlers.
- `/api/ws` and `/api/ws/dashboard` — websockets, which a request/response CLI cannot wrap.

```sh
fabric agent-gateway api get /v1/dashboard/stats --output json
fabric agent-gateway api get /v1/dashboard/metrics/hierarchical --output json
```

## Resources

Dedicated commands cover common operations:

```sh
fabric agent-gateway surfaces list
fabric agent-gateway surfaces get <surface-id> --output json
fabric agent-gateway surfaces create --name "Sales Agent" --description "Routes sales traffic"
fabric agent-gateway surfaces create --file surface.json
fabric agent-gateway surfaces update <surface-id> --file surface.json
fabric agent-gateway surfaces update <surface-id> --set access_point.rate_limit.requests=100 --set name="Sales Agent" --unset description
fabric agent-gateway surfaces update <surface-id> --add tags=beta --remove transit.points=billing
fabric agent-gateway surfaces update <surface-id> --set access_point.route=/billing --dry-run
fabric agent-gateway policies create --id allow-sales --name "Allow sales" --policy-file allow-sales.rego
fabric agent-gateway surfaces add-feature <surface-id> rate-limit --json '{"requests":100,"window_secs":60}'
fabric agent-gateway surfaces tool-gate-preview <surface-id> --tool delete_user,get_user
fabric agent-gateway surfaces tool-gate-preview --gates-file gates.json --tool delete_user --condition admins=met
fabric agent-gateway connection-points create --file connection-point.json
fabric agent-gateway connections list
fabric agent-gateway tokens rotate <token-id> --yes
```

`tool-gate-preview` shows whether each tool would be allowed or denied (RESULT) and which gate, or the default, decided it (DECIDED BY).

Create commands print the created entity ID in table mode. Use `--output json` to receive the complete response. Full JSON documents preserve access to the complete Gateway model without duplicating every nested setting as a CLI flag.

`surfaces update --file` replaces the whole surface. `--set <path>=<value>` and `--unset <path>` instead change single fields, and `--add <path>=<item>` and `--remove <path>=<item>` add or remove one list item; all four can be repeated and none can be combined with `--file`. They go to the gateway as one JSON Merge Patch, so fields they do not name keep their current values. A path is dot-separated field names, and a value or item is read as JSON when it parses (`100`, `true`, `'"100"'`, `'{"requests":100}'`) and as plain text otherwise. Wrap a value in quotes (`'"1.0"'`) to send something that looks like a number, boolean or JSON as text. Setting an object merges it into the existing object rather than replacing it, and setting a list replaces the whole list.

Because a list is replaced whole, `--add` and `--remove` read the surface first and send its list with only their items changed. `--remove` names a text item by its value (`tags=beta`) and an object by its `id`, else its `alias` (`transit.points=billing`), or, when it has neither, by some of its fields as JSON (`outbound_credentials='{"credential_provider_id":"cp-1"}'`), since the gateway fills in defaults you never typed. Removes run before adds, so `--remove access_point.trust_check_list=tc-1 --add access_point.trust_check_list='{"id":"tc-1",...}'` replaces one trust check in place, and an added object with no `id` keeps the `id` of the item it replaces. A change someone else makes to the same list between that read and the write is overwritten.

Every surface edit (`update`, `add-feature` and `remove-feature`) is checked on your machine before it is sent: the CLI reads the surface, merges the change into it and refuses it with the gateway's own message when `name`, `access_point.listen_address`, `access_point.route` or `target.endpoint` would end up empty, as in `access_point.route is required`. `update --file` checks the file the same way. A route without its leading `/` is accepted, because the gateway adds it. Every other check, such as whether referenced policies, secrets and credential providers exist or whether the route or listen address collides with another surface, only runs on the gateway. Reading the surface needs the `surfaces.view` permission. A token without it can still edit with `update --set` and `--unset`, which warns and sends the edit unchecked, but `--add`, `--remove`, `--dry-run`, `add-feature` and `remove-feature` need the surface and fail with the gateway's missing permission error without sending anything.

`--dry-run` on `update`, `add-feature` and `remove-feature` runs those checks too without saving anything: after the local check passes, the CLI sends the patch as `PATCH /v1/surfaces/<surface-id>?dry_run=true`, which runs every check a real edit runs and answers with the surface as it would be saved, except that ids the gateway generates for new items, such as a transit point sent without an `id`, will differ in the real save. `PUT /v1/surfaces/<surface-id>` and `PATCH /v1/surfaces/<surface-id>/variants/<variant-id>` ignore `dry_run` and save. Table output prints the patch, then each changed field as `path: before -> after`, where the after side includes defaults the gateway fills in, then `Dry run: nothing was saved.`. `--output json` prints one object, `{"dry_run": true, "checked": "gateway", "patch": ..., "before": ..., "after": ...}`. A refused edit prints the gateway's error and exits with 1, like a real one, and that includes a 404, which means the surface was deleted or is out of your reach. An edit the local check refuses is never sent: the CLI prints the patch and the locally merged changes (`"checked": "local"` with an `error` in JSON), then the error, and exits with 1. When the gateway's checks could not run (the gateway does not support a dry run, did not answer, or failed with a server error), the CLI never sends the real patch: it prints the locally merged surface, labelled as checked on this machine only (`"checked": "local"` with a `warning` in JSON), warns that the gateway checks were skipped, and exits with 3. `--dry-run` cannot be combined with `--file`, which replaces the whole surface.

### Identity and access

Users, did:webvh identities, API keys, tenant ownership, and JWT verification strategies each have their own command, because none of them is plain CRUD. Every `--file` in this section is a request document, not the entity it acts on; [Request documents](#request-documents) lists the keys each one requires. The `users`, `api-keys` and `jwt-verification-strategies` deletes confirm on standard output in table mode, and `--output json` keeps the gateway's own answer, which is `null` for the empty body a delete returns.

```sh
fabric agent-gateway users list
fabric agent-gateway users get <user-id>
fabric agent-gateway users update <user-id> --file user.json
fabric agent-gateway users delete <user-id>
```

Users are created by passkey or SAML registration, so there is no `fabric agent-gateway users create`. A user is addressed by the UUID that `list` prints, not by username, and `update` changes only the fields the document contains. `integrations` is a separate route under the same prefix, so `fabric agent-gateway users get integrations` returns the integration assignments rather than a user. `update` refuses that id outright: the same path answers PUT by replacing the whole user-integration configuration, so any document sent there would clear every assignment and report success. Rewrite the assignments deliberately with `fabric agent-gateway api put /v1/users/integrations --file <file>`.

```sh
fabric agent-gateway identities list
fabric agent-gateway identities get <id>
fabric agent-gateway identities get <id> --reveal
fabric agent-gateway identities create
fabric agent-gateway identities create --file identity.json
fabric agent-gateway identities update <id> --file identity-update.json
fabric agent-gateway identities rotate-keys <id>
fabric agent-gateway identities rotate-keys <id> --file rotate-keys.json
fabric agent-gateway identities transfer <id> --file transfer.json
fabric agent-gateway identities history <id>
fabric agent-gateway identities trust-policy get <id>
fabric agent-gateway identities trust-policy set <id> --file trust-policy.json
fabric agent-gateway identities deactivate <id>
```

`get` returns the identity's stored key pair, private key included, so the CLI drops `key_pair` from the output unless `--reveal` asks for it. `list`, `create`, `rotate-keys` and `history` carry public key material only. `deactivate` is the delete route: it clears the identity's active flag and keeps the record, which stays readable afterwards. `create` and `rotate-keys` have the gateway generate the key pair when no `--file` supplies one, and both refuse a `--file` document that carries a key pair outside its wrapper, which is `key_pair` for `create` and `new_key_pair` for `rotate-keys`; the refusal prints a template of the document to send, with placeholder Ed25519 JWKs. Table output identifies an identity by its UUID and DID; `--output json` returns the whole record.

`identities trust-policy` reads and writes a per-identity trust-score policy — a minimum score and the weights of its components. It is unrelated to `fabric agent-gateway policies`, which manages the Rego policy definitions the gateway enforces on traffic: the gateway stores a trust-score policy in the identity's metadata and hands it back on request, but nothing in the gateway applies it. `trust-policy get` answers with the gateway's built-in defaults for an identity that has never had one set, so a result does not prove one was configured.

```sh
fabric agent-gateway api-keys list
fabric agent-gateway api-keys list --agent-id <surface-id>
fabric agent-gateway api-keys get <key-id>
fabric agent-gateway api-keys create <surface-id> --client-id billing --label team=payments
fabric agent-gateway api-keys create <surface-id> --file api-key.json
fabric agent-gateway api-keys rotate <key-id>
fabric agent-gateway api-keys revoke <key-id> --actor ops-team
fabric agent-gateway api-keys delete <key-id> --agent-id <surface-id>
```

`get`, `revoke`, `rotate` and `delete` take the key's own ID. The gateway addresses a key by its Agent Surface and then its ID, so the CLI reads `GET /v1/api-keys` first and takes the surface from the key's own record. `--agent-id` names the surface and skips that lookup — needed when the token carries `api_keys.edit` or `api_keys.delete` but not `api_keys.view`, since the key's own route is open to it and the collection is not. A key id no visible surface carries is reported as not found, and a key id on two surfaces is refused by name rather than guessed at: the gateway generates key ids at random and does not enforce their uniqueness. `create` still takes its surface as a positional, because a new key has no ID to look up.

`create` and `rotate` return a secret the gateway keeps only as a hash and will never show again; in table mode they print that secret on its own so it can be captured (`SECRET=$(fabric agent-gateway api-keys create ...)`), and report the key ID on standard error. `--output json` prints the whole response. A key cannot be edited after creation — `rotate` replaces its secret in place, keeping the key ID. The gateway refuses to rotate a key that has already been revoked, so replace a revoked key with a new one. `revoke` and `rotate` take `--actor`, the name recorded against the change in the key's audit trail; it defaults to `api`.

```sh
fabric agent-gateway tenant-ownership impact surfaces <surface-id>
fabric agent-gateway tenant-ownership set surfaces <surface-id> --tenant acme
fabric agent-gateway tenant-ownership set surfaces <surface-id> --clear
```

`impact` reports the references a reassignment would cross; `set` moves the resource. The gateway reads a request with no tenant in it as a request to clear ownership, so `--clear` has to be given outright and `set` with neither flag fails before anything is sent. The resource kind is a fixed list that `--help` prints; `api-keys` and `connection-points` appear in it but are rejected, because their ownership follows their parent resource. A reassignment the gateway blocks comes back as a conflict, and `impact` lists the references behind it.

```sh
fabric agent-gateway jwt-verification-strategies list
fabric agent-gateway jwt-verification-strategies get <id>
fabric agent-gateway jwt-verification-strategies create --file strategy.json
fabric agent-gateway jwt-verification-strategies update <id> --file strategy.json
fabric agent-gateway jwt-verification-strategies delete <id>
fabric agent-gateway jwt-verification-strategies validate-jwks-uri https://idp.example.com/.well-known/jwks.json
```

`validate-jwks-uri` fetches the URI and reports whether it serves a parseable key set. A URI that cannot be reached or parsed is a non-zero exit carrying the gateway's reason. `update` replaces the whole strategy, so it takes the same document as `create`.

#### Request documents

Each `--file` above carries the handler's request body, which is not the same document the matching `get` returns. The required top-level keys are:

| Command | Required | Optional |
| --- | --- | --- |
| `users update` | none | `role`, `status`, `first_name`, `last_name`, `email`, `department`, `job_title` |
| `identities create` | none | `did_path`, `metadata`, `key_pair` |
| `identities update` | `did_document` | `update_keys`, `ttl` |
| `identities rotate-keys` | `new_key_pair` | none |
| `identities transfer` | `new_controller`, `current_owner_authorization` | `new_owner_authorization`, `new_ownership_proof`, `transfer_reason` |
| `identities trust-policy set` | `config` | none |
| `api-keys create` | `client_id` | `labels` |
| `jwt-verification-strategies create`, `update` | `name`, `expected_issuer`, `jwks_source` | `tenant_id` |

A key pair is `{"public_key": <JWK>, "private_key": <JWK>, "key_type": "Ed25519"}`, and `identities rotate-keys` takes it wrapped: `{"new_key_pair": {…}}`. `identities trust-policy set` takes the policy wrapped the same way the response carries it, so `fabric agent-gateway identities trust-policy get <id> --output json` produces the document to edit and send back, and a bare policy is refused before anything is sent:

```sh
fabric agent-gateway identities trust-policy get <id> --output json > trust-policy.json
fabric agent-gateway identities trust-policy set <id> --file trust-policy.json
```

`jwks_source` is tagged by a `type` field and carries the keys for that type:

```json
{
  "name": "Partner IdP",
  "expected_issuer": "https://idp.example.com/",
  "jwks_source": {"type": "remote", "jwks_uri": "https://idp.example.com/.well-known/jwks.json"}
}
```

```json
{
  "name": "Pinned keys",
  "expected_issuer": "https://idp.example.com/",
  "jwks_source": {"type": "static", "jwks": [{"kty": "RSA", "kid": "2026-09", "n": "…", "e": "AQAB"}]}
}
```

A document missing a required key is rejected by the gateway as a 422 naming it, before anything is written. `identities create` and `identities rotate-keys` have no required key at the gateway, so a key pair left outside its wrapper is not a 422 there: the gateway reads it as no key pair at all, generates and installs one of its own and reports success — 201 for `create`, 200 for `rotate-keys` — leaving the caller holding a private key that does not control the DID. The CLI refuses both of those documents itself and prints a template of the wrapped document to send, with placeholder Ed25519 JWKs. Both keys are JWKs: a PEM string reaches the gateway's JWK parser and comes back as a 500.
`fabric agent-gateway tokens rotate` replaces a personal access token's secret while keeping its ID, name, and scopes. The old secret stops working immediately and the new one is shown only once. Without `--yes` it asks for confirmation, and it refuses to run non-interactively.

### Surface features

Agent Surfaces are composed from features, the same elements shown in the dashboard's surface builder. List everything that can be added, with its target path and placement:

```sh
fabric agent-gateway surfaces features
fabric agent-gateway surfaces features --output json
```

Add a feature to a surface. The surface ID and the feature are positional, in that order; the place is worked out from the feature name, so `--edge` (`ap-ma` or `ma-external`), `--response` and `--transit-point <alias>` are optional overrides, needed only when the command says the feature can go in more than one place.

With no flags the CLI uses the surface place whenever the feature has no other choice to make. `--transit-point <alias>` picks the transit point place instead, as for tool gating and networking. `policy`, `custom-metadata` and `identity` have more than one choice, so they list the flags to add.

Configuration comes from `--policy-id` (policy shortcut), `--json`, or `--file`:

```sh
# Policy on the request edge (policy-ref shortcut)
fabric agent-gateway surfaces add-feature <id> policy --policy-id allow-sales --edge ap-ma

# Inbound rate limit (aliases: throttling, network.throttling)
fabric agent-gateway surfaces add-feature <id> rate-limit --json '{"requests":100,"window_secs":60}'

# Target networking (timeout / retry / circuit breaker)
fabric agent-gateway surfaces add-feature <id> networking --file networking.json

# Append a Trust Check element (list feature)
fabric agent-gateway surfaces add-feature <id> trust-check --file trust-check.json

# Per-transit-point response policy
fabric agent-gateway surfaces add-feature <id> policy --transit-point github --response --policy-id allow-gh
```

Remove a feature from a placement:

```sh
fabric agent-gateway surfaces remove-feature <id> rate-limit
fabric agent-gateway surfaces remove-feature <id> policy --response
```

`add-feature` and `remove-feature` fetch the surface and send only the part they change as a JSON Merge Patch, returning the updated surface. Adding an object feature replaces what was there, a list feature is appended to its list, and a transit point feature sends the whole transit point list with that one point changed. A value holding `null` inside an object is refused, because the gateway would read it as removing that field. Both commands run the same local check as `surfaces update` and take `--dry-run` to preview the change without saving it.

### Secrets and certificates

Both resources store credentials, so their `get`, `create`, and `update` hide the credential itself by default. Pass `--reveal` to print it. Masking applies to these two commands' output only — the raw `fabric agent-gateway api` passthrough prints whatever the gateway returns.

```sh
fabric agent-gateway secrets get <id>
fabric agent-gateway secrets get <id> --reveal
fabric agent-gateway certificates get <id> --reveal --output json
```

A masked document must not be sent back. The placeholder is a real string, so replaying a masked `get` through `create` or `update` would store it as the credential and the masked response would look unchanged. The CLI refuses any request body still carrying it, whether it came from a `--file` document or inline from `fabric agent-gateway api --data`: re-read the entity with `--reveal`, or drop the masked field to leave the stored credential alone.

`get`, `update`, and `delete` accept what `list` shows, not only the `id`. Name a secret by its `id`, its `secret_id`, or its name, and a certificate by its `id` or its name:

```sh
fabric agent-gateway secrets get stripe-live
fabric agent-gateway secrets delete "Stripe live"
fabric agent-gateway certificates get "Edge TLS" --reveal
```

The CLI lists the collection and calls the gateway with the `id` of the one entity the argument names. An argument equal to an entity's `id` always picks that entity, even when another entity carries the same string as its name or `secret_id`. Any other argument is compared with the name fields of every entity at once. One that matches nothing is reported as not found. Names are not unique, and one secret's name can equal another's `secret_id`, so one that matches more than one entity is refused with each candidate's `id`; pass one of those instead.

The lookup needs the view permission, `secrets.view` or `certificates.view`. With it, any of those fields works. Without it, for example with a personal access token scoped to `secrets.delete` alone, `get` fails whatever you pass, because reading one entity needs the same permission as the list. For `update` and `delete`, only the `id` works: the gateway refuses the list, so the CLI sends a UUID straight to the entity route, which checks the permission for the action itself and reports a UUID that is no entity's `id` as not found. A name or `secret_id` given without the view permission is refused with the gateway's reason and a pointer to the `id`.

Certificates use the reusable CRUD commands, with the document supplying the PEM content as a JSON string:

```sh
fabric agent-gateway certificates list
fabric agent-gateway certificates create --file certificate.json
fabric agent-gateway certificates update <id> --file certificate.json
fabric agent-gateway certificates delete <id>
```

Two things to watch on certificates. The `certificate_id` field in the response is a second UUID that the gateway never looks a certificate up by, so the CLI does not match it either: pass the `id` or the name. And `expires_at` must be a complete RFC 3339 timestamp such as `2027-01-01T00:00:00Z`; a bare date is rejected.

Secrets are created from flags or from a document. The value is stored exactly as given, so a trailing newline that matters in a PEM block or signing key survives; `--value-stdin` strips only the single line ending a shell pipeline appends:

```sh
fabric agent-gateway secrets create --name "Stripe live" --secret-id stripe-live --value-stdin < key.pem
fabric agent-gateway secrets create --name "Stripe live" --secret-id stripe-live --value "$STRIPE_KEY" \
  --description "Billing API key" --type ApiKey --tag billing
fabric agent-gateway secrets create --file secret.json
printf '{"name":"Stripe live","secret_id":"stripe-live","value":"%s"}' "$STRIPE_KEY" |
  fabric agent-gateway secrets create --file -
fabric agent-gateway secrets list --tag billing
fabric agent-gateway secrets delete <id>
```

`--description` records what the secret is for, and `--type` sets the secret type the gateway stores; omit it for the gateway default, `General`. The type is what other configuration filters on — caller authentication, for example, only offers secrets typed `ApiKey`. `--file` takes a complete creation document instead, with `-` reading standard input; the other creation flags are ignored when it is given.

`--secret-id` is the machine-readable name that `$SECRET:<secret-id>` references elsewhere in the gateway configuration. The gateway refuses a second secret with the same `secret_id`, and an update cannot change it. The separate `id` is a UUID the gateway assigns; `list --output json` shows both.

`secrets update` takes a full JSON document. The gateway applies a `value` only when `update_value` is true, so a document that sets one without the other reports success and changes nothing; the CLI rejects that combination rather than guessing which you meant. It also replaces `description` with whatever the document carries rather than patching it, so an update that omits `description` clears the stored one — restate it, including when all you are rotating is the value:

```sh
printf '{"value":"%s","update_value":true,"description":"Billing API key"}' "$NEW_KEY" |
  fabric agent-gateway secrets update <id> --file -
```

Neither command exposes `--tenant-id`. An appliance-wide personal access token is rejected with 403 if it tries to assign tenant ownership, and a tenant-scoped token can only create inside its own tenant.

A delete returns no document. Table output confirms what it removed; `--output json` prints `null`, the same as every other delete command.

### Delegated credential grants

`delegation-vault` reads and revokes the credential grants users have delegated to agents. There is no create and no update: a grant is minted only when a user completes the provider's OAuth flow in a browser.

```sh
fabric agent-gateway delegation-vault list --output json
fabric agent-gateway delegation-vault get <id>
fabric agent-gateway delegation-vault revoke <id>
fabric agent-gateway delegation-vault revoke-user sha256:<hex>
```

`revoke-user` takes a user identity hash rather than a grant ID and revokes every grant held for that user, reporting how many it removed in both output modes. A single `revoke` returns no document, so it confirms the grant in table output and prints `null` under `--output json`. Grants carry no name or description, so the table listing shows IDs only — use `--output json` for the agent DID, provider, user hash, and expiry.

Revoking needs a session token or an appliance-wide personal access token. A token created with `--resource-pattern` can list grants but never revoke one, because the delegation vault is not among the path families that pattern scoping recognises.

### Output format

A failed request prints the reason from the response body, stripped of control characters, including the Unicode bidirectional controls that reorder displayed text, and capped at 500 characters. A gateway, or a proxy in front of it, can echo the request's headers back in that body, so the credentials the request carried are replaced with `[redacted]` first: the bearer token, and for `metrics scrape --username --password` the password, the `username:password` pair, and its base64 form. The rest of the message is kept. In table output, the `message` that `metrics config set` prints is cleaned the same way, and in either output so is the failure message of `metrics test-endpoint`, because the gateway builds both from the underlying apply or connection error. With `--output json`, `metrics config set` prints the gateway's response as it is.

A permission refusal that names the permission it needed keeps the gateway's own wording, which tells a role that lacks the permission apart from a personal access token whose scopes leave it out, for example `access token scope does not include 'access_tokens.view'`. When the gateway names only the permission, the CLI reports `missing required scope '<permission>'`. A `401` is reported as `gateway rejected the bearer token:` followed by the gateway's reason.

A `get` (single entity) prints the **entire configuration** — the same document shown in the dashboard's config view — as formatted JSON. A `list` prints a compact `id  name  description` summary, one row per entity. `--output json` returns full JSON for both. `create` prints the new entity ID in table mode so it can be captured in a variable (`ID=$(fabric agent-gateway surfaces create ...)`).

The reusable CRUD commands also cover Issuers, Authorities, Trust Registries, Mediators, MCP and A2A Proxies, STS clients, credential providers, certificates, and integrations. The authenticated API command covers every remaining endpoint:

```sh
fabric agent-gateway api get /v1/limits --output json
fabric agent-gateway api patch /v1/surfaces/<surface-id> --data '{"description":"Updated"}'
fabric agent-gateway api post /v1/policy-definitions/<policy-id>/simulate --file input.json
```

## Gateway configuration

These commands read and write the configuration of the gateway you are connected to. They are distinct from `fabric agent-gateway config`, which manages local connection profiles on this machine and never contacts a gateway.

None of these resources is a collection: each is a singleton or a set of verbs, so they use `show`, `set`, `reset` and `reload` rather than `list`, `get <id>`, `create` and `delete <id>`.

`fabric agent-gateway terms deactivate`, `fabric agent-gateway notifications welcome-template set` and `fabric agent-gateway notifications send-welcome` answer `204 No Content`. In table mode they print a confirmation line instead of the empty document; with `--output json` they print `null`, which is what the gateway returned and what every other command does for an empty body. Warnings about a request body go to stderr, so standard output stays machine-readable in either mode.

### Runtime configuration

`fabric agent-gateway runtime` exposes the gateway's live, startup-derived configuration and triggers a reload. Nothing here is written by `show`, and `reload` writes nothing either — it re-reads the configured source and swaps surfaces in place.

```sh
fabric agent-gateway runtime show surface-routing
fabric agent-gateway runtime show x402
fabric agent-gateway runtime show networking
fabric agent-gateway runtime reload
fabric agent-gateway runtime reload --surface <config-id>
```

Surfaces changed through this CLI or the dashboard already reload themselves, so `reload` is for configuration edited outside the gateway, such as a direct `_storage/` edit. `--surface` takes the surface id that `fabric agent-gateway surfaces list` shows, and a successful reload prints the gateway's answer, the surface's `channel_name` and `is_fallback`.

The gateway answers a reload of an id no surface has with a `500`, not a `404`, so after a server error the CLI checks the id itself, as `fabric agent-gateway surfaces get` does. When that lookup answers `404`, the CLI says the surface was not found and keeps the gateway's error underneath as the cause: with the DynamoDB configuration source the reload reads DynamoDB while the lookup reads the gateway's own surface store, so the two can disagree. Any other failure keeps the gateway's own error.

`show networking` is read-only by design: it reports the gateway's inbound client-certificate (mTLS) authentication, which is applied at startup and has no counterpart that sets it. `show x402` answers `500`, not `404`, on a gateway with no x402 configuration file.

### Appliance settings

`fabric agent-gateway settings` manages the single appliance-wide settings document. `set` is a partial update: fields the document omits are left unchanged.

```sh
fabric agent-gateway settings show --output json > settings.json
fabric agent-gateway settings set --file settings.json
fabric agent-gateway settings reset --force
```

`set` and `reset --force` print the settings as read back from the gateway after the write, so their output is what the next `settings show` returns. The write routes answer with the stored document instead, which lacks the `feature_flags.terms` that every read adds. If the read-back fails, the write has still happened: the command exits non-zero, says the write succeeded but reading the settings back failed, and prints no document.

`set` refuses a document carrying `feature_flags.terms`, whatever its value, and sends nothing. The gateway reports that flag from its `network.terms` configuration on every read and ignores any stored value, so the write could never take effect. A document produced by `show` always carries it: delete `terms` from `feature_flags` before sending. Terms of Use are switched on or off in the gateway's configuration, not through settings.

Three more behaviours are worth knowing before editing a document produced by `show`. The CLI warns on stderr whenever a document you send contains any of them:

- `feature_flags` **replaces** the stored map rather than merging into it, so any flag missing from the document is removed.
- `payments_min_display` appears in the response but is not part of an appliance update and is silently ignored. It is settable only per user.
- `prometheus_auth_password_hash` is blanked on every response. To change the password, send `prometheus_auth_password`, which travels as plaintext and is hashed by the gateway.

A field sent as an explicit `null` draws no warning, because every settings field is optional and a null leaves the stored value alone.

`reset` is not a restore of the fields nobody set. It writes the built-in defaults over the whole document, so it clears:

- `prometheus_auth_enabled`, and with it `prometheus_auth_username` and the stored password hash. `/v1/metrics/prometheus` stops checking credentials from that moment.
- `audit_enabled` and `audit_categories`. Audit logging stops without a further message.
- every entry in `feature_flags`.
- every window, interval and threshold, back to its default.

Because two of those are security controls, `reset` refuses unless you pass `--force`, printing what it would clear. Nothing is sent to the gateway when it refuses.

A `settings show` backup does not make the reset recoverable: `show` blanks `prometheus_auth_password_hash`, and re-enabling Prometheus authentication from that document is refused with `400 Password is required when enabling Prometheus authentication for the first time`. Keep the plaintext password somewhere else before resetting, and send it back as `prometheus_auth_password`.

### Personal settings

`fabric agent-gateway user-settings` manages the signed-in principal's own overrides. It is a separate store from `fabric agent-gateway settings`, with separate permissions, and the identifier is the authenticated principal rather than anything you pass.

```sh
fabric agent-gateway user-settings show
fabric agent-gateway user-settings show --overrides
fabric agent-gateway user-settings set --file overrides.json
fabric agent-gateway user-settings reset
```

**Use `--overrides` before building a `set` payload.** Plain `show` returns the effective document — appliance defaults merged with your overrides — so a field you never set still looks set. `--overrides` is the only view of what is actually stored against the account.

`set` refuses a document carrying fields a per-user update cannot store, naming them, because such a document can only have come from `show` without `--overrides` and sending it would persist every appliance default as a personal override. `--force` submits it anyway, but only once `feature_flags.terms` is deleted from it: a plain `show` document always carries that flag, and `set` refuses the flag even with `--force`.

`set` also refuses a document carrying `feature_flags.terms`, as `fabric agent-gateway settings set` does, before any other check, and `--force` does not override that: the effective per-user settings report the flag from the gateway's `network.terms` configuration on every read too, so a stored override could never take effect.

A single override cannot be cleared. Omitting a field, or sending null, is indistinguishable from leaving it alone; only `reset` clears, and it clears all of them.

Unlike `settings reset`, `user-settings reset` needs no `--force`. It deletes this account's own override document and nothing else — no appliance setting, no other account — and a `show --overrides` taken beforehand restores it through `set`, with one exception: a stored `feature_flags.terms` override is refused on restore, and it never took effect anyway. Delete it from the backup before restoring.

The appliance settings route blanks `prometheus_auth_password_hash` before answering, but every per-user response merges it in from the appliance document unblanked. The CLI drops that key from all `user-settings` output rather than print a bcrypt password hash to a terminal or a CI log.

### Terms of Use

```sh
fabric agent-gateway terms show
fabric agent-gateway terms applicable
fabric agent-gateway terms status
fabric agent-gateway terms provider-health
fabric agent-gateway terms draft --file terms.json
fabric agent-gateway terms publish
fabric agent-gateway terms deactivate
```

Accepting terms is deliberately absent. **When authenticated with a personal access token**, the gateway refuses every route until terms are accepted, including the acceptance route itself, so a `fabric agent-gateway terms accept` could only ever return `403` for those callers; acceptance has to be completed in a browser. A session-token login (the default `fabric agent-gateway login` browser flow) is exempt on that one route and can accept with `fabric agent-gateway api post /v1/terms/acceptances --file <json>`.

`draft` saves a JSON document with `version`, `title` and `url`, plus an optional `requires_reconsent` that defaults to `false`.

Terms failures carry a machine-readable `code` and no message, so the CLI adds an explanation for the ones that are easy to misread. A `404` with `TERMS_DISABLED` means the feature is switched off on that gateway, not that the route is missing. The others are `409 TERMS_VERSION_STALE`, `409 TERMS_DRAFT_REQUIRED` and `503 TERMS_OPERATIONAL_FAILURE`.

When the signed-in user has not accepted the gateway's Terms and Conditions, the gateway refuses every route except the terms status ones with a code-only `403 TERMS_ACCEPTANCE_REQUIRED`. Whatever the command, the CLI then says to accept the Terms in the Agent Gateway dashboard, or with `fabric agent-gateway api post /v1/terms/acceptances --file <json>` as described above, and retry, and that `fabric agent-gateway terms status` lists what is required.

### Notifications

```sh
fabric agent-gateway notifications welcome-template show
fabric agent-gateway notifications welcome-template set --file template.json
fabric agent-gateway notifications send-welcome --user-id <user-id> --title "Welcome" --message "Your account is ready"
```

Only these three verbs are offered. Listing, reading, creating, updating and deleting a user's own notifications are deliberately absent: those gateway handlers ignore the marker the authentication middleware sets and re-validate the bearer token through the session manager, which consults session storage only and never the personal access token authenticator. **When authenticated with a personal access token**, `list` would therefore return `200 []` and exit `0` while the user has unread notifications, and the rest would return `401`. A silently empty list is worse than no command. The three verbs above take no session extractor at all, so they work for either credential.

A session-token login (the default `fabric agent-gateway login` browser flow) can reach the omitted routes directly with `fabric agent-gateway api get /v1/notifications`.

Neither `welcome-template set` nor `send-welcome` is permission-checked by the gateway, despite both handlers being documented as administrator-only. Any authenticated caller can replace the template every future user receives, and `send-welcome` takes the recipient from the request body, so it can post a notification into any user's feed.

The gateway also never checks that the recipient exists, so a mistyped `--user-id` would succeed and reach nobody. `send-welcome` therefore reads the user with `GET /v1/users/<user-id>` first, and refuses an id the gateway answers `404` for without sending anything. Reading another user needs the `users.view` permission (administrators only by default), which sending does not, so a caller refused that lookup with `403` gets a warning that the recipient went unverified and the notification is sent anyway. A lookup that finds the user is an ordinary user read, so it also records an `accessed` user event in the gateway's metrics and fires any integration configured for the gateway's `user.accessed` event.

Run `fabric agent-gateway help` or `fabric agent-gateway <resource> help` for the complete command and option reference.