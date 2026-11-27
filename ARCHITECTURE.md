# Architecture

How the Affinidi Trust Fabric CLI is put together, and where in `src/` each part lives.

This page is for contributors changing the code. For what the CLI does and how to use it,
start with the [`README.md`](README.md) and the [user documentation](docs/README.md). For
the rules a change must follow, use [`CONTRIBUTING.md`](CONTRIBUTING.md).

## System shape

The CLI is one Rust binary, `fabric`, built from [`src/`](src/). There is no library
target: [`Cargo.toml`](Cargo.toml) declares a single `[[bin]]` whose entry point is
[`src/main.rs`](src/main.rs). Arguments are defined with clap's derive API.

Every command is addressed to an appliance first, so a command line reads
`fabric agent-gateway <group> <command>`. A second appliance, `agent-stream`, is being
built behind the `agent-stream` Cargo feature in [`src/agent_stream/`](src/agent_stream/):
it is off by default and in releases, so the shipped binary rejects `fabric agent-stream`.
The CLI talks to the gateway's management API over HTTP; it has no server component of
its own, apart from the short-lived loopback listener used during browser login.

| Concern | Where it lives |
| --- | --- |
| Command definitions, help text, and handlers | [`src/commands.rs`](src/commands.rs) |
| Saved connections (name and host) | [`src/config.rs`](src/config.rs), in `config.toml` for Agent Gateway and `agent-stream.toml` for Agent Stream |
| Tokens | [`src/credentials.rs`](src/credentials.rs), in the OS credential store |
| HTTP to the gateway | [`src/client.rs`](src/client.rs) |
| Output | [`src/tables.rs`](src/tables.rs) and the print helpers at the end of `commands.rs` |
| Surface editing | [`src/features.rs`](src/features.rs), [`src/surface_patch.rs`](src/surface_patch.rs), [`src/surface_validate.rs`](src/surface_validate.rs), [`src/tool_gate_preview.rs`](src/tool_gate_preview.rs) |

`commands.rs` is by far the largest file. Most changes land there.

## State and storage

The CLI keeps two pieces of local state, and keeps them apart.

| State | Where | Notes |
| --- | --- | --- |
| Connections | `fabric/config.toml` under the user configuration directory (`dirs::config_dir`), so `~/Library/Application Support/fabric/config.toml` on macOS, `$XDG_CONFIG_HOME/fabric/config.toml` on Linux, and `%APPDATA%\fabric\config.toml` on Windows | `Config` holds the `current` connection name and a map of named `Connection`s, each just a `host`. On Unix the file is written owner-only (`0600`). |
| Tokens | The OS credential store, through the `keyring` crate: macOS Keychain, Windows Credential Manager, or Linux Secret Service (over D-Bus with the pure Rust `zbus` client, so the binary does not link `libdbus`) | The service name is `affinidi-trust-fabric-cli`. The account is the connection name. The host the token was issued for is kept beside it under `<name>#bound-host`. |

Because the bound host shares the account namespace, `login` refuses a connection name
containing `#`, and `Config::hash_name_warnings` warns about any such name already saved.

Agent Stream connections (feature build only) use the same `Config` type and
`CredentialStore` trait, but live in `fabric/agent-stream.toml` beside `config.toml` and
under the keyring service `affinidi-trust-fabric-cli/agent-stream`, so each product can
have a connection named `default` and a CLI from before the feature never sees the file.
`agent_stream::dispatch` treats that file as `dispatch` treats `config.toml`. It prints
the `#` name warnings and moves a `token` line it finds into the Agent Stream keyring
service before any command rewrites the file, except on a command other than `login`,
`logout` and `config` given both a host and a token, which never touches the keyring.
An error from a keyring that cannot be reached gets one hint, as on a gateway command:
the move adds its own, which names the connection, and the command's own error gets the
general one. Each `CredentialStore` says which product's connections it keeps
(`CredentialStore::product`), and the code both products share (`command_target`,
`check_token_host`, `run_config`, `remove_connection`, `save_login`) reads it to name
that product's connections, file, and `login` command in its messages.

Older versions wrote the token into `config.toml`. `Connection` still reads that `token`
field (into `legacy_token`) but never writes it, and `Config::migrate_legacy_tokens` moves any token
it finds into the credential store, records its bound host, and rewrites the file
without it. This runs on every command that reaches `dispatch` and is not handled by
`run_offline`.

## The life of a command

```mermaid
flowchart TB
    A["main: inline_secret_warnings"] --> B["clap: Cli::command().get_matches()"]
    B --> C["env_token_and_host_note"]
    C --> D{"Command::Shell?"}
    D -- yes --> S["interactive::run"]
    D -- no --> R["commands::run"]
    S -- each line --> R
    R --> O{"run_offline?"}
    O -- yes --> P["Print"]
    O -- no --> L["Config::load, migrate_legacy_tokens"]
    L --> W["dispatch_with"]
    W --> H["Resolve connection, host, token"]
    H --> G["GatewayClient"]
    G --> RP["run_and_print"]
    RP --> X["Group handler: run_surfaces, run_crud, ..."]
    X --> P
```

### Argument parsing

[`main.rs`](src/main.rs) does three things before any command runs.

1. `inline_secret_warnings` scans the raw arguments for a secret typed on the command
   line (`--token`, `--pat`, `--value`, `--password`) and prints a `warning:` for each,
   naming the safer source to use instead. It stops at `--`.
2. clap parses the arguments into `Cli`. The tree is `Cli` → `Appliance` (`AgentGateway`,
   plus `AgentStream` in the feature build) → `AgentGatewayArgs` → `Command`.
3. `env_token_and_host_note` prints a `note:` when both the token and the host came from
   environment variables (`FABRIC_TOKEN` and `FABRIC_HOST`), so the two do not meet
   silently. It runs once per process, here, rather than inside `run`, because the
   interactive shell passes its host and token to every line as typed flags.

`AgentGatewayArgs` holds the global flags every Agent Gateway command shares.
`AgentStreamArgs` has the same flags for `fabric agent-stream`, except that its
`--connection` has no environment variable, so `FABRIC_CONNECTION` only ever names an
Agent Gateway connection:

| Flag | Environment | Purpose |
| --- | --- | --- |
| `--connection`, `-c` | `FABRIC_CONNECTION` (Agent Gateway only) | Which saved connection to use, or which to save on `login` |
| `--host` | `FABRIC_HOST` | Override the saved host for this command |
| `--token` | `FABRIC_TOKEN` | Override the saved token for this command |
| `--allow-http` | none | Allow plain `http://` to a host that is not loopback |
| `--allow-host-override` | none | Send the saved token to a host other than the one it is bound to |
| `--output`, `-o` | none | `table` (default) or `json` |

`Command` is the list of command groups. Each group is a variant carrying its own
subcommand enum (`SurfaceCommand`, `PolicyCommand`, `SecretCommand`, and so on), or the
shared `CrudCommand`.

### Resolving the connection, host, and token

`run` calls `dispatch`, which first tries `run_offline` for commands that need no
connection at all (today, `surfaces tool-gate-preview --gates-file`). Otherwise it
creates the real `OsCredentialStore`, loads `Config`, migrates any plaintext legacy
tokens into the credential store, and calls `dispatch_with`, which takes the config and
a `&impl CredentialStore` as arguments so tests can supply both. The migration is
skipped when `skips_the_credential_store` says the command was given both a host and a
token and is not `login`, `logout` or `config`, because such a command never reads the
credential store, so a server with no desktop session never reaches the keyring.

Before a token is sent, the command calls `product::check_product`. In a binary built
without the `agent-stream` Cargo feature, as every release is, that call returns at
once: no token is refused, no host is asked anything, and a gateway command sends
exactly the requests it sent before the check existed. The rest of this part describes
a binary built with the feature.

There, `check_product` makes sure the command is not aimed at the other product. A
token whose prefix says the other product issued it (`agpat_` is Agent Gateway;
`aspat_` and the older `atgpat_` are Agent Stream) is refused without a request.
Whitespace around the token is ignored when its prefix is read. Otherwise the CLI asks
the host which product it is, through `GET /api/v1/permissions/public` with no token, and
refuses a host that answers as the other product: the key `pipes.view` exists only on
Agent Stream. Each caller passes a `product::Given` saying whether the host and the token
were given on this run, and `must_ask_host` in `product.rs` decides from it, so the
callers cannot drift apart. The host is asked when it was typed with `--host` or set in
`FABRIC_HOST`, even when the token has the command's own prefix, so an `agpat_` token is
not sent to a typed host that answers as Agent Stream, nor an `aspat_` token to one that
answers as Agent Gateway. A saved connection's host is asked too when the token was given
with `--token` or `FABRIC_TOKEN` and has no product's prefix, such as a browser session
token, so a session of one product exported in `FABRIC_TOKEN` is not sent to a saved
connection of the other. A saved connection is not asked when the command uses its saved
token, which was checked against the host at login, or a given token with the command's
own prefix. When the probe cannot tell, a gateway command carries on and an Agent Stream
command stops. Both refusals get their text from
`wrong_product_message`, which never sees the token and names the command group to use
for the other product, such as `fabric agent-stream ...`.

`login` always has a typed host, so `login_and_save` asks it before it reads a token or
opens the browser, and stops before `check_auth` or `check_pat_auth` and before anything
is saved when the host answers as Agent Stream. This holds for `login --pat` and for a
token that already has the `agpat_` prefix. A token already in hand with the Agent Stream
prefix is refused without a request. A token read afterwards (standard input, a prompt,
the browser) still has its prefix checked. In the interactive shell, `login --paste` prompts
for the token before `login_and_save` runs, so there the host is asked after the token
is typed, and still before the token is sent.

The interactive shell runs every line as a command against the same host, so
`interactive::run` runs under `product::remembering_probes`, which keeps each host's
answer for as long as the shell is open. Only a product the host named is kept. A host
that could not be read is asked again on the next line, so it is still refused if it
later answers as the other product. A one-shot command, and a test that does not open
that scope, remembers nothing.

Every command of either product that sends a token calls `check_product` first, except
`logout`, which must remove the local copy whatever token is saved, so it reads the
saved token's prefix with `product::token_product` itself instead. In a binary built
with the feature, when the prefix names Agent Stream, the gateway's
`end_remote_credential` builds no client and sends nothing (no session end, no token
lookup, and no revoke), removes the local copy, and prints a note that the token stays
valid on the host until it expires. `fabric agent-stream logout` sends nothing for a
token with the Agent Gateway prefix, nor for an Agent Stream access token, since Agent
Stream has no route that names the token in use. Any other token is a session token,
which it sends to `/auth/logout` on the host the token was saved for, to end the
session there. `fabric agent-stream login` refuses a given token with the Agent Gateway prefix without a
request, asks the host before it reads any other token, and checks the prefix again once it has it. The rules sit in
`stop_if_other_product`, which the unit tests call directly, so they are tested in
both builds.

`GatewayClient` carries the product it talks to. Its messages say `gateway` for Agent
Gateway, as they always have, and `Agent Stream` otherwise. On Agent Stream,
`product_error` words three answers itself. A 401, which comes with an empty body,
says what it means for the token in use: a session that ended (after a while without
use, and by default 12 hours after sign-in), or an access token that is revoked,
expired, or owned by a user who is no longer approved. A 403 with the code
`TERMS_ACCEPTANCE_REQUIRED` and no message says to accept the Terms and Conditions in
the Agent Stream dashboard; when Agent Stream sends its own message, as it does for an
access token, that message is shown. A 403 with an empty body names the role, the
access token's scopes, or a header a resource-scoped access token requires. A session
whose `/auth/check` answer says `consent_required` is still saved by `login`, with a
warning, because accepting the terms makes the same session work.

`dispatch_with` first handles the commands that do not take the shared path below
(`login`, `logout`, `config`, `whoami`, and the feature list with no surface). For every
other command, and for `whoami`, `command_target` picks the host and token:

1. With no `--connection` and no `current` connection, and both a `--host` and a
   `--token` (typed or from `FABRIC_HOST` and `FABRIC_TOKEN`), it uses those two as they
   are, after `normalize_user_host`, and never touches the credential store.
2. Otherwise it resolves the connection with `Config::resolve_for`, for the product
   whose connections the credential store keeps: the `--connection` value, else the
   `current` one.
3. It picks the host with `command_host`: a `--host` value goes through
   `normalize_user_host`, which refuses plain `http://` to a non-loopback host unless
   `--allow-http` is set; otherwise the saved host is used, with a warning (once per
   host per process) if it is plain `http://` to a remote machine.
4. It picks the token: `--token` if given, without opening the credential store; otherwise `check_token_host` confirms the host
   matches the connection's bound host, and the token is read from the credential store.
   A mismatch is refused unless `--allow-host-override` was typed. For a connection
   saved before bound hosts existed, the saved host is recorded as the bound host on
   first use.

The command then builds a `GatewayClient` for that host and token. On Linux, `dispatch`
passes any error from `dispatch_with` through `add_no_keyring_hint`, which adds a hint
naming `FABRIC_HOST` and `FABRIC_TOKEN` when a Secret Service call failed because there
is no D-Bus session or the message bus answered `ServiceUnknown`. A running keyring that
refuses a call gets no hint. The legacy token migration runs before `dispatch_with` and
reruns on every command that may use the store, so it adds its own hint through
`add_no_keyring_migration_hint`: copy the plaintext `token` value into `FABRIC_TOKEN`,
delete that line from `config.toml`, and set `FABRIC_HOST` too.

### The HTTP client

`GatewayClient` in [`client.rs`](src/client.rs) wraps one `reqwest::Client` built by
`build_http_client`, which the browser login shares.

| Setting | Value | Constant |
| --- | --- | --- |
| Connect timeout | 10 s | `CONNECT_TIMEOUT` |
| Inactivity (read) timeout | 120 s | `READ_TIMEOUT` |
| Whole-request timeout | 300 s, on every call except the log archive download and the version request | `TOTAL_TIMEOUT` |
| Version request timeout | 10 s, on the gateway version request `whoami` makes | `VERSION_TIMEOUT` |
| Redirects | At most 5, and only to the same origin; any other redirect is not followed and the 3xx is reported | `MAX_REDIRECTS`, `same_origin_redirects` |
| User agent | `affinidi-trust-fabric-cli/<version>` | `build_http_client` |

Paths are relative to the gateway's `/api` prefix: `GatewayClient::url` adds `/api`
unless the path already starts with `/api/`, and refuses a path that does not start with `/`
or that contains a `..` or `.` segment, a backslash, a control character, or an encoded
slash, after repeated percent-decoding (`has_unsafe_segments`).

The request methods are:

| Method | Use |
| --- | --- |
| `request` | JSON in, JSON out, bearer token. An empty body becomes `null`. |
| `get_with_headers` | `GET`, also returning response headers (used to detect surface dry-run support) |
| `merge_patch` | `PATCH` with `application/merge-patch+json`, which the gateway's surface routes require |
| `request_bytes` | Non-JSON success bodies, such as the Prometheus exposition; bearer or HTTP Basic (`RawAuth`) |
| `download_bytes` | The log archive, with only the inactivity timeout applied |
| `check_auth`, `check_pat_auth`, `end_session` | Login validation and logout |
| `gateway_version` | The gateway's version from the public `/v1/version` route, sent without the token and held to `VERSION_TIMEOUT` (10 s). An answer over `MAX_VERSION_BODY_BYTES` (4 KiB) is refused; from the version text only ASCII letters, digits, `.`, `-` and `+` are kept, cut to 64 characters. A non-200 answer keeps its status for `response_status`, so `whoami` can stay quiet on a 404 and warn on anything else |

A non-success status becomes a `GatewayStatusError` built by `gateway_error`. It picks
the reason out of the known error body shapes (`message`, or `error` with `details`),
prefers the gateway's own wording when the body names a `required_permission`, and
keeps the status so a caller can branch on it with `response_status`. Before any
gateway text reaches the terminal, the credentials the request carried
(`GatewayClient::secrets`) are replaced with `[redacted]`, and the text is passed
through `sanitize_for_terminal`, which strips control and bidirectional characters,
folds line breaks, and caps the length. `sanitize_whole` and `sanitize_multiline` are
the uncapped and multi-line variants.

### Dispatch to handlers

After the client is built, `dispatch_with` calls `run_and_print`, which does some
per-command preparation, then calls the group's handler. `fabric agent-stream secrets`,
`users`, `identities`, `api-keys`, `policies`, `connections`, `connection-points`,
`mediators`, `settings`, `user-settings`, `terms`, `notifications`, `certificates`,
`credential-providers`, `jwt-verification-strategies`, `delegation-vault`, `audit`,
`metrics`, and `logs` reach the same function through `run_shared`, with a `SharedCommand` mapped from their own clap enums, so both products
print the same tables and confirmation lines. `tenant-ownership` takes Agent Stream's
own resource kinds, so `run_shared` sends it straight to `run_ownership_change`, which
the Agent Gateway command also ends in. An Agent Stream delete or revoke without `--yes`
(`policies delete`, `connections delete`, `certificates delete`,
`credential-providers delete`, `jwt-verification-strategies delete`,
`delegation-vault revoke`, and `revoke-user`) carries `ask_first`, so `run_shared` asks first through a `Prompter`, the terminal in a
real run and `ScriptedPrompter` in tests, and `refuse_before_connecting` refuses it with
no terminal before anything is sent. Before asking, `revoke-user` counts the hash's grants
in the grant list, so the question says how many the list shows; with none, it asks whether
to revoke anyway. When the grant list can't be read, for example without
`delegation_vault.view`, the question names every grant of the hash instead. The revoke
removes every grant the hash has when it runs, and the result line reports that number.

Inside `run_and_print`:

- `resolve_surface_command` swaps a surface name for its ID in every surface command
  that names one, printing `note: using surface <id> (<name>)` to standard error.
- `create_kind`, `delete_confirmation`, `update_confirmation`, `list_layout`, and
  `list_scope` read the command before it is consumed, to decide how the result prints.
- The handler runs: `run_crud` for resources that fit the shared CRUD shape, or a
  group-specific function such as `run_surfaces`, `run_secrets`, `run_policies`, or
  `run_api`.

Agent Stream has no `metrics status`, because it has no OpenTelemetry export status
route.

Handlers return in one of three ways:

| Return | Meaning | Examples |
| --- | --- | --- |
| `Result<Value>` | The shared printer prints it | `run_crud`, `run_policies`, `run_users` |
| `Result<Option<Value>>` | `None` means the handler already printed its outcome | `run_surfaces`, `run_secrets`, `run_certificates` |
| `return` from `run_and_print` | The handler prints everything itself | `run_audit`, `run_payments`, `run_metrics`, `run_logs`, `run_api_keys`, `run_access_tokens` |

`run` wraps every Agent Gateway error with `add_terms_hint`, because the gateway's Terms
of Use gate can refuse any route. Agent Stream's gate can too, so `agent_stream::dispatch_with`
wraps the error of every Agent Stream command once the same way, reading the code off the
answer's body. There `TERMS_ACCEPTANCE_REQUIRED` gets no hint, because `product_error` already
words that refusal (see the Agent Stream paragraph above).

### Output

Standard output carries the result. Standard error carries everything else, with a
fixed prefix.

| Prefix | Meaning |
| --- | --- |
| `note:` | Information, such as which surface a name resolved to |
| `warning:` | Something the user should act on, but the command continues |
| `error:` | The command failed. Printed by `main` (or by the shell for one line) as `error: {error:#}`, so the whole `anyhow` context chain shows. |

In `run_and_print`, a value is printed by one of three paths:

- A delete or update with a confirmation prints one line from `confirmation_line`, such
  as `Deleted issuer 'i-1'`, through `print_outcome`. `users delete` takes its line from
  `user_delete_line`: `Disabled user '<id>'` when Agent Stream answers `{"outcome":
  "disabled"}`, because it kept the record of a user who signs in through an identity
  provider, with a `note:` on standard error saying so, and `Deleted user '<id>'`
  otherwise.
- A list with a layout prints through `print_list`, which renders a `tables::Layout`
  with `tables::render_scoped`.
- Anything else goes through `print_created_or_value`: `print_issued` for a create, else
  `print_value`.

With `--output json`, these print the appliance's document. The shared printer,
`print_value`, uses `pretty_json_for_terminal`, which escapes characters a terminal
could act on while keeping the JSON valid. A create or rotate whose answer carries a
secret shown once prints that secret alone on standard output, so `$(...)` captures just
the secret, and the confirmation and a `note:` on standard error.

[`tables.rs`](src/tables.rs) is the one table format. A `Layout` names its empty-list
line and its columns; a `Column` names its header, the dotted paths to try in a row, and
its width cap. Identifier columns (`whole`, `id`) are never cut short, because people
copy them into the next command. Every cell is passed through `table_cell` or
`whole_cell`.

The exit status comes from `exit_code`: `1` for a failed command, and
`INCOMPLETE_DRY_RUN_EXIT_CODE` (`3`) for a `--dry-run` whose gateway checks did not run.
clap's own exit status for an invalid command line is `2`.

### Interactive shell

[`interactive.rs`](src/interactive.rs) runs the `shell` command of either appliance
with `rustyline`: `fabric agent-gateway shell`, and in a binary built with the
`agent-stream` feature, `fabric agent-stream shell`. `Cli::interactive_prefix` gives the
appliance's command group plus the global flags the shell was started with, through
`commands::shell_prefix`; each line is split with `shell_words`, appended to that
prefix, and parsed by the same `Cli`, so every command of that appliance is available in
the shell without extra wiring, and the other appliance's commands are not. Each parsed
line goes through `commands::run`, the same path as a one-shot command. What the shell
shows (banner, prompt, the note for `shell` typed inside it, the `login --paste`
prompt, and the name it gives the token) comes from the appliance's `ShellText`:
`GATEWAY_SHELL_TEXT` in `commands.rs` and `SHELL_TEXT` in `agent_stream/mod.rs`.

The shell runs `inline_secret_warnings` on every line and keeps a line that triggers one
out of its history. `login --paste` prompts without echo. Warnings that would repeat on
every line, such as the plain-http warning for a saved host, are shown once per process through
`first_warning_for` and the `WARNED_ONCE` list in `commands.rs`. In a binary built with
the `agent-stream` feature, the question of which product a host is gets asked
once per shell as well, through `product::remembering_probes`.

### Browser login

[`browser_login.rs`](src/browser_login.rs) implements loopback redirect with PKCE
(RFC 8252). `browser_login`:

1. Binds a listener on `127.0.0.1` on a free port.
2. Generates a random verifier and state, and the S256 challenge.
3. Opens `<host>/api/auth/cli/authorize?port=…&state=…&challenge=…` in the browser, and
   prints the URL in case the browser did not open.
4. Waits up to `CALLBACK_TIMEOUT` (300 s) for a request to `/callback`, refusing a state
   mismatch.
5. Exchanges the code and verifier at `<host>/api/auth/cli/exchange` for the session
   token, with a client from `build_http_client` and the `TOTAL_TIMEOUT` limit.

The token never appears in a browser URL. `acquire_login_token` in `commands.rs` decides
whether browser login runs at all: an explicit token, `--pat`, `--token-stdin`,
`--paste`, or piped standard input each take precedence. In a binary built with the
`agent-stream` feature, `login_and_save` first asks the host which product it is and
refuses an Agent Stream, `--pat` included (see
[Resolving the connection, host, and token](#resolving-the-connection-host-and-token)).
`login_and_save` validates the token against the gateway, then `save_login`, which
`fabric agent-stream login` uses too, saves it and restores the previous token and bound
host if saving fails.

## Surface editing

Agent Surfaces have the richest editing in the CLI. Four modules do the work locally, so
a bad edit fails with a clear message before anything is sent.

| Module | Owns | Used by |
| --- | --- | --- |
| [`surface_patch.rs`](src/surface_patch.rs) | `build_patch` turns `--set`, `--unset`, `--add`, and `--remove` into one JSON Merge Patch (RFC 7396). Handles bracketed selectors such as `gates[g-1]` and `transit.points[billing]`, and refuses overlapping paths. | `surfaces update`, `add-transit-point`, `remove-transit-point` |
| [`features.rs`](src/features.rs) | The `FEATURES` registry: each `Feature` has a key, aliases, a description, and `Placement`s (edge, direction, JSON pointer, `ValueKind`). `build_patch` makes the merge patch that adds or removes one feature. `on_surface` reports which features a surface has. | `surfaces features`, `add-feature`, `remove-feature` |
| [`surface_validate.rs`](src/surface_validate.rs) | `merge` applies a merge patch the way the gateway does; `check_surface` checks the fields every surface needs; `changes` lists what a patch changes. | Every surface edit, and dry runs |
| [`tool_gate_preview.rs`](src/tool_gate_preview.rs) | Follows the gateway's MCP tool-gating rules (`decide`, `preview`) to show which gate allows or denies each tool, trying unpinned condition policies both ways. | `surfaces tool-gate-preview`, and pattern checks in `surface_patch` |

A surface edit in `commands.rs` follows one shape (the exceptions are `surfaces update
--file`, which runs `check_surface` and sends a `PUT`, and a `--set` or `--unset` edit that
is sent unchecked when the token cannot read the surface):

1. `fetch_surface` reads the current surface with `get_with_headers`, and notes whether
   the gateway sent the `x-surface-dry-run` header (`SURFACE_DRY_RUN_HEADER`).
2. A patch is built, by `surface_patch::build_patch` (for `update` and the transit-point
   commands) or `features::build_patch`.
3. `send_surface_patch` merges the patch locally and runs `check_surface`. Without
   `--dry-run` it sends the patch with `merge_patch`. With `--dry-run` it sends it with
   `?dry_run=true` when the gateway supports that, prints the report, and returns
   `IncompleteDryRun` if only the local checks ran. A dry run never sends the patch
   without the query parameter.

`fabric agent-stream surfaces` (in [`agent_stream/surfaces.rs`](src/agent_stream/surfaces.rs))
reuses `surface_patch::build_patch`, `surface_validate::merge`, and
`surface_validate::changes`, but not `check_surface`, which checks Agent Gateway fields.
Agent Stream serves surfaces at `/v1/pipes`, has no `PATCH`, no dry run, and no version
check, and drops a field it does not know without an error. So field names are checked
before anything is sent. A top-level name must be in `SURFACE_FIELDS`, a copy of the
field names of Agent Stream's `PipeConfig`, or in the stored surface. On `update`, from
the flags or `--file`, a name inside an object the stored surface has must already be in
that object unless `--allow-new-field` is given; a name inside an object the surface
lacks, or inside a list item, is not checked. `create` has nothing stored to compare
with, so it checks top-level names only. Flag paths with brackets or list positions,
which only Agent Gateway paths use, and flags on `id`, `created_at`, `updated_at`,
`tenant_id`, or `owner_user_id` are refused before anything is read or sent, and so is any
`update` flag on `status` other than `--set status=<value>`. Both commands refuse a
`status` other than `enabled` or `disabled`, and a `pipe_type.type` other than `llm`,
`webhook`, or `ide_catalog` (on `update`, the stored surface's own type is accepted too,
for a type a newer Agent Stream added).

`update` reads the surface, builds the whole new surface on this machine, reads the
surface again, and sends it with `PUT` only when `updated_at` has not moved. A surface
with no `updated_at` is refused, since a later save could not be told apart. A `--file`
must carry the current `updated_at`, and its `status`, `created_at`, `tenant_id`, and
`owner_user_id` are replaced with the stored ones. After the save, table output lists
the changed fields, and `--output json` reads the surface once more and prints it,
because Agent Stream answers a save with an `updated_at` its store then replaces, so
only a fresh read can go back to `--file`. A dry run of `create` or `update` prints the
same JSON shape (`dry_run`, `changes`, `after`), and `create --dry-run` runs before any
connection is resolved, so it needs no saved connection.

## Invariants

Breaking one of these is a correctness bug, not a style question.

| Invariant | Enforced by | Consequence if broken |
| --- | --- | --- |
| A token is never written to `config.toml`. | `Connection` skips serialising `legacy_token`; `migrate_legacy_tokens` moves old ones out | A token would sit in a plain file |
| A saved token is sent only to the host it was saved for, unless `--allow-host-override` is typed. The flag has no environment variable. | `check_token_host` | A mistyped or swapped host, or a project's environment, could receive the token |
| Redirects are followed only within the origin of the request. | `same_origin_redirects` | The `Authorization` header could reach another host |
| Plain `http://` to a non-loopback host needs `--allow-http`. | `normalize_user_host` | A token could cross the network unencrypted without the user choosing it |
| Credentials the request carried are redacted from every error message. | `gateway_error`, `GatewayClient::secrets` | An echoed `Authorization` header would print the token |
| Gateway-supplied text is sanitised before it reaches the terminal. | `sanitize_for_terminal` and its variants, `tables::table_cell`, `pretty_json_for_terminal` | Control sequences in a response could rewrite the terminal |
| A request path cannot climb out of `/api`. | `GatewayClient::url`, `has_unsafe_segments` | An ID or a raw `api` path could address another route |
| A body carrying the masking placeholder is refused. | `checked_body` | A document captured from `get` and replayed through `create` or `update` would store the placeholder as the credential |
| A failed login of either product leaves the previous token and bound host in place. | `save_login`, `restore_credentials` | A failed re-login would lose a working connection |

## Module map

Every file in [`src/`](src/) and what it owns.

| Module | Owns |
| --- | --- |
| [`main.rs`](src/main.rs) | Entry point. Secret warnings, parsing, the environment note, then `interactive::run` or `commands::run`. Prints the final `error:` and sets the exit status. |
| [`commands.rs`](src/commands.rs) | The clap definitions (`Cli`, `Command`, every subcommand enum), their help text, `dispatch_with`, connection and token resolution, every group handler, and the print helpers. |
| [`client.rs`](src/client.rs) | `GatewayClient`, the shared HTTP client, path checks, `gateway_error`, redaction, and the terminal sanitisers. |
| [`config.rs`](src/config.rs) | `Config` and `Connection`, the `config.toml` and `agent-stream.toml` paths and file permissions, host normalisation, the plain-http rules, and legacy token migration. |
| [`credentials.rs`](src/credentials.rs) | The `CredentialStore` trait, including the bound-host methods, and `OsCredentialStore` over `keyring`, one instance per product's keyring service. |
| [`product.rs`](src/product.rs) | `Product`, the token prefixes of each product, the anonymous probe of a host's public permission list, `check_product`, which stops a command aimed at the other product in a binary built with the `agent-stream` feature and does nothing in one built without it, `remembering_probes`, which keeps a host's answer for the length of an interactive shell, and the names messages give each product (`message_name`, `message_subject`, `connection_noun`, `surface_noun`). |
| [`agent_stream/`](src/agent_stream/) | `fabric agent-stream` (feature `agent-stream` only): the clap definitions, global flags, and dispatch in `mod.rs` (`api` and `shell` included), one file per command group (`config.rs`, `login.rs` for `login` and `logout`, `whoami.rs`, `surfaces.rs`, `tokens.rs`, which maps onto the shared access token commands, and `secrets.rs`, `users.rs`, `identities.rs`, `api_keys.rs`, `policies.rs`, `connections.rs`, `connection_points.rs`, `mediators.rs`, `settings.rs`, `user_settings.rs`, `terms.rs`, `notifications.rs`, `tenant_ownership.rs`, `certificates.rs`, `credential_providers.rs`, `jwt_verification_strategies.rs`, `delegation_vault.rs`, `audit.rs`, `metrics.rs`, and `logs.rs`, which map onto the shared commands through `run_shared`: the Agent Gateway enums, or `OwnershipChange`, which both products' `tenant-ownership` map onto, and `governance.rs` and `drift.rs`), the helpers those last two share (`prompt_content.rs` hides prompt content, `request.rs` builds query strings and names the permission a 403 lacked, and `when.rs` reads `--since`, `--until` and `--window`), and `test_support.rs` for what their tests share, including a scripted Agent Stream. |
| [`browser_login.rs`](src/browser_login.rs) | Loopback listener, PKCE, the callback, and the code exchange. |
| [`interactive.rs`](src/interactive.rs) | The `shell` command's read loop and line parsing. |
| [`tables.rs`](src/tables.rs) | `Layout`, `Column`, `Scope`, every list layout, and the cell helpers. |
| [`features.rs`](src/features.rs) | The surface feature registry and feature merge patches. |
| [`surface_patch.rs`](src/surface_patch.rs) | The `surfaces update` path syntax and merge patch builder. |
| [`surface_validate.rs`](src/surface_validate.rs) | Local merge patch application and the required-field check. |
| [`tool_gate_preview.rs`](src/tool_gate_preview.rs) | Local evaluation of MCP tool gates and pattern limits. |

## Where to look

| Task | Start here |
| --- | --- |
| Add or change a command | The group's subcommand enum and its `run_*` function in `commands.rs`; see [`MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md) |
| Change how a list prints | The layout in `tables.rs`, and `list_layout` in `commands.rs` |
| Change a delete, update, or create confirmation | `delete_confirmation`, `update_confirmation`, `create_kind`, `confirmation_line` |
| Change how a gateway error reads | `gateway_error` and `error_detail` in `client.rs` |
| Change timeouts or redirect handling | The constants and `build_http_client` in `client.rs` |
| Change which host or token a command uses | `dispatch_with`, `command_host`, `check_token_host` |
| Change login | `login_and_save` and `acquire_login_token` in `commands.rs`, `browser_login.rs` |
| Change where connections or tokens are stored | `config.rs`, `credentials.rs` |
| Add an Agent Stream command group | A new file under `src/agent_stream/`, declared in its `mod.rs` |
| Change a group Agent Stream shares with Agent Gateway | The group's file under `src/agent_stream/` for its help and its mapping onto the shared enum, then the shared `run_*` function in `commands.rs`, reached through `SharedCommand` and `run_shared`. A refusal that must send nothing goes in `refuse_before_connecting` in `agent_stream/mod.rs`, which `run_command` calls before `connect`. Only refusals that need neither the host nor a file go there: `metrics config set` compares the file with the live configuration, so it refuses after `connect` |
| Add a surface feature | `FEATURES` in `features.rs` |
| Change the `surfaces update` path syntax | `surface_patch.rs` |
| Look a resource up by name | `Lookup`, `resolve_id`, and `resolve_surface_id` in `commands.rs` |

## Related

- [`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md): build and run the CLI from source.
- [`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md): recipes for common changes.
- [`docs/development/TESTING.md`](docs/development/TESTING.md): test layers and how to run them.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): what a contribution has to include.
- [`docs/README.md`](docs/README.md): the user documentation index.
