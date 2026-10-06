# Scripting and output

How commands print results and errors, how to get JSON for scripts, and how to reach any endpoint with `fabric agent-gateway api`.

## On this page

| Topic | What it covers |
| --- | --- |
| [Get JSON for a script](#get-json-for-a-script) | `--output json` and what it returns |
| [Capture a new ID or secret](#capture-a-new-id-or-secret) | Reading a created record's ID, and secrets shown only once |
| [Call an endpoint with no dedicated command](#call-an-endpoint-with-no-dedicated-command) | The raw `api` command |
| [Manage other resources](#manage-other-resources) | The shared `list` / `get` / `create` / `update` / `delete` groups |
| [How results print](#how-results-print) | Table and JSON output for each kind of command |
| [How errors print](#how-errors-print) | Redaction, permission messages, and `401` |
| [Environment variables](#environment-variables) | Variables the CLI reads |
| [Exit codes](#exit-codes) | What each exit code means |

All commands start with `fabric agent-gateway`.

## Get JSON for a script

```sh
fabric agent-gateway surfaces list --output json
fabric agent-gateway -o json surfaces list
```

Output is a table by default. Add `--output json` (or `-o json`) to any command, before or after the subcommand.

> [!WARNING]
> Table columns are padded with **spaces, not tabs**. A script that splits table output on tabs should use `--output json` instead.

Good to know:

- `--output json` prints what the gateway returned for lists, creates, updates, and deletes, with these exceptions: masked fields stay masked unless you pass `--reveal`, `audit list` is redacted unless you pass `--reveal`, `payments list` prints summary rows merged from every payment store, and `identities list` prints the list without the gateway's `count` wrapper.
- Most deletes get an empty body back, which prints as `null`.
- `get` returns the record as JSON in both modes, with secret values and private keys masked unless you pass `--reveal`. `list` returns full JSON with `--output json`.
- Yes or no fields print `true` or `false` in JSON (`yes` or `no` in a table).

## Capture a new ID or secret

```sh
ID=$(fabric agent-gateway -o json surfaces create ... | jq -r .surface_id)
```

In table mode, `create` prints a confirmation line (and `surfaces create` adds a short summary), so use `--output json` to capture the new ID.

Some secrets are shown only once, such as a token or API key secret. In table mode, the CLI prints that secret **alone on standard output**. The confirmation line and a `note:` go to standard error, so `$(...)` captures just the secret. With `--output json` it prints the whole response, and the `note:` still goes to standard error.

## Call an endpoint with no dedicated command

```sh
fabric agent-gateway api get /v1/limits --output json
fabric agent-gateway api patch /v1/surfaces/<surface-id> --data '{"description":"Updated"}'
fabric agent-gateway api post /v1/policy-definitions/<policy-id>/simulate --file input.json
```

`api` calls any authenticated management API endpoint. It covers every endpoint the other commands don't.

| Argument | Meaning |
| --- | --- |
| Method | `get`, `post`, `put`, `patch`, or `delete` |
| Path | The API path, such as `/v1/limits` |
| `--data` | Inline JSON request body. Can't be combined with `--file` |
| `--file` / `-f` | JSON request body from a file. `-` reads standard input |

Good to know:

- `api patch` sends its body as `application/merge-patch+json`, and it needs `--data` or `--file`.
- A call whose response is a JSON array prints a `NAME  ID  DESCRIPTION` table. Any other response prints as formatted JSON.
- The `api` table never cuts a value.

## Manage other resources

```sh
fabric agent-gateway connections list
fabric agent-gateway connection-points create --file connection-point.json
```

Several resources share the same five commands:

| Command | What it does |
| --- | --- |
| `list` | List the records |
| `get <id>` | Get a record by ID |
| `create --file <json>` | Create a record from a JSON document |
| `update <id> --file <json>` | Update a record from a JSON document (see below) |
| `delete <id>` | Delete a record by ID |

`--file -` reads the document from standard input. The ID is sent as given: these commands don't look up names, except `certificates`, which also accepts a certificate's name.

> [!CAUTION]
> `delete` runs as soon as the command runs. There is no confirmation prompt and no `--yes` flag.

`update` sends the document as an HTTP `PUT`. What happens to fields the document leaves out depends on the resource:

| Behaviour | Resources |
| --- | --- |
| **Replaces the whole record**: a field left out is cleared | authorities, STS clients, integrations, JWT verification strategies |
| **Changes only the fields sent**: the rest are kept | connections, connection points, issuers, trust registries, mediators, MCP proxies, A2A proxies, credential providers, certificates |

An issuer `update` must still include `name`: the gateway refuses a document without it, or with an empty one.

> [!WARNING]
> Connections and connection points accept only some fields on `update` and ignore the rest without an error:
>
> - A connection takes only `name`, `description`, and `status`. Its DID can't change.
> - A connection point takes `name`, `description`, `enabled`, and its integration list, which `update` reads as `integration_integrations` although `get` prints it as `integrations`.

A JWT verification strategy keeps its tenant on `update`; change it with `tenant-ownership set`.

Either way, the safest way to update is to start from the current record:

```sh
fabric agent-gateway issuers get <id> --output json > record.json
# edit record.json
fabric agent-gateway issuers update <id> --file record.json
```

These shared commands cover connections, connection points, Issuers, Authorities, Trust Registries, Mediators, MCP and A2A Proxies, STS clients, credential providers, certificates, integrations, and JWT verification strategies. For anything else, use [`api`](#call-an-endpoint-with-no-dedicated-command).

## How results print

| Command kind | Table output | `--output json` |
| --- | --- | --- |
| `list` | One table with a header row and one row per entity | What the gateway returned |
| `get` (one entity) | The **entire configuration** as formatted JSON, the same document as the dashboard's config view | Full JSON |
| `create` | `Created <kind> '<id>'` | What the gateway returned |
| `update` | `Updated <kind> '<id>'` | What the gateway returned |
| `delete` | One line, such as `Deleted credential provider '<id>'` | What the gateway returned (`null` for an empty body) |
| `api` returning a JSON array | A `NAME  ID  DESCRIPTION` table | What the gateway returned |

### Lists

- Each table shows the columns that matter for that resource. For surfaces: `NAME  ID  PROTOCOL  ROUTE  TARGET  TRANSIT POINTS`.
- `audit list` and `payments list` use the same kind of table.
- `surfaces features` (without a surface) and `tokens scopes` are catalogues and print plain lines.
- A cell that mixes named and unnamed items shows the names, then `+N more`.
- Long values end in `...`. IDs, DIDs, and names you can pass to another command always print whole.
- A yes or no field such as `ENABLED` prints `yes` or `no`.
- An empty expiry prints `never`, and an empty STS client scope list prints `any`. The gateway reads both as no limit.

An empty list prints a short line instead of a table:

| Line | When |
| --- | --- |
| `No surfaces yet.` | The collection is empty |
| `No matching secrets.` | A filter (`--tag`, `--status`, `--decision`, and so on) was given, or you asked for a page past the first |
| `No payments returned.` | A payments store failed to answer. A store that isn't set up doesn't change the line |

### Creates, updates, and deletes

- `surfaces create` follows its `Created` line with the surface's id, name, route, protocol, and target.
- Secret, certificate, and grant deletes get a `204` from the gateway.
- `surfaces delete` and `identities deactivate` get a body back, but still print one line in table mode (`Deleted surface '<id>'`, `Deactivated identity '<id>'`).
- `metrics truncate` and `logs truncate` don't delete one item, so they print the gateway's result.

### Standard error

- Notes, warnings, and errors on standard error start with `note:`, `warning:`, or `error:`.
- The browser sign-in instructions (opening the browser, the URL to visit) and confirmation prompts stay plain, and so does the confirmation line that moves to standard error when a secret is printed.

## How errors print

A failed request prints the reason from the response body. Before printing, the CLI:

- strips control characters, including the Unicode bidirectional controls that reorder displayed text
- caps the message at 500 characters
- replaces the request's credentials with `[redacted]`, keeping the rest of the message

Redaction exists because a gateway, or a proxy in front of it, can echo the request's headers back in the body. The credentials replaced are:

- the bearer token
- for `metrics scrape --username --password`: the password, the `username:password` pair, and its base64 form

<details>
<summary>Messages from <code>metrics config set</code> and <code>metrics test-endpoint</code></summary>

The gateway builds these messages from the underlying apply or connection error, so the CLI cleans them the same way:

- `metrics config set`: the `message` it prints in table output. With `--output json` it prints the gateway's response as it is.
- `metrics test-endpoint`: the failure message, in either output.

</details>

### Permission and sign-in errors

| Gateway response | What the CLI prints |
| --- | --- |
| A refusal, in the gateway's own words, that names the permission it needed | The gateway's wording, unchanged, for example `access token scope does not include 'access_tokens.view'` |
| A refusal that names only the permission | `missing required scope '<permission>'` |
| `401` | `gateway rejected the bearer token:` followed by the gateway's reason |

The gateway's own wording tells a role that lacks the permission apart from a personal access token whose scopes leave it out.

## Environment variables

| Variable | Used by | Effect |
| --- | --- | --- |
| `FABRIC_CONNECTION` | every command | Selects a saved connection, like `--connection` |
| `FABRIC_HOST` | every command, `login` | Overrides the gateway host, like `--host` |
| `FABRIC_TOKEN` | every command, `login` | Supplies a bearer token, like `--token`. Prefer it to typing the token on the command line |
| `FABRIC_PAT` | `login --pat` | Supplies the personal access token. Read only when `--pat` is given |
| `FABRIC_METRICS_USERNAME`, `FABRIC_METRICS_PASSWORD` | `metrics scrape` | HTTP Basic credentials for the Prometheus route. Set both or neither |

> [!IMPORTANT]
> `FABRIC_HOST`, `FABRIC_TOKEN`, `--host`, and `--token` override a **saved connection**; they don't replace one. With no saved connection, a command fails with `no gateway connection configured`. In CI, sign in first, for example `printf '%s' "$PAT" | fabric agent-gateway login --host <URL> --pat --token-stdin`, then run commands.

A saved connection's host and token live in the configuration file and the OS credential store, described in [Authentication](AUTHENTICATION.md#tokens-live-in-the-os-credential-store).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command succeeded |
| `1` | The command failed. The reason is printed on standard error, starting with `error:` |
| `2` | The arguments were invalid, for example an unknown flag or a missing required value |
| `3` | A `--dry-run` could only run the checks on this machine, because the gateway's checks could not run. Nothing was saved |

`whoami` exits `0` even when the token is rejected; read its `authenticated` field (see [Check who you are signed in as](AUTHENTICATION.md#check-who-you-are-signed-in-as)).

## Related

- [Authentication](AUTHENTICATION.md): signing in non-interactively
- [Interactive shell](INTERACTIVE_SHELL.md): running several commands in one session
