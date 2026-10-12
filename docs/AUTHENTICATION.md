# Authentication

Sign in to an Agent Gateway, manage saved connections, and use personal access tokens for automation.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`login`](#sign-in-with-a-browser) | Sign in through the browser and save the connection |
| [`login --paste` / `--token-stdin`](#sign-in-with-a-token-you-already-have) | Sign in with a session token you supply yourself |
| [`login --pat`](#sign-in-with-a-personal-access-token) | Sign in with a personal access token |
| [`config list` / `use <name>`](#switch-between-gateways) | List saved connections and pick the current one |
| [`config remove <name>`](#remove-a-saved-connection) | Forget a connection locally, without contacting the gateway |
| [`logout [--revoke-token]`](#sign-out) | Forget a connection and end its session on the gateway |
| [`whoami`](#check-who-you-are-signed-in-as) | Show the current connection and check its token live |
| [`tokens list` / `get <id>`](#list-and-inspect-tokens) | List or show personal access tokens |
| [`tokens scopes`](#see-which-scopes-you-can-grant) | List the scopes you can grant a new token |
| [`tokens create`](#create-a-token) | Create a personal access token |
| [`tokens revoke <id>`](#revoke-a-token) | Revoke a token |
| [`tokens rotate <id>`](#rotate-a-token) | Replace a token's secret, keeping its ID |

All commands start with `fabric agent-gateway`. Where tokens are stored, which host they go to, and how long sessions and requests last are covered in [How connections and tokens behave](#how-connections-and-tokens-behave).

## Login

### Sign in with a browser

```sh
fabric agent-gateway login --host https://gateway.example.com
```

By default, `login` opens your browser to complete the gateway's normal passkey or SAML SSO login. It captures the session token automatically over a loopback redirect, so there is no manual copy-paste. When standard input is piped, `login` reads the token from there instead.

The `https://` scheme may be omitted: bare gateway hostnames default to HTTPS.

The flow is:

1. The CLI starts a temporary listener on `127.0.0.1` and opens `/api/auth/cli/authorize` in your browser.
2. You sign in with passkey or SSO. If you are already signed in, the browser continues immediately.
3. The gateway redirects back to `http://127.0.0.1:<port>/callback` with a single-use code.
4. The CLI exchanges the code plus a PKCE verifier for the session token over a direct back channel. The token never appears in a browser URL or history.

The captured token is validated with `/api/auth/check`, then stored in the OS credential store (see [Tokens live in the OS credential store](#tokens-live-in-the-os-credential-store)).

### Sign in with a token you already have

For automation, or a machine with no browser, supply the token manually instead of using the browser. `login` still saves the token in the OS credential store; on a Linux server with no desktop session, which has none, [run without a saved connection](#run-without-a-saved-connection) instead.

```sh
fabric agent-gateway login --host https://gateway.example.com --paste          # prompt to paste a token
printf '%s' "$TOKEN" | fabric agent-gateway login --host https://gateway.example.com --token-stdin
FABRIC_TOKEN="$TOKEN" fabric agent-gateway login --host https://gateway.example.com
```

| Flag | Meaning |
| --- | --- |
| `--paste` | Prompt for a bearer token instead of opening the browser |
| `--token-stdin` | Read the token from standard input |
| `--token` / `FABRIC_TOKEN` | The token itself. Prefer `FABRIC_TOKEN` or `--token-stdin`, because a typed `--token` stays in shell history (see [Keep tokens out of shell history](#keep-tokens-out-of-shell-history)) |

### Sign in with a personal access token

```sh
fabric agent-gateway login --host https://gateway.example.com --pat              # prompt for the token
printf '%s' "$PAT" | fabric agent-gateway login --host https://gateway.example.com --pat --token-stdin
FABRIC_PAT="$PAT" fabric agent-gateway login --host https://gateway.example.com --pat
```

A personal access token is a long-lived bearer token that starts with `agpat_`, for scripts and CI jobs that can't complete a browser login. Pass `--pat` to log in with one. The token can:

- follow the flag (it then stays in shell history),
- come from `FABRIC_PAT`, or
- come from standard input with `--token-stdin`. Piped input is read even without it.

With none of those, the CLI prompts for it without echoing.

Before storing anything, the CLI checks the token:

- A value without the `agpat_` prefix is refused before anything is sent.
- The token is checked against `/v1/token-info`. Only a `200` passes, so a token the gateway doesn't accept, such as a revoked one, or any other answer saves nothing.
- A token that passes is saved to the OS credential store under the connection, the same way a session login is.

> [!NOTE]
>
> - `FABRIC_PAT` is only read once `--pat` is given. On its own it doesn't select PAT login, and a plain `login` still opens the browser.
> - `--pat` can't be combined with `--token` or `--paste`. A `FABRIC_TOKEN` set in the environment counts as `--token`, so unset it first.

To create a token, see [Create a token](#create-a-token).

### Save or replace a connection

```sh
fabric agent-gateway --connection production login --host https://gateway.example.com
```

`login` saves the host and token under the connection named by `--connection` (or `FABRIC_CONNECTION`), or `default` when neither is set, and makes it current. Later commands use the current connection automatically, so the host and token don't need to be repeated:

```sh
fabric agent-gateway surfaces list
fabric agent-gateway policies list
```

Good to know:

- The same `--connection` flag selects a saved connection on the commands that talk to a gateway.
- Per-resource `--name` flags always name the resource being created, never a connection.
- Logging in under a connection name that already exists replaces its saved token and host. This is also how you refresh an expired session.
- A login the gateway rejects changes nothing.

> [!WARNING]
> Replacing a connection is reported on standard error, naming both the old and the new host when the host changed. Read that line: it is what stops a stale `FABRIC_CONNECTION` or a pasted command from repointing a connection unnoticed.

## Connections

`config` manages local connection profiles only. It never contacts a gateway, unlike `runtime`, which inspects the gateway's own configuration.

### Switch between gateways

```sh
fabric agent-gateway --connection production login --host https://gateway.example.com
fabric agent-gateway config list
fabric agent-gateway config use production
fabric agent-gateway --connection production surfaces list
```

`config list` shows the saved connections and `config use <name>` makes one current. `--connection <name>` selects a saved connection on the commands that talk to a gateway.

### Remove a saved connection

```sh
fabric agent-gateway config remove <name>
```

`config remove` only removes the local profile and its credential-store entry. It doesn't contact the gateway, so a browser session stays open and a personal access token stays valid there. Use [`logout`](#sign-out) to end the session or revoke the token as well.

When the removed connection was current, another saved connection, if any, becomes current (the first by name).

## Logout

### Sign out

```sh
fabric agent-gateway logout
fabric agent-gateway logout --revoke-token     # revoke a personal access token without asking
```

`logout` removes the local profile and its OS credential-store entry, and also ends the session on the gateway when it can be reached.

Good to know:

- A browser login is the browser's own gateway session, so `logout` signs you out of the browser as well.
- For a personal access token, `logout` asks whether to revoke it, naming its token ID, while it still holds the token. Pass `--revoke-token` to revoke it without asking (for scripts).
- Without `--connection`, `logout` removes the current connection. Another saved connection, if any, becomes current (the first by name), so the next command may go to a different gateway.

> [!WARNING]
> Without a terminal and without `--revoke-token`, a personal access token **stays valid on the gateway**. `logout` prints how to revoke it later with [`tokens revoke`](#revoke-a-token).

## Whoami

### Check who you are signed in as

```sh
fabric agent-gateway whoami
fabric agent-gateway whoami --output json
```

`whoami` shows:

- the connection and host in use, and whether the token was read from the OS credential store (`token_stored`), which is `false` for a token given with `--token` or `FABRIC_TOKEN`;
- checked live against the gateway, whether that token is still accepted;
- the signed-in username, role, email, user ID, and name.

For a personal access token it also shows the token's ID and name and the scopes the token was granted. The name is left out when the token lacks `access_tokens.view`. A session login holds its whole role and shows no token or scopes.

Use `whoami` to check whether a stored session is still valid (see [Sessions stay alive while you use them](#sessions-stay-alive-while-you-use-them)).

> [!WARNING]
> `whoami` exits `0` even when the gateway rejects the token. In a script, check the `authenticated` field instead, for example `fabric agent-gateway whoami --output json | jq -e .authenticated`.

## Personal access tokens

`tokens` manages personal access tokens. To sign in with one, see [Sign in with a personal access token](#sign-in-with-a-personal-access-token).

### List and inspect tokens

```sh
fabric agent-gateway tokens list
fabric agent-gateway tokens get <token-id>
```

`list` prints one row per token:

| Column | Meaning |
| --- | --- |
| `NAME`, `ID` | The token's name and ID |
| `STATUS` | `REVOKED` once the token has been revoked or has expired, `ACTIVE` otherwise |
| `SCOPES` | Scope names joined with commas, up to 40 characters, ending with `+N more` for the ones that didn't fit. A name is never cut in half. A token created with `--full-role` shows `full role` |
| `CREATED`, `EXPIRES` | Creation and expiry times |

`get` prints the token's whole record as JSON. `get` and `--output json` show the full scope list.

### See which scopes you can grant

```sh
fabric agent-gateway tokens scopes
```

`scopes` lists the scopes your role holds, which you can give a new token, one per line. The list comes from your role only. When you are signed in with a scoped personal access token, a new token can get only scopes that token also holds.

### Create a token

```sh
fabric agent-gateway tokens create --name ci-deploy --scope surfaces.view --scope surfaces.edit --expires-at 2027-01-01T00:00:00Z
fabric agent-gateway tokens create --file token.json
```

| Flag | Meaning |
| --- | --- |
| `--name` | Token name. Required unless `--file` is given |
| `--description` | What the token is for |
| `--scope` | A scope to grant; repeat it for each scope. A token needs at least one, or `--full-role` |
| `--full-role` | Carry your whole role instead of listed scopes. Can't be combined with `--scope` |
| `--expires-at` | An RFC 3339 timestamp, such as `2027-01-01T00:00:00Z`. Defaults to 90 days from now |
| `--required-header`, `--resource-pattern` | Narrow where the token works. See [Limit where a token works](#limit-where-a-token-works) |
| `--file` | A complete creation document (`-` reads standard input). The other creation flags, except `--full-role`, are ignored. The document still needs scopes (or `--full-role`) |

The gateway keeps only a hash of the secret, so creation is the one time it is shown:

| Output | Standard output | Standard error |
| --- | --- | --- |
| Table (default) | The secret alone, so `PAT=$(fabric agent-gateway tokens create ...)` captures just that | `Created access token '<id>'` and a `note:` about the secret |
| `--output json` | The whole response, secret included | The `note:` about the secret |

Good to know:

- The CLI never asks for a token with no expiry. Omitting `--expires-at`, or leaving `expires_at` empty or null in a `--file` body, gives 90 days, so give a later date for a long-lived token. The gateway refuses, with a `400`, a date that isn't in the future or is more than 3650 days (10 years) ahead.
- In table mode, a secret containing control characters is not printed, even though the token has been created. The CLI tells you to revoke the token, or rotate it with `--output json` to get a new secret.

<details>
<summary>Why the gateway refuses a scope</summary>

- A scope your own role doesn't hold is refused with a `403`, which the CLI shows as `access-token scopes must not exceed the caller's own role`. Nothing is created. `tokens scopes` shows what you can grant.
- When you create a token while logged in with a scoped personal access token, the new token must ask for at least one scope, all of them held by the token you are using.
- A token carrying a resource pattern or required headers can't create tokens at all.
- A scope name the gateway doesn't recognise is refused as `unknown scope: <name>`, and the CLI adds a pointer to `tokens scopes`.

</details>

### Limit where a token works

```sh
fabric agent-gateway tokens create --name acme-surfaces --scope surfaces.view \
  --required-header x-tenant-id=acme --resource-pattern 'TENANT:${x-tenant-id}:surfaces:.*'
```

| Flag | Meaning |
| --- | --- |
| `--required-header name=pattern` | A header the caller must send, and a regex its whole value must match. Repeat for more. A value that isn't `name=pattern` with both parts non-empty is refused before anything is sent |
| `--resource-pattern` | Limits the token to the resources it matches. Omit it for an appliance-wide token |

A resource pattern must take the form `TENANT:${header}:<resource-kind>:<resource-id-pattern>`. `${header}` names one of the token's required headers, and the resource kind is a path family such as `surfaces`, `gateways`, or `secrets`. Anything else is refused with a `400`.

> [!IMPORTANT]
> The caller picks the header's value on each request, so the caller decides the tenant. The gateway therefore refuses, with a `400`, a pattern for the header named in `${…}` that isn't a single exact value such as `acme`. The exception is a deployment whose `tenancy.trusted_tenant_header` names that header with `edge_strips_client_values: true`, for a proxy that overwrites it. An existing token that breaks this rule is refused with a `403` on every request.

### Revoke a token

```sh
fabric agent-gateway tokens revoke <token-id>
fabric agent-gateway tokens revoke <token-id> --yes
```

`revoke` asks `Revoke access token '<name>' (<id>) on <host>? [y/N]` on standard error and revokes only on `y` or `yes`. Any other answer leaves the token alone and exits successfully. Pass `--yes` or `-y` to skip the prompt.

When standard input isn't a terminal the prompt could never be answered, so `revoke` without `--yes` fails there and sends nothing.

> [!CAUTION]
> A revoke can't be undone. If this CLI is logged in with the token you revoke, that saved connection stops working too.

### Rotate a token

```sh
fabric agent-gateway tokens rotate <token-id> --yes
```

`rotate` replaces a personal access token's secret while keeping its ID, name, and scopes. Without `--yes` (or `-y`) it asks for confirmation, and it refuses to run non-interactively.

> [!CAUTION]
> The old secret stops working immediately, and the new one is shown only once. Update every script that uses the token.

## How connections and tokens behave

These rules apply to `login`, `logout`, `whoami`, and every command that talks to a gateway.

### Tokens live in the OS credential store

Tokens are stored in the operating system credential store: macOS Keychain, Windows Credential Manager, or Linux Secret Service. Bearer tokens are never written to the CLI configuration file.

On Linux the CLI reaches the Secret Service over the D-Bus session bus, which a server with no desktop session does not have. There, any command that needs the credential store, such as `login`, `logout`, or `config remove`, fails with an error that suggests `FABRIC_HOST` and `FABRIC_TOKEN`; see [Run without a saved connection](#run-without-a-saved-connection).

If the configuration file still holds a plaintext token from an older version, the CLI can't move it into the store there either, and the error says so instead. The error names the connection whose token could not be moved and that connection's saved host, which may not be the current connection. Copy that connection's `token` value into `FABRIC_TOKEN`, set `FABRIC_HOST` to the host the error shows, and delete that `token` line from the file. If more than one connection still holds a token, the next command names the next one.

Non-secret connection metadata, such as profile names, hosts, and the current profile, stays in the user configuration directory:

| OS | Configuration file |
| --- | --- |
| macOS | `~/Library/Application Support/fabric/config.toml` |
| Linux | Normally `~/.config/fabric/config.toml` |
| Windows | `%APPDATA%\fabric\config.toml` |

A configuration from an older version that still holds plaintext tokens is migrated to the OS credential store and scrubbed on the next command that may use the store. A command given both a host and a token never opens the store, so it leaves the file as it is; `login`, `logout`, and `config` always migrate.

<details>
<summary>How credential-store entries are named</summary>

- Credentials use the `affinidi-trust-fabric-cli` service name, with the connection profile name as the account key.
- The host a token was issued for is kept beside it under `<name>#bound-host`, so connection names can't contain `#`.
- A configuration that already has such a name prints a warning once per run of the CLI (once per interactive shell session).
- If the host can't be saved on first use, the CLI warns, also once per connection, that the token keeps following `config.toml`.

</details>

### A saved token only goes to its own host

A saved token is only sent to the host it was saved for. `--host` with a different host is refused unless you pass `--allow-host-override`.

- `--allow-host-override` is a flag only. No environment variable turns it on, so a project file can't.
- A token you pass yourself with `--token` goes where you point it.
- A token saved by an older version has no recorded host, so it is bound to the host in the configuration the first time it is used.

> [!NOTE]
> When both `FABRIC_TOKEN` and `FABRIC_HOST` come from the environment, the CLI prints one note on standard error naming the host. Otherwise a `FABRIC_HOST` set by a project file would receive a `FABRIC_TOKEN` from your shell profile without a word. A typed `--token` or `--host`, or a host from the saved connection, prints no note.

### `--host` and `--token` last for one command

The global `--host` and `--token` options, and `FABRIC_HOST` and `FABRIC_TOKEN`, apply to a single command and are never saved.

- With a saved connection selected, by `--connection`, `FABRIC_CONNECTION`, or the current connection, they override that connection's host or token for this command. A command given both never opens the OS credential store.
- With no saved connection selected, a command needs both of them, as described below. With only one, it fails with `no gateway connection configured`, which says to run `login` or set both.

### Run without a saved connection

With no saved connection selected, a command given both a host and a token sends that token to that host and never opens the OS credential store. This is how to use the CLI on a Linux server with no desktop session, in a container, or in CI, without running `login`:

```sh
export FABRIC_HOST=https://gateway.example.com
export FABRIC_TOKEN="$PAT"
fabric agent-gateway whoami
fabric agent-gateway surfaces list --output json
```

- `whoami` shows no `connection` line, because none is used.
- `--connection` (or `FABRIC_CONNECTION`) naming a connection that isn't saved still fails, so a typo can't send the token somewhere unexpected.
- `login`, `logout`, and `config` work on saved connections, so they still need the credential store.
- The usual host checks apply: plain `http://` to a host other than this machine needs `--allow-http`, and the CLI prints a note naming the host when both values come from the environment.

### Keep tokens out of shell history

Prefer `FABRIC_TOKEN`, `--token-stdin` (on `login`), or a prompt over typing a secret on the command line, where shell history keeps it. The CLI warns when you type one.

```sh
printf '%s' "$TOKEN" | fabric agent-gateway login --host https://gateway.example.com --token-stdin
FABRIC_TOKEN="$TOKEN" fabric agent-gateway --host https://gateway.example.com surfaces list --output json
```

### Sessions stay alive while you use them

Gateway sessions use a **sliding expiration**: every authenticated CLI call extends the session by the gateway's idle-timeout window. An actively used connection keeps working without re-authenticating.

There is no separate refresh token. Once the session has been idle past the timeout, run `login` again under the same connection name. Use [`whoami`](#check-who-you-are-signed-in-as) to check whether the stored token is still valid.

### Requests time out and stay on one host

- Every request waits at most 10 seconds to connect and gives up when no data arrives for 120 seconds.
- Every call except `logs download` also ends after 5 minutes in total, so a gateway that sends one byte at a time can't hold the CLI. The log archive is only held to the 120 second limit, so a large download that keeps arriving isn't cut off.
- Redirects are followed only within the same scheme, host, and port, so the token never goes to another host. The browser login's code exchange follows the same rules.
- A plain `http://` host other than this machine, typed with `--host` or set in `FABRIC_HOST` (including on `login`), is refused unless you pass `--allow-http`, because the token would be sent unencrypted. With `--allow-http` the CLI warns on standard error. `--allow-http` is a flag only, with no environment variable.
- A saved connection that uses plain `http` to a remote host prints a warning once per host in a run.

## Related

- [Scripting and output](SCRIPTING_AND_OUTPUT.md): environment variables, JSON output, and exit codes
- [Identity and access](IDENTITY_AND_ACCESS.md): users, API keys, and tenant ownership
- [Interactive shell](INTERACTIVE_SHELL.md): shell defaults for a connection
