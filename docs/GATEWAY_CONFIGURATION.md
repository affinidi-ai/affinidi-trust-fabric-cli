# Gateway configuration

Read and change the configuration of the gateway you are connected to: runtime configuration, appliance and personal settings, Terms of Use, and notifications.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`runtime show <view>`](#show-runtime-configuration) | Show a read-only runtime configuration view |
| [`runtime reload [--surface <id>]`](#reload-surfaces) | Reload surface configuration from its source |
| [`settings show` / `set --file <json>`](#back-up-and-change-settings) | Read or partially update the appliance-wide settings |
| [`settings reset --force`](#reset-settings-to-defaults) | Overwrite the appliance settings with the built-in defaults |
| [`user-settings show [--overrides]`](#show-your-own-settings) | Show your effective settings, or only your stored overrides |
| [`user-settings set --file <json>`](#change-your-own-overrides) | Store personal overrides |
| [`user-settings reset`](#clear-your-own-overrides) | Clear every personal override |
| [`terms show` / `applicable` / `status` / `provider-health`](#read-terms-of-use) | Read Terms of Use definitions, acceptance status, and provider health |
| [`terms draft` / `publish` / `deactivate`](#publish-terms-of-use) | Save, publish, or deactivate the customer Terms of Use |
| [`notifications welcome-template show` / `set`](#manage-the-welcome-template) | Read or replace the welcome notification template |
| [`notifications send-welcome`](#send-a-welcome-notification) | Send a welcome notification to a user |

All commands start with `fabric agent-gateway`. Some behaviour is shared across these commands, such as empty responses and the Terms flag: see [How gateway configuration commands behave](#how-gateway-configuration-commands-behave).

## Runtime configuration

`runtime` exposes the gateway's runtime configuration and triggers a reload. The `x402` view is read from its configuration file on each request; the other views reflect what the gateway loaded at startup.

### Show runtime configuration

```sh
fabric agent-gateway runtime show surface-routing
fabric agent-gateway runtime show x402
fabric agent-gateway runtime show networking
```

| View | What it shows |
| --- | --- |
| `surface-routing` | Surface routes, listen addresses, and the OAuth callback route |
| `x402` | The x402 payment policy |
| `networking` | Inbound client-certificate (mTLS) authentication |

Good to know:

- `show` writes nothing.
- `show networking` is read-only by design: mTLS is applied at startup and has no counterpart that sets it.
- `show x402` answers `500`, not `404`, on a gateway with no x402 configuration file.

### Reload surfaces

```sh
fabric agent-gateway runtime reload
fabric agent-gateway runtime reload --surface <config-id>
```

`reload` changes no configuration you set, though a full reload can persist housekeeping fixes, such as upgrading legacy `channel.policy` definitions. It re-reads the configured source and swaps surfaces in place.

Surfaces changed through this CLI or the dashboard already reload themselves. Use `reload` for configuration edited outside the gateway, such as a direct `_storage/` edit.

| Flag | Meaning |
| --- | --- |
| `--surface` | Reload one surface instead of all of them. Takes the surface id that `fabric agent-gateway surfaces list` shows |

A successful reload prints the gateway's answer: `channels_count`, `surfaces_count`, and `is_fallback` for a full reload, or the surface's `channel_name` and `is_fallback` with `--surface`, plus a `warning` when the gateway sends one.

<details>
<summary>What happens when <code>--surface</code> names an unknown id</summary>

The gateway answers a reload of an id no surface has with a `500`, not a `404`. So after a server error the CLI reads the id straight from the surfaces API (`GET /v1/surfaces/<id>`), without the name lookup `fabric agent-gateway surfaces get` does.

- When that lookup answers `404`, the CLI says the surface was not found and keeps the gateway's error underneath as the cause.
- The cause is kept because the two can disagree: with the DynamoDB configuration source, the reload reads DynamoDB while the lookup reads the gateway's own surface store.
- Any other failure keeps the gateway's own error.

</details>

## Appliance settings

`settings` manages the single appliance-wide settings document.

### Back up and change settings

```sh
fabric agent-gateway settings show --output json > settings.json
fabric agent-gateway settings set --file settings.json
```

`set` is a partial update: fields the document omits are left unchanged. `--file -` reads the document from standard input.

`set` prints the settings as read back from the gateway after the write, so its output is what the next `settings show` returns. See [Writes print the settings read back](#writes-print-the-settings-read-back).

> [!IMPORTANT]
> **Delete `terms` from `feature_flags` before sending a `show` document.** A document produced by `show` always carries `feature_flags.terms`, and `set` refuses it whatever its value. See [The Terms flag can't be set through settings](#the-terms-flag-cant-be-set-through-settings).

Three more behaviours are worth knowing before editing a document produced by `show`. The CLI warns on stderr whenever a document you send contains any of them:

> [!WARNING]
>
> - **`feature_flags` replaces the stored map** rather than merging into it, so any flag missing from the document is removed.
> - **`payments_min_display` is silently ignored.** It appears in the response but is not part of an appliance update. It is settable only per user, with `fabric agent-gateway user-settings set`.
> - **`prometheus_auth_password_hash` is blanked on every response.** To change the password, send `prometheus_auth_password`, which travels as plaintext and is hashed by the gateway.

Good to know:

- A field sent as an explicit `null` draws no warning. Every settings field is optional, and a null leaves the stored value alone.

### Reset settings to defaults

```sh
fabric agent-gateway settings reset --force
```

`reset` is not a restore of the fields nobody set. It writes the built-in defaults over the whole document and prints the result as read back from the gateway.

> [!CAUTION]
> `reset` switches off two security controls. It clears:
>
> - `prometheus_auth_enabled`, and with it `prometheus_auth_username` and the stored password hash. `/v1/metrics/prometheus` stops checking credentials from that moment.
> - `audit_enabled` and `audit_categories`. Audit logging stops without a further message.
> - every entry in `feature_flags`.
> - every window, interval, and threshold, back to its default.

Because of those security controls, `reset` refuses unless you pass `--force`, and prints what it would clear. Nothing is sent to the gateway when it refuses.

> [!WARNING]
> **A `settings show` backup does not restore the Prometheus password.** `show` blanks `prometheus_auth_password_hash`, and re-enabling Prometheus authentication from that document is refused with `400 Password is required when enabling Prometheus authentication for the first time`. Keep the plaintext password somewhere else before resetting, and send it back as `prometheus_auth_password`.

## Personal settings

`user-settings` manages the signed-in principal's own overrides. It is a separate store from `fabric agent-gateway settings`, with separate permissions. The identifier is the authenticated principal, not anything you pass.

### Show your own settings

```sh
fabric agent-gateway user-settings show
fabric agent-gateway user-settings show --overrides
```

| Command | What it returns |
| --- | --- |
| `show` | The effective document: appliance defaults merged with your overrides. A field you never set still looks set |
| `show --overrides` | Only what is actually stored against your account. This is the only view of it |

> [!IMPORTANT]
> **Use `--overrides` before building a `set` payload.** Sending a plain `show` document would persist the current value of every per-user field, and every feature flag, as a personal override, so `set` refuses it (see [Change your own overrides](#change-your-own-overrides)).

Good to know:

- The CLI drops `prometheus_auth_password_hash` from all `user-settings` output. The appliance settings route blanks that key, but the effective-settings responses (`show`, `set`, and `reset`) carry it unblanked from the appliance document, and the CLI won't print a bcrypt password hash to a terminal or a CI log.

### Change your own overrides

```sh
fabric agent-gateway user-settings set --file overrides.json
```

Every field present becomes a personal override. `--file -` reads the document from standard input.

| Flag | Meaning |
| --- | --- |
| `--file`, `-f` | The JSON document (`-` reads standard input) |
| `--force` | Submit a document carrying fields a per-user update cannot store. A document carrying `feature_flags.terms` is still refused |

`set` checks the document before sending it:

1. **`feature_flags.terms` is refused first**, before any other check, and `--force` does not override it. See [The Terms flag can't be set through settings](#the-terms-flag-cant-be-set-through-settings).
2. **Fields a per-user update cannot store are refused, by name.** Such a document can only have come from `show` without `--overrides`, and sending it would persist the current value of every per-user field, and every feature flag, as a personal override. `--force` submits it anyway, but only once `feature_flags.terms` is deleted from it, because a plain `show` document always carries that flag.

> [!NOTE]
> A single setting override cannot be cleared: omitting a field, or sending null, is indistinguishable from leaving it alone. `feature_flags` is the exception: a document carrying it replaces your stored flag overrides, so a flag missing from it is cleared. Only `reset` clears everything.

### Clear your own overrides

```sh
fabric agent-gateway user-settings reset
```

`reset` deletes this account's own override document and shows the resulting settings. It touches no appliance setting and no other account.

Good to know:

- Unlike `settings reset`, `user-settings reset` needs no `--force`.
- A `show --overrides` taken beforehand restores your overrides through `set`.
- One exception: a stored `feature_flags.terms` override is refused on restore, and it never took effect anyway. Delete it from the backup before restoring.

## Terms of Use

### Read Terms of Use

```sh
fabric agent-gateway terms show
fabric agent-gateway terms applicable
fabric agent-gateway terms status
fabric agent-gateway terms provider-health
```

| Command | What it shows |
| --- | --- |
| `show` | The Terms of Use definitions |
| `applicable` | The terms that apply to this gateway |
| `status` | Whether the signed-in principal has accepted the current terms, and what is required |
| `provider-health` | The health of the upstream terms provider |

### Publish Terms of Use

```sh
fabric agent-gateway terms draft --file terms.json
fabric agent-gateway terms publish
fabric agent-gateway terms deactivate
```

| Command | What it does |
| --- | --- |
| `draft --file <json>` | Save the customer Terms of Use draft. `-` reads standard input |
| `publish` | Publish the saved draft as a new version |
| `deactivate` | Deactivate the published customer Terms of Use. Answers `204 No Content` (see [Empty responses print a confirmation line](#empty-responses-print-a-confirmation-line)) |

The `draft` document carries `version`, `title`, and `url`, plus an optional `requires_reconsent` that defaults to `false`.

Failures carry a code the CLI explains: see [Terms errors are explained](#terms-errors-are-explained).

### Accept Terms of Use

There is no `terms accept` command, by design.

| How you signed in | How to accept |
| --- | --- |
| Personal access token | In a browser. The gateway refuses every route until terms are accepted, including the acceptance route itself, so a `terms accept` could only ever return `403` |
| Session token (the default `fabric agent-gateway login` browser flow) | Exempt on the acceptance route: `fabric agent-gateway api post /v1/terms/acceptances --file <json>` |

## Notifications

Only three verbs are offered: show and replace the welcome template, and send a welcome notification. They take no session extractor at all, so they work with either a session token or a personal access token.

### Manage the welcome template

```sh
fabric agent-gateway notifications welcome-template show
fabric agent-gateway notifications welcome-template set --file template.json
```

The `set` document carries `title` and `message`, and replaces the template every future user receives. `set` answers `204 No Content` (see [Empty responses print a confirmation line](#empty-responses-print-a-confirmation-line)).

> [!NOTE]
> `welcome-template set` changes what every future user receives, so treat it as an administrator task.

### Send a welcome notification

```sh
fabric agent-gateway notifications send-welcome --user-id <user-id> --title "Welcome" --message "Your account is ready"
```

| Flag | Meaning |
| --- | --- |
| `--user-id` | Gateway user id of the recipient |
| `--title` | Heading shown in the recipient's notification feed |
| `--message` | Body of the notification |

`send-welcome` answers `204 No Content` (see [Empty responses print a confirmation line](#empty-responses-print-a-confirmation-line)).

The gateway accepts any recipient id, so a mistyped `--user-id` would succeed and reach nobody. The CLI therefore reads the user with `GET /v1/users/<user-id>` first:

| Lookup result | What the CLI does |
| --- | --- |
| `404` | Refuses the id and sends nothing |
| `403` (other than `TERMS_ACCEPTANCE_REQUIRED`) | Warns that the recipient went unverified, and sends the notification anyway |
| User found | Sends the notification |
| Any other failure | Stops and sends nothing |

Good to know:

- Reading another user needs the `users.view` permission (administrators only by default). Sending doesn't, which is why a `403` lookup still sends.
- A lookup that finds the user is an ordinary user read. It records an `accessed` user event in the gateway's metrics and fires any integration configured for the gateway's `user.accessed` event.

<details>
<summary>Why there are no commands for your own notifications</summary>

Listing, reading, creating, updating, and deleting a user's own notifications are deliberately absent. Those gateway handlers ignore the marker the authentication middleware sets and re-validate the bearer token through the session manager. The session manager consults session storage only, never the personal access token authenticator.

**When authenticated with a personal access token**, `list` would therefore return `200 []` and exit `0` while the user has unread notifications, and the rest would return `401`. A silently empty list is worse than no command.

A session-token login (the default `fabric agent-gateway login` browser flow) can reach the omitted routes directly with `fabric agent-gateway api get /v1/notifications`.

</details>

## How gateway configuration commands behave

These rules apply across the `runtime`, `settings`, `user-settings`, `terms`, and `notifications` commands.

### These commands configure the gateway, not this machine

They read and write the configuration of the gateway you are connected to. They are distinct from `fabric agent-gateway config`, which manages local connection profiles on this machine and never contacts a gateway.

### These resources are singletons, not collections

Each resource is a singleton or a set of verbs. So they use `show`, `set`, `reset`, and `reload` rather than `list`, `get <id>`, `create`, and `delete <id>`.

### Empty responses print a confirmation line

`terms deactivate`, `notifications welcome-template set`, and `notifications send-welcome` answer `204 No Content`.

| Output mode | What is printed |
| --- | --- |
| Table | A confirmation line instead of the empty document |
| `--output json` | `null`, which is what the gateway returned and what every other command prints for an empty body |

Warnings about a request body go to stderr, so standard output stays machine-readable in either mode.

### Writes print the settings read back

`settings set` and `settings reset --force` print the settings as read back from the gateway after the write, so their output is what the next `settings show` returns.

- The write routes answer with the stored document instead, which lacks the `feature_flags.terms` that every read adds.
- If the read-back fails, the write has still happened. The command exits non-zero, says the write succeeded but reading the settings back failed, and prints no document.

### The Terms flag can't be set through settings

`settings set` and `user-settings set` refuse a document carrying `feature_flags.terms`, whatever its value, and send nothing. `--force` does not override this.

- The gateway reports that flag from its `network.terms` configuration on every read, for both the appliance and the effective per-user settings, and ignores any stored value. The write could never take effect.
- A document produced by `show` always carries it. Delete `terms` from `feature_flags` before sending.
- Terms of Use are switched on or off in the gateway's configuration, not through settings.

### Terms errors are explained

Most Terms failures carry only a machine-readable `code` (`400 TERMS_INVALID` adds a `message`, and `409 TERMS_VERSION_STALE` adds `required_terms`), so the CLI adds an explanation for the ones that are easy to misread:

| Status and code | Meaning |
| --- | --- |
| `404 TERMS_DISABLED` | The feature is switched off on that gateway, not that the route is missing |
| `409 TERMS_VERSION_STALE` | The versions submitted for acceptance are not the ones currently required, usually because the published terms changed since they were read. The response lists `required_terms`. The CLI says to re-read `terms show` and retry; the required versions are listed by `terms status` |
| `409 TERMS_DRAFT_REQUIRED` | There is no saved draft to publish. Save one with `terms draft --file <json>` first |
| `503 TERMS_OPERATIONAL_FAILURE` | The upstream terms provider is unavailable. Check `terms provider-health` |

When the signed-in user has not accepted the gateway's Terms and Conditions, the gateway answers `403 TERMS_ACCEPTANCE_REQUIRED`:

- A session token is refused on every route except `/v1/terms/applicable`, `/v1/terms/status`, `/v1/terms/acceptances`, and the auth check and logout routes, with a code-only body.
- A personal access token is refused on every authenticated route, the Terms status and acceptance routes included, with a body that also carries a `message`.

Whatever the command, the CLI then says to:

- accept the Terms in the Agent Gateway dashboard, or with `fabric agent-gateway api post /v1/terms/acceptances --file <json>` (see [Accept Terms of Use](#accept-terms-of-use)), and retry.
- run `fabric agent-gateway terms status` to list what is required. This works with a session-token login only: with a personal access token it is refused too, so accept in a browser (see [Accept Terms of Use](#accept-terms-of-use)).

## Related

- [Observability](OBSERVABILITY.md): what the audit and metrics settings control
- [Authentication](AUTHENTICATION.md): local connection profiles, managed by fabric agent-gateway config
