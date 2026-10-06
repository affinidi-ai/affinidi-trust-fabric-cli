# Secrets and credentials

Store secrets and TLS certificates, and inspect or revoke the credential grants users have delegated to agents.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`secrets create`](#create-a-secret) | Create a secret from flags or a JSON document |
| [`secrets list [--tag <tag>]`](#read-secrets) | List secrets. Values are never included |
| [`secrets get <secret>`](#read-secrets) | Show one secret, with its value masked |
| [`secrets update <secret> --file <json>`](#update-a-secret) | Change a secret's details or value |
| [`secrets delete <secret>`](#delete-a-secret) | Delete a secret |
| [`certificates list` / `get` / `create` / `update` / `delete`](#certificates) | The same operations for TLS certificates |
| [`delegation-vault list` / `get`](#delegated-credential-grants) | Inspect delegated credential grants |
| [`delegation-vault revoke <id>`](#delegated-credential-grants) | Revoke one grant |
| [`delegation-vault revoke-user <hash>`](#delegated-credential-grants) | Revoke every grant held for one user |

All commands start with `fabric agent-gateway`. Secrets and certificates share some behaviour, such as masking and lookup by name: see [How secrets and certificates behave](#how-secrets-and-certificates-behave).

## Secrets

### Create a secret

```sh
# Value from a file or pipe (recommended: keeps it out of shell history)
fabric agent-gateway secrets create --name "Stripe live" --secret-id stripe-live --value-stdin < key.pem

# Value and metadata from flags
fabric agent-gateway secrets create --name "Stripe live" --secret-id stripe-live --value "$STRIPE_KEY" \
  --description "Billing API key" --type ApiKey --tag billing

# A complete JSON document, from a file or standard input
fabric agent-gateway secrets create --file secret.json
printf '{"name":"Stripe live","secret_id":"stripe-live","value":"%s"}' "$STRIPE_KEY" |
  fabric agent-gateway secrets create --file -
```

| Flag | Meaning |
| --- | --- |
| `--name` | Human-readable name |
| `--secret-id` | Machine-readable name that `$SECRET:<secret-id>` references use elsewhere in the gateway configuration. Must be unique, and can't be changed later |
| `--value` / `--value-stdin` | The secret value. One of them is required unless you use `--file` |
| `--description` | What the secret is for |
| `--type` | Secret type. Defaults to `General`. The gateway doesn't check it when it resolves a secret, but the dashboard filters on it: its caller-authentication picker, for example, only offers secrets typed `ApiKey` |
| `--tag` | A tag to attach; repeat for more |
| `--file` | A complete creation document (`-` reads standard input). The other flags are ignored |

Good to know:

- The gateway stores the value **exactly as sent**. `--value` and `--file` send it unchanged, so a trailing newline that matters in a PEM block or signing key survives.
- `--value-stdin` strips only the single line ending a shell pipeline appends, so it also removes a file's final newline.
- The gateway also assigns each secret a UUID `id`, separate from `secret_id`. `list --output json` shows both.

### Read secrets

```sh
fabric agent-gateway secrets list --tag billing
fabric agent-gateway secrets get stripe-live            # value masked
fabric agent-gateway secrets get stripe-live --reveal   # value shown
```

The value is masked unless you pass `--reveal` (see [Values are masked in output](#values-are-masked-in-output)). You can name a secret by its `id`, its `secret_id`, or its name (see [Refer to a record by name](#refer-to-a-record-by-name)).

### Update a secret

`secrets update` sends a JSON document to the gateway. Fields you leave out are kept, except `description` (see below):

```sh
printf '{"value":"%s","update_value":true,"description":"Billing API key"}' "$NEW_KEY" |
  fabric agent-gateway secrets update stripe-live --file -
```

> [!WARNING]
>
> - **Set `update_value: true` to change the value.** The gateway ignores `value` without it and still reports success, so the CLI refuses a document that sets `value` without an `update_value` key.
> - **Restate `description`.** The gateway replaces it with whatever the document carries, so leaving it out clears the stored description, even when you only meant to rotate the value.

### Delete a secret

```sh
fabric agent-gateway secrets delete "Stripe live"
```

> [!CAUTION]
> The secret is deleted as soon as the command runs. There is no confirmation prompt.

Table output confirms the deletion in one line. `--output json` prints what the gateway returned, which is `null` for an empty answer.

## Certificates

Certificates use the shared CRUD commands. The JSON document carries the PEM content as a string:

```sh
fabric agent-gateway certificates list
fabric agent-gateway certificates get "Edge TLS" --reveal
fabric agent-gateway certificates create --file certificate.json
fabric agent-gateway certificates update <id> --file certificate.json
fabric agent-gateway certificates delete <id>
```

Good to know:

- `get`, `create`, and `update` mask the private key unless you pass `--reveal`. See [Values are masked in output](#values-are-masked-in-output).
- `expires_at` must be a complete RFC 3339 timestamp, such as `2027-01-01T00:00:00Z`. A bare date is rejected.
- Name a certificate by its `id` or its name (see [Refer to a record by name](#refer-to-a-record-by-name)). The `certificate_id` field in the response is a second UUID the gateway never looks certificates up by, so the CLI doesn't match it either.
- `delete` runs immediately, with no confirmation prompt.

## Delegated credential grants

`delegation-vault` reads and revokes the credential grants users have delegated to agents. There is no create or update: the gateway creates grants itself, when a user completes the provider's OAuth flow in a browser, or when it caches a client-credentials token for a provider.

```sh
fabric agent-gateway delegation-vault list
fabric agent-gateway delegation-vault get <id>
fabric agent-gateway delegation-vault revoke <id>
fabric agent-gateway delegation-vault revoke-user sha256:<hex>
```

| Command | Table output | `--output json` |
| --- | --- | --- |
| `list` | `ID  AGENT DID  PROVIDER  EXPIRES  EXPIRED` | Full records, including the user hash, scopes, and token type |
| `revoke <id>` | A confirmation line | `null` |
| `revoke-user <hash>` | `Revoked N grants for user '<hash>'` | `{"revoked": N}` |

Good to know:

- `revoke-user` takes a **user identity hash**, not a grant ID, and revokes every grant held for that user.
- Revoking needs the `delegation_vault.delete` permission (administrators by default), through a session token or an appliance-wide personal access token. A token created with `--resource-pattern` can list grants but never revoke one, because pattern scoping doesn't cover the delegation vault.
- Revokes run immediately, with no confirmation prompt.

## How secrets and certificates behave

These rules apply to both the `secrets` and `certificates` commands.

### Values are masked in output

Secret values and certificate private keys are masked in the output of `get`, `create`, and `update`. Pass `--reveal` to print them.

> [!IMPORTANT]
> **Never send a masked document back.** The mask is a real string, so it would be stored as the credential. The CLI refuses any request body that still contains it, whether from `--file` or from `fabric agent-gateway api --data`. Either re-read the record with `--reveal`, or remove the masked field to keep the stored credential.

Masking applies to the `secrets` and `certificates` commands only. The raw `fabric agent-gateway api` command prints whatever the gateway returns.

### Refer to a record by name

`get`, `update`, and `delete` accept what `list` shows, not just the `id`:

| Resource | Accepted names |
| --- | --- |
| Secret | `id`, `secret_id`, or name |
| Certificate | `id` or name |

```sh
fabric agent-gateway secrets get stripe-live
fabric agent-gateway secrets delete "Stripe live"
fabric agent-gateway certificates get "Edge TLS" --reveal
```

- An exact `id` always wins, even if another record uses the same text as its name or `secret_id`.
- A name that matches nothing is reported as not found.
- A name that matches more than one record is refused, with each candidate's `id`. Pass one of those instead.

<details>
<summary>How the lookup works, and what happens without view permission</summary>

The CLI lists the collection and calls the gateway with the `id` of the one record the argument names. Names aren't unique, and one secret's name can equal another's `secret_id`, so every name field is compared at once.

The lookup needs the view permission, `secrets.view` or `certificates.view`. Without it, for example with a personal access token scoped to `secrets.delete` alone:

- `get` fails whatever you pass, because reading one record needs the same permission as listing.
- `update` and `delete` work only with the `id`. The CLI sends the UUID straight to the record's route, which checks the permission for that action. An unknown UUID gets a not-found error: `404` for certificates, or `400` with the message `Secret not found` for secrets.
- A name or `secret_id` is refused with the gateway's reason and a pointer to use the `id`.

</details>

### Tenant ownership

Neither `secrets` nor `certificates` has a `--tenant-id` flag. A `tenant_id` in a `--file` document is sent to the gateway, which applies these rules:

- A session token may set `tenant_id`.

- An appliance-wide personal access token is refused with `403` if it tries to assign tenant ownership.
- A tenant-scoped token can only create records inside its own tenant.

## Related

- [Agent Surfaces](SURFACES.md): where secrets are referenced
- [Identity and access](IDENTITY_AND_ACCESS.md): API keys and identities
- [Scripting and output](SCRIPTING_AND_OUTPUT.md): masking, redaction, and JSON output
