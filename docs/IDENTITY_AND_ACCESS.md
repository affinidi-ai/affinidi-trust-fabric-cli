# Identity and access

Manage users, did:webvh identities, API keys, tenant ownership, and JWT verification strategies.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`users list` / `get`](#read-users) | List users, or show one |
| [`users update <user-id> --file <json>`](#update-a-user) | Change some of a user's fields |
| [`users delete <user-id>`](#delete-a-user) | Delete a user |
| [`identities list` / `get` / `history`](#read-identities) | List identities, show one, or show its history |
| [`identities create`](#create-an-identity) | Create a did:webvh identity |
| [`identities update <id> --file <json>`](#update-an-identity) | Update an identity's DID document |
| [`identities rotate-keys <id>`](#rotate-an-identitys-keys) | Replace an identity's key pair |
| [`identities transfer <id> --file <json>`](#transfer-an-identity) | Hand an identity to a new controller |
| [`identities trust-policy get` / `set`](#read-or-set-an-identitys-trust-policy) | Read or write an identity's trust-score policy |
| [`identities deactivate <id>`](#deactivate-an-identity) | Deactivate an identity, keeping its record |
| [`api-keys list` / `get`](#read-api-keys) | List API keys, or show one key's metadata |
| [`api-keys create <surface-id>`](#create-an-api-key) | Create an API key for an Agent Surface |
| [`api-keys revoke` / `rotate` / `delete <key-id>`](#revoke-rotate-or-delete-an-api-key) | Revoke, rotate, or delete a key |
| [`tenant-ownership impact <kind> <id>`](#check-the-impact-of-a-reassignment) | Report what reassigning a resource would cross |
| [`tenant-ownership set <kind> <id>`](#reassign-or-clear-tenant-ownership) | Assign a resource to a tenant, or clear its ownership |
| [`jwt-verification-strategies list` / `get` / `create` / `update` / `delete`](#manage-strategies) | Manage JWT verification strategies |
| [`jwt-verification-strategies validate-jwks-uri <uri>`](#validate-a-jwks-uri) | Check that a URI serves a parseable key set |

All commands start with `fabric agent-gateway`. Every `--file` on this page is a request document, not the entity it acts on: see [Request documents](#request-documents) for the keys each one takes.

Good to know:

- Each of these groups has its own command, because none of them is plain CRUD.
- Their deletes print one line in table mode.
- `--output json` prints the gateway's own answer, which is `null` for the empty body most of them return.

## Users

Users are created by passkey or SAML registration, so there is no `fabric agent-gateway users create`.

### Read users

```sh
fabric agent-gateway users list
fabric agent-gateway users get <user-id>
```

`list` prints `USERNAME  ID  ROLE  STATUS  EMAIL`. Address a user by the UUID that `list` prints, not by username.

> [!NOTE]
> `integrations` is a separate route under the same prefix. `fabric agent-gateway users get integrations` returns the integration assignments, not a user.

### Update a user

```sh
fabric agent-gateway users update <user-id> --file user.json
```

`update` changes only the fields the document contains. See [Request documents](#request-documents) for the accepted keys.

> [!CAUTION]
> **`update` refuses the id `integrations`.** That path answers PUT by replacing the whole user-integration configuration, so any document sent there would clear every assignment and still report success. To rewrite the assignments deliberately, use `fabric agent-gateway api put /v1/users/integrations --file <file>`.

### Delete a user

```sh
fabric agent-gateway users delete <user-id>
```

## Identities

Identities are did:webvh identities, each with a stored key pair.

### Read identities

```sh
fabric agent-gateway identities list
fabric agent-gateway identities get <id>
fabric agent-gateway identities get <id> --reveal
fabric agent-gateway identities history <id>
```

`list` prints `DID  ID  VERSION  ACTIVE  UPDATED`, and `--output json` prints the list of identities without the gateway's `count` wrapper. `get` returns the whole record.

Good to know:

- `get` returns the identity's stored key pair, private key included, so the CLI drops `key_pair` from the output unless you pass `--reveal`.
- `create`, `rotate-keys`, and `history` carry public key material only, and `list` carries no key material.

### Create an identity

```sh
fabric agent-gateway identities create
fabric agent-gateway identities create --file identity.json
```

Without `--file`, the gateway generates the key pair. To supply your own, put it under `key_pair` in the document (see [Key pairs](#key-pairs)).

> [!WARNING]
> **Keep a supplied key pair inside its `key_pair` wrapper.** The CLI refuses a document with the key pair outside it, and prints a template of the document to send, with placeholder Ed25519 JWKs. See [Request documents](#request-documents) for why.

### Update an identity

```sh
fabric agent-gateway identities update <id> --file identity-update.json
```

The document requires `did_document`. See [Request documents](#request-documents).

### Rotate an identity's keys

```sh
fabric agent-gateway identities rotate-keys <id>
fabric agent-gateway identities rotate-keys <id> --file rotate-keys.json
```

Without `--file`, the gateway generates the new key pair. To supply your own, wrap it as `{"new_key_pair": {…}}` (see [Key pairs](#key-pairs)).

> [!WARNING]
> **Keep a supplied key pair inside its `new_key_pair` wrapper.** The CLI refuses a document with the key pair outside it, and prints a template of the document to send, with placeholder Ed25519 JWKs.

### Transfer an identity

```sh
fabric agent-gateway identities transfer <id> --file transfer.json
```

The document requires `new_controller` and `current_owner_authorization`. See [Request documents](#request-documents).

### Read or set an identity's trust policy

```sh
fabric agent-gateway identities trust-policy get <id> --output json > trust-policy.json
fabric agent-gateway identities trust-policy set <id> --file trust-policy.json
```

`identities trust-policy` reads and writes a per-identity trust-score policy: a minimum trust score (0.0 to 1.0) and, for each of five components, a threshold, a weight, and whether it is required. `set` takes the policy wrapped the same way `get` returns it, so the output of `trust-policy get <id> --output json` is the document to edit and send back.

Good to know:

- `set` refuses a bare policy before anything is sent.
- `get` answers with the gateway's built-in defaults for an identity that has never had a policy set, so a result does not prove one was configured.

> [!NOTE]
> **Nothing in the gateway applies a trust-score policy.** The gateway stores it in the identity's metadata and hands it back on request. It is unrelated to `fabric agent-gateway policies`, which manages the Rego policy definitions the gateway enforces on traffic.

### Deactivate an identity

```sh
fabric agent-gateway identities deactivate <id>
```

`deactivate` is the delete route. It appends a deactivation entry to the DID log, clears the identity's active flag, and keeps the record, which stays readable afterwards. A deactivated identity cannot be updated, rotated, transferred, or deactivated again.

## API keys

An API key belongs to an Agent Surface.

### Read API keys

```sh
fabric agent-gateway api-keys list
fabric agent-gateway api-keys list --agent-id <surface-id>
fabric agent-gateway api-keys get <key-id>
```

`list` prints `KEY ID  SURFACE  CLIENT ID  STATUS`, for every surface or, with `--agent-id`, for one. `get` returns the key's metadata; the secret is never returned. See [How API keys are addressed](#how-api-keys-are-addressed) for how `get` finds the key.

### Create an API key

```sh
fabric agent-gateway api-keys create <surface-id> --client-id billing --label team=payments
fabric agent-gateway api-keys create <surface-id> --file api-key.json
SECRET=$(fabric agent-gateway api-keys create <surface-id> --client-id billing)
```

| Flag | Meaning |
| --- | --- |
| `<surface-id>` | ID of the Agent Surface the key belongs to. A surface name is not accepted. A new key has no ID to look up, so the surface is a positional here |
| `--client-id` | External client identifier the key is issued to. Required unless you use `--file` |
| `--label` | A label as `name=value`, both non-empty. Repeat for more |
| `--file` | A document `{client_id, labels?}`. The other flags are ignored |

| Output | Where |
| --- | --- |
| The secret, alone | Standard output (table mode) |
| `Created API key '<key-id>'` and the same `note:` that tokens use | Standard error |
| The whole response | Standard output, with `--output json` |

> [!IMPORTANT]
> **The secret is shown only once.** The gateway keeps only a hash and will never show it again. Capture it as it is printed.

Good to know:

- A key cannot be edited after creation. To change its `client_id` or labels, create a new key and revoke or delete the old one.

### Revoke, rotate, or delete an API key

```sh
fabric agent-gateway api-keys rotate <key-id> --yes
fabric agent-gateway api-keys revoke <key-id> --actor ops-team --yes
fabric agent-gateway api-keys delete <key-id> --agent-id <surface-id> --yes
```

| Command | Effect |
| --- | --- |
| `revoke` | Revokes the key without removing its record |
| `rotate` | Replaces the key's secret in place, keeping the key ID, `client_id`, and labels |
| `delete` | Deletes the key |

| Flag | Meaning |
| --- | --- |
| `--agent-id` | The key's Agent Surface ID. Skips the surface lookup (see [How API keys are addressed](#how-api-keys-are-addressed)) |
| `--actor` | `revoke` and `rotate` only. The name the gateway logs for the change. `rotate` also stores it as the key's `issuer.actor`. Defaults to `api` |
| `--yes`, `-y` | Skip the confirmation prompt. Required when standard input is not a terminal |

Each command asks on standard error, with its own verb, and acts only on `y` or `yes`:

```text
Revoke API key '<name>' (<id>) on <host> of Agent Surface <surface>? [y/N]
```

The quoted name is the key's `client_id`. `rotate` adds that the current secret stops working immediately.

Good to know:

- When standard input is not a terminal, the prompt could never be answered, so the command without `--yes` fails before the key lookup and sends nothing.
- `rotate` returns a new secret, shown only once, exactly as `create` does: the secret alone on standard output, and `Rotated API key '<key-id>'` with the `note:` on standard error.
- The gateway refuses to rotate a key that has already been revoked. Replace a revoked key with a new one.

### How API keys are addressed

`get`, `revoke`, `rotate`, and `delete` take the key's own ID. The gateway addresses a key by its Agent Surface and then its ID, so the CLI reads `GET /v1/api-keys` first and takes the surface from the key's own record.

`--agent-id` names the surface and skips that lookup. You need it when the token carries `api_keys.edit` or `api_keys.delete` but not `api_keys.view`: the key's own route is open to that token, but the collection is not.

<details>
<summary>Unknown and duplicate key IDs</summary>

- A key ID that no visible surface carries is reported as not found.
- A key ID on two surfaces is refused by name rather than guessed at. The gateway generates key IDs at random and does not enforce their uniqueness.

</details>

## Tenant ownership

### Check the impact of a reassignment

```sh
fabric agent-gateway tenant-ownership impact surfaces <surface-id>
```

`impact` reports the references a reassignment would cross. A reassignment the gateway blocks comes back as a conflict from `set`, and `impact` lists the references behind it.

### Reassign or clear tenant ownership

```sh
fabric agent-gateway tenant-ownership set surfaces <surface-id> --tenant acme
fabric agent-gateway tenant-ownership set surfaces <surface-id> --clear
```

| Flag | Meaning |
| --- | --- |
| `--tenant` | Tenant to assign the resource to |
| `--clear` | Clear tenant ownership, making the resource globally owned. Can't be combined with `--tenant` |

> [!IMPORTANT]
> **Pass `--tenant` or `--clear`.** The gateway reads a request with no tenant in it as a request to clear ownership, so `--clear` has to be given outright. `set` with neither flag fails before anything is sent.

Good to know:

- The resource kind is a fixed list that `--help` prints.
- `api-keys` and `connection-points` appear in that list but are rejected, because their ownership follows their parent resource.

<details>
<summary>All resource kinds</summary>

`secrets`, `certificates`, `api-keys`, `surfaces`, `gateways`, `connection-points`, `mediators`, `mcp-proxies`, `a2a-proxies`, `trust-registries`, `issuers`, `authorities`, `integrations`, `policy-definitions`, `surface-templates`, `credential-providers`, `jwt-verification-strategies`, `sts-clients`.

</details>

## JWT verification strategies

### Manage strategies

```sh
fabric agent-gateway jwt-verification-strategies list
fabric agent-gateway jwt-verification-strategies get <id>
fabric agent-gateway jwt-verification-strategies create --file strategy.json
fabric agent-gateway jwt-verification-strategies update <id> --file strategy.json
fabric agent-gateway jwt-verification-strategies delete <id>
```

`list` prints `NAME  ID  ISSUER  UPDATED`. `update` replaces the strategy's `name`, `expected_issuer`, and `jwks_source`, so it takes the same document as `create`. It ignores `tenant_id` and keeps the strategy's current tenant: use `tenant-ownership set jwt-verification-strategies <id>` to change it. For the document and its `jwks_source` examples, see [Request documents](#request-documents).

### Validate a JWKS URI

```sh
fabric agent-gateway jwt-verification-strategies validate-jwks-uri https://idp.example.com/.well-known/jwks.json
```

`validate-jwks-uri` fetches the URI and reports whether it serves a parseable key set. A URI that cannot be reached or parsed is a non-zero exit carrying the gateway's reason.

## Request documents

Each `--file` on this page carries the handler's request body, which is not the same document the matching `get` returns. The required and optional top-level keys are:

| Command | Required | Optional |
| --- | --- | --- |
| `users update` | none | `role`, `status`, `first_name`, `last_name`, `email`, `department`, `job_title` |
| `identities create` | none | `did_path`, `metadata`, `key_pair` |
| `identities update` | `did_document` | `update_keys`, `ttl` |
| `identities rotate-keys` | none (the CLI requires `new_key_pair` when you pass `--file`) | `new_key_pair` |
| `identities transfer` | `new_controller`, `current_owner_authorization` | `new_owner_authorization`, `new_ownership_proof`, `transfer_reason` |
| `identities trust-policy set` | `config` | none |
| `api-keys create` | `client_id` | `labels` |
| `jwt-verification-strategies create` | `name`, `expected_issuer`, `jwks_source` | `tenant_id` |
| `jwt-verification-strategies update` | `name`, `expected_issuer`, `jwks_source` | none (`tenant_id` is ignored) |

The gateway rejects a document missing a required key with a 422 naming it, before anything is written.

### Key pairs

A key pair is:

```text
{"public_key": <JWK>, "private_key": <JWK>, "key_type": "Ed25519"}
```

`identities create` takes it under `key_pair`, and `identities rotate-keys` takes it wrapped as `{"new_key_pair": {…}}`. Both keys must be JWKs: a PEM `private_key` reaches the gateway's JWK parser and comes back as a 500.

> [!CAUTION]
> **A key pair outside its wrapper is silently replaced.** `identities create` and `identities rotate-keys` have no required key at the gateway, so an unwrapped key pair is not a 422 there. The gateway reads it as no key pair at all, generates and installs one of its own, and reports success (201 for `create`, 200 for `rotate-keys`). You would be left holding a private key that does not control the DID. The CLI refuses both documents itself and prints a template of the wrapped document to send, with placeholder Ed25519 JWKs.

### Trust policies

`identities trust-policy set` takes the policy wrapped the same way the response carries it, and refuses a bare policy before anything is sent. `trust-policy get <id> --output json` produces the document to edit and send back (see [Read or set an identity's trust policy](#read-or-set-an-identitys-trust-policy)).

### JWKS sources

`jwks_source` is tagged by a `type` field and carries the keys for that type.

A remote key set, fetched from a URI:

```json
{
  "name": "Partner IdP",
  "expected_issuer": "https://idp.example.com/",
  "jwks_source": {"type": "remote", "jwks_uri": "https://idp.example.com/.well-known/jwks.json"}
}
```

A static key set, pinned in the document:

```json
{
  "name": "Pinned keys",
  "expected_issuer": "https://idp.example.com/",
  "jwks_source": {"type": "static", "jwks": [{"kty": "RSA", "kid": "2026-09", "n": "…", "e": "AQAB"}]}
}
```

## Related

- [Authentication](AUTHENTICATION.md): personal access tokens for the CLI itself
- [Agent Surfaces](SURFACES.md): the surfaces API keys belong to
- [Secrets and credentials](SECRETS_AND_CREDENTIALS.md): credential grants and certificates
