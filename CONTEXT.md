# Affinidi Trust Fabric CLI

The Affinidi Trust Fabric CLI, `fabric`, is the command-line client for managing Affinidi Trust Fabric appliances, starting with Agent Gateway. It calls an appliance's management API on behalf of a signed-in user or a personal access token.

This document is the project glossary: the terms used in the CLI's commands, help text, source, and documentation. Gateway concepts are defined once, in the [Agent Gateway glossary](https://github.com/affinidi-ai/agent-gateway/blob/main/CONTEXT.md). This page repeats only what a CLI user needs and adds the terms that belong to the CLI itself.

## Command structure

| Term | Meaning |
| --- | --- |
| **Appliance** | A Trust Fabric product the CLI manages. Commands take the shape `fabric <appliance> <command>`. Release builds have one appliance, Agent Gateway, under `agent-gateway`. |
| **Agent Stream** | The second appliance, under `agent-stream`. It exists only in builds with the `agent-stream` Cargo feature, which releases leave out. |
| **Command group** | The second word of a command, such as `surfaces` or `secrets`, naming the kind of resource or area it works on. |
| **Shared CRUD commands** | The `list`, `get`, `create`, `update`, and `delete` commands that several groups share, such as `issuers`, `mediators`, and `connections`. `update` sends a JSON document; depending on the resource, the gateway replaces the whole record or changes only the fields sent (see [Manage other resources](docs/SCRIPTING_AND_OUTPUT.md#manage-other-resources)). |
| **Interactive shell** | `fabric agent-gateway shell`, which reads Agent Gateway commands without the `fabric agent-gateway` prefix and parses them exactly as one-shot commands. Builds with the `agent-stream` feature also have `fabric agent-stream shell`, which does the same for Agent Stream commands. |

## Connections and credentials

| Term | Meaning |
| --- | --- |
| **Connection** (_connection profile_) | An appliance host saved on this machine under a name, with its token in the OS credential store. Agent Gateway connections live in `config.toml` and the credential-store service `affinidi-trust-fabric-cli`. Agent Stream connections (only in builds with the `agent-stream` feature) live in `agent-stream.toml` and the service `affinidi-trust-fabric-cli/agent-stream`, so each product has its own names. Selected with `--connection`; Agent Gateway also reads `FABRIC_CONNECTION`, and Agent Stream reads no environment variable for it. Managed with `login`, `logout`, and `config` for each product. _Not the same as a gateway connection or a Trust Fabric connection, below._ |
| **Product** | The appliance a token or host belongs to. In builds with the `agent-stream` feature, the wrong-product check stops a command before it sends a token when the token's prefix (`agpat_` for Agent Gateway; `aspat_` or `atgpat_` for Agent Stream) shows the other product, or when the host shows it in its answer to an anonymous probe. The host is probed when it was typed, or when a typed token has neither prefix, and `logout` sends nothing for a saved Agent Stream token. Release builds have no such check. |
| **Current connection** | The connection commands use when none is named. `login` makes the connection it saves current, and `config use` changes it. |
| **Bound host** | The host a saved token was issued for. The CLI sends a saved token only to its bound host, unless `--allow-host-override` is passed. |
| **Session token** | The token a browser login captures. It expires after the gateway's idle timeout and is renewed by use. An Agent Stream session token is pasted from a signed-in browser, since `fabric agent-stream login` has no browser sign-in, and ends after a while without use, and by default 12 hours after sign-in. |
| **Personal access token** (_PAT_) | A long-lived token starting with `agpat_`, for scripts and CI. Its authority is the user's role, narrowed by the token's scopes. Managed with `fabric agent-gateway tokens`. |
| **Agent Stream access token** | A long-lived token starting with `aspat_` (or the older `atgpat_`), for scripts and CI against an Agent Stream. Its authority is the user's role, narrowed by the token's scopes. Managed with `fabric agent-stream tokens`; `fabric agent-stream logout` removes only the local copy, so the token stays valid until it is revoked. Only in builds with the `agent-stream` feature. |
| **Tenant** (Agent Stream) | The owner an Agent Stream records on a resource, named by 1 to 128 letters, digits, `.`, `_`, `:`, or `-`, or no tenant at all. A create from a session login names it with `tenant_id`. `fabric agent-stream tenant-ownership impact` shows it and `tenant-ownership set` changes it. |
| **Tenant-limited access token** (Agent Stream) | An Agent Stream access token limited to one tenant. Its creates always use its own tenant and it refuses another. It reads only its own tenant's resources, apart from appliance-wide policy definitions and prompts, which belong to no tenant and which every caller can read. It cannot change or delete a resource that belongs to no tenant, and it cannot reassign ownership. An appliance-wide access token is not limited to a tenant, and refuses `tenant_id` on a create. |
| **System-owned resource** (Agent Stream) | A resource Agent Stream will not move to another tenant. `tenant-ownership impact` reports it as `immutable`, and `tenant-ownership set` refuses it. |
| **Grant** (_delegated credential grant_) | The access and refresh tokens a user's OAuth consent to a credential provider leaves in the delegation vault, held for one agent (`agent_did`) and one user (`user_identity_hash`). Listed and revoked with `delegation-vault`; the CLI never prints a grant's tokens. A revoked grant comes back only when that user completes the provider's OAuth flow again. |
| **OS credential store** | The macOS Keychain, Windows Credential Manager, or Linux Secret Service, where the CLI keeps tokens. Tokens are never written to the configuration file. |
| **Gateway connection** | A gateway-to-gateway link managed with `fabric agent-gateway connections`. Unrelated to a connection profile. |

## Agent Surfaces

| Term | Meaning |
| --- | --- |
| **Agent Surface** (_surface_) | The configuration for one managed agent: one access point, one target, and zero or more transit points. Most `fabric agent-gateway surfaces` commands accept a surface's name as well as its ID. |
| **Agent Stream surface** | A surface of an Agent Stream, managed with `fabric agent-stream surfaces` (only in builds with the `agent-stream` feature): an LLM Surface, which fronts one model provider, or an IDE Surface, which offers editors one model menu. Agent Stream's API calls both kinds a _pipe_ and serves them at `/v1/pipes`; the CLI says surface, except in `tenant-ownership`, which names the kind `pipes` as Agent Stream's routes do, because its `surfaces` kind would mean a Fabric surface, which it refuses. These commands take a surface's ID only. An API key can belong to one, and `fabric agent-stream api-keys list --agent-id <surface-id>` lists its keys. In the audit log, a policy decision on an LLM Surface has the scope `pipe`, and one on an IDE Surface the scope `ide`. |
| **Fabric surface** (Agent Stream) | An Agent Stream record that serves the requests a peer appliance forwards to it over the Trust Fabric. It is not an Agent Stream surface: it is not served at `/v1/pipes`, its ID is kept apart from theirs, and `fabric agent-stream surfaces` does not manage it. An API key can belong to one, and in the audit log a policy decision on one has the scope `surface`. |
| **Policy type** (Agent Stream) | The type of an Agent Stream policy definition: `appliance` (the whole Agent Stream), `llm`, or `ide`. |
| **Agent Stream feature** | One cost or safety setting of an Agent Stream surface, such as a rate limit, cost tracking, usage limits, a prompt guard, failover, or routing rules. On Agent Stream each is a field of the surface, not a route of its own. Listed by `fabric agent-stream surfaces features`, added or replaced with `add-feature`, and removed with `remove-feature`. A setting feature is one object, replaced whole. A list feature gains one item per `add-feature`, and `remove-feature` removes one item with `--item` or the whole list with `--all`. Only in builds with the `agent-stream` Cargo feature. _Not the same as an Agent Gateway feature, below, or the `agent-stream` Cargo feature._ |
| **Switch** (Agent Stream) | A surface flag that decides whether Agent Stream uses the items of a list feature: `usage_alerts_enabled` for usage alerts and `routing_enabled` for routing rules. While it is false, Agent Stream keeps the items but ignores all of them. `add-feature` turns it on only when it is false and it adds the first item; a missing switch counts as on, as Agent Stream reads it. |
| **Surface budget** (Agent Stream) | This month's spend of an Agent Stream surface against the `monthly_budget_usd` of its cost-tracking feature, read with `fabric agent-stream surfaces budget`. Agent Stream counts it only while cost tracking is enabled with a budget above 0 and an alert threshold. |
| **Access point** | The inbound side of a surface: the route and protocol callers use to reach the managed agent. |
| **Target** | The managed-agent side of a surface: the endpoint inbound traffic is forwarded to, with its credentials and policies. Exactly one per surface. Its endpoint is set with `--target-endpoint` or in the surface document. |
| **Transit point** | An outbound route the managed agent uses to reach an external destination, known on its surface by an alias. Added with `surfaces add-transit-point`. |
| **Surface variant** | A named variation of a surface, selected by route alias. `surfaces features` notes when an enabled variant changes what the gateway serves. |
| **Feature** (Agent Gateway) | One element of a surface's configuration, such as a policy, a rate limit, or tool gating, matching the dashboard's surface builder. Listed by `surfaces features` and changed with `add-feature` and `remove-feature`. |
| **Placement** | Where on a surface a feature is set: an edge, a direction, and, for a transit point, its alias. The CLI works it out from the feature name unless the feature can go in more than one place. |
| **Edge** | The leg of a surface's traffic a placement applies to: `ap-ma` (access point to managed agent), `ma-external` (managed agent to external destinations, surface-wide), or `ma-tp` (managed agent to a transit point, and the target leg of trust-check). |
| **Tool gate** | A rule in a surface's MCP tool gating that allows or denies tools by pattern. `surfaces tool-gate-preview` evaluates gates on this machine before they are saved. |
| **Path syntax** | The dot-separated field paths `surfaces update` takes with `--set`, `--unset`, `--add`, and `--remove`, such as `access_point.rate_limit.requests`. On Agent Gateway, square brackets pick one gate or transit point; Agent Stream paths take no brackets. |
| **Dry run** | `--dry-run` on surface edits: the change is checked and the result is shown without saving. Agent Gateway checks it on this machine and on the gateway. Agent Stream has no dry run of its own, so `fabric agent-stream surfaces` checks it on this machine only. |

## Trust Fabric

| Term | Meaning |
| --- | --- |
| **Connection point** | A DIDComm endpoint, with its own DID and keys, through which an appliance exchanges messages with a peer appliance over the Trust Fabric. Managed with `fabric agent-gateway connection-points`. On Agent Stream, the connection point manages its own identity, so `fabric agent-stream identities` cannot change it. _Not the same as an access point._ |
| **Trust Fabric connection** (Agent Stream) | An Agent Stream's record of one appliance in the Trust Fabric, itself or a peer, which its API calls a gateway and serves at `/v1/gateways`. A policy can be set on it, and in the audit log a decision by that policy has the scope `gateway`. The Agent Stream counterpart of a gateway connection. _Not the same as a connection, the saved profile._ |

## Agent Stream governance and drift

Only in builds with the `agent-stream` feature. See [Governance and drift](docs/agent-stream/GOVERNANCE_AND_DRIFT.md).

| Term | Meaning |
| --- | --- |
| **Governance record** | Agent Stream's signed record of one model call on a surface that records them: its stages, metrics and attribution, and, unless the surface stores none, the prompt and the answer. Read with `fabric agent-stream governance records`, which hides the prompt content and reads one page of at most 500 records at a time. _Not the same as an audit event._ |
| **Prompt content** | The prompts and model answers that governance records and drift runs carry. The CLI replaces them with a placeholder unless one record or run is asked for with `--reveal`, and then warns on standard error. Lists never show them. |
| **Chain verification** | `governance verify`: Agent Stream checks that a surface's governance records are each unchanged and each linked to the one before. A `broken`, `truncated` or `index_mismatch` chain is a security finding, and the command exits 1 when any chain is not valid or could not be checked. |
| **Drift baseline** | A surface's pinned mean of each drift dimension over a window, which its drift is measured against. A surface has at most one; `drift baseline set` replaces it. |
| **Drift verdict** | How far each dimension's recent mean has moved from the baseline: `stable`, `warn`, `drift`, or `unknown`. Shown by `drift status`. |
| **Drift run** | One replay of a surface's captured sessions, which sends real, billed model calls and scores the answers. Started with `drift run`, which asks first and refuses while another run that replays or targets the surface is in progress. |
| **Experiment** | A drift run against another surface (a `--target` other than the surface itself) or a variant (`--variant`). It never feeds the surface's drift series or verdict. |

## Output

| Term | Meaning |
| --- | --- |
| **Table output** | The default output: one table for a list, one line for a create, update, or delete, and formatted JSON for a single record. Agent Gateway's `surfaces create` adds a short summary, and Agent Stream's `surfaces update` lists each changed field with its old and new value above its line. |
| **JSON output** | `--output json`: what the gateway or Agent Stream returned, for scripts, with masked values still masked and removed fields still left out. Agent Stream's `surfaces create --dry-run` and `surfaces update --dry-run` print a preview the CLI builds, `{dry_run, changes, after}`, and send nothing, and `surfaces update` prints the surface read back after the save. |
| **Masked value** | A secret value, private key, or similar field the CLI hides in output unless `--reveal` is passed. A masked document must not be sent back, and the CLI refuses one that is. Agent Stream's `certificates`, `identities`, and `delegation-vault` have no `--reveal`, because Agent Stream never sends a private key or a grant's tokens: an identity carries only its `public_key`, and the CLI removes a certificate's `private_key_pem` or a grant's `access_token` and `refresh_token` should one appear, and prints a `note: hid` line naming what it removed. |
| **Redaction** | Replacing credentials and personal data with `[redacted]`: always in error messages, and in audit and payment records unless `--reveal` is passed, so output can be logged safely. |

## Related

- [Agent Gateway glossary](https://github.com/affinidi-ai/agent-gateway/blob/main/CONTEXT.md): the gateway's own terms in full
- [Architecture](ARCHITECTURE.md): how the CLI is built
- [Documentation index](docs/README.md)
