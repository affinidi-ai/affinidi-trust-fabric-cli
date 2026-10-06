# Affinidi Trust Fabric CLI

The Affinidi Trust Fabric CLI, `fabric`, is the command-line client for managing Affinidi Trust Fabric appliances, starting with Agent Gateway. It calls an appliance's management API on behalf of a signed-in user or a personal access token.

This document is the project glossary: the terms used in the CLI's commands, help text, source, and documentation. Gateway concepts are defined once, in the [Agent Gateway glossary](https://github.com/affinidi-ai/agent-gateway/blob/main/CONTEXT.md). This page repeats only what a CLI user needs and adds the terms that belong to the CLI itself.

## Command structure

| Term | Meaning |
| --- | --- |
| **Appliance** | A Trust Fabric product the CLI manages. Commands take the shape `fabric <appliance> <command>`. Agent Gateway, under `agent-gateway`, is the only appliance today. |
| **Command group** | The second word of a command, such as `surfaces` or `secrets`, naming the kind of resource or area it works on. |
| **Shared CRUD commands** | The `list`, `get`, `create`, `update`, and `delete` commands that several groups share, such as `issuers`, `mediators`, and `connections`. `update` replaces the whole record from a JSON document. |
| **Interactive shell** | `fabric agent-gateway shell`, which reads Agent Gateway commands without the `fabric agent-gateway` prefix and parses them exactly as one-shot commands. |

## Connections and credentials

| Term | Meaning |
| --- | --- |
| **Connection** (_connection profile_) | A gateway saved on this machine under a name: its host in the configuration file and its token in the OS credential store. Selected with `--connection` or `FABRIC_CONNECTION`, and managed with `login`, `logout`, and `config`. _Not the same as a gateway connection, below._ |
| **Current connection** | The connection commands use when none is named. `login` makes the connection it saves current, and `config use` changes it. |
| **Bound host** | The host a saved token was issued for. The CLI sends a saved token only to its bound host, unless `--allow-host-override` is passed. |
| **Session token** | The token a browser login captures. It expires after the gateway's idle timeout and is renewed by use. |
| **Personal access token** (_PAT_) | A long-lived token starting with `agpat_`, for scripts and CI. Its authority is the user's role, narrowed by the token's scopes. Managed with `fabric agent-gateway tokens`. |
| **OS credential store** | The macOS Keychain, Windows Credential Manager, or Linux Secret Service, where the CLI keeps tokens. Tokens are never written to the configuration file. |
| **Gateway connection** | A gateway-to-gateway link managed with `fabric agent-gateway connections`. Unrelated to a connection profile. |

## Agent Surfaces

| Term | Meaning |
| --- | --- |
| **Agent Surface** (_surface_) | The configuration for one managed agent: one access point, one target, and zero or more transit points. Most `surfaces` commands accept a surface's name as well as its ID. |
| **Access point** | The inbound side of a surface: the route and protocol callers use to reach the managed agent. |
| **Target** | The managed-agent side of a surface: the endpoint inbound traffic is forwarded to, with its credentials and policies. Exactly one per surface. Its endpoint is set with `--target-endpoint` or in the surface document. |
| **Transit point** | An outbound route the managed agent uses to reach an external destination, known on its surface by an alias. Added with `surfaces add-transit-point`. |
| **Surface variant** | A named variation of a surface, selected by route alias. `surfaces features` notes when an enabled variant changes what the gateway serves. |
| **Feature** | One element of a surface's configuration, such as a policy, a rate limit, or tool gating, matching the dashboard's surface builder. Listed by `surfaces features` and changed with `add-feature` and `remove-feature`. |
| **Placement** | Where on a surface a feature is set: an edge, a direction, and, for a transit point, its alias. The CLI works it out from the feature name unless the feature can go in more than one place. |
| **Edge** | The leg of a surface's traffic a placement applies to: `ap-ma` (access point to managed agent), `ma-external` (managed agent to external destinations, surface-wide), or `ma-tp` (managed agent to a transit point, and the target leg of trust-check). |
| **Tool gate** | A rule in a surface's MCP tool gating that allows or denies tools by pattern. `surfaces tool-gate-preview` evaluates gates on this machine before they are saved. |
| **Path syntax** | The dot-separated field paths `surfaces update` takes with `--set`, `--unset`, `--add`, and `--remove`, such as `access_point.rate_limit.requests`, with square brackets to pick one gate or transit point. |
| **Dry run** | `--dry-run` on surface edits: the change is checked on this machine and by the gateway, and the result is shown without saving. |

## Output

| Term | Meaning |
| --- | --- |
| **Table output** | The default output: one table for a list, one line for a create, update, or delete (`surfaces create` adds a short summary), and formatted JSON for a single record. |
| **JSON output** | `--output json`: what the gateway returned, with masked values still masked, for scripts. |
| **Masked value** | A secret value, private key, or similar field the CLI hides in output unless `--reveal` is passed. A masked document must not be sent back, and the CLI refuses one that is. |
| **Redaction** | Replacing credentials and personal data with `[redacted]`: always in error messages, and in audit and payment records unless `--reveal` is passed, so output can be logged safely. |

## Related

- [Agent Gateway glossary](https://github.com/affinidi-ai/agent-gateway/blob/main/CONTEXT.md): the gateway's own terms in full
- [Architecture](ARCHITECTURE.md): how the CLI is built
- [Documentation index](docs/README.md)
