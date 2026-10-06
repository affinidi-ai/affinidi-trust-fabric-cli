# Agent Surfaces

Create and edit Agent Surfaces, add and remove features and transit points, and preview tool gates.

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`surfaces list`](#list-and-read-surfaces) | List surfaces in a table |
| [`surfaces get <surface>`](#list-and-read-surfaces) | Show one surface's full configuration |
| [`surfaces create`](#create-a-surface) | Create a surface from flags or a JSON document |
| [`surfaces delete <surface>`](#delete-a-surface) | Delete a surface |
| [`surfaces update <surface> --file <json>`](#replace-a-surface-from-a-file) | Replace the whole surface |
| [`surfaces update <surface> --set` / `--unset`](#change-single-fields) | Change or remove single fields |
| [`surfaces update <surface> --add` / `--remove`](#add-or-remove-list-items) | Add or remove one list item |
| [`surfaces update <surface> --add 'gates[<gate>]…'`](#change-one-tool-pattern) | Add or remove one tool pattern on one gate |
| [`surfaces update <surface> … --dry-run`](#preview-an-edit-with---dry-run) | Check an edit with the gateway without saving it |
| [`surfaces features [<surface>]`](#list-features) | List the features you can add, or the ones a surface has |
| [`surfaces add-feature <surface> <feature>`](#add-a-feature) | Add a feature to a surface |
| [`surfaces remove-feature <surface> <feature>`](#remove-a-feature) | Remove a feature from a surface |
| [`surfaces add-transit-point <surface>`](#add-a-transit-point) | Add a transit point from an alias and endpoint |
| [`surfaces remove-transit-point <surface> <point>`](#remove-a-transit-point) | Remove a transit point by alias or id |
| [`surfaces tool-gate-preview`](#preview-tool-gates) | Show which tools a set of MCP tool gates would allow or deny |
| [`policies list`](#list-and-read-policies) | List policy definitions in a table |
| [`policies get <policy-id>`](#list-and-read-policies) | Show one policy definition, including its Rego source |
| [`policies create`](#create-a-policy-to-attach) | Create a policy that a surface can enforce |
| [`policies update <policy-id> --file <json>`](#replace-a-policy-from-a-file) | Replace the whole policy definition |
| [`policies impact <policy-id>`](#check-where-a-policy-is-used) | Show how many surfaces and gateways use a policy |
| [`policies delete <policy-id>`](#delete-a-policy) | Delete a policy definition |
| [`policies versions <policy-id>`](#list-a-policys-versions) | List the saved versions of a policy |

All commands start with `fabric agent-gateway`. Every surface edit follows the same rules for lookup by name, local checks, permissions, and concurrent changes: see [How surface edits behave](#how-surface-edits-behave).

## Surfaces

### List and read surfaces

```sh
fabric agent-gateway surfaces list
fabric agent-gateway surfaces get <surface-id> --output json
fabric agent-gateway surfaces get "Sales Agent"
```

`list` prints the columns `NAME  ID  PROTOCOL  ROUTE  TARGET  TRANSIT POINTS`, or `No surfaces yet.` when there are none. `get` takes the surface's ID or its name (see [A surface can be named by its ID or its name](#a-surface-can-be-named-by-its-id-or-its-name)).

### Create a surface

```sh
fabric agent-gateway surfaces create --name "Sales Agent" --description "Routes sales traffic"
fabric agent-gateway surfaces create --file surface.json
```

| Flag | Meaning |
| --- | --- |
| `--name` | Surface name. Required unless you use `--file` |
| `--description` | What the surface is for. Defaults to empty |
| `--listen-address` | Address the gateway listens on for inbound traffic. Defaults to `0.0.0.0:8080` |
| `--route` | Inbound route. Defaults to a URL-safe form of the name |
| `--protocol` | Inbound protocol: `a2a` (default), `ap2`, `mcp`, or `didcomm` |
| `--target-endpoint` | Endpoint of the agent or service the surface forwards to. Defaults to `http://127.0.0.1:3000` |
| `--tags` | Tags to attach, comma-separated or with the flag repeated |
| `--file` | A complete AgentSurface JSON document. The other flags are ignored |

Table output prints `Created surface '<id>'`, then indented lines with the surface's id, name, route, protocol, and target. The target shows only scheme, host, and port, without credentials, path, query, or fragment.

Good to know:

- Use `--output json` to receive the complete response. This is also how a script reads the new ID.
- Full JSON documents give access to the complete Gateway model, so the CLI doesn't duplicate every nested setting as a flag.

### Delete a surface

```sh
fabric agent-gateway surfaces delete <surface-id>
```

Table output confirms with `Deleted surface '<id>'`. The surface is deleted as soon as the command runs; there is no confirmation prompt.

## Edit a surface

`surfaces update` either replaces the whole surface with `--file`, or changes parts of it with `--set`, `--unset`, `--add`, and `--remove`. Every edit is [checked on your machine first](#every-edit-is-checked-on-your-machine-first).

### Replace a surface from a file

```sh
fabric agent-gateway surfaces update <surface-id> --file surface.json
```

> [!WARNING]
> **`--file` replaces the whole surface.** It can't be combined with `--set`, `--unset`, `--add`, `--remove`, or `--dry-run`.

The file gets the same local check as other edits.

### Change single fields

```sh
fabric agent-gateway surfaces update <surface-id> --set access_point.rate_limit.requests=100 --set name="Sales Agent" --unset description
fabric agent-gateway surfaces update "Sales Agent" --set access_point.rate_limit.requests=200
```

`--set <path>=<value>` changes one field and `--unset <path>` removes one. Both can be repeated. All the flags in one command go to the gateway as one JSON Merge Patch, so fields they don't name keep their current values.

Good to know:

- Setting an object merges it into the existing object rather than replacing it.
- Setting a list replaces the whole list. Use [`--add` and `--remove`](#add-or-remove-list-items) to change one item.
- `--set` and `--unset` don't accept square brackets.

### Write paths and values

| Part | Rule | Example |
| --- | --- | --- |
| Path | Dot-separated field names | `access_point.rate_limit.requests` |
| Value or item | Read as JSON when it parses and has no surrounding spaces, as plain text otherwise | `100`, `true`, `'"100"'`, `'{"requests":100}'` |
| Text that looks like JSON | Wrap it in quotes | `'"1.0"'` sends the text `1.0` |
| One tool pattern (`--add` and `--remove` only) | Name the gate in square brackets, by `id`, else name, and for a transit point's gate, the transit point by `id`, else alias. Brackets work only in a path ending `.action.patterns` | `target.mcp_tool_gating.gates[g-1].action.patterns`, `transit.points[billing].mcp_tool_gating.gates[g-1].action.patterns` |
| Item for `--remove` | A text item by its value; an object by its `id`, else its `alias`, else some of its fields as JSON | `tags=beta`, `transit.points=billing`, `outbound_credentials='{"credential_provider_id":"cp-1"}'` |

Quote a flag that contains brackets or JSON so the shell leaves it alone. `--remove` can match an object by only some of its fields because the gateway fills in defaults you never typed.

### Add or remove list items

```sh
fabric agent-gateway surfaces update <surface-id> --add tags=beta --remove transit.points=billing
```

`--add <path>=<item>` adds one item to a list and `--remove <path>=<item>` removes one. Both can be repeated. Because the gateway replaces a list whole, the CLI reads the surface first and sends its list with only your items changed.

> [!WARNING]
> A change someone else makes to the same list between that read and the write is overwritten. See [A list edit overwrites concurrent changes](#a-list-edit-overwrites-concurrent-changes).

Good to know:

- An item already in the list is refused by `--add`.
- Removes run before adds, so `--remove access_point.trust_check_list=tc-1 --add access_point.trust_check_list='{"id":"tc-1",...}'` replaces one trust check in place.
- An added object with no `id` keeps the `id` of the item it replaces.
- A transit point added with `--add transit.points` and no `protocol` takes the protocol of the surface's `access_point`, including one changed by a `--set` in the same command. On a `didcomm` surface the gateway refuses it, because a transit point can't use `didcomm`.

### Change one tool pattern

```sh
# Add one tool pattern to one gate, quoted for the shell
fabric agent-gateway surfaces update <surface-id> --add 'target.mcp_tool_gating.gates[g-1].action.patterns=fs_.*'
fabric agent-gateway surfaces update <surface-id> --remove 'transit.points[billing].mcp_tool_gating.gates[g-1].action.patterns=fs_.*'
```

Put the gate in square brackets to change one pattern without retyping the gate. `gates[g-1]` picks a gate by `id`, else name, and `transit.points[billing]` picks a transit point by `id`, else alias. The pattern is always sent as text, with surrounding spaces trimmed.

These are refused before anything is sent:

- a pattern the gateway would refuse
- a gate that doesn't exist
- adding a pattern that is already there, or removing one that isn't
- removing a gate's last pattern

> [!WARNING]
> The CLI sends the surface's whole gates list (or the whole `transit.points` list), so a change someone else makes to that list between the read and the write is overwritten.

### Preview an edit with `--dry-run`

```sh
fabric agent-gateway surfaces update <surface-id> --set access_point.route=/billing --dry-run
```

`--dry-run` checks an edit with the gateway and shows what it would change, without saving anything. It works on `update`, `add-feature`, `remove-feature`, `add-transit-point`, and `remove-transit-point`, but not with `update --file`, which replaces the whole surface.

After the [local check](#every-edit-is-checked-on-your-machine-first) passes, the CLI sends the patch as `PATCH /v1/surfaces/<surface-id>?dry_run=true`. The gateway runs every check a real edit runs and answers with the surface as it would be saved. Table output prints the patch, then each changed field as `path: before -> after`, then `Dry run: nothing was saved.`

Good to know:

- The after side includes defaults the gateway fills in.
- IDs the gateway generates for new items, such as a transit point sent without an `id`, will differ in the real save.
- A dry run needs the `surfaces.view` permission (see [Most edits need the `surfaces.view` permission](#most-edits-need-the-surfacesview-permission)).

> [!NOTE]
> Only that `PATCH` honours `dry_run`. `PUT /v1/surfaces/<surface-id>` and `PATCH /v1/surfaces/<surface-id>/variants/<variant-id>` ignore it and save.

<details>
<summary>JSON output, refused edits, and exit codes</summary>

`--output json` prints one object:

```text
{"dry_run": true, "checked": "gateway", "patch": ..., "before": ..., "after": ...}
```

| Outcome | What the CLI prints | Exit code |
| --- | --- | --- |
| The gateway refuses the edit | The gateway's error, like a real edit. A `404` means the surface was deleted or is out of your reach | 1 |
| The local check refuses the edit | The patch and the locally merged changes, then the error (`"checked": "local"` with an `error` in JSON). Nothing is sent | 1 |
| The gateway's checks couldn't run: it doesn't support a dry run, didn't answer, or failed with a server error | The locally merged surface, labelled as checked on this machine only (`"checked": "local"` with a `warning` in JSON), and a warning that the gateway checks were skipped. The real patch is never sent | 3 |

</details>

## Features

Agent Surfaces are composed from features, the same elements shown in the dashboard's surface builder.

### List features

```sh
# Everything that can be added, with its target path and placement
fabric agent-gateway surfaces features
fabric agent-gateway surfaces features --output json

# Which features one surface has, and where
fabric agent-gateway surfaces features <id-or-name>
fabric agent-gateway surfaces features <id-or-name> --output json
```

The feature names shown are the ones `add-feature` and `remove-feature` take. With a surface ID or name, the table shows each feature, whether it is `on` or `off`, where it is set, and the flags `remove-feature` needs to take it from that place. `remove with no flags` means the feature name is enough.

Good to know:

- A place with a value of `{}` counts as `on`, and an empty list as `off`.
- On or off reflects the surface itself, not what an enabled variant changes. A `Notes` section under the table flags those cases (see below).

<details>
<summary>Variant notes</summary>

When an enabled variant changes what the gateway serves, the `Notes` section says which variant and features, for example `The default variant 'blue' sets policy; this table reads only the surface itself.`

- **A complete variant** replaces each block it has in full (target, access point, identity slots, outbound credentials, and transit points when its `transit` block has `points`). It gets one note naming those blocks and any feature it sets. Every feature that can sit in those blocks is marked, on or off, because the ones it leaves out are off for the gateway.
- **A variant that isn't complete and has transit points** gets a note that transit point features may not match, on the features that can sit on a transit point, because its transit point changes aren't itemized.
- A `null` in a variant that isn't complete means it keeps the surface's value, so it isn't noted.

In JSON, the affected features get a `variant_notes` list. The JSON stays a list of features, and features with no note have no `variant_notes`.

</details>

<details>
<summary>JSON fields for one surface's features</summary>

With `--output json`, each feature has `on` and a `placements` list. Each placement has:

| Field | Meaning |
| --- | --- |
| `place` | Where the feature is set |
| `field` | The field it is set in |
| `transit_point` | The transit point's alias, or `null` |
| `index` | The transit point's position in the list, `null` when the place is not on a transit point |
| `remove_flags` | The flags `remove-feature` needs. `""` means no flags; `null` means `remove-feature` can't pick it |

</details>

### Add a feature

```sh
# Policy on the request edge (policy-ref shortcut)
fabric agent-gateway surfaces add-feature <id> policy --policy-id allow-sales --edge ap-ma

# Inbound rate limit (aliases: throttling, network.throttling)
fabric agent-gateway surfaces add-feature <id> rate-limit --json '{"requests":100,"window_secs":60}'

# Target networking (timeout / retry / circuit breaker)
fabric agent-gateway surfaces add-feature <id> networking --file networking.json

# Append a Trust Check element (list feature)
fabric agent-gateway surfaces add-feature <id> trust-check --file trust-check.json

# Trust Check element on the target leg
fabric agent-gateway surfaces add-feature <id> trust-check --edge ma-tp --file trust-check.json

# Per-transit-point response policy
fabric agent-gateway surfaces add-feature <id> policy --transit-point github --response --policy-id allow-gh
```

The surface ID or name and the feature are positional, in that order. The place is worked out from the feature name. With no flags, the CLI uses the surface place, and the request direction when a feature has both.

| Flag | Meaning |
| --- | --- |
| `--policy-id` | Configuration shortcut for policy features: the policy definition id. Ignored when `--json` or `--file` is given |
| `--json` | Configuration as inline JSON |
| `--file` | Configuration from a JSON file (`-` reads standard input) |
| `--response` | Use the response place instead of the request place |
| `--transit-point <alias>` | Use that transit point's place instead, as for tool gating, networking, and policy |
| `--edge` | `ap-ma`, `ma-external`, or `ma-tp`. `ma-tp` picks a transit point edge place that has no alias, which is the target leg of trust-check |
| `--dry-run` | [Preview the change](#preview-an-edit-with---dry-run) without saving it |

The placement flags are optional overrides, needed only when the command says the feature can go in more than one place. Only `identity --response` has to be told the edge (`--edge ap-ma` or `--edge ma-external`), and the command lists both.

Good to know:

- An object feature replaces what was there, and a list feature is appended to its list.
- A transit point feature sends the whole transit point list with that one point changed (see [A list edit overwrites concurrent changes](#a-list-edit-overwrites-concurrent-changes)).
- For an object or policy feature, a value holding `null` inside an object is refused, because the gateway would read it as removing that field.
- Table output prints `Updated surface '<id>'`. `--output json` returns the updated surface.

### Remove a feature

```sh
fabric agent-gateway surfaces remove-feature <id> rate-limit
fabric agent-gateway surfaces remove-feature <id> policy --response
```

`remove-feature` finds the place from the feature name, the same way as `add-feature`, and takes the same `--edge`, `--response`, `--transit-point`, and `--dry-run` flags. [`surfaces features <surface>`](#list-features) shows the flags needed for each place. A feature that isn't set at that place is refused.

Like `add-feature`, it fetches the surface and sends only the part it changes as a JSON Merge Patch. Table output prints `Updated surface '<id>'`; `--output json` returns the updated surface.

## Transit points

### Add a transit point

```sh
fabric agent-gateway surfaces add-transit-point <id> --alias billing --endpoint http://billing:3000
```

`add-transit-point` builds the transit point from plain options instead of JSON written by hand, and appends it to the surface's transit points. `--alias` and `--endpoint` are required. A point added this way always takes the protocol of the surface's `access_point` (the command has no protocol option). On a `didcomm` surface the gateway refuses it, because a transit point can't use `didcomm`.

These are refused before anything is sent:

- a blank alias or endpoint
- an alias that isn't lowercase letters, digits, and `-` starting with a letter, or is longer than 63 characters
- an alias the surface already uses

### Remove a transit point

```sh
fabric agent-gateway surfaces remove-transit-point <id> billing
```

`remove-transit-point` takes the point's alias or id. When no point has that name, it lists the ones that exist.

Good to know:

- Both commands send the whole transit point list, so an edit made by someone else in the meantime is overwritten (see [A list edit overwrites concurrent changes](#a-list-edit-overwrites-concurrent-changes)).
- Both take `--dry-run` to [preview the change](#preview-an-edit-with---dry-run).

## Tool gates

### Preview tool gates

```sh
fabric agent-gateway surfaces tool-gate-preview <surface-id> --tool delete_user,get_user
fabric agent-gateway surfaces tool-gate-preview --gates-file gates.json --tool delete_user --condition admins=met
```

`tool-gate-preview` shows whether each tool would be allowed or denied (RESULT, `ALLOW` or `DENY`) and which gate, or the default, decided it (DECIDED BY). The gates come from a surface's saved gating or from a JSON file, so you can check gates before saving them. Nothing is changed.

| Flag | Meaning |
| --- | --- |
| `<surface>` | Surface ID or name whose saved gates to check. Give this or `--gates-file` |
| `--gates-file` | JSON file holding the gating itself, as `{"default_effect": "allow", "gates": [...]}` (`-` reads standard input). Nothing is read from the gateway |
| `--tool` | Tool name to check. Required; repeat it or separate names with commas |
| `--condition` | Whether the caller meets a gate's condition policy, as `POLICY_ID=met` or `POLICY_ID=unmet`. Repeatable |

A tool gets one row per combination of conditions, named in a `CONDITION` column, only when its result or deciding gate depends on them. Otherwise each tool gets a single row and the `CONDITION` column is left out.

Good to know:

- Only the surface's own gating (`target.mcp_tool_gating`) is previewed, not the gating of its variants or transit points.
- Every condition policy you don't pin with `--condition` is tried both ways. At most 3 can be left unpinned.
- A `--condition` naming a policy no gate uses is refused.
- A pattern matches anywhere in a tool name unless it is anchored. With alternatives, each needs its own `^`, or wrap them as `^(?:a|b)`.

> [!IMPORTANT]
> A condition whose policy doesn't exist or is disabled acts as a block gate that is on and an allow gate that is off, and the preview can't tell. Check that the policy exists.

## Policies

### List and read policies

```sh
fabric agent-gateway policies list
fabric agent-gateway policies get allow-sales --output json
```

`list` prints the columns `NAME  ID  DESCRIPTION  ENABLED  VERSION  UPDATED`, or `No policies yet.` when there are none. `get` takes the policy's ID. In its JSON, the Rego source is the `policy` field, as a string.

### Create a policy to attach

```sh
fabric agent-gateway policies create --id allow-sales --name "Allow sales" --policy-file allow-sales.rego
fabric agent-gateway surfaces add-feature <id> policy --policy-id allow-sales --edge ap-ma
```

`policies create` reads the file as Rego source, not a JSON document, and sends it as the policy's `policy` field. The file must declare `package surface.policy`, or `package gateway.policy` with `--policy-type gateway`; the gateway refuses any other package. The new policy is enabled as soon as it is created. To enforce it on a surface, attach it with [`add-feature … policy --policy-id <id>`](#add-a-feature).

| Flag | Meaning |
| --- | --- |
| `--id` | ID that surfaces and other commands use to refer to the policy |
| `--name` | Human-readable name |
| `--description` | What the policy is for. Defaults to empty |
| `--policy-type` | `agent-surface` (default) or `gateway`. It can't be changed after the policy is created |
| `--policy-file` | File holding the policy's Rego source |

### Replace a policy from a file

```sh
fabric agent-gateway policies get allow-sales --output json > allow-sales.json
# edit allow-sales.json, then:
fabric agent-gateway policies update allow-sales --file allow-sales.json
```

`update` sends the file as the complete policy definition (`-` reads standard input). Table output prints `Updated policy '<id>'`.

> [!WARNING]
> **The document replaces the whole stored definition.** Start from the output of `policies get <policy-id> --output json` so no field is lost.

Good to know:

- The document's `id` must match the policy ID you pass, and its `policy_type` can't change. The gateway refuses either mismatch.
- A document without `enabled` turns a disabled policy back on, because the gateway reads a missing `enabled` as `true`.

### Check where a policy is used

```sh
fabric agent-gateway policies impact allow-sales
```

`impact` reports how many surfaces and gateways reference the policy, out of how many in total, and whether it is enforced appliance-wide, with the planes that enforce it. Nothing is changed.

### Delete a policy

```sh
fabric agent-gateway policies impact allow-sales
fabric agent-gateway policies delete allow-sales
```

Table output confirms with `Deleted policy '<id>'`.

> [!CAUTION]
> The definition is deleted as soon as the command runs; there is no confirmation prompt. The gateway doesn't check whether surfaces or gateways still use it, so run [`policies impact`](#check-where-a-policy-is-used) first.

Good to know:

- The gateway also removes the policy from the appliance-wide assignments before deleting it.

### List a policy's versions

```sh
fabric agent-gateway policies versions allow-sales
```

`versions` lists the saved versions newest first, with the columns `VERSION  HASH  CREATED  BY  NOTE`, or `No versions yet.` when there are none.

## How surface edits behave

These rules apply to the `surfaces` commands that read or edit one surface.

### A surface can be named by its ID or its name

`get`, `update`, `delete`, `features`, `add-feature`, `remove-feature`, `add-transit-point`, `remove-transit-point`, and `tool-gate-preview` accept the surface's name when only one surface has it.

```sh
fabric agent-gateway surfaces get "Sales Agent"
fabric agent-gateway surfaces update "Sales Agent" --set access_point.rate_limit.requests=200
```

- When a name is used, the CLI prints `note: using surface <id> (<name>)` to standard error.
- When more than one surface has the name, the CLI lists the matching IDs and asks for the ID.
- Finding a surface by name needs the `surfaces.view` permission. A token without it must pass the surface ID (a UUID), including for `update --set`, as with secrets.

### Every edit is checked on your machine first

`update`, `add-feature`, `remove-feature`, `add-transit-point`, and `remove-transit-point` read the surface, merge the change into it, and check the result before sending anything. `update --file` checks the file the same way.

The CLI refuses the edit when any of these would end up missing or empty, with the message the gateway gives for an empty value:

- `name`
- `access_point.listen_address`
- `access_point.route`, as in `access_point.route is required`
- `target.endpoint`

Good to know:

- A route without its leading `/` is accepted, because the gateway adds it.
- Every other check runs only on the gateway, such as whether referenced policies, secrets, and credential providers exist, or whether the access point's route is already used by another surface on the same listener, or a transit point's listen path collides with another.
- [`--dry-run`](#preview-an-edit-with---dry-run) runs the gateway's checks too, without saving.

### Most edits need the `surfaces.view` permission

Reading the surface for the local check needs `surfaces.view`.

| Command | Without `surfaces.view` |
| --- | --- |
| `update --set` / `--unset` | Warns and sends the edit unchecked |
| `update --add` / `--remove`, `--dry-run`, `add-feature`, `remove-feature`, `add-transit-point`, `remove-transit-point` | Fails with the gateway's missing permission error, without sending anything |

### A list edit overwrites concurrent changes

The gateway replaces a list whole, so commands that change one item read the surface and send the whole list back with that item changed. This applies to `update --add` and `--remove` (including one tool pattern in brackets), transit point features in `add-feature`, `add-transit-point`, and `remove-transit-point`.

> [!CAUTION]
> A change someone else makes to the same list between the read and the write is overwritten.

## Related

- [Identity and access](IDENTITY_AND_ACCESS.md): API keys an Agent Surface authenticates callers with
- [Secrets and credentials](SECRETS_AND_CREDENTIALS.md): secrets that surfaces reference
- [Project glossary](../CONTEXT.md): surface, access point, transit point, feature, edge
