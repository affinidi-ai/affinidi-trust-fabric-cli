# Agent Stream members and teams

Register the callers of an Agent Stream as members, and group them into teams. Agent Stream counts usage, limits, and spend against the member a call comes from and against its teams.

`fabric agent-stream` exists only in builds with the `agent-stream` Cargo feature, which releases leave out. See [Build From Source](../development/GETTING_STARTED.md).

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`members list`](#read-members) | List members with their identifiers |
| [`members get <id>`](#read-members) | Show one member, limits included |
| [`members create`](#create-a-member) | Create a member from identifiers or a JSON document |
| [`members update <id>`](#change-a-member) | Change the name, description, status, or identifiers, or replace the whole member |
| [`members delete <id>`](#delete-a-member) | Delete a member that is in no team |
| [`teams list`](#read-teams) | List teams with their number of members |
| [`teams get <id>`](#read-teams) | Show one team and a table of its members |
| [`teams create`](#create-a-team) | Create a team, with members named by id or identifier |
| [`teams update <id>`](#change-a-team) | Change the name, description, or status, or replace the whole team |
| [`teams add-member <team> <member>`](#add-and-remove-members) | Add a member to a team |
| [`teams remove-member <team> <member>`](#add-and-remove-members) | Remove a member from a team |
| [`teams delete <id>`](#delete-a-team) | Delete a team |

All commands start with `fabric agent-stream`. Reading members needs the `members.view` permission, creating and changing them `members.edit`, and deleting them `members.delete`. Teams work the same way with `teams.view`, `teams.edit` (adding and removing members included), and `teams.delete`. By default only administrators have any of them. `members update`, `teams update`, `teams add-member`, and `teams remove-member` read the record first, so they need the view permission too. Naming a member by identifier in a `teams` command, and the members table of `teams get`, need `members.view`.

Budgets, token caps, rate limits, and allowed models are not set by these commands. `update` keeps them as they are, `update --file` refuses a document that changes them, and `create` refuses a document that sets them.

## Members

### Identifiers

A member is recognised by its identifiers. The flags write each one as `KIND:VALUE`:

| Form | Matches a call by |
| --- | --- |
| `email:ADDRESS` | An email address, such as one in a JWT claim |
| `subject:JWT_SUBJECT` | The subject (`sub`) of a JWT |
| `api_key:KEY_NAME` | The name of the API key the call used |
| `custom:VALUE` | Any other value a surface reads, such as a header |

Agent Stream compares identifiers by value, without regard to case, surrounding spaces, or kind, so `custom:bob-key` and `api_key:bob-key` are the same identifier to it. Agent Stream itself only checks a member's first identifier against the others, so before `members create`, and before an `update` that changes identifiers, the CLI reads the member list and refuses any identifier whose value another member already has. A `create --dry-run` skips that check, since it needs no saved login. An email must have one `@` and a `.` after it. Quote a value that holds a shell character, such as `'subject:auth0|ada'`.

### Read members

```sh
fabric agent-stream members list
fabric agent-stream members get 6f1c2d3e-0000-4000-8000-000000000001
```

- Agent Stream leaves deleted members out of `list`. `get` still returns one, with `status` set to `deleted`, because Agent Stream keeps it for its usage history.
- `--output json` prints the whole members, limits included.

### Create a member

```sh
fabric agent-stream members create --name "Ada Lovelace" \
  --identifier email:ada@example.com --identifier 'subject:auth0|ada'

fabric agent-stream members create --file member.json --dry-run
```

| Flag | Meaning |
| --- | --- |
| `--identifier KIND:VALUE` | An identifier. At least one is required with flags; repeat for more. The first names the member when it has no name |
| `--name` | Display name |
| `--description` | What the member is |
| `--file` | A complete member document (`-` reads standard input). Can't be combined with the flags above |
| `--dry-run` | Print the member and send nothing. Needs no saved login |

Agent Stream gives each new member an id of its own. The CLI sends an empty `id`, replacing any in `--file`, and table output prints the new id.

### Change a member

```sh
fabric agent-stream members update 6f1c2d3e-0000-4000-8000-000000000001 --status disabled

fabric agent-stream members update 6f1c2d3e-0000-4000-8000-000000000001 \
  --remove-identifier email:ada@old.example --add-identifier email:ada@example.com
```

- `--add-identifier` refuses one the member already has, and one whose value another member has, of any kind. `--remove-identifier` refuses one it lacks, and refuses to remove the last one. Removes run before adds.
- A disabled member's calls are refused.
- A deleted member can't be changed.
- How the save works, `--file` and `--dry-run` included, is in [How changes are saved](#how-changes-are-saved).

### Delete a member

```sh
fabric agent-stream members delete 6f1c2d3e-0000-4000-8000-000000000001
```

- A member still in a team can't be deleted. Remove it from each team first; Agent Stream's refusal names the teams.
- A built-in member, such as `anonymous`, can't be deleted. Disable it instead.
- Agent Stream keeps a deleted member for its usage history, and stops recognising callers by its identifiers. There is no confirmation prompt.

## Teams

### Read teams

```sh
fabric agent-stream teams list
fabric agent-stream teams get 0b7e4a52-0000-4000-8000-000000000001
```

- `list` shows each team's number of members. Agent Stream leaves deleted teams out.
- Agent Stream keeps only member ids on a team. In table output, `teams get` prints the team, then a table of its members read from `members list`, with "(not listed)" for a member that is deleted or not visible to you. When the members can't be read, a warning says why and the table shows only each member's id. `--output json` prints the team only.

### Create a team

```sh
fabric agent-stream teams create --name Research \
  --member email:ada@example.com --member 6f1c2d3e-0000-4000-8000-000000000002
```

| Flag | Meaning |
| --- | --- |
| `--name` | Display name. Required with flags |
| `--member` | A member, by id or identifier. Repeatable |
| `--description` | What the team is for |
| `--file` | A complete team document (`-` reads standard input). Can't be combined with the flags above |
| `--dry-run` | Print the team and send nothing. Needs a saved login only to look up members named by identifier |

A member named by identifier is looked up in `members list`. The command stops, sending nothing, when the identifier matches no member or more than one. As with members, Agent Stream gives each new team its own id.

### Change a team

```sh
fabric agent-stream teams update 0b7e4a52-0000-4000-8000-000000000001 --name "Applied research"
```

`update` keeps the team's members, budget, and token cap. A disabled team no longer counts its members' calls. See [How changes are saved](#how-changes-are-saved).

### Add and remove members

```sh
fabric agent-stream teams add-member 0b7e4a52-0000-4000-8000-000000000001 email:ada@example.com
fabric agent-stream teams remove-member 0b7e4a52-0000-4000-8000-000000000001 api_key:billing-job --dry-run
```

- The member is named by id or identifier, as for `teams create`.
- A member already in the team, for `add-member`, or not in it, for `remove-member`, sends nothing.
- Agent Stream makes the change to the team as it is stored, so nothing else in the team is overwritten.
- Table output lists the team's member ids before and after. `--dry-run` shows the same and sends nothing.
- Removing a member from a team keeps the member.

### Delete a team

```sh
fabric agent-stream teams delete 0b7e4a52-0000-4000-8000-000000000001
```

Its members stay, and its usage history is dropped. A built-in team, such as `anonymous`, can't be deleted; disable it instead. There is no confirmation prompt.

## How changes are saved

Agent Stream replaces the whole member or team on every save and has no version check. So `members update` and `teams update` work like this:

1. The CLI reads the record and makes the change on this machine.
2. It checks the result the way Agent Stream would, and refuses a field name Agent Stream does not know, because Agent Stream would drop it without an error.
3. It reads the record again, and stops with nothing saved if someone else saved it in the meantime. A save that lands in the short gap before the send is still overwritten.
4. It sends the whole record. A change that leaves the record as it was sends nothing.

`--file` replaces the whole record. It must carry the record's current `updated_at`, so start from a fresh `get`; a copy read before another save is refused. Its `created_at`, `updated_at`, `tenant_id`, `system`, `auto_provisioned`, and `test_fixture` are replaced with the stored ones, with a note for each that differed. A member document can't have both `identifiers` and the older `identifier`, which Agent Stream can't read together. Its budgets and limits must match the stored ones, and any it leaves out are kept. A deleted record can't be changed.

After a save, table output lists each changed field with its old and new value, and `--output json` prints the record as Agent Stream answered the save, which can go straight back to `--file`. `--dry-run` shows the changes and saves nothing; with `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }`.
