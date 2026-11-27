# Agent Stream prompt templates

Create, version, preview, and roll back the prompt templates of an Agent Stream. A model request names a template by its id and fills in its `{{name}}` placeholders, instead of sending the whole prompt text, so a prompt can be changed in one place.

`fabric agent-stream` exists only in builds with the `agent-stream` Cargo feature, which releases leave out. See [Build From Source](../development/GETTING_STARTED.md).

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`prompts list`](#read-templates) | List templates: id, name, status, version numbers, default version. Never their messages |
| [`prompts get <id>`](#read-templates) | Show one template, messages included |
| [`prompts create`](#create-a-template) | Create a template from text files or a JSON document |
| [`prompts update <id>`](#change-a-template) | Change the name, description, or status, or replace the whole template |
| [`prompts add-version <id>`](#add-a-version) | Add a numbered version, never overwriting one |
| [`prompts set-default <id> <version>`](#choose-the-default-version-and-roll-back) | Choose the version callers get when they name none |
| [`prompts remove-version <id> <version>`](#remove-a-version) | Remove a version that is not the default |
| [`prompts render <id>`](#preview-a-template-with-render) | Show the messages a template gives for some variables |
| [`prompts delete <id>`](#delete-a-template) | Delete a template |

All commands start with `fabric agent-stream`. Reading and rendering need the `prompts.view` permission. Creating and changing need `prompts.edit`, and deleting needs `prompts.delete`; by default only administrators have those two.

## What a template holds

```json
{
  "id": "support-greeter",
  "name": "Support greeter",
  "status": "enabled",
  "default_version": 1,
  "versions": [
    {
      "version": 1,
      "label": "first",
      "messages": [
        { "role": "system", "content": "You greet customers of {{product}}." }
      ]
    }
  ]
}
```

- `id`: what requests name the template by. Letters, digits, `-`, and `_`, up to 128 characters.
- `versions`: numbered versions, each with one or more messages (a `role` and its `content`) and an optional `label`.
- `default_version`: the version a request gets when it names none. Without it, the highest version wins.
- `status`: `enabled` or `disabled`. A disabled template can't be used or rendered.

## Read templates

```sh
fabric agent-stream prompts list
fabric agent-stream prompts get support-greeter
```

- `list` never prints messages, in table output or with `--output json`. `get` prints the whole template.
- Agent Stream lists enabled templates only. A disabled template is left out of `list`, but `get` still returns it.

## Create a template

```sh
# From text files, one per message, in order
fabric agent-stream prompts create --id support-greeter --name "Support greeter" \
  --message system=system.txt --message user=user.txt --label first

# From a complete JSON document, after checking it
fabric agent-stream prompts create --file template.json --dry-run
fabric agent-stream prompts create --file template.json
```

| Flag | Meaning |
| --- | --- |
| `--id` | Id of the new template. Required with flags |
| `--name` | Display name. Required with flags |
| `--message ROLE=FILE` | One message of version 1: its role and a text file holding its content. Required with flags; repeat for each message, in order |
| `--description` | What the template is for |
| `--label` | Label of version 1 |
| `--file` | A complete template document (`-` reads standard input). Can't be combined with the flags above |
| `--dry-run` | Print the template and send nothing. Needs no saved login |

Good to know:

- A message file is read as UTF-8, and one line break at its end is dropped, since editors add one.
- With flags, version 1 becomes the default version.
- Before anything is sent, the CLI checks the template the way Agent Stream would: the id, a name that is not blank, at least one version and no two with one number, at least one message per version, each with a role, and a default version that exists. It also refuses a field name Agent Stream does not know, because Agent Stream would drop it without an error.

## Change a template

```sh
fabric agent-stream prompts update support-greeter --status disabled
fabric agent-stream prompts update support-greeter --name "Greeter" --description "Front desk"

# Edit the whole document
fabric agent-stream prompts get support-greeter > template.json
fabric agent-stream prompts update support-greeter --file template.json --dry-run
fabric agent-stream prompts update support-greeter --file template.json
```

Agent Stream replaces the whole template on every save and has no version check. So every change (`update`, `add-version`, `set-default`, and `remove-version`) works the same way:

1. The CLI reads the template and makes the change on this machine.
2. It checks the result, as `create` does.
3. It reads the template again, and stops with nothing saved if someone else saved it in the meantime. A save that lands in the short gap before the send is still overwritten.
4. It sends the whole template. A change that leaves the template as it was sends nothing.

`--file` replaces the whole template, versions included, so a version left out of the file is removed, and a file with no versions is refused. The file must carry the template's current `updated_at`, so start from a fresh `prompts get`. A copy read before another save is refused. Its `created_at`, `updated_at`, and `tenant_id` are replaced with the stored ones.

After a save, table output lists each change. A version shows as added, removed, or changed by its number, never by its messages. `--output json` prints the template as Agent Stream has it after the save.

`--dry-run` shows the changes and saves nothing. With `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }`, where `after` is the whole template that would be sent. Agent Stream has no dry run of its own, so its own checks run only on a real save.

## Add a version

```sh
# From text files, without changing what callers get
fabric agent-stream prompts add-version support-greeter \
  --message system=system-v2.txt --message user=user.txt --label shorter

# From a JSON object, making it the default
fabric agent-stream prompts add-version support-greeter --file v3.json --make-default
```

- The new version's number is `--version`, else the file's `version`, else one more than the highest version. A number the template already has is refused, so an existing version is never overwritten.
- `--file` holds one version: `{"messages": [...], "label": "...", "version": 3}`, with `label` and `version` optional.
- Without `--make-default`, callers who name no version keep the version they get now. When the template has no `default_version`, which means callers get the highest version, the CLI sets `default_version` to that version and prints a note saying so (on a dry run too, as part of the change it shows), so the new version doesn't reach them.

## Choose the default version and roll back

```sh
fabric agent-stream prompts set-default support-greeter 1 --dry-run
fabric agent-stream prompts set-default support-greeter 1
```

There is no separate rollback. To roll back, set the default to an earlier version. Every caller that names no version gets it on their next request. Callers that name a version keep it.

## Remove a version

```sh
fabric agent-stream prompts remove-version support-greeter 2
```

- The version callers get by default can't be removed. That is the `default_version`, or the highest version when the template has none. Set another default first.
- The last version can't be removed either. Delete the template instead.
- Agent Stream keeps no copy of a removed version, so keep one with `prompts get` first if you may need it.

## Preview a template with `render`

```sh
fabric agent-stream prompts render support-greeter --var product=Widgets
fabric agent-stream prompts render support-greeter --version 2 --vars-file variables.json
```

- Agent Stream fills each `{{name}}` placeholder and returns the messages, without calling a model. Table output prints each message's role in brackets, then its content. `--output json` prints Agent Stream's answer, which also lists the variables the version uses.
- `--var name=value` is used as text. `--vars-file` is a JSON object; a value there that is not text is filled in as its JSON. A `--var` wins over the same name in the file.
- A missing variable is refused, with all the missing names. A disabled template can't be rendered.

## Delete a template

```sh
fabric agent-stream prompts get support-greeter > template.json
fabric agent-stream prompts delete support-greeter
```

Requests that name the template are refused from then on. There is no confirmation prompt. A template with the same id can be created again later.
