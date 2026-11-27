# Agent Stream LLM providers

Manage the Model catalog of an Agent Stream: the LLM providers it knows, with their endpoints, models, and prices. Agent Stream uses the catalog to route calls and to work out what each call costs.

`fabric agent-stream` exists only in builds with the `agent-stream` Cargo feature, which releases leave out. See [Build From Source](../development/GETTING_STARTED.md).

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`providers list`](#read-the-catalog) | List built-in and custom providers |
| [`providers get <id>`](#read-the-catalog) | Show one provider |
| [`providers models <id>`](#read-the-catalog) | List a provider's models and prices |
| [`providers create`](#add-a-provider) | Add a provider to the custom catalog |
| [`providers update <id>`](#change-a-provider) | Change a provider with path flags, or replace it from a file |
| [`providers enable-model <id> <model>`](#models-and-prices) | Enable a model |
| [`providers disable-model <id> <model>`](#models-and-prices) | Disable a model |
| [`providers set-price <id> <model>`](#models-and-prices) | Set a model's input and output prices |
| [`providers delete <id>`](#delete-a-provider) | Delete a provider |

All commands start with `fabric agent-stream`. Every one of them, reading included, needs the `llm_catalog.edit` permission, which by default only administrators have.

## API keys are not in the catalog

No `providers` command takes or prints an API key, because the catalog holds none. A provider's key is stored in Agent Stream as a secret, and each surface that uses the provider names that secret. The catalog only describes the key a provider expects, in fields such as `api_key_label` and `api_key_required`.

## Built-in and custom providers

Agent Stream keeps providers in two stores:

| Store | What it is | How the CLI changes it |
| --- | --- | --- |
| Built-in | The providers Agent Stream ships. A catalog refresh replaces them, undoing any change made to them | One provider at a time |
| Custom | Providers added here or in the dashboard. They survive a refresh | By sending the whole custom catalog with only the one provider changed |

`list` shows both, with a SOURCE column. Every other command finds the provider in whichever store has it, and uses that store's route. A provider id is matched exactly.

## Read the catalog

```sh
fabric agent-stream providers list
fabric agent-stream providers get openai
fabric agent-stream providers models openai
```

- `list --output json` prints each provider as Agent Stream keeps it, with a `source` field added.
- In `models`, ENABLED is `no` only for a model whose `enabled` is false: Agent Stream treats a model with no `enabled` as enabled, so `enable-model` on such a model sends nothing. INPUT and OUTPUT are USD per 1,000 tokens, and `-` means the catalog sets no price.

## Add a provider

```sh
fabric agent-stream providers create --id acme-llm --name "Acme LLM" \
  --base-url https://llm.acme.example --api-schema openai

fabric agent-stream providers create --file provider.json --dry-run
```

| Flag | Meaning |
| --- | --- |
| `--id` | The provider's id, its `enum_value`: letters, digits, `-`, and `_`, up to 128 characters. A surface names the provider by it. Required with flags |
| `--name` | Display name. Required with flags |
| `--base-url` | The API address (`default_base_url`), without `/v1` |
| `--api-schema` | The API format the provider speaks, such as `openai` |
| `--description` | What the provider is |
| `--disabled` | Save the provider turned off (`enabled` false). Without it, the provider is saved with `enabled` true |
| `--file` | A whole provider document (`-` reads standard input). Can't be combined with the flags above |
| `--dry-run` | Read the catalog, show the new provider, and save nothing |

- A new provider always goes into the custom catalog, so a refresh doesn't remove it.
- The provider is saved with `enabled` true unless `--disabled` is given or a `--file` document sets `enabled` itself. Agent Stream treats a provider with no `enabled` as on, but the dashboard's provider list shows it as disabled, so the CLI always writes it. `list` shows ENABLED `no` only for a provider whose `enabled` is false.
- Its id can't be one another provider, built-in or custom, already has, whatever its case.
- Before anything is sent, the CLI checks the provider the way Agent Stream would: an id and a name; `api_key_validation`, when set, of `mandatory`, `optional`, or `none`; a name and a path on each endpoint; a name and a value on each model; and prices from 0 to 100 USD per 1,000 tokens. Agent Stream also requires a base URL that resolves to a public address.
- Agent Stream keeps fields it doesn't know, so the CLI doesn't refuse them.

## Change a provider

```sh
fabric agent-stream providers update acme-llm \
  --set default_base_url=https://llm2.acme.example --dry-run

fabric agent-stream providers update acme-llm \
  --add 'models={"name":"Acme Large","value":"acme-large"}'

fabric agent-stream providers update acme-llm --remove 'models={"value":"acme-large"}'
```

- `--set`, `--unset`, `--add`, and `--remove` take dot paths such as `default_base_url` or `hero.title`, and read values as `fabric agent-gateway surfaces update` does. Unlike there, a path can't use brackets or a list position. To change a list, give its own path to `--add` or `--remove`, or use the model commands below.
- `--add` refuses an item equal to one already in the list, and every save refuses two models with the same `value`, since a model is named by it.
- `--file` replaces the whole provider. Its `enum_value` must be the provider's id, because the id can't change; create a new provider instead.
- Agent Stream has no version or `updated_at` on a provider, so the CLI can't tell whether a `--file` was copied before someone else's save. Start from a fresh `providers get`, and save soon after.
- A built-in provider changed here is replaced again by the next catalog refresh.

How every change is saved, including the model commands:

1. The CLI reads both stores and makes the change on this machine.
2. It checks the result, as `create` does.
3. It reads again, and stops with nothing saved if, since the first read, the provider changed (for a built-in one) or anything in the custom catalog changed (for a custom one). A save that lands in the short gap before the send is still overwritten.
4. It saves the provider, or for a custom one the whole custom catalog with only that provider changed. A change that leaves the provider as it was sends nothing.

After a save, table output lists each changed field, and `--output json` prints the provider as Agent Stream has it then. `--dry-run` shows the changes and saves nothing; with `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }`.

## Models and prices

```sh
fabric agent-stream providers disable-model openai gpt-4o --dry-run
fabric agent-stream providers enable-model openai gpt-4o
fabric agent-stream providers set-price openai gpt-4o-mini --input-price 0.00015 --output-price 0.0006
```

- A model is named by its `value`, as `providers models` lists it.
- Agent Stream hides a disabled model from the dashboard's model pickers and refuses to save a surface that uses it.
- Prices are USD per 1,000 tokens, from 0 to 100. Give `--input-price`, `--output-price`, or both. Agent Stream uses them for every call on a surface that sets no price of its own, so a change changes every cost and budget figure from then on.

## When the custom catalog blocks a save

Agent Stream checks the whole custom catalog on every save. A custom entry it refuses, such as one whose id a built-in provider also has after a catalog refresh, blocks every custom create, change, and delete. The CLI names such entries before it sends anything; fix them in the dashboard's custom catalog. Until then, a provider id that both stores have can't be changed or deleted here, and `get` and `models` show the built-in one with a warning.

## Delete a provider

```sh
fabric agent-stream providers get acme-llm > provider.json
fabric agent-stream providers delete acme-llm
```

- A built-in provider is deleted on its own, and comes back with the next catalog refresh.
- A custom provider is removed by sending the custom catalog without it.
- `--output json` prints `{"deleted": "<id>"}` for either store.
- There is no confirmation prompt. A surface that uses the provider stops working.

## Not covered here

- Refreshing the built-in catalog from its published source, and rolling a refresh back: use the dashboard, or `fabric agent-stream api post /v1/llm-providers/refresh`.
- Connecting a provider and its key to a surface.
