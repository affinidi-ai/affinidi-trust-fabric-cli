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
| [`providers connect <id>`](#connect-a-provider-to-a-surface) | Point an LLM surface at a provider, a model, and the secret holding the key |

All commands start with `fabric agent-stream`. Every one of them, reading included, needs the `llm_catalog.edit` permission, which by default only administrators have. `connect` also needs `pipes.view` and `pipes.edit` to read and change the surface.

## API keys are not in the catalog

No `providers` command takes or prints an API key, because the catalog holds none. A provider's key is stored in Agent Stream as a secret, and each surface that uses the provider names that secret; [`providers connect`](#connect-a-provider-to-a-surface) sets that name. The catalog only describes the key a provider expects, in fields such as `api_key_label` and `api_key_required`.

## Built-in and custom providers

Agent Stream keeps providers in two stores:

| Store | What it is | How the CLI changes it |
| --- | --- | --- |
| Built-in | The providers Agent Stream ships. A catalog refresh replaces them, undoing any change made to them | One provider at a time |
| Custom | Providers added here or in the dashboard. They survive a refresh | By sending the whole custom catalog with only the one provider changed |

`list` shows both, with a SOURCE column. Every other command finds the provider in whichever store has it, and uses that store's route. A provider id is matched exactly, so `OPENAI` and `openai` are different ids here; see [When the custom catalog blocks a save](#when-the-custom-catalog-blocks-a-save).

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
- If an id is a built-in provider's, the refusal points to `providers update <id>` instead; the next catalog refresh undoes a change made that way.
- If an id is already a custom provider's, an earlier `create` may have saved it, for example one whose answer was lost after a timeout or a 502 or 504 from a proxy; see it with `providers get <id>`. Pressing Ctrl-C while a save is running prints nothing, and the change may have been saved too.
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

After a save, table output lists each changed field, and `--output json` prints the provider as Agent Stream answered the save. A model is named by its `value` and an endpoint by its `path`, so a price change reads `models[gpt-4o-mini].cost_per_1k_input: 0.00015 -> 0.0002`, and an added or removed model shows whole. `--dry-run` shows the changes and saves nothing; with `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }`.

## Models and prices

```sh
fabric agent-stream providers disable-model openai gpt-4o --dry-run
fabric agent-stream providers enable-model openai gpt-4o
fabric agent-stream providers set-price openai gpt-4o-mini --input-price 0.00015 --output-price 0.0006
```

- A model is named by its `value`, as `providers models` lists it.
- Agent Stream hides a disabled model from the dashboard's model pickers and refuses to save a surface that uses it.
- Prices are USD per 1,000 tokens, from 0 to 100. Give `--input-price`, `--output-price`, or both. Agent Stream uses a model's catalog prices only when both are set, so `set-price` refuses to leave a model with only one: give the other price too when the model has none.
- Agent Stream uses the prices for every call on a surface that sets no price of its own, so a change changes every cost and budget figure from then on. An endpoint's own prices win over the model's.

## When the custom catalog blocks a save

Agent Stream checks the whole custom catalog on every save, so a custom entry it refuses blocks every custom create, change and delete, except deleting the blocking entry itself. With custom `acme` and `OPENAI` beside built-in `openai`, for example, `providers delete acme` is refused, because `OPENAI` would still be sent. Before it sends anything, the CLI names the entries that would still be there after the change: an id that isn't valid, an id a built-in provider also has in any case (a catalog refresh can add one), and two custom ids that differ only in case. Agent Stream reports any other problem, such as a model without a `value`, in its own error.

To clear the block, delete the entry by its exact id, such as `fabric agent-stream providers delete OPENAI`; that save is allowed because the entry is gone afterwards. This works for an id that differs from a built-in one, or from another custom one, only in case. An entry whose id isn't valid, such as `my llm`, can't be named on the command line, and a custom id exactly equal to a built-in one is refused as being in both stores: fix those in the dashboard's custom catalog. Changes to built-in providers never touch the custom catalog, so they go ahead. `get` and `models` show the exactly matching provider with a warning: Agent Stream ignores a custom provider whose id a built-in one has, so its models and prices are not the ones in use. An id that both stores have exactly can't be changed here; fix it in the dashboard's custom catalog.

## Delete a provider

```sh
fabric agent-stream providers get acme-llm > provider.json
fabric agent-stream providers delete acme-llm
```

- A custom provider is removed by sending the custom catalog without it. Surfaces that use it stop working.
- A built-in provider is deleted on its own. Agent Stream supports those providers itself, so surfaces on it keep working, but without the catalog's prices and model switches, until the next catalog refresh brings the provider back.
- `--output json` prints `{"deleted": "<id>"}` for either store.
- There is no confirmation prompt.

## Connect a provider to a surface

```sh
fabric agent-stream providers connect openai --surface s-1a2b3c4d5e6f \
  --secret openai-key --model gpt-4o-mini --dry-run
fabric agent-stream providers connect openai --surface s-1a2b3c4d5e6f \
  --secret openai-key --model gpt-4o-mini
```

`connect` changes an existing LLM surface so that its calls go to the provider, with the model and the API key you name. It sets the surface's `pipe_type.provider`: `provider_type`, `model`, `api_key_secret`, and, with `--base-url`, `base_url`.

| Flag | What it sets |
| --- | --- |
| `--surface` | The LLM surface to change (required) |
| `--secret` | The id of the stored secret that holds the provider's API key (required). See `fabric agent-stream secrets list` |
| `--model` | The model, by its `value` in `providers models`. Without it, the surface keeps its model |
| `--base-url` | Where the surface sends the provider's calls, instead of the catalog's base URL |
| `--dry-run` | Show the changes, and save nothing |

- The surface keeps only the secret's id. The key itself is never read, sent, or printed. A `--secret` that looks like an API key, 32 characters or more starting the way provider keys do, such as `sk-`, is refused, as is one that can't name a secret: 1 to 256 letters, digits, `-`, `_`, or `.`, without `..`.
- The model must be in the provider's catalog entry and enabled there, whether it comes from `--model` or is the surface's own. Otherwise nothing is sent, and the error points to `providers models` or `providers enable-model`.
- `--base-url` must be an http or https URL with no user name or password. It is refused for providers whose surface settings have no base URL, such as `anthropic`, `gemini`, `cohere`, `mistral`, and a custom provider with the `anthropic` or `gemini` API schema, because Agent Stream would drop it without an error.
- `azure` and `custom` are refused: a surface describes them with other fields, such as an Azure deployment name. Set those with `surfaces update`.
- On a surface already on the provider, its other provider settings, such as an organization id or a base URL, are kept. Moving a surface to another provider keeps only `temperature`, `max_tokens`, `top_p`, `frequency_penalty`, and `presence_penalty`, and drops the rest, along with `pipe_type.endpoint_path`, the upstream path Agent Stream's execute API calls: they belong to the provider it leaves. Without `--base-url`, Agent Stream then uses the catalog's base URL.
- Surface variants and failover targets that name their own provider are left as they are.
- A webhook or IDE surface, and a deleted surface, are refused.

`connect` saves the way `surfaces update` does, except that in place of its field-name check it writes only the fields the provider takes on a surface. A disabled provider and a plain `http` `--base-url` to a host other than this machine get a warning. It reads the surface, reads it again just before saving, and stops with nothing sent if it was saved in between. A change that leaves the surface as it is sends nothing. After a save, table output lists each changed field, such as `pipe_type.provider.model: "claude-x" -> "gpt-4o-mini"`, and `--output json` prints the surface as Agent Stream has it after the save. `--dry-run` shows the same list; with `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }` with the whole new surface.

## Not covered here

- Refreshing the built-in catalog from its published source, and rolling a refresh back: use the dashboard, or `fabric agent-stream api post /v1/llm-providers/refresh`.
