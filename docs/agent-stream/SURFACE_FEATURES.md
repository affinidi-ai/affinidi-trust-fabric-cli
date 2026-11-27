# Agent Stream surface features

Set the cost and safety features of an Agent Stream surface: rate limits, cost tracking and budgets, usage limits and alerts, prompt guard, judge, jury, decider, expert witnesses, routing rules, canary, load balancing, failover, circuit breaker, and retry. Then read the surface's spend against its monthly budget.

`fabric agent-stream` exists only in builds with the `agent-stream` Cargo feature, which releases leave out. See [Build From Source](../development/GETTING_STARTED.md).

## Commands at a glance

| Command | What it does |
| --- | --- |
| [`surfaces features`](#list-the-features) | List every feature a surface can have. Needs no saved connection |
| [`surfaces features <id>`](#see-the-features-of-a-surface) | Show the features a surface has, the variants that override each, and how to remove each |
| [`surfaces add-feature <id> <feature>`](#add-or-change-a-feature) | Add a feature, replace its settings, or add one item to a list feature |
| [`surfaces remove-feature <id> <feature>`](#remove-a-feature) | Remove a feature, one item of a list feature, or a whole list |
| [`surfaces budget <id>`](#read-the-budget) | Show this month's spend against the monthly budget |

All commands start with `fabric agent-stream`. Reading a surface needs the `pipes.view` permission, and `add-feature` and `remove-feature` need `pipes.edit` as well, since they read the surface before they save it. `surfaces budget` needs `metrics.view`.

## Features

On Agent Stream each feature is one field of the surface, not a route of its own. The commands take the feature name or its alias, in any case.

| Feature | Alias | Surface field | Kind | What it does |
| --- | --- | --- | --- | --- |
| `rate-limit` | | `rate_limit` | setting | Caps requests, and optionally tokens, per minute |
| `cost-tracking` | `budget` | `cost_tracking` | setting | The surface's own model prices, and a monthly budget with an alert threshold |
| `usage-limits` | | `usage_limits` | list | Monthly spend or token caps; a call past a cap is refused with 429 |
| `usage-alerts` | | `usage_alerts` | list | Alerts on cost, tokens, error rate, or a cost spike |
| `prompt-guard` | `pii` | `prompt_guard` | setting | Filters personal data and other sensitive content in requests and responses |
| `judge` | | `judge` | setting | A model checks each request before it is sent on |
| `jury` | | `jury` | setting | Models check each response before it is returned |
| `decider` | | `decider` | setting | A model picks which candidate provider serves each request |
| `expert-witness` | | `expert_witnesses` | list | External safety classifiers check requests or responses |
| `routing-rules` | | `routing_rules` | list | Routes a request by header, body field, or modality; the first rule that matches wins |
| `canary` | | `canary` | setting | Splits traffic across variants by weight; off unless `enabled` |
| `load-balancing` | | `load_balancing` | setting | Spreads requests over a weighted pool of providers |
| `failover` | | `failover` | setting | Retries a failed request on backup providers in order |
| `circuit-breaker` | | `circuit_breaker` | setting | Stops calling a failing provider for a while |
| `retry` | | `retry_policy` | setting | Retries a failed call with backoff |

A setting is one JSON object. A list holds items, and `usage_limits` and `expert_witnesses` items each have an `id`, while routing rules and usage alerts have none.

Other surface fields, such as `cache`, `source_auth`, and `opa_policy`, are not features here. Change them with `surfaces update --set`.

### Switches

Usage alerts and routing rules each have a switch on the surface: `usage_alerts_enabled` and `routing_enabled`. While a switch is false, Agent Stream keeps the items but ignores all of them. So `add-feature` turns a switch on only when it adds the first item:

| Before | `add-feature` adds an item, and |
| --- | --- |
| The list is empty and the switch is false | sets the switch to true, so the new item is used |
| The list has items and the switch is false | leaves the switch false, and prints a note with the command that turns the whole list on |
| The switch is true | leaves it true |

```sh
fabric agent-stream surfaces update s-1a2b3c4d5e6f --set routing_enabled=true
```

`remove-feature` never changes a switch.

## List the features

```sh
fabric agent-stream surfaces features
```

`--output json` prints each feature with its alias, field, kind, switch, and whether a variant can override it.

## See the features of a surface

```sh
fabric agent-stream surfaces features s-1a2b3c4d5e6f
```

```text
FEATURE       FIELD         STATE    VARIANTS  REMOVE WITH
rate-limit    rate_limit    on       frozen    fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f rate-limit
usage-limits  usage_limits  1 item   -         fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-limits (--item <id> | --all)
judge         judge         not set  strict    -
```

- STATE is `on` or `off` for a setting with an `enabled` flag, `set` for one without, and the number of items for a list, with a note when its switch is off. Cost tracking that is off but has a price set shows `off (prices used)`, because Agent Stream prices the surface's calls with those prices whatever `enabled` says.
- VARIANTS names the variants that use their own value of the feature. See [Variants](#variants).
- A feature only variants set shows as `not set`, with no remove command, since `remove-feature` changes only the base surface.
- A deleted surface shows no remove commands, and a line under the table says it is deleted, since a deleted surface can't be changed.
- `--output json` prints each feature with its `field`, `state`, base `value`, and `overridden_by` variants.

## Add or change a feature

```sh
fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f rate-limit \
  --json '{"enabled":true,"requests_per_minute":60}' --dry-run

fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f usage-limits \
  --json '{"id":"tokens","monthly_token_cap":1000000}'

fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f failover --file failover.json
```

| Flag | Meaning |
| --- | --- |
| `--json` | The settings as inline JSON: the whole field for a setting, or one item for a list |
| `--file` | The same from a file (`-` reads standard input). Can't be combined with `--json` |
| `--allow-new-field` | Let the settings hold a name the surface's field does not have yet |
| `--dry-run` | Show the changes and save nothing |

The JSON is read and its shape checked before anything is sent: a setting takes one object, and a list takes one object as its new item.

### Settings are replaced, list items are appended

- **A setting** is replaced whole by the JSON given, so a setting it leaves out is gone. Running `add-feature` again changes the feature. To change one setting and keep the others, use `surfaces update`:

  ```sh
  fabric agent-stream surfaces update s-1a2b3c4d5e6f --set rate_limit.requests_per_minute=120
  ```

- **A list** gets the JSON appended as one item, at the end. An item already in the list, by its `id` or by the same fields, is refused. A new routing rule goes last, and Agent Stream uses the first rule that matches.

A name inside the JSON must be one the surface's field already has, unless `--allow-new-field` is given, because a typo would otherwise be dropped by Agent Stream without an error. Agent Stream leaves empty optional settings out of the surface it returns, so a correct name can look new; for example, `alert_threshold_percent` when `cost_tracking` has none yet. So `cost-tracking` names are always checked against every setting Agent Stream knows, even on a surface with no `cost_tracking` yet, and `monthly_budget` instead of `monthly_budget_usd` is refused. Nothing is checked inside any other field the surface does not have yet, or inside a list item.

### Cost tracking and prices

`cost_tracking` holds two things: the surface's own model prices (`input_price_per_1k` and `output_price_per_1k`) and the monthly budget (`monthly_budget_usd` and `alert_threshold_percent`). Agent Stream prices the surface's calls with those prices whether or not `enabled` is true, and counts the budget only while `enabled` is true.

So `add-feature cost-tracking` keeps the stored `enabled`, `input_price_per_1k`, and `output_price_per_1k` when the JSON leaves them out, and prints a note naming each one kept. Give a value to change one, or `null` to drop a price. Agent Stream needs `enabled`, so the command refuses settings with no `enabled` when the surface has none stored either.

```sh
fabric agent-stream surfaces add-feature s-1a2b3c4d5e6f cost-tracking \
  --json '{"enabled":true,"monthly_budget_usd":100,"alert_threshold_percent":80}'
```

### Surface types

Agent Stream serves model calls only on `llm` surfaces. Every feature can still be added to any surface, because a variant can switch a surface to `llm`, but `add-feature` prints a note when the feature does nothing where it is set:

| Surface type | Note |
| --- | --- |
| `webhook` | Agent Stream refuses every call, so the feature takes effect only through a variant whose `pipe_type` is `llm`. `judge`, `decider`, and `expert-witness` still run on each call before it fails, and their own calls can cost money |
| `ide_catalog` | Each call is handed to the member surface serving the model, so the feature is not used here; set it on the member surfaces |

`rate-limit` gets no note: Agent Stream checks it on every surface, `ide_catalog` included.

## Remove a feature

```sh
fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f rate-limit

fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-limits --item tokens --dry-run

fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-alerts \
  --item '{"alert_type":"cost_threshold"}'

fabric agent-stream surfaces remove-feature s-1a2b3c4d5e6f usage-limits --all
```

- A setting is removed whole. `--item` and `--all` are refused for it.
- A list feature needs `--item` to remove one item, or `--all` to remove the whole list. With neither, the command stops before anything is sent, so a whole list is never removed by leaving a flag out.
- `--item` takes the item's `id`. Routing rules and usage alerts have no id, so give some of the item's fields as JSON instead, which must match exactly one item.
- A feature the surface does not have set is refused.
- Removing `cost-tracking` removes the surface's own prices too, and a note says so. To stop only the budget and keep the prices, turn it off instead:

  ```sh
  fabric agent-stream surfaces update s-1a2b3c4d5e6f --set cost_tracking.enabled=false
  ```

## Variants

A surface variant can set its own value of `prompt_guard`, `judge`, `jury`, `expert_witnesses`, `rate_limit`, `circuit_breaker`, `retry_policy`, `cost_tracking`, and `usage_alerts`. A variant with `complete` set takes all of them from itself, an empty one included, so it overrides every one the base surface has.

`features <id>`, `add-feature`, and `remove-feature` read and change only the base surface. When a variant overrides the feature being changed, a note names it: calls through that variant do not see the change. To change a variant's own value, edit its `overrides` in the surface document and save it with `surfaces update --file`.

## Read the budget

```sh
fabric agent-stream surfaces budget s-1a2b3c4d5e6f
```

```text
MONTH    SPENT   LIMIT    USED   REMAINING  EXCEEDED
2026-11  $12.50  $100.00  12.5%  $87.50     no
```

- Agent Stream counts spend only while `cost_tracking` has `enabled` set to true, a `monthly_budget_usd` above 0, and an `alert_threshold_percent`. The command says so instead of printing a table only when nothing was counted this month.
- It counts only the surface's own model calls. Judge and jury calls count against usage limits instead.
- Spend counted earlier this month stays, with the limit it was counted under, until the month ends. So after cost tracking is turned off or removed mid-month, the table still shows that SPENT and LIMIT.
- A changed limit shows in LIMIT only after the next counted call, so until then LIMIT shows the old one.
- A 403 that gives no reason of its own adds that the route needs `metrics.view`. A 403 with a reason, such as Terms and Conditions not yet accepted, shows that reason alone.
- `--output json` prints Agent Stream's answer, so a script can stop once the budget is used up:

  ```sh
  fabric agent-stream surfaces budget s-1a2b3c4d5e6f --output json | jq -e '.budget_exceeded | not'
  ```

## How changes are saved

Agent Stream replaces the whole surface on every save and has no version check. So `add-feature` and `remove-feature` save the way `surfaces update` does:

1. The CLI reads the surface and makes the change on this machine.
2. It checks the field names, as described above.
3. It reads the surface again, and stops with nothing saved if someone else saved it in the meantime. A save that lands in the short gap before the send is still overwritten.
4. It sends the whole surface. A change that leaves the surface as it was sends nothing.

When Agent Stream gives no answer to the send, such as a timeout, a dropped connection, or a 502 or 504 from a proxy in front of it, the surface may have been saved anyway. The error then says so: check it with `surfaces get <id>` or `surfaces features <id>` before running the command again, because a second `add-feature` or `remove-feature` can fail on the change the first one already made. A refusal from Agent Stream, such as a 400, prints as it is.

After a save, table output lists each changed field with its old and new value, and `--output json` prints the surface as Agent Stream has it after the save. `--dry-run` shows the changes and saves nothing; with `--output json` it prints `{ "dry_run": true, "changes": [...], "after": {...} }`. Agent Stream has no dry run of its own, so its checks only run on a real save: a route another surface uses and the drift block on any surface, and those on failover targets, canary splits, and usage limits only on an `llm` surface.

Notes go to standard error, so `--output json` stays one JSON document.
