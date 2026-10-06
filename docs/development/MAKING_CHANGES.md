# Making Changes

Recipes for the changes that come up repeatedly, organised by what you want to do rather
than by the file it lands in.

Each recipe lists the places to touch in order, and names an existing example to read
first. Read the example: it is more reliable than this page, which describes the shape
rather than the detail.

Before starting, read [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for how a command runs.
Every change needs tests; see [`TESTING.md`](TESTING.md) and
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

Most of these recipes land in [`src/commands.rs`](../../src/commands.rs). Its big
`match` statements are exhaustive, so after adding a variant, `cargo build` points at most
of the places that need a new arm. The places the compiler does not find, because they
end in a `_ => None` arm, are called out below.

## Add a command to an existing group

**Read first:** `SurfaceCommand::AddTransitPoint`, added in commit `50d8275`. It touches
every place on this list that applies to a command that changes a surface: all but
`create_kind`, `delete_confirmation`, and `list_layout`.

| Order | Place | Change |
| --- | --- | --- |
| 1 | The group's subcommand enum, such as `SurfaceCommand` | Add the variant. Its `///` doc comment becomes the help text; see [Write help text and examples](#write-help-text-and-examples). |
| 2 | An `Args` struct beside it, such as `AddTransitPointArgs` | Hold the arguments when there are more than one or two. |
| 3 | The group's handler, such as `run_surfaces` | Add the arm. The compiler finds this. |
| 4 | A handler function, such as `add_transit_point` | Do the work through the `GatewayClient`. |
| 5 | `resolve_surface_command` | Surface commands only: resolve a surface name to its ID. The compiler finds this. Do any validation that needs no gateway here too, so a bad argument fails before a request. |
| 6 | `update_confirmation`, `delete_confirmation`, `create_kind` | If the command changes, removes, or creates something, add it so table output prints one confirmation line. Not found by the compiler. |
| 7 | `list_layout` | If the command prints a list, give it a layout; see [Add a table layout for a list](#add-a-table-layout-for-a-list). Not found by the compiler. |
| 8 | Tests | Unit tests in the relevant `#[cfg(test)]` module of `commands.rs`, and an integration test in [`tests/`](../../tests/) if the output on standard output or standard error matters. |
| 9 | User documentation | Describe the command; see [`CONTRIBUTING.md`](../../CONTRIBUTING.md). |

**Watch for:**

- Decide what the handler returns. A `Value` goes to the shared printer. A handler that
  prints its own outcome returns `Option<Value>` and gives back `None`, as `run_surfaces`
  does for `create`.
- A command that sends a secret, or prints one, follows the existing pattern: read it from
  standard input or the environment, and add its flag to the `secret_flags` array in
  `inline_secret_warnings` if it can be typed inline. The interactive shell runs the same
  check on each line, and keeps a line that trips it out of its history.
- The interactive shell parses each line with the same `Cli`, so a new command needs no
  shell wiring.

## Add a new command group

**Read first:** `Command::JwtVerificationStrategies` and `run_jwt_strategies`, a small
group with one command beyond CRUD.

| Order | Place | Change |
| --- | --- | --- |
| 1 | `Command` | Add the variant, with `#[command(name = "…")]` when the name has a hyphen, and `command: <Group>Command` as a subcommand field. Its doc comment is the group's one-line summary in `fabric agent-gateway --help`. |
| 2 | A new `<Group>Command` enum | Define the group's commands. Reuse `CrudCommand` where it fits; see [the next recipe](#add-a-resource-that-fits-the-shared-crud-commands). |
| 3 | A new `run_<group>` function | Handle each command. Take `&GatewayClient`, plus `Output` if it prints itself. |
| 4 | The inner `match command` in `dispatch_with` | Add the arm that calls `run_<group>`. The compiler finds this. |
| 5 | `list_layout`, `create_kind`, `delete_confirmation`, `update_confirmation` | As in the previous recipe. Not found by the compiler. |
| 6 | Tests and user documentation | As in the previous recipe. |

**Watch for:**

- A group that needs no gateway, no token, and no saved connection belongs before the
  connection is resolved: either in the outer `match` of `dispatch_with`, as `config` is,
  or in `run_offline`, as `surfaces tool-gate-preview --gates-file` is. A variant handled
  in the outer `match` also goes in the `unreachable!()` arm at the end of the inner
  `match command`, which the compiler points at.
- A group whose output is not one value, such as a file written to disk or several
  tables, returns from `dispatch_with` directly, as `Audit`, `Payments`, `Metrics`, and
  `Logs` do.
- Every error passes through `add_terms_hint` in `run`. Do not add it again.

## Add a resource that fits the shared CRUD commands

`CrudCommand` gives a resource `list`, `get <id>`, `create --file`, `update <id> --file`,
and `delete <id>`. `run_crud` maps them onto `GET`, `GET {id}`, `POST`, `PUT {id}`, and
`DELETE {id}` under one base path, reading `--file` (or `-` for standard input) through
`read_json`.

**Read first:** `Command::Issuers`. For a resource with extra commands, read
`JwtStrategyCommand`. For per-group help, read `Command::Certificates`.

| Order | Place | Change |
| --- | --- | --- |
| 1 | `Command` | Add the variant with `command: CrudCommand`. |
| 2 | The inner `match command` in `dispatch_with` | Add `Command::<Name> { command } => run_crud(&client, "/v1/<path>", command).await?`. |
| 3 | [`src/tables.rs`](../../src/tables.rs) and `list_layout` | Add a layout for `list`. Without one, the list prints with the `GENERIC` layout. |
| 4 | `create_kind`, `delete_confirmation`, `update_confirmation` | Name the kind the way the other lines do, such as `"trust registry"`. |
| 5 | Unit tests in `commands.rs` | Add the resource to `each_list_command_prints_the_header_of_its_own_resource`, `every_create_kind_has_its_exact_name`, `every_delete_on_the_shared_commands_confirms_with_its_kind_and_id`, and `every_shared_update_names_its_kind_and_the_id_the_user_passed`. |
| 6 | [`tests/lists_and_deletes.rs`](../../tests/lists_and_deletes.rs) | Assert the table and the delete line. |

**When the resource needs more than CRUD**, wrap `CrudCommand` instead of copying it:

```rust
enum JwtStrategyCommand {
    #[command(flatten)]
    Crud(CrudCommand),
    /// Check that a JWKS URI is reachable and serves a parseable key set.
    #[command(name = "validate-jwks-uri")]
    ValidateJwksUri { uri: String },
}
```

The handler sends the `Crud` arm to `run_crud` and handles the rest itself, as
`run_jwt_strategies` does.

**When one group needs different help** on a shared subcommand, change it on that group
with `mut_subcommand` rather than editing `CrudCommand`, which every other group shares.
`Command::Certificates` does this with `certificate_reference_help`, which rewrites the
`about` and the `id` argument of `get`, `update`, and `delete` to say a name is accepted.
The test `only_certificates_describe_a_name_lookup_in_their_help` checks the change does
not leak into other groups.

**When the resource can be named by name as well as ID**, add a `Lookup` constant, as
`CERTIFICATE_LOOKUP` and `SECRET_LOOKUP` do, and resolve the reference with `resolve_id`
before calling `run_crud`, as `run_certificates` does.

**Watch for:** a resource whose routes do not follow the pattern does not belong in
`run_crud`. Secrets create through `/v1/secrets/new`, so `run_secrets` has its own enum
and handler.

## Add a table layout for a list

Every `list` command prints through one table format in
[`src/tables.rs`](../../src/tables.rs).

**Read first:** `tables::SURFACES`, which uses nested paths, a wide column, and a list
column.

| Order | Place | Change |
| --- | --- | --- |
| 1 | `src/tables.rs` | Add a `pub static <NAME>: Layout`. |
| 2 | `list_layout` in `commands.rs` | Map the list command to it. |
| 3 | `list_scope` in `commands.rs` | Only if the command takes a filter, so an empty result reads `No matching …` rather than `No … yet.` |
| 4 | `each_list_command_prints_the_header_of_its_own_resource` in `commands.rs` | Add the list command and its header row. |
| 5 | [`tests/lists_and_deletes.rs`](../../tests/lists_and_deletes.rs) | Assert the exact output, as `surfaces_list_prints_a_header_and_aligned_columns` does. |

A layout is an empty-list line and a list of columns:

```rust
pub static SURFACES: Layout = Layout {
    empty: "No surfaces yet.",
    columns: &[
        whole("NAME", &["name"]),
        id(&["surface_id", "id"]),
        col("PROTOCOL", &["access_point.protocol"]),
        col("ROUTE", &["access_point.route"]),
        wide("TARGET", &["target.endpoint"]),
        col("TRANSIT POINTS", &["transit.points"]),
    ],
};
```

| Helper | Column |
| --- | --- |
| `col(header, keys)` | Cut at 40 characters |
| `wide(header, keys)` | Cut at 60 characters, for URLs and DIDs |
| `whole(header, keys)` | Never cut, for names and identifiers people copy |
| `id(keys)` | `whole` with the header `ID` |
| `.or(text)` | Print `text` instead of `-` when the row has no value |

`keys` are dotted paths into each row, tried in order; the first with a value wins. A
`true` or `false` prints as `yes` or `no`, and a list prints its items' `alias`, `name`,
or `id`, comma separated, with a `+N more` suffix when they do not fit.

**Watch for:** write `empty` as `No <noun> yet.` The filtered and partial wordings,
`No matching <noun>.` and `No <noun> returned.`, are derived from that form, and any other
wording is printed unchanged for every scope.

## Write help text and examples

The `///` doc comments on clap commands and arguments are the `--help` users read.

**Read first:** `SurfaceCommand::ToolGatePreview` and `TOOL_GATE_PREVIEW_EXAMPLES`.

| Part | Where | Shown in |
| --- | --- | --- |
| First paragraph of the doc comment | On the variant or argument | `-h`, and the command lists of the parent's help |
| Later paragraphs | Same doc comment, after a blank `///` line | `--help` only |
| Examples | A `const` string, attached with `#[command(after_long_help = CONST)]` | The end of `--help` |

```rust
#[command(after_long_help = TOOL_GATE_PREVIEW_EXAMPLES)]
ToolGatePreview(ToolGatePreviewArgs),

/// Examples shown at the bottom of `tool-gate-preview --help`.
const TOOL_GATE_PREVIEW_EXAMPLES: &str = r#"Examples:
  Check the gates a surface has saved, named by its name or ID:
    fabric agent-gateway surfaces tool-gate-preview my-agent --tool delete_user,get_user

  Check gates that are not saved yet, from a file:
    fabric agent-gateway surfaces tool-gate-preview --gates-file gates.json --tool delete_user
..."#;
```

Write a one-line summary that says what the command does. Add a long description and
examples for a command that takes a JSON document, changes something that cannot be
undone, or has flags that interact. Where an argument names an entity, say where to find
it, as in `Surface ID or name (see \`fabric agent-gateway surfaces list\`)`.

**Watch for:** test the rendered help when it carries examples or behaviour users rely
on. `tool_gate_preview_help_ends_with_examples` finds the subcommand with
`Cli::command()`, renders it with `render_long_help`, and asserts on the text.

## Add a surface feature

Features are what `surfaces add-feature`, `remove-feature`, and `features` work with. They
are data, in the `FEATURES` registry in [`src/features.rs`](../../src/features.rs), which
mirrors the dashboard surface builder's map from element to payload path.

**Read first:** the `rate-limit` entry, which has one placement, and `mcp-tool-gating`,
which has one on the surface and one per transit point.

| Order | Place | Change |
| --- | --- | --- |
| 1 | `FEATURES` | Add a `Feature` with its `key`, `aliases`, `description`, and `placements`. |
| 2 | Each placement | Write it with `place!(Edge, Direction, "/json/pointer", ValueKind)`. |
| 3 | The `features.rs` tests | Add the feature to the expected list in `places_every_feature_with_no_flags`, which fails until every registry entry has an expectation. Add tests for any placement choice it introduces. |
| 4 | User documentation | Name the feature and the value it takes. |

| Field | Meaning |
| --- | --- |
| `key` | The name users type. Matched case-insensitively, like `aliases`. |
| `Edge` | `ApMa` (access point to managed agent), `MaExternal` (managed agent to external destinations, surface-wide), or `MaTp` (managed agent to a transit point; a pointer without `{tp}` on this edge is the target leg, as in `trust-check`) |
| `Direction` | `Request` or `Response` |
| Pointer | The JSON pointer on the surface document. `{tp}` stands for a transit point and is resolved from `--transit-point`. |
| `ValueKind` | `Object` replaces the object at the pointer; `List` appends to a list. Both take their value from `--json` or `--file`. `PolicyRef` builds a `{ policy_definition_id, require_agent_context }` reference from `--policy-id`, or takes `--json` or `--file` like the others. |

No other code needs to change. `features::find` resolves the name,
`Feature::select_placement` picks the placement from the flags, `features::build_patch`
makes the merge patch, and `on_surface` and `describe` pick the feature up for
`surfaces features`.

**Watch for:**

- A pointer containing `{tp}` must be on the `MaTp` edge.
  `every_pointer_with_a_transit_point_slot_is_on_the_ma_tp_edge` enforces it.
- Two placements of one feature that write the same pointer with the same kind count as
  one place, so they do not force the user to choose an edge.
- The pointer must match the gateway's surface document exactly. Before sending, the CLI
  refuses a `null` inside an object value and checks the surface's required fields with
  `surface_validate::check_surface`; it does not check the feature's own value. The
  gateway does, and `--dry-run` asks it to without saving.

## Related

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): the map this page assumes.
- [`GETTING_STARTED.md`](GETTING_STARTED.md): build and run the CLI from source.
- [`TESTING.md`](TESTING.md): which test layer each change belongs in.
