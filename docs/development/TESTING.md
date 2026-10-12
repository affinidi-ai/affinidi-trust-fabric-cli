# Testing

Two test layers, what belongs in each, and how to run them.

[`CONTRIBUTING.md`](../../CONTRIBUTING.md) states the requirement: every change needs
tests, and the gateway is never mocked: tests run against a local HTTP server. This page says which layer to put a test in and
which helpers to reuse.

## Layers

| Layer | Lives in | Covers | Needs |
| --- | --- | --- | --- |
| Unit | `#[cfg(test)] mod tests` inline in each file under [`src/`](../../src/) | A function, a type, or a whole command run through `dispatch_with` against a local scripted server | Nothing |
| Integration | [`tests/`](../../tests/) | The built `fabric` binary as a user runs it: arguments, environment, standard output, standard error, and exit status | Nothing beyond `cargo test`, which builds the binary |

The crate is a binary with no library target, so unit tests compile into the binary's
test target, and integration tests reach the CLI only by running it.

At the time of writing there are about 860 unit tests and 73 integration tests.
`commands.rs` holds most of the unit tests, in several modules: `tests`,
`gateway_config_tests`, `secrets_certs_tests`, `identity_access_tests`, and
`observability_tests`.

## Choosing a layer

| The change is | Test it as |
| --- | --- |
| A pure function: a parser, a patch builder, a validator, a formatter | Unit, in the same file |
| A command's requests: method, path, body, and the order of calls | Unit, through `dispatch_with` or the handler, against a scripted server |
| How the client treats a response: errors, redaction, timeouts, redirects | Unit, in `client.rs`, against a local server |
| Which connection, host, or token a command uses | Unit, with an in-memory credential store |
| What a user sees on standard output or standard error | Integration |
| Behaviour that depends on the environment, `main.rs`, or the exit status | Integration |
| Help text | Unit, rendering the help from `Cli::command()` |

Assert values, not the absence of an error. Cover the refused case as well as the
accepted one. When a command must send nothing, assert that the server recorded no
request, or only the lookups you expect.

## Unit tests

Inline, in the module they cover:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_feature_by_key_and_alias() { /* … */ }
}
```

Async tests use `#[tokio::test]`.

### Local servers instead of mocks

The gateway is never mocked. A test that needs a gateway starts a real HTTP server on
`127.0.0.1:0`, points a `GatewayClient` or a saved connection at it, and asserts on what
the server received. Each test module defines the servers it needs; copy the closest one
rather than inventing a new shape.

| Helper | Where | Behaviour |
| --- | --- | --- |
| `one_shot_server` | `client.rs`, and the `tests` and `gateway_config_tests` modules of `commands.rs` | Answers the first request with a given status line (and, in `commands.rs`, a body), then stops. Returns the base URL. The `gateway_config_tests` version also returns a receiver carrying the request line, so a test can assert the method and path. |
| `scripted_server` | `gateway_config_tests` in `commands.rs` | Answers successive connections from a list of `(status line, body)` pairs and records each whole request, headers and body. A request beyond the script is recorded and answered with `UNSCRIPTED`, a `418`, so an unexpected call shows up in the recording rather than failing silently. |
| `scripted_server` | `secrets_certs_tests` in `commands.rs` | The same idea, recording request lines in an `Arc<Mutex<Vec<String>>>`. Used where a name lookup's list call and the call that follows must both be seen. |
| `capturing_server`, `echoing_server`, `dripping_server`, `silent_server` | `client.rs` | Capture the request head; echo the request's `Authorization` header back in the body (for redaction tests); send one byte at a time; or never answer (the last two for timeout tests) |

The scripted servers answer with `connection: close`, so every request arrives on a new
connection and is recorded in order.

To run a whole command, call `dispatch_with` with a `Config` pointing at the server and a
test credential store. The `dispatched_requests` helper in `gateway_config_tests` does
exactly that and returns the request lines.

### Credential stores in tests

A unit test must never read or write the OS keyring. `CredentialStore` is a trait, and
`dispatch_with` takes `&impl CredentialStore`, so tests pass an in-memory implementation
instead of `OsCredentialStore`.

| Store | Where | Behaviour |
| --- | --- | --- |
| `MemoryCredentials` | `config.rs` tests, `tests` in `commands.rs` | A `HashMap` behind a `Mutex`. Bound hosts work through the trait's default methods. |
| `MemoryStore` | `credentials.rs` tests | The same, for the trait's own tests |
| `NoCredentials` | `gateway_config_tests` in `commands.rs` | Holds nothing, and every write fails. For commands that pass `--token`. |
| `UnreachableKeyring` | `tests` in `commands.rs` | Panics on any use, for commands given both a host and a token, which must never open the credential store |
| `UnwritableCredentials` | `tests` in `commands.rs` | Wraps `MemoryCredentials`, but `set_token` fails, for the path where a bound host cannot be recorded |
| `FailingCredentials` | `config.rs` tests | Writes fail, for legacy token migration |
| `NoSecretService` | `config.rs` tests, Linux only | Every call fails as the Secret Service client does with no D-Bus session, for the migration hint |

The one test that does use the real keyring, `os_keyring_round_trip` in
`credentials.rs`, is marked `#[ignore]` so it never runs by default.

### Environment variables

Some code reads process-wide environment variables, such as the Prometheus credentials
and the `FABRIC_*` variables clap reads at parse time. A test that reads or changes one
takes the lock that guards it first, so tests do not race each other:

| Lock | Where | Guards |
| --- | --- | --- |
| `PROCESS_ENV_LOCK` | `commands.rs`, used by `observability_tests` | `FABRIC_METRICS_USERNAME` and `FABRIC_METRICS_PASSWORD`, which `clear_metrics_credentials` removes before a parse |
| `FABRIC_CONNECTION_ENV_LOCK` | `tests` in `commands.rs` | `FABRIC_CONNECTION` |
| `FABRIC_PAT_ENV_LOCK` | `tests` in `commands.rs` | `FABRIC_PAT` |

### Help text

A test can render help from the clap definition and assert on it, as
`tool_gate_preview_help_ends_with_examples` does with `Cli::command()` and
`render_long_help`. `only_certificates_describe_a_name_lookup_in_their_help` also calls
clap's `debug_assert`, which fails on a conflicting or malformed definition.

## Integration tests

Each file in [`tests/`](../../tests/) runs the built binary through
`env!("CARGO_BIN_EXE_fabric")`.

| File | Covers |
| --- | --- |
| [`lists_and_deletes.rs`](../../tests/lists_and_deletes.rs) | The tables lists print, the one-line confirmations of deletes and other changes, and what goes to standard output versus standard error |
| [`env_token_and_host_note.rs`](../../tests/env_token_and_host_note.rs) | The `note:` printed when both the token and the host come from the environment, including in the interactive shell |

Every run is isolated from your own configuration:

- `HOME` is a fresh temporary directory, and `XDG_CONFIG_HOME` is a directory inside it.
- A `config.toml` with a saved connection is written to both
  `Library/Application Support/fabric/` and `xdg/fabric/` under that home, because the
  configuration directory differs between macOS and Linux.
- `FABRIC_HOST`, `FABRIC_CONNECTION`, and `FABRIC_TOKEN` are removed from the inherited
  environment, and each test sets only the ones it needs. `lists_and_deletes.rs` always
  sets `FABRIC_TOKEN` to a test value.
- The binary still uses the OS credential store, which the tests do not replace. A token
  from `FABRIC_TOKEN` or `--token` means none is read from it, but an
  `env_token_and_host_note.rs` test that passes no token, such as
  `a_host_from_the_environment_alone_prints_no_note`, looks up the `test` connection
  there before the command fails.

In `lists_and_deletes.rs`, the `fabric` helper takes a list of `Reply` values, built with
`reply(method, path, status, body)`, and starts a server on a thread that answers each
request whose method and path match, with `/api` added to the path and the query
ignored. Anything else gets `404 Not Found`. The helper returns an `Output` with
`stdout`, `stderr`, the recorded `requests`, and `success`.

`env_token_and_host_note.rs` needs no server: its saved and environment hosts are
unreachable loopback ports, and it asserts only on standard error.

## Running tests

| Command | Runs |
| --- | --- |
| `cargo test` | Everything |
| `cargo test --bin fabric` | Unit tests only |
| `cargo test --bin fabric <filter>` | Unit tests whose path contains `<filter>`, such as `surface_patch::` or `pkce_challenge` |
| `cargo test --test lists_and_deletes` | One integration test file |
| `cargo test --test lists_and_deletes <filter>` | Matching tests in that file |
| `cargo test --bin fabric os_keyring_round_trip -- --ignored` | The ignored keyring test. It writes, then deletes, a temporary entry in your real credential store. |
| `cargo test --no-run` | Compile the tests without running them |

## Coverage

CI's `coverage` job fails below 80% coverage, the threshold set in
[`.github/workflows/checks.yaml`](../../.github/workflows/checks.yaml). New code that is
reachable only through a gateway call is covered by running the command against a local
server, as above, not by skipping it.

## Before opening a pull request

The checks from [`CONTRIBUTING.md`](../../CONTRIBUTING.md):

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

And, when you added or updated a dependency:

```bash
cargo deny check
```

## Related

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): the code the tests exercise.
- [`GETTING_STARTED.md`](GETTING_STARTED.md): build and run the CLI, and the CI toolchain.
- [`MAKING_CHANGES.md`](MAKING_CHANGES.md): which tests each recipe needs.
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md): what a contribution has to include.
