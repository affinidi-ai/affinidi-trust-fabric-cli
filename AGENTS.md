# Agent Instructions

This file holds the project rules for both human contributors and AI agents. Agent tools that support the `AGENTS.md` convention, including Claude Code, read it automatically. [`CONTEXT.md`](CONTEXT.md) is the terminology glossary, [`ARCHITECTURE.md`](ARCHITECTURE.md) maps the source, and [`CONTRIBUTING.md`](CONTRIBUTING.md) covers the contribution workflow.

## Project

`fabric` is a single Rust binary: the command-line client for Affinidi Trust Fabric appliances, starting with Agent Gateway. Commands are clap derive definitions in `src/commands.rs`; each one calls the gateway's management API through `GatewayClient` in `src/client.rs` and prints a table or JSON.

## Rules

- **Help text is documentation.** The `///` doc comments on clap commands and arguments are what users read in `--help`. Every statement in them must match what the handler does; read the handler before writing or changing help text. Use `#[command(after_long_help = ...)]` for examples, following `TOOL_GATE_PREVIEW_EXAMPLES`.
- **Never expose credentials.** Don't print, log, or include tokens, secrets, or private keys in output or error messages unless the user asked with `--reveal`. A saved token is only sent to its bound host.
- **Tests run against a scripted local server.** No mocks or stubs. Integration tests in `tests/` run the built binary with a temporary `HOME` and `XDG_CONFIG_HOME` and with `FABRIC_HOST`, `FABRIC_CONNECTION` and, unless the test sets it, `FABRIC_TOKEN` removed. See [`docs/development/TESTING.md`](docs/development/TESTING.md).
- **Keep docs in sync.** A change to a command updates its help text, the matching guide in [`docs/`](docs/README.md), and the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md) in the same change.
- **Use the glossary's terms.** In particular, a *connection* is a saved profile on this machine; a *gateway connection* is the `connections` resource.

## Checks

Before calling a change done:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Commits must be signed and follow [Conventional Commits](https://www.conventionalcommits.org).
