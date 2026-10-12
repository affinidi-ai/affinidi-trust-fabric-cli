# Build And Run The CLI From Source

This is the first-run path for building the Affinidi Trust Fabric CLI from this source
tree, running it against a gateway, and running the same checks CI runs. It is not the
user guide; for installing and using the CLI, start with the [`README.md`](../../README.md)
and the [user documentation](../README.md).

## Outcome

At the end of this guide you will have:

- a locally built `fabric` binary, codesigned on macOS if you have an identity,
- a saved connection to an Agent Gateway, with its token in your OS credential store, and
- a clean run of formatting, linting, tests, and the dependency licence check.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Git | Used to clone and work with the repository |
| Rust `1.85.0` or newer | The minimum version, declared as `rust-version` in [`Cargo.toml`](../../Cargo.toml). The crate uses the 2024 edition. Install with [rustup](https://rustup.rs). |
| An OS credential store | macOS Keychain, Windows Credential Manager, or Linux Secret Service. Tokens are stored there, never in a file. On Linux the CLI talks to the Secret Service over D-Bus with a pure Rust client, so building needs no system D-Bus library. |
| `make` | Optional. The [`Makefile`](../../Makefile) wraps the build and the macOS codesign step. |
| A macOS codesigning identity | Optional, macOS only. See [Codesigning on macOS](#codesigning-on-macos). |
| [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) | Optional. Needed to run the licence and advisory check locally. |
| An Agent Gateway you can sign in to | Needed to run commands that talk to a gateway |

CI builds, tests, lints, and measures coverage with Rust `1.96.0`, the toolchain pinned in
[`.github/workflows/checks.yaml`](../../.github/workflows/checks.yaml). A newer local
toolchain can report Clippy lints CI does not, and an older one can miss lints CI
reports. Use `1.96.0` when a lint result differs from CI:

```bash
rustup toolchain install 1.96.0
cargo +1.96.0 clippy --all-targets -- -D warnings
```

## Build

From the repository root:

```bash
git clone https://github.com/affinidi-ai/affinidi-trust-fabric-cli.git
cd affinidi-trust-fabric-cli
make build
```

| Command | Builds | Binary |
| --- | --- | --- |
| `make build` | Debug build, then codesign on macOS | `target/debug/fabric` |
| `make build-release` | Release build, then codesign on macOS | `target/release/fabric` |
| `make sign BIN=<path>` | Codesign an existing binary only | the path given |
| `make` or `make help` | Lists the targets | |
| `cargo build` | Debug build, unsigned | `target/debug/fabric` |

The first build downloads and compiles every dependency, so it takes a few minutes. Later
builds are incremental.

## Codesigning on macOS

Tokens live in the macOS Keychain. The Keychain ties an "Always Allow" choice to the
binary's code signature, and an unsigned or ad-hoc signed binary's signature is pinned to
its content hash. Every rebuild then looks like a new program, and macOS asks for Keychain
access again.

`make build` and `make build-release` avoid that by running the `sign` target, which signs
the binary with a stable identifier, `com.affinidi.trust-fabric-cli` (the `BUNDLE_ID`
variable), so the Keychain's trust survives rebuilds.

| Situation | What `sign` does |
| --- | --- |
| Not macOS | Prints a notice and skips signing |
| No codesigning identity | Prints a notice and skips signing. `security find-identity -v -p codesigning` lists what you have. |
| One identity | Signs with it |
| Several identities | Signs with the first, and prints a warning naming it |

To choose the identity yourself:

```bash
make build SIGN_IDENTITY="Developer ID Application: ..."
```

A plain `cargo build` works on macOS too; expect a Keychain prompt after each rebuild.

## Run Against A Gateway

Run the binary from `target/`, or through Cargo:

```bash
./target/debug/fabric agent-gateway --help
cargo run -- agent-gateway --help
```

Sign in and save a connection. By default this opens your browser for the gateway's
passkey or SSO login, and captures the token through a loopback redirect:

```bash
./target/debug/fabric agent-gateway login --host https://gateway.example.com
```

The connection is saved as `default` unless you name it with `--connection`. To sign in
with a personal access token instead, use `--pat`, and the CLI prompts for it.

Check the session, then try a read-only command:

```bash
./target/debug/fabric agent-gateway whoami
./target/debug/fabric agent-gateway surfaces list
```

For a gateway running on your own machine over plain HTTP, a loopback host such as
`http://localhost:<port>` or `http://127.0.0.1:<port>` is accepted as it is. Plain
`http://` to any other host is refused unless you pass `--allow-http`.

Where things are kept:

| What | Where |
| --- | --- |
| Connection names and hosts | `fabric/config.toml` in your user configuration directory: `~/Library/Application Support/fabric/config.toml` on macOS, `$XDG_CONFIG_HOME/fabric/config.toml` (usually `~/.config`) on Linux, `%APPDATA%\fabric\config.toml` on Windows |
| Tokens | The OS credential store, under the service name `affinidi-trust-fabric-cli` |

To remove a connection and its token, run `fabric agent-gateway logout`, which also ends a
browser session on the gateway, or `fabric agent-gateway config remove <name>`, which
does not contact the gateway.

## Run The Checks Locally

Run the same checks CI runs before you push:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

| Check | CI job | Notes |
| --- | --- | --- |
| `cargo fmt --check` | `fmt` | Style is set in [`rustfmt.toml`](../../rustfmt.toml), including a 120-column line width. Run `cargo fmt` to fix. |
| `cargo clippy --all-targets -- -D warnings` | `clippy` | Every warning fails the build. CI passes `-D warnings` as the Rust flags of the check, test, fmt, clippy, and coverage jobs. |
| `cargo test` | `test` | Unit and integration tests. See [`TESTING.md`](TESTING.md). |
| `cargo deny check` | `cargo-deny` | Licences, advisories, bans, and sources, configured in [`deny.toml`](../../deny.toml). Run it whenever you add or update a dependency. |

CI also runs `cargo check` (the `check` job), a dependency audit (`audit`), a security
scan (`rust-scan`), and a coverage check with an 80% threshold (`coverage`). Pull requests from forks skip the security scan, because forks don't receive
repository secrets; it runs once the change reaches `main`.

[`deny.toml`](../../deny.toml) allows exactly the licences Affinidi has approved. A
dependency under any other licence needs a maintainer's approval before it is added to the
list, so raise it in the pull request rather than adding an exception.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| macOS asks for Keychain access after every rebuild | Build with `make build` and a codesigning identity, as in [Codesigning on macOS](#codesigning-on-macos). |
| `make build` warns that several identities were found | Pass `SIGN_IDENTITY="..."` with the one you want. |
| Login refuses a plain `http://` host | Use `https://`, a loopback host, or pass `--allow-http` on a network you trust. |
| A command refuses to send the saved token to `--host` | The token is bound to the host it was saved for. Log in to the new host with its own `--connection`, or pass `--allow-host-override` if you mean it. |
| Clippy passes locally but fails in CI, or the reverse | Run Clippy with the CI toolchain: `cargo +1.96.0 clippy --all-targets -- -D warnings`. |
| `cargo deny check` reports a licence | The dependency's licence is not on the approved list in `deny.toml`. Choose another dependency, or raise it in the pull request. |

## Next Steps

- Read [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for how a command runs, end to end.
- Use [`MAKING_CHANGES.md`](MAKING_CHANGES.md) for the files to touch for common changes.
- Use [`TESTING.md`](TESTING.md) to choose where a test belongs.
- Read [`CONTRIBUTING.md`](../../CONTRIBUTING.md) before proposing a change.

## Related

- [`ARCHITECTURE.md`](../../ARCHITECTURE.md): how the CLI is put together.
- [`MAKING_CHANGES.md`](MAKING_CHANGES.md): recipes for common changes.
- [`TESTING.md`](TESTING.md): test layers and how to run them.
