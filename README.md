# Affinidi Trust Fabric CLI

_Manage Affinidi Trust Fabric from your terminal._

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml) [![Documentation](https://img.shields.io/badge/docs-Trust_Fabric-9047ff.svg)](https://docs.affinidi.com/products/affinidi-trust-fabric/) [![GitHub Issues](https://img.shields.io/badge/GitHub-Issues-181717?logo=github)](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues)

`fabric` is the command-line client for [Affinidi Trust Fabric](https://www.affinidi.com/trust-fabric), the control layer for AI agents. It manages an [Agent Gateway](https://github.com/affinidi-ai/agent-gateway) through its management API: the same Agent Surfaces, policies, identities, secrets, and settings you see in the dashboard, from a terminal, a script, or a CI job.

> [!IMPORTANT]
> **Project status:** the CLI is under active development. Commands and output may change between minor releases.

## Why use it

- **Scriptable.** Every command that returns data can print JSON with `--output json`, and `fabric agent-gateway api` calls any management endpoint that has no dedicated command.
- **Safe with credentials.** Tokens live in the OS credential store, never in a file, and a saved token is only sent to the host it was issued for, unless you pass `--allow-host-override`. Secrets and private keys stay masked in output unless you pass `--reveal`.
- **Small, precise edits.** Change one field of an Agent Surface with `--set`, add a feature or transit point by name, and check an edit with `--dry-run` before saving it.
- **Built for automation.** Sign in through the browser for day-to-day work, or with a personal access token in CI.

## How it works

Commands take the shape `fabric <appliance> <command>`. Agent Gateway is the first appliance, under `agent-gateway`:

```sh
fabric agent-gateway surfaces list
```

`fabric agent-gateway login` signs you in to a gateway and saves it as a named connection. Later commands use the current connection, so the host and token don't need repeating. Each command makes one or more calls to the gateway's management API and prints the result as a table or as JSON.

## What you can manage

| Area | Command groups | Guide |
| --- | --- | --- |
| Sign-in and tokens | `login`, `logout`, `config`, `whoami`, `tokens` | [Authentication](docs/AUTHENTICATION.md) |
| Agent Surfaces | `surfaces`, `policies` | [Agent Surfaces](docs/SURFACES.md) |
| Identity and access | `users`, `identities`, `api-keys`, `tenant-ownership`, `jwt-verification-strategies` | [Identity and access](docs/IDENTITY_AND_ACCESS.md) |
| Secrets and credentials | `secrets`, `certificates`, `delegation-vault` | [Secrets and credentials](docs/SECRETS_AND_CREDENTIALS.md) |
| Observability | `audit`, `payments`, `metrics`, `logs` | [Observability](docs/OBSERVABILITY.md) |
| Gateway configuration | `runtime`, `settings`, `user-settings`, `terms`, `notifications` | [Gateway configuration](docs/GATEWAY_CONFIGURATION.md) |
| Trust and connectivity | `issuers`, `authorities`, `trust-registries`, `mediators`, `connections`, `connection-points`, `mcp-proxies`, `a2a-proxies`, `sts-clients`, `credential-providers`, `integrations` | [Manage other resources](docs/SCRIPTING_AND_OUTPUT.md#manage-other-resources) |
| Anything else | `api`, `shell` | [Scripting and output](docs/SCRIPTING_AND_OUTPUT.md), [Interactive shell](docs/INTERACTIVE_SHELL.md) |

## What it looks like

Lists print as aligned tables:

```text
$ fabric agent-gateway surfaces list
NAME         ID                                    PROTOCOL  ROUTE         TARGET                   TRANSIT POINTS
Sales Agent  3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c1a90  a2a       /sales-agent  http://sales-agent:3000  -
Support Bot  9a1d7c44-2e3f-4b8a-b6d1-7f0e3c5a2b18  mcp       /support      http://support:8080      github,slack
```

Add `--output json` to get JSON instead, for scripts and tools such as `jq`.

## Quickstart

### Before you start

You need access to a running Agent Gateway: its address, such as `https://gateway.example.com`, and an account that can sign in through the browser or a personal access token. To deploy a gateway, see the [hosted Agent Gateway documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/).

### Install

Install with Cargo, using Rust 1.85 or newer from [rustup](https://rustup.rs):

```sh
cargo install --git https://github.com/affinidi-ai/affinidi-trust-fabric-cli
fabric --version
```

There are no prebuilt binaries yet. To upgrade later, run the same command with `--force`. Tokens are stored in the macOS Keychain, Windows Credential Manager, or Linux Secret Service.

> [!NOTE]
> On macOS, "Always Allow" on the Keychain prompt lasts until you reinstall, because an unsigned binary is identified by its content. Building from source with `make build` signs the binary, if your Keychain has a codesigning identity, so the choice survives rebuilds.

### Sign in

```sh
fabric agent-gateway login --host https://gateway.example.com          # browser: passkey or SSO
fabric agent-gateway login --host https://gateway.example.com --pat    # personal access token, for CI
fabric agent-gateway whoami
```

### Run your first commands

```sh
fabric agent-gateway surfaces list
fabric agent-gateway surfaces create --name "Sales Agent" --target-endpoint http://sales-agent:3000
fabric agent-gateway surfaces update "Sales Agent" --set access_point.rate_limit.requests=100 --dry-run
fabric agent-gateway surfaces get "Sales Agent" --output json
```

Run `fabric agent-gateway --help` to list every command group, add `--help` to any command for its options, or run `fabric agent-gateway shell` to work interactively.

## Documentation

| Goal | Documentation |
| --- | --- |
| Sign in, save connections, and use personal access tokens | [`docs/AUTHENTICATION.md`](docs/AUTHENTICATION.md) |
| Look up a term | [`CONTEXT.md`](CONTEXT.md) |
| Find the guide for a command group | [`docs/README.md`](docs/README.md) |
| Use the CLI in scripts: JSON, environment variables, exit codes | [`docs/SCRIPTING_AND_OUTPUT.md`](docs/SCRIPTING_AND_OUTPUT.md) |
| Understand how the CLI works and where the code is | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Build from source and make a change | [`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md) |
| Contribute a change | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Learn about Trust Fabric and Agent Gateway | [Hosted product documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/) |

## What is in this repository

One Rust binary, `fabric`, built from [`src/`](src/) with [clap](https://docs.rs/clap) for argument parsing and [reqwest](https://docs.rs/reqwest) for the management API. There is no local state beyond a small configuration file and the tokens in the OS credential store. [`ARCHITECTURE.md`](ARCHITECTURE.md) maps the CLI to the source tree.

## Contributing and support

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the discuss-first workflow, required checks, and tests.

For usage questions, use the [Affinidi support form](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v). For reproducible problems or feature requests, search or open a [GitHub issue](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues).

To report a security vulnerability, follow the private disclosure process in [`SECURITY.md`](SECURITY.md).

## License

Licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
