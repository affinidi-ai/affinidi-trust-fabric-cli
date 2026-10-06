# Repository Documentation

The documents here explain what the Affinidi Trust Fabric CLI does, how it is built, and how to change it. They describe the checked-out revision exactly, including how each command behaves against the gateway and the edge cases it handles.

The hosted [Affinidi Trust Fabric documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/) covers the products themselves: what Agent Gateway is, how to deploy and operate it, and its concepts.

## Start Here

| Document | Scope |
| --- | --- |
| [README](../README.md) | What the CLI is, installing it, and a quickstart |
| [Authentication](AUTHENTICATION.md) | Signing in, saved connections, session lifetime, and personal access tokens |
| [Project glossary](../CONTEXT.md) | The terms used in commands, help text, and these documents |
| [Scripting and output](SCRIPTING_AND_OUTPUT.md) | How results and errors print, JSON output, environment variables, and exit codes |
| [Interactive shell](INTERACTIVE_SHELL.md) | Running Agent Gateway commands without the `fabric agent-gateway` prefix |

## Agent Gateway Commands

| Document | Command groups |
| --- | --- |
| [Agent Surfaces](SURFACES.md) | `surfaces`: create and edit surfaces, the `--set`/`--add` path syntax, dry runs, features, transit points, and tool gate previews |
| [Identity and access](IDENTITY_AND_ACCESS.md) | `users`, `identities`, `api-keys`, `tenant-ownership`, `jwt-verification-strategies`, and their request documents |
| [Secrets and credentials](SECRETS_AND_CREDENTIALS.md) | `secrets`, `certificates`, and `delegation-vault` |
| [Observability](OBSERVABILITY.md) | `audit`, `payments`, `metrics`, `logs`, and the dashboard endpoints left to `api` |
| [Gateway configuration](GATEWAY_CONFIGURATION.md) | `runtime`, `settings`, `user-settings`, `terms`, and `notifications` |

Every command also documents its options in its help text: `fabric agent-gateway <group> <command> --help`.

## Development

| Document | Scope |
| --- | --- |
| [Architecture](../ARCHITECTURE.md) | How the CLI is put together and where in `src/` each part lives |
| [Build From Source](development/GETTING_STARTED.md) | Build, sign, and run this source tree locally |
| [Making Changes](development/MAKING_CHANGES.md) | Recipes for the recurring change shapes, such as adding a command |
| [Testing](development/TESTING.md) | The test layers, the scripted local server, and how to run tests |
| [Contributing](../CONTRIBUTING.md) | Contribution process and required checks |
| [Security policy](../SECURITY.md) | Private vulnerability reporting |
