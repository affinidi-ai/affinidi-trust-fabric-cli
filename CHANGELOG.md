# Changelog

All notable changes to Affinidi Trust Fabric CLI are documented in this file. Entries are written from pull request titles when a release is made, and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-13

### ✨ New

- `fabric agent-gateway` commands for managing Affinidi Agent Gateway, including login, connection profiles, surfaces, identity and access resources, secrets and certificates, observability, and gateway configuration.
- An interactive shell, `fabric agent-gateway shell`.
- `surfaces tool-gate-preview`, which shows whether tools would be allowed or denied by a surface's tool gates.
- `surfaces features`, which shows the features a surface has and how to remove them.
- `surfaces add-transit-point` and `surfaces remove-transit-point`.
- Surface commands accept a surface name as well as its ID.
- `surfaces add-feature` and `remove-feature` pick the feature placement automatically.
- `surfaces update` can add or remove one tool pattern without resending the whole gate.
- `surfaces create` shows the new surface's id, name, route, protocol and target.
- Every list prints as one table and every delete as one line.
- `whoami` shows details of the personal access token in use, and the gateway's version as `gateway_version`.
- `FABRIC_HOST` and `FABRIC_TOKEN` (or `--host` and `--token`) together run any gateway command without `login` and without the OS credential store, so the CLI works on a Linux server with no desktop session. `whoami` reports `token_stored: false` for a token given that way.
- A saved token is only sent to the host it was saved for unless `--allow-host-override` is given, and a remote `http://` host is refused unless `--allow-http` is given.
- Prebuilt Linux binaries for x86_64 and aarch64, with a `SHA256SUMS` file, attached to each GitHub release. On Linux the binary doesn't link `libdbus`, and a Secret Service that can't be reached over D-Bus gives an error that suggests `FABRIC_HOST` and `FABRIC_TOKEN`.
