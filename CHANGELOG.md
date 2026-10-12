# Changelog

All notable changes to Affinidi Trust Fabric CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `fabric agent-gateway` commands for managing Affinidi Agent Gateway, including login, connection profiles, surfaces, identity and access resources, secrets and certificates, observability, and gateway configuration.
- An interactive shell, `fabric agent-gateway shell`.
- `surfaces tool-gate-preview`, which shows whether tools would be allowed or denied by a surface's tool gates.
- `surfaces features`, which shows the features a surface has and how to remove them.
- `surfaces add-transit-point` and `surfaces remove-transit-point`.
- `whoami` shows details of the personal access token in use.
- With no saved connection selected, `FABRIC_HOST` and `FABRIC_TOKEN` (or `--host` and `--token`) together run any gateway command without `login` and without the OS credential store, so the CLI works on a Linux server with no desktop session.

### Changed

- Every list prints as one table and every delete as one line.
- `surfaces create` output is clearer.
- With a saved connection selected, a command given both `FABRIC_HOST` and `FABRIC_TOKEN` (or `--host` and `--token`) no longer opens the OS credential store either, and `whoami` reports `token_stored: false` for a token given that way.
- On Linux the binary no longer links the system `libdbus` library, and a Secret Service that can't be reached over D-Bus gives an error that suggests `FABRIC_HOST` and `FABRIC_TOKEN`.

### Fixed

- Surface commands accept a surface name as well as its ID.
- `surfaces add-feature` and `remove-feature` pick the feature placement automatically.
- `surfaces update` can add or remove one tool pattern without resending the whole gate.
- Hardened token handling.
