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

### Changed

- Every list prints as one table and every delete as one line.
- `surfaces create` output is clearer.

### Fixed

- Surface commands accept a surface name as well as its ID.
- `surfaces add-feature` and `remove-feature` pick the feature placement automatically.
- `surfaces update` can add or remove one tool pattern without resending the whole gate.
- Hardened token handling.
