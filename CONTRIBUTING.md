# Contributing

Affinidi Trust Fabric CLI is a single Rust binary, `fabric`. To propose a change, first discuss it by creating a new [GitHub issue](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/new). To report a security vulnerability, follow [`SECURITY.md`](SECURITY.md) instead.

## Development Requirements

- Rust `1.85` or newer, 2024 Edition (the minimum is declared in [`Cargo.toml`](Cargo.toml))
- An OS credential store: the macOS Keychain, Windows Credential Manager, or Linux Secret Service

For building, signing, and running the source, see [`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md). To find your way around the code, start with [`ARCHITECTURE.md`](ARCHITECTURE.md). For the recurring change shapes, such as adding a command or a table layout, see [`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md).

## Code Quality Expectations

1. Make the smallest correct change, with no dead code.
2. Cover changes with tests, positive and negative cases, and assert what is printed or sent rather than just the absence of errors. Don't use mocks or stubs: tests run against a scripted local server. [`docs/development/TESTING.md`](docs/development/TESTING.md) explains the layers and helpers.
3. Write comments that explain *why*, such as a gateway behaviour or a security reason, not *what* the code does.
4. Use clear, unambiguous names; avoid single letters and abbreviations.
5. Never print, log, or put tokens or secrets in error messages.
6. Treat help text as documentation. A new or changed command needs an accurate one-line summary, and an explanation and examples when it takes a JSON document, can't be undone, or has flags that interact.
7. Keep docs in sync with code in the same change (see [`docs/README.md`](docs/README.md)), and add user-facing changes to the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md).

## Commits

The repository only accepts commits that:

- **are signed** with a key GitHub can verify. See GitHub's guide to [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
- **follow [Conventional Commits](https://www.conventionalcommits.org)**: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, and so on, followed by a summary.

Pull requests are squash-merged, so the pull request title becomes the commit on `main` and follows the same format.

## Before Opening A Pull Request

Run the local checks and make sure CI passes:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. If you added or changed a dependency: `cargo deny check`

CI also runs a dependency audit, a security scan, and a coverage check that requires at least 80% coverage. Pull requests from forks don't run the security scan, because forks don't receive repository secrets; it runs once the change reaches `main`.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
