# Contributing

Affinidi Trust Fabric CLI is a single Rust binary, `fabric`. To propose a change, first discuss it by creating a new [GitHub issue](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/new). To report a security vulnerability, follow [`SECURITY.md`](SECURITY.md) instead.

## Development Requirements

- Rust `1.85` or newer, 2024 Edition (the minimum is declared in [`Cargo.toml`](Cargo.toml))
- An OS credential store: the macOS Keychain, Windows Credential Manager, or Linux Secret Service

For building, signing, and running the source, see [`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md). To find your way around the code, start with [`ARCHITECTURE.md`](ARCHITECTURE.md). For the recurring change shapes, such as adding a command or a table layout, see [`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md).

## Code Quality Expectations

1. Make the smallest correct change, with no dead code.
2. Cover changes with tests, positive and negative cases, and assert what is printed or sent rather than just the absence of errors. Don't mock the gateway: tests run against a scripted local HTTP server. [`docs/development/TESTING.md`](docs/development/TESTING.md) explains the layers and helpers.
3. Write comments that explain *why*, such as a gateway behaviour or a security reason, not *what* the code does.
4. Use clear, unambiguous names; avoid single letters and abbreviations.
5. Never print, log, or put tokens or secrets in error messages.
6. Treat help text as documentation. A new or changed command needs an accurate one-line summary, and an explanation and examples when it takes a JSON document, can't be undone, or has flags that interact.
7. Keep docs in sync with code in the same change (see [`docs/README.md`](docs/README.md)), and add user-facing changes to the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md).

## Commits

Commits:

- **must follow [Conventional Commits](https://www.conventionalcommits.org)**: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, and so on, followed by a summary. The repository rejects other commit messages.
- **should be signed** with a key GitHub can verify. See GitHub's guide to [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

Pull requests should be squash-merged, so the pull request title becomes the commit on `main`; write it in the same format.

## Before Opening A Pull Request

Run the local checks and make sure CI passes:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. If you added or changed a dependency: `cargo deny check`

CI also runs a dependency audit, a security scan, and a coverage check that requires at least 80% coverage. Pull requests from forks don't run the security scan, because forks don't receive repository secrets; it runs once the change reaches `main`.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding obvious comments about things like code styling and indentation.
  **If you see yourself wanting to do that more than once - open an issue to update the
  clippy/rustfmt rules to address this concern once and for all. Code reviews should be
  about logic, not indenting or adding more newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
