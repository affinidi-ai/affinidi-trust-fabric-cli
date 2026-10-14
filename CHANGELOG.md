# Changelog

All notable changes to Affinidi Trust Fabric CLI are documented in this file. Entries are written from pull request titles when a release is made, and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commits/v0.1.0) (2026-10-13)

### ✨ New

* `fabric agent-gateway` commands for managing Affinidi Agent Gateway, including login, connection profiles, surfaces, identity and access resources, secrets and certificates, observability, and gateway configuration
* an interactive shell, `fabric agent-gateway shell`
* `surfaces tool-gate-preview`, which shows whether tools would be allowed or denied by a surface's tool gates ([#3](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/3)) ([a49aa1a](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/a49aa1a5e8b8172deb8a027f186daddf0f12b609))
* `surfaces features`, which shows the features a surface has and how to remove them ([#6](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/6)) ([784acb6](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/784acb6e1cca43f1e8725fa932e6e031313bb993))
* `surfaces add-transit-point` and `surfaces remove-transit-point` ([#11](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/11)) ([50d8275](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/50d8275f135c1f39d3b56a87119664eeab3f1d41))
* `surfaces create` shows the new surface's id, name, route, protocol and target, and `whoami` shows details of the personal access token in use ([#12](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/12)) ([a141524](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/a141524fa0690a98d5fc949ca92f75c6e4f53a18))
* prebuilt Linux binaries for x86_64 and aarch64, with a `SHA256SUMS` file, attached to each GitHub release ([#19](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/19)) ([87833b7](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/87833b7d6183566accf0b2f343c248fa8a67094f))

### 🛠️ Fixes

* `surfaces add-feature` and `remove-feature` pick the feature placement automatically ([#4](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/4)) ([5e8cebb](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/5e8cebbeda7cb6227cb521f016674a1c9a86fdd0))
* surface commands accept a surface name as well as its ID ([#5](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/5)) ([d2216f6](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/d2216f6e4fff6e5f4fad498ff52473d074d1e13d))
* `surfaces update` can add or remove one tool pattern without resending the whole gate ([#7](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/7)) ([96805f3](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/96805f360ff24207690d6540a28fbc1f8d3f5f79))
* every list prints as one table and every delete as one line ([#9](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/9)) ([dec89bd](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/dec89bd5c9cf148a9393735897041fc1756a6562))
* `whoami` shows the gateway's version as `gateway_version` ([#17](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/17)) ([e7334be](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/e7334be57d93f4bcab4dd43579fc14f0b26cd60a))
* `FABRIC_HOST` and `FABRIC_TOKEN` (or `--host` and `--token`) together run any gateway command without `login` and without the OS credential store, so the CLI works on a Linux server with no desktop session, and `whoami` reports `token_stored: false` for a token given that way. On Linux the binary doesn't link `libdbus`, and a Secret Service that can't be reached over D-Bus gives an error that suggests `FABRIC_HOST` and `FABRIC_TOKEN` ([#18](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/18)) ([e8bb5fe](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/e8bb5fe03aa0f177a63c9c0370f59f6140d3c9ff))

### 🔒 Security

* a saved token is only sent to the host it was saved for unless `--allow-host-override` is given, and a remote `http://` host is refused unless `--allow-http` is given ([#10](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/10)) ([290981a](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/commit/290981a41846681a62919f52cbba96ca0f8dc982))
