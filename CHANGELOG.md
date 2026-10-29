# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org). Until 1.0, a minor version may change the config, the database schema, or the CLI.

## [0.1.0-beta] - Unreleased

The first public beta. [Release notes](docs/releases/v0.1.0-beta.md).

### Added

- HTTP reverse proxy that holds real API keys and accepts `kmn_…` virtual keys, with profiles for OpenAI-compatible APIs (including OpenRouter), Anthropic, and any header-authenticated HTTP API.
- Credential storage with AES-256-GCM envelope encryption, credential rotation, and master key rotation (`keman rekey`).
- Virtual keys: create, disable, enable, revoke, expire (90 days by default), and rotate with a grace period (`keman key rotate`).
- Canary keys that answer like the real provider's 401 and raise a critical alert.
- Policies: CIDR and country allowlists, path and model allowlists, requests per minute, and daily and monthly spend caps for LLM keys.
- Detection rules: rate spike, spend spike, new country, new ASN, repeated allowlist violations, upstream auth-error bursts, use of a disabled or revoked key, and canary use. Opt-in auto-disable with a dry run.
- Alerts to Slack and HMAC-signed webhooks, with the commands to respond.
- `keman scan`: offline search for provider keys in files and git history.
- `keman exposure`: keys that are open to every address, never expire, or sit unused.
- `keman detection test`: replay built-in or your own abuse scenarios, or fire a live one.
- Terminal UI as the default command, a one-shot CLI, an admin API, Prometheus metrics, and an audit log.
- Release binaries for Linux, macOS, and Windows (amd64 and arm64 where supported), with SBOMs and cosign signatures; a signed multi-arch image on GHCR; and `scripts/install.sh`.

### Security

- The path allowlist refuses paths with `.` or `..` segments, backslashes, or control characters, so an upstream cannot resolve a request to an endpoint the allowlist refuses.

[0.1.0-beta]: https://github.com/kirank55/keman/releases/tag/v0.1.0-beta
