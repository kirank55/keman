# Beta

An open-source, self-hosted proxy that holds your real API keys. Apps get virtual keys instead. Each virtual key can be limited, watched and revoked without touching the real key.

The beta supports HTTP only. Later versions add other protocols, starting with MongoDB and Redis.

## Beta scope

**In**

- Single binary and Docker image. Single instance.
- HTTP reverse proxy for bearer-token and header-key APIs.
- Provider profiles:
  - OpenAI-compatible: full support, including token usage and cost.
  - Anthropic: full support, including token usage and cost.
  - Generic HTTP: any host, with auth in a header, and a path allowlist.
- Encrypted storage of real keys.
- Virtual keys: create, list, disable, enable, revoke, expire.
- Canary keys: decoy virtual keys that alert on any use.
- Inline limits: rate limit, spend caps, path and model allowlists, CIDR and country allowlists.
- Behavior alerts: rate spike, spend spike, new country or ASN, upstream auth-error burst, use of a disabled or revoked key.
- Opt-in auto-disable.
- Alerts to Slack, email and signed webhooks.
- CLI and admin API.
- Audit log.
- SQLite storage.

**Out**

- Non-HTTP protocols.
- Multi-instance or high-availability deployment, and Postgres.
- Dashboard UI.
- Hosted version, SSO and teams.
- Model routing, fallbacks and caching.
- Storing request or response bodies, and content inspection.
- TLS-intercepting forward proxy mode.

## How it works

1. The app sends its request to the proxy with a virtual key. For OpenAI-style SDKs, only the base URL and the key change.
2. The proxy finds the key by its prefix and checks its status, expiry and network rules.
3. Inline limits run in memory.
4. The proxy decrypts the real key, swaps it into the auth header and forwards to the credential's fixed upstream host.
5. The response streams back unbuffered. Token usage is read from the response, and spend is reconciled.
6. A metadata event is queued. A background worker stores it, updates per-key baselines, runs the detection rules and sends alerts.

## Core model

Every model is protocol-agnostic, so new protocols add an adapter instead of a new data model.

| Entity | Purpose |
| --- | --- |
| `upstream` | Target service: protocol (`http` in beta), host, port, TLS settings. |
| `credential` | The real secret for an upstream, encrypted. Write-only. |
| `virtual_key` | What apps use. Prefix plus a random secret; only the hash is stored. Status: `active`, `disabled`, `revoked`, `canary`. |
| `policy` | Limits and allowlists for a virtual key. Mode: `alert_only` (default) or `auto_disable`. |
| `event` | Metadata for one request: time, key, IP, country, ASN, operation, status, latency, sizes, tokens, cost. |
| `detection` | A rule that fired, with its evidence. Evidence is counts and categories, never content. |
| `audit_log` | Append-only record of admin actions and key lifecycle changes. |

## Protocol adapters

Each protocol implements one interface:

- **Accept:** listen and speak the protocol to the client.
- **Authenticate:** pull the virtual credential out of the protocol's auth step.
- **Inject:** connect upstream using the real credential.
- **Describe:** turn each request or command into an event (operation, target, size).
- **Enforce:** apply that protocol's allowlists, such as paths, models, commands or collections.

| Protocol | Version | Virtual credential | Operation |
| --- | --- | --- | --- |
| HTTP | Beta | Bearer token or API-key header | Method plus path template |
| Redis | Later | `AUTH` username and password | Command |
| MongoDB | Later | SCRAM username and password | Command plus database and collection |

## Security

- Envelope encryption. A master key from an env var or file wraps a data key, and the data key encrypts each credential with AES-256-GCM. The credential id is bound to the ciphertext so ciphertexts can't be swapped.
- Real keys are never returned by any API. Only their last 4 characters are shown.
- Virtual keys are 32+ random bytes, shown once and stored as SHA-256 hashes. A fixed prefix makes them detectable by secret scanners.
- The upstream host is fixed per credential and never taken from the request. Redirects to other hosts are blocked, and routing headers are stripped.
- Auth headers are redacted everywhere. Tests assert that no key material appears in logs.
- The admin API runs on a separate port or Unix socket and needs an admin token.
- Bodies, headers and query strings are never logged. Event retention is 14 days by default.
- No telemetry and no phone-home.
- Releases are signed, with an SBOM.
- Not protected: anyone who can read the proxy's memory can read the keys. Run it isolated from the apps that use it: non-root, read-only filesystem, network egress only to upstream hosts.

## Failure behavior

| Failure | Behavior |
| --- | --- |
| Store unavailable | Fail closed (503). |
| Limit or allowlist violated | Block: 403, or 429 for rate limits. |
| Detection or alert delivery fails | Fail open. Count the skipped events. |
| Event queue full | Drop the oldest events and increment a counter. |
| Key disabled or revoked | Takes effect on the next request. |

## Detection rules

- Behavior rules only alert. Inline blocking only enforces limits the user set.
- Each key has a learning period of 7 days or 500 requests before behavior rules fire.
- Every ratio rule has an absolute floor.
- Auto-disable is opt-in per key. It needs 3 medium-or-higher signals within 15 minutes and has a cooldown. It disables the key and never revokes it.
- Dry-run mode shows which requests auto-disable would have blocked before you turn it on.
- Alerts are deduplicated per incident and include the evidence plus the CLI command to disable the key or allowlist the source.

## Targets

| Metric | Target |
| --- | --- |
| Proxy overhead, p50 | < 3 ms |
| Proxy overhead, p99 | < 10 ms |
| Quickstart, fresh machine | < 10 min |

Publish the benchmark in the repo.

## Beta is done when

- OpenAI, Anthropic and one generic HTTP API work through one binary, including streaming with the official SDKs.
- Revoking a key blocks its next request.
- A canary key and a replayed attack scenario both trigger the right alerts and auto-disable.
- The p99 overhead target is met in the published benchmark.
- A stranger completes the quickstart unaided.
- The README, threat model and `SECURITY.md` are published.
