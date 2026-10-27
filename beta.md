# Beta

`beta.md` takes priority. `PLAN.md` is old and is not the decision maker. Where they disagree, follow this document.

An open-source, self-hosted proxy that holds your real API keys. Apps get virtual keys instead. Each virtual key can be limited, watched and revoked without touching the real key.

The beta supports HTTP only. Other protocols, such as Redis and MongoDB, may come later. The beta keeps a `protocol` field on upstreams but does not build anything else for them.

## Decisions

- **Stack:** Go, the standard library `net/http` reverse proxy, and a pure-Go SQLite driver, so the binary needs no CGO.
- **License:** Apache-2.0.
- **Configuration:** server settings live in a YAML config file, with env var overrides. Upstreams, credentials, keys and policies live in SQLite and are managed through the CLI or admin API.
- **Listeners:** the proxy listens on `0.0.0.0:8080`. The admin API and `/metrics` listen on `127.0.0.1:8081` or a Unix socket, and need the admin token.
- **GeoIP:** not bundled. The user points the config at a GeoLite2 or DB-IP `.mmdb` file. Without one, country and ASN rules are off, and any policy that uses a country allowlist fails at startup.
- **Virtual key format:** `kmn_<id>_<secret>`. The id is 8 random base62 characters, used for lookup. The secret is 32 random bytes in base62. Canary keys use the same format.
- **Money:** integer microdollars everywhere. No floats.
- **Time:** UTC everywhere. All time-based logic reads from an injectable clock, so tests can replay history.

## Beta scope

**In**

- Single binary and Docker image. Single instance.
- HTTP reverse proxy, HTTP/1.1 and HTTP/2, for APIs that authenticate with a header or HTTP Basic.
- Provider profiles:
  - OpenAI-compatible: full support, including token usage and cost.
  - Anthropic: full support, including token usage and cost.
  - Generic HTTP: any host, auth in a header or HTTP Basic, and a required path allowlist.
- Encrypted storage of real keys, credential rotation and master key rotation.
- Virtual keys: create, list, disable, enable, revoke, expire.
- Canary keys: decoy virtual keys that alert on any use.
- Inline limits: per-key rate limit, daily and monthly spend caps, path and model allowlists, CIDR and country allowlists.
- Behavior alerts: rate spike, spend spike, new country, new ASN, repeated allowlist violations, upstream auth-error burst, use of a disabled or revoked key, canary use.
- Opt-in auto-disable, with a dry-run mode.
- Alerts to Slack and signed webhooks.
- CLI, admin API and Prometheus metrics.
- Audit log.
- SQLite storage.

**Out**

- Non-HTTP protocols, and a protocol adapter layer.
- WebSockets, including the OpenAI Realtime API.
- Auth in the query string.
- Email alerts. Use a webhook to bridge to email.
- Multi-instance or high-availability deployment, and Postgres.
- Cloud KMS for the master key.
- Dashboard UI, and "this was me" buttons in alerts. Alerts include CLI commands instead.
- Hosted version, SSO and teams.
- Model routing, fallbacks and caching.
- Storing request or response bodies, and content inspection.
- TLS-intercepting forward proxy mode.
- A bundled GeoIP database.

## How it works

1. The app sends its request to the proxy with a virtual key. For OpenAI-style SDKs, only the base URL and the key change.
2. The proxy works out the client IP (see Client IP), parses the key id, finds the key in memory and compares the secret hash in constant time.
3. It checks the key's kind, status, expiry and network rules. A canary key stops here with a fake 401 and a critical alert.
4. For LLM profiles, it reads only `model`, `stream`, `max_tokens` and `stream_options` from the request body. It then applies the path and model allowlists, the rate limit and the spend reservation, all in memory.
5. It decrypts the real key, swaps it into the auth header and forwards to the credential's fixed upstream host.
6. The response streams back unbuffered. For LLM profiles, only the usage fields are read, and spend is reconciled.
7. A metadata event is queued. A background worker stores it, updates the per-key baseline, runs the detection rules and sends alerts.

## Core model

| Entity | Purpose |
| --- | --- |
| `upstream` | Target service: protocol (`http` only in beta), profile (`openai`, `anthropic`, `generic`), host, port, TLS settings. |
| `credential` | The real secret for an upstream, encrypted, with a `key_version`. Auth style: header template or HTTP Basic. Write-only. |
| `virtual_key` | What apps use. Id plus a hashed secret. Kind: `standard` or `canary`. Status: `active`, `disabled` or `revoked`. Optional expiry. |
| `policy` | Limits and allowlists for a virtual key. Mode: `alert_only` (default), `dry_run` or `auto_disable`. |
| `spend_counter` | Committed spend per key, per day and per month. Kept apart from events so dropped events never lose spend. |
| `event` | Metadata for one request: time, key, IP, country, ASN, operation, status, latency, sizes, tokens, cost, and whether the cost is estimated. |
| `baseline` | Rolling per-key profile: 5-minute request counts, hourly spend, countries and ASNs seen. |
| `detection` | A rule that fired, with its severity and evidence. Evidence is counts and categories, never content. |
| `audit_log` | Append-only record of admin actions and key lifecycle changes, including auto-disable. |

All keys and policies are loaded into memory at startup. Every admin write updates SQLite and the in-memory copy before it returns.

## Provider profiles

**Auth styles**

- Header template, such as `Authorization: Bearer {key}` or `x-api-key: {key}`.
- HTTP Basic, with the real key as the password and a fixed or empty username, or as `user:pass`.

The proxy strips the client's auth header and replaces it with the real one.

**Path allowlists**

- Entries are a method plus a path pattern, such as `POST /v1/charges` or `GET /v1/customers/*`. `*` matches one segment and `**` matches the rest of the path.
- The matching entry becomes the event's operation, so baselines see a bounded set of operations.
- Generic HTTP needs an allowlist, and anything not on it is denied.
- OpenAI and Anthropic ship with built-in allowlists for their documented endpoints. A policy can narrow them.

**LLM profiles**

- Model allowlists and spend caps work only on OpenAI and Anthropic profiles. A policy that sets either on a generic upstream is rejected.
- OpenAI-compatible: when `stream` is true and the client didn't set `stream_options.include_usage`, the proxy sets it, so the last chunk carries usage. Official SDKs ignore that chunk. A per-upstream setting turns this off for compatible servers that reject the field.
- Anthropic: usage comes from the `message_start` and `message_delta` stream events, or from the response body when not streaming.

## Spend and cost

- **Prices:** an embedded `prices.json` versioned in the repo, overridable by a file path in the config. Each model has input, output, cached input and cache write prices per million tokens.
- **Reservation:** before forwarding, the proxy reserves request bytes / 4 × the input price, plus `max_tokens` × the output price. If `max_tokens` is unset, it reserves `default_reservation_usd` (default $0.10).
- **Cap check:** a request is blocked if committed spend plus open reservations plus the new reservation would exceed the cap.
- **Reconcile:** when the response ends, actual cost replaces the reservation. If usage is missing, the reservation is charged and the event is marked as estimated.
- **Unknown model:** if the key has a spend cap, the proxy blocks with `unknown_model_price`. Otherwise it forwards and records the cost as null.
- **Caps:** daily and monthly, reset at 00:00 UTC.
- **Persistence:** spend counters are flushed to SQLite every 5 seconds and on shutdown, and loaded at startup. A crash can lose up to 5 seconds of spend, so a cap can be overshot slightly. Actual cost can also go over the reservation. The docs say both.

## Client IP

- The config has a `trusted_proxies` list of CIDRs. It's empty by default.
- By default the client IP is the TCP peer address.
- If the peer is a trusted proxy, the client IP is the rightmost `X-Forwarded-For` entry that isn't a trusted proxy.
- All CIDR, country and ASN rules, events and per-IP limits use this one value.
- The proxy never adds `X-Forwarded-For` or other client headers to upstream requests.

## Errors

Proxy errors use an OpenAI-shaped JSON body, so SDKs show the message. They also carry an `X-Keman-Error` header, so clients can tell them from upstream errors.

```json
{"error": {"type": "keman_error", "code": "key_revoked", "message": "This virtual key has been revoked."}}
```

| Code | Status |
| --- | --- |
| `invalid_key`, `key_disabled`, `key_revoked`, `key_expired` | 401 |
| `path_not_allowed`, `model_not_allowed`, `network_not_allowed` | 403 |
| `spend_cap_reached`, `unknown_model_price` | 403 (not 429, because SDKs retry 429) |
| `rate_limited` | 429, with `Retry-After` |
| `upstream_redirect_blocked` | 502 |
| `store_unavailable` | 503 |

A canary key returns a 401 shaped like its upstream profile's own error, not a `keman_error`.

## Security

- **Envelope encryption.** A 32-byte master key from `KEMAN_MASTER_KEY` or a file wraps a data key. The data key encrypts each credential with AES-256-GCM. The credential id is bound to the ciphertext as authenticated data, so ciphertexts can't be swapped.
- **Rotation.**
  - `credential rotate <id>` replaces the real key in place, and its virtual keys keep working.
  - `rekey` takes the old and new master keys and re-wraps the data key.
- **Real keys** are never returned by any API. Only their last 4 characters are shown.
- **Virtual key secrets** are shown once and stored as SHA-256 hashes. The fixed `kmn_` prefix makes them detectable by secret scanners.
- **Admin token.** `init` generates it, shows it once and stores its hash. `admin-token rotate` replaces it.
- **Upstream routing.** The upstream host is fixed per credential and never taken from the request. Redirects to other hosts are blocked. Hop-by-hop headers, `Host` overrides, `X-Forwarded-Host` and `Forwarded` are stripped.
- **Invalid keys.** Requests with invalid keys are rate limited per client IP. Request and header sizes are capped, and connect and header timeouts are set. Streams have no total timeout.
- **Logging.** Auth headers are redacted everywhere. Tests assert that no key material appears in logs. Bodies, headers and query strings are never logged. Query strings are forwarded upstream as-is.
- **Retention.** Events are kept 14 days by default, and detections 90 days. The audit log is kept indefinitely.
- No telemetry and no phone-home.
- Releases and images are signed with cosign, with an SBOM.
- **Not protected:** anyone who can read the proxy's memory can read the keys. Run it isolated from the apps that use it: non-root, read-only filesystem, network egress only to upstream hosts.

## Failure behavior

| Failure | Behavior |
| --- | --- |
| SQLite unreadable at startup | Refuse to start. |
| Admin write fails | The admin API returns an error. The in-memory state is unchanged. |
| Spend counters can't be flushed for 60 seconds | Keys with spend caps fail closed (503). Other keys keep working. |
| Limit or allowlist violated | Block, using the codes in Errors. |
| Detection or alert delivery fails | Fail open. Count the skipped events in metrics. |
| Event queue full (default 10,000) | Drop the oldest events and count them in metrics. |
| Key disabled or revoked | Takes effect on the next request. |

## Detection rules

**Rules**

| Rule | Fires when (defaults, configurable) | Severity | Counts toward auto-disable |
| --- | --- | --- | --- |
| Canary used | Any request with a canary key | Critical | Not applicable |
| Disabled or revoked key used | Any request with that key | High | No, the key is already off |
| Spend spike | Last hour's spend > max($5, 5 × hourly p95 over 7 days) | High | Yes |
| Rate spike | 5-minute count > max(100, 10 × 5-minute median over 7 days) | Medium | Yes |
| New country | First request from a country not seen for this key | Medium | Yes |
| Repeated allowlist violations | 5 or more blocked requests in 5 minutes | Medium | Yes |
| Upstream auth-error burst | 10 or more upstream 401 or 403 responses in 5 minutes | Medium | No, it usually means the real key is broken |
| New ASN | First request from an ASN not seen for this key | Low | No |

**Learning and alerting**

- Behavior rules only alert. Inline blocking only enforces limits the user set.
- Each key has a learning period of 7 days or 500 requests, whichever comes first. During it, the baseline, spike and new-location rules only record. The canary, disabled-key and allowlist-violation rules fire from the first request.
- Alerts are grouped into one incident per key and rule, which stays open until an hour passes with no new firing.
- Each alert includes the evidence, the baseline, the observed value, and the CLI commands to disable the key, lower a limit or allowlist the source.

**Webhooks**

- Webhook alerts are signed with HMAC-SHA256 over the timestamp and body, sent as `X-Keman-Signature: t=<unix>,v1=<hex>`.
- Slack alerts use an incoming webhook URL.

**Auto-disable**

- Auto-disable is opt-in per key with the `auto_disable` mode. It fires on 3 medium-or-higher detections from at least 2 different rules within 15 minutes.
- It disables the key and never revokes it. After someone re-enables the key, auto-disable is paused for 1 hour.
- The `dry_run` mode runs the same logic but only records when the key would have been disabled and how many requests would have been blocked.
- Switching a key to `auto_disable` prints its dry-run report from the last 7 days and asks for confirmation, unless `--yes` is passed.

## Targets

| Metric | Target |
| --- | --- |
| Proxy overhead, p50 | < 3 ms |
| Proxy overhead, p99 | < 10 ms |
| Quickstart, fresh machine | < 10 min |

Publish the benchmark in the repo.

## Beta is done when

- OpenAI, Anthropic and one generic HTTP API work through one binary, including streaming with the official Python and Node SDKs.
- Revoking a key blocks its next request.
- Any use of a canary key sends a critical alert within 5 seconds.
- A replayed attack against a key with a seeded baseline fires the expected alerts and auto-disables the key. Dry-run mode reports the same result. The test suite includes the injectable clock and a fixture loader for past events.
- Restarting the proxy does not reset spend caps.
- An `X-Forwarded-For` header from an untrusted peer is ignored.
- Fuzz tests cover key parsing, header handling and path matching.
- The p99 overhead target is met in the published benchmark.
- A stranger completes the quickstart unaided in under 10 minutes.
- A signed release with an SBOM is published.
- The README, threat model and `SECURITY.md` are published.

## Build order

1. Proxy to OpenAI with streaming, error format, header stripping and redirect blocking.
2. Encrypted credentials, virtual keys, CLI, admin API, revocation and rotation.
3. Client IP, rate limits, allowlists, and spend tracking with persistence.
4. Anthropic and generic HTTP profiles. Record the first benchmark.
5. Event pipeline, GeoIP, baselines, injectable clock and fixture loader.
6. Detection rules, alerts, canary keys, dry-run and auto-disable.
7. Hardening, fuzz tests, signed release, docs, and a quickstart test with a stranger.
