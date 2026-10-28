# Threat model

Keman sits between your applications and an upstream API. Callers present a virtual key (`kmn_…`). Keman checks it, applies the policy, and sends the real credential to a host that was configured ahead of time.

## Assets

- Real upstream credentials.
- Virtual-key secrets (shown once; only a SHA-256 of the secret is stored).
- The admin token.
- The master key and the wrapped data key.
- Spend counters, which enforce the caps you set.
- The audit log.

## Actors

- A caller who has a virtual key, including one that leaked.
- A caller who does not have a virtual key.
- A network peer that tries to spoof `X-Forwarded-For`.
- An upstream that answers with a redirect.
- An operator with the admin token.
- Someone who can read the database file but not the master key.
- Someone who can read the process memory.

## Boundaries

```text
app --virtual key--> keman proxy --real credential--> upstream host
operator --admin token--> admin API (localhost) --> SQLite
```

The upstream host, port, and TLS settings come from the credential's upstream record. They are never taken from the request URL.

## What the beta resists

| Threat | Control |
| --- | --- |
| Stolen virtual key used from anywhere | Revoke it. The next request is rejected. Optional expiry, RPM, path, model, country, and CIDR limits. |
| Canary token checked in or pasted into a client | The response looks like an upstream 401. A critical alert is sent. |
| Guessing keys | 256-bit secrets, constant-time compare, per-IP limit on invalid keys. |
| Credential theft from the database | AES-256-GCM under a data key. The master key wraps that data key. The credential id is the AAD, so rows cannot be swapped. |
| Admin token theft from the database | Only SHA-256 is stored. |
| Header smuggling of the virtual key or a client IP | Hop-by-hop, auth, and forwarding headers are stripped. `X-Forwarded-For` is not added. Untrusted peers' forwarding headers are ignored. |
| Open redirect through the proxy | A 3xx to another host or port becomes `502 upstream_redirect_blocked`. Redirects are not followed. |
| Ambient HTTP proxy seeing the real key | The outbound transport ignores `HTTP_PROXY`. |
| Spend cap bypass via a restart | Counters flush every 5 seconds and on shutdown. |
| Spend cap bypass while the disk is failing | After 60 seconds, capped keys fail closed. |
| Log scraping | The default logger redacts `kmn_…` tokens and credential plaintext. Bodies, headers, and query strings are not logged. |
| Burst of odd behavior | Detection rules alert. Auto-disable is opt-in and never revokes. |

## What the beta does not resist

- Memory inspection, a debugger, or a core dump. Plaintext credentials are cached.
- A malicious operator who already has the admin token and the master key.
- An upstream that is itself compromised. Keman will send the real credential there, because that is the host you configured.
- GeoIP without a database you supply. Country rules stay off, and a country allowlist refuses to save.
- A lost master key. There is no recovery path.
- A crash in the five seconds after a spend update and before the next flush. The cap can be overshot by that window. Open reservations are memory-only and are released on restart.
- Detection when the event queue is full. The oldest events are dropped. Caps still apply, because they are not taken from the queue.

## Detection

Rules, severities, the learning period, incident grouping, webhook signing (`X-Keman-Signature: t=<unix>,v1=<hex>` over `<unix>.<body>`), and auto-disable thresholds are the ones in `beta.md`. Alerts fail open. A failed alert is counted and the request is not failed.

## Out of scope

A web dashboard, multi-tenant installs, and TLS termination on the proxy listener. `keman`, with no command, is a terminal client of the admin API and uses the same admin token. When the admin listener is down, `keman` starts the server in-process and stops it on exit, so that process holds the master key and decrypted credentials the same way `keman serve` does. The listener is HTTP/1.1 and cleartext HTTP/2.
