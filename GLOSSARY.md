# Keman

Keman is a self-hosted proxy that holds real upstream API keys and hands apps virtual keys that can be limited, watched, and revoked.

## Language

**Upstream**:
The fixed target service a request is forwarded to. In the beta its protocol is always HTTP.
_Avoid_: Provider, backend, destination

**Profile**:
The upstream's request and usage shape. One of `openai`, `anthropic`, or `generic`.

**Credential**:
The real secret for one upstream, stored encrypted. Apps never see it.
_Avoid_: Real key, provider key, secret (too broad)

**Virtual key**:
The secret an app sends to Keman. It looks up one credential. The secret is shown once and only its hash is stored.
_Avoid_: Token, API key (ambiguous with credential)

**Canary key**:
A virtual key whose only job is to alert when anyone uses it. It is never forwarded upstream.

**Policy**:
The limits and allowlists attached to one virtual key, plus the mode that says what behavior alerts may do.

**Mode**:
How behavior alerts treat a virtual key: `alert_only`, `dry_run`, or `auto_disable`.

**Spend counter**:
Committed spend for one virtual key in one UTC day or UTC month. Kept apart from events.

**Reservation**:
A temporary hold on a virtual key's spend, taken before the upstream call and replaced by the actual cost when the response ends.

**Event**:
Metadata for one request. It never contains a body, header, or query string.

**Operation**:
The allowlist entry that matched a request, such as `POST /v1/chat/completions`. Baselines count operations, not raw paths.

**Baseline**:
The rolling per-key profile detection compares against: request volume, spend, countries, and ASNs.

**Detection**:
A detection rule firing for a virtual key, with a severity and evidence made of counts and categories.

**Incident**:
The open stretch of one detection rule on one virtual key. It stays one incident until an hour passes with no new firing.

**Audit log**:
The append-only record of admin actions and virtual-key lifecycle changes, including auto-disable.

**Master key**:
The 32-byte key, from the environment or a file, that wraps the data key. It is not stored in the database.

**Data key**:
The key that encrypts each credential. The master key wraps it.

**Client IP**:
The single address used for network rules, events, and per-IP limits. It is the TCP peer unless that peer is a trusted proxy.

**Trusted proxy**:
A peer address in the configured CIDR list. Only then is `X-Forwarded-For` consulted.
