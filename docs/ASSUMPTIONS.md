# Assumptions

`beta.md` is the source of truth. These are the points it leaves open. Each one was resolved from its decisions rather than left for later. `PLAN.md` is background only.

1. **One data key per install.** The beta is a single instance with no tenants. The master key wraps that one data key. `rekey` re-wraps it and does not re-encrypt credentials.

2. **Admin token form.** `init` prints `kma_` plus 32 random bytes in base62. It is not a virtual key. The database stores SHA-256 of the whole token.

3. **CLI writes go through the admin API.** A second process that wrote SQLite directly would leave the running server’s memory stale, so revocation would lie. `init` is the offline exception. `serve` must be running for every other mutation. If the admin API is down, the CLI exits with an error.

4. **Reservation when `max_tokens` is missing.** The hold is the input estimate (`request body bytes / 4`, rounded up at the input price) plus `default_reservation_usd` (default $0.10, stored as 100,000 microdollars). When `max_tokens` is set, that default is replaced by `max_tokens` times the output price. `max_completion_tokens` counts as `max_tokens` when `max_tokens` is absent. OpenAI’s newer chat models send the completion field.

5. **Money parsing.** Caps and the default reservation are integer microdollars. The CLI accepts a decimal dollar string such as `1.50` and converts it with decimal arithmetic, not floating point. More than six decimal places is rejected.

6. **Unknown model.** `unknown_model_price` applies when the JSON body has a `model` and that model is not in the price table and the virtual key has a spend cap. Requests with no `model` field (for example `GET /v1/models`) are not spend-checked. A virtual key with a spend cap and a known model is reserved and reconciled. Without a spend cap, an unknown model is forwarded and the event cost is null.

7. **Generic profile has no spend and no model allowlist.** Setting either on a virtual key whose upstream is `generic` is rejected. Generic upstreams must have a path allowlist or creation fails.

8. **Path allowlists narrow.** OpenAI and Anthropic use a built-in allowlist. An upstream allowlist, when set, replaces the built-in list. A policy allowlist, when set, must also match. The operation recorded on the event is the policy pattern when the policy has one, otherwise the upstream or built-in pattern. `**` is only valid as the final segment and matches the rest of the path, including nothing.

9. **Prices.** `prices.json` is a snapshot of public standard-tier, short-context prices taken on 2026-10-27. A `prices_file` is merged on top and replaces entries by model name. Long-context, batch, fast, and dated snapshot model ids are not inferred. Cache write uses the 5-minute write price. A missing cached-input or cache-write price bills those tokens as normal input so a cap cannot be skipped.

10. **Usage shape.** OpenAI `prompt_tokens` and Responses `input_tokens` include cached tokens. Anthropic `input_tokens` does not; cache read and cache write are separate fields. The profile decides which reading applies.

11. **Missing usage after a response.** The reservation is charged and the event is marked estimated. If the upstream connection fails before a response, the reservation is released. A crash can also lose reservations still in memory.

12. **Accept-Encoding is stripped on the way upstream.** `net/http` may then decompress the response so usage can be read. The client receives the uncompressed body. Query strings are still forwarded unchanged. The reverse proxy uses `Director` and sets `X-Forwarded-For` to a nil slice so Go does not add a client address. `Rewrite` would have scrubbed the raw query.

13. **Canary keys always pretend to fail upstream auth.** Any presented canary whose secret matches returns the profile’s own 401 and raises a critical alert, even if the canary is disabled, revoked, expired, or off-network. The body is not a `keman_error` and there is no `X-Keman-Error` header.

14. **Trusted proxies.** The client IP is the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy. If every entry is trusted, the client IP is the leftmost entry. If the header is empty, the client IP is the peer. An untrusted peer’s `X-Forwarded-For` is ignored. Invalid entries are skipped.

15. **Invalid virtual keys** are limited per client IP (default 60 per minute). Over the limit the response is `429 rate_limited`.

16. **Rate limit shape.** A policy RPM is a sliding one-minute window. Unset means unlimited. `Retry-After` is at least one second.

17. **Spend fail-closed.** The clock starts when a spend flush first fails. Sixty seconds later, virtual keys that have a daily or monthly cap get `503 store_unavailable`. Other keys keep working. A successful flush clears the timer. Counters flush every five seconds and on shutdown.

18. **Learning period.** Behavior rules that need a baseline (rate spike, spend spike, new country, new ASN) only record until the virtual key has 500 requests or is seven days old, whichever comes first. Canary, disabled-key, allowlist-violation, and upstream auth-burst rules can fire immediately. Auth-burst is not a baseline rule.

19. **Auto-disable evidence.** Each request that satisfies a rule writes one detection. Alerts are still one incident per key and rule until an hour is quiet. Auto-disable needs three medium-or-higher detections that count toward it, from at least two rules, inside 15 minutes. The request that trips it has already been proxied; the next request sees the key disabled. Dry-run counts requests after that trip as would-have-blocked and does not block them.

20. **Webhook signing payload.** `X-Keman-Signature` is `t=<unix>,v1=<hex>` where `v1` is HMAC-SHA256 of `<unix>.<raw body>` using the destination secret. Slack destinations get `{"text": "..."}` and no signature.

21. **GeoIP.** Country and ASN come from MaxMind-format `.mmdb` files the user supplies. No database is bundled. A policy that sets a country allowlist refuses to save, and the process refuses to start, when no country database is configured. Without a database the new-country and new-ASN rules stay off.

22. **Body cap.** Request bodies are limited (default 32 MiB). LLM profiles are buffered up to that cap so `model`, `stream`, `max_tokens`, and `stream_options` can be read. Generic profiles stream through. Over the cap the code is `request_too_large` (413). An upstream that cannot be dialed is `upstream_unavailable` (502). Neither code is in the beta error table; both are operational.

23. **Redirects.** A 3xx whose `Location` has a different host or port than the credential’s upstream becomes `502 upstream_redirect_blocked`. Relative redirects are passed to the client. Keman does not follow them.

24. **HTTP/2.** The proxy listener speaks HTTP/1.1 and cleartext HTTP/2 (h2c). Upstream TLS uses HTTP/2 when the server negotiates it. The beta listener is not a TLS terminator.

25. **Direct connections only.** The outbound transport ignores `HTTP_PROXY`. The real credential must not be sent to an ambient proxy.

26. **Retention jobs** delete events older than 14 days and detections older than 90 days. Baselines keep countries and ASNs indefinitely so an old country does not look new after events age out. The audit log is never pruned.

27. **What this environment did not finish.** No stranger ran the quickstart. No cosign signature or SBOM was published. The release workflow is scaffolded. Official Python and Node SDK runs depend on those SDKs being installable here; the suite always covers the same streaming transcript with a mock upstream.
