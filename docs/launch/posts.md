# Posts

Edit freely. Each post fits its platform's norms: HN is plain and technical, X is short with images, and Reddit leads with what's useful to that subreddit. Replace `PH_LINK` and `SITE` once you have them.

## Show HN

Title (80 characters max; this is 73):

> Show HN: Keman – a self-hosted proxy that makes leaked API keys worthless

URL: https://github.com/kirank55/keman

Text:

> Keman sits between your apps and an API provider. Apps get virtual keys (kmn_…); Keman checks each request and forwards it with the real key, which never leaves Keman. The point is to make the leak itself less of an event: a leaked virtual key can be locked to the addresses or countries it runs from, the paths and models it may call, a request rate and a dollar cap; it expires after 90 days by default; and `keman key rotate <app> --grace 0` replaces it without touching the real key or any other app.
>
> It also watches for the shapes leaks take: use from a new country or ASN, rate and spend spikes against a learned baseline, repeated blocked requests, a disabled key coming back, and canary keys that never forward anything and alert on first use. Alerts go to Slack or an HMAC-signed webhook and lead with the command to run.
>
> Some details:
>
> - Single Go binary, pure-Go SQLite, no CGO. Terminal UI (Bubble Tea), CLI, and an admin API on localhost.
> - OpenAI-compatible APIs (including OpenRouter), Anthropic, and any HTTP API that authenticates with a header (Stripe, GitHub). Generic APIs require a path allowlist.
> - Streaming is passed through unbuffered. For LLM calls it reads only `model`, `stream`, `max_tokens` and `stream_options` from the request, and the usage counts from the response. Bodies, headers and query strings are never logged.
> - Real keys are encrypted at rest; virtual keys are stored as SHA-256 hashes.
> - Overhead on loopback is about 71 µs p50 and 555 µs p99.
> - `keman scan . --history` finds provider keys in files and every commit, offline.
>
> It's a beta: single instance, HTTP only (no WebSockets yet), and you bring your own GeoIP database for the country rules. `./scripts/demo.sh` seeds a week of traffic with a stolen key and the alerts it causes, against a local mock, if you want to see it without a provider key.
>
> The threat model is in docs/THREAT-MODEL.md. In short: it does not protect you if someone can read the proxy's memory. I'd especially like to hear where the detections are too noisy or too quiet for real traffic.

## X / Twitter

Thread. Attach the image named on each post.

1. *(01-hero.png)*
   > Your API keys will leak. Make the leaked copy worthless.
   >
   > Keman is live on Product Hunt today: an open-source proxy that gives apps virtual keys you can lock, watch, and kill.
   >
   > PH_LINK
2. *(02-how-it-works.png)*
   > How it works: apps hold a kmn_ virtual key. Keman checks it (address, country, expiry, endpoints, models, rate, dollars) and swaps in the real key, which never leaves Keman.
   >
   > A leaked copy used from somewhere else is refused.
3. *(03-stolen-key.png)*
   > If a copy does get used, you see it: every address that called the key, its network and country, and what it cost.
   >
   > Here, a stolen support-bot key burning Opus credits from a new country.
4. *(04-alert.png)*
   > And you hear about it. Alerts go to Slack or a signed webhook, and lead with the exact command to run.
5. *(06-contain.png)*
   > Kill it in one command. `keman key rotate support-bot --grace 0`. The app gets a replacement with the same policy, and the real key and every other app stay as they are.
6. *(07-canary.png)*
   > Plant decoys. Canary keys look real, never reach the provider, and set off a critical alert on first use.
7. *(08-scan.png)*
   > Start with `keman scan . --history`. It finds keys already sitting in your git history, offline, no setup.
   >
   > One Go binary, Apache-2.0, no telemetry. https://github.com/kirank55/keman

## LinkedIn

> API keys leak: committed to a repo, printed in a CI log, baked into an image, copied off a laptop. When one does, it works for anyone, from anywhere, until someone notices.
>
> Today I'm launching the public beta of Keman on Product Hunt. It's an open-source proxy you run yourself. Your apps get virtual keys and the real key never leaves Keman, so a leaked copy:
>
> → only works from the addresses or countries you allow
> → expires on its own after 90 days
> → sets off a Slack or webhook alert with the exact command to respond
> → can be killed in one command, without touching the real key or any other app
>
> It also plants decoy keys that alert on first use, and `keman scan` finds the keys already in your git history.
>
> It works with OpenAI, Anthropic, OpenRouter, and any API that takes a key in a header, such as Stripe or GitHub. It's free and Apache-2.0.
>
> I'd value your feedback, especially from anyone who's had to clean up after a leaked key: PH_LINK

Attach `01-hero.png`, or the first four gallery images as a carousel.

## Reddit

Read each subreddit's self-promotion rules first, and post from an account that takes part there. Answer comments for the rest of the day. Don't cross-post the same text to several subreddits at once.

### r/selfhosted

Title: **Keman: a self-hosted proxy that gives your apps virtual API keys you can lock, watch, and revoke**

> [One line on why you built it.]
>
> Keman runs on your box (single Go binary or a distroless Docker image, SQLite, no account, no telemetry). Apps get a `kmn_…` virtual key and Keman forwards requests with the real one. Each virtual key can be locked to IPs or countries, endpoints, models, a rate and a daily dollar cap, and expires after 90 days by default. Leaks show up as alerts (new country, spend spike, a disabled key in use, decoy keys) to Slack or a webhook, and `keman key rotate app --grace 0` swaps the leaked key without touching the real one.
>
> Docker:
>
> ```
> docker run --rm -v keman-data:/home/nonroot ghcr.io/kirank55/keman:beta init
> docker run --rm -p 8080:8080 -v keman-data:/home/nonroot ghcr.io/kirank55/keman:beta serve
> ```
>
> It's a beta (single instance, HTTP only). Repo and screenshots: https://github.com/kirank55/keman. Feedback very welcome.

### r/golang

Title: **Keman: an API-key proxy in Go with a Bubble Tea UI, pure-Go SQLite, and no CGO**

> Sharing a project I've been building: a reverse proxy that hands apps virtual API keys and keeps the real ones encrypted, so a leaked key can be locked down, detected and revoked on its own.
>
> Some Go bits that might interest people here:
>
> - `modernc.org/sqlite`, so every release binary is static (`CGO_ENABLED=0`): Linux and macOS on amd64 and arm64, and Windows on amd64
> - streaming responses passed through unbuffered, reading only the usage fields from OpenAI and Anthropic SSE
> - a Bubble Tea and Lip Gloss terminal UI that talks to the same admin API as the CLI
> - an injectable clock, so the time-based tests are deterministic
> - fuzz targets for key parsing, header stripping and path matching
> - about 71 µs p50 overhead on loopback
>
> https://github.com/kirank55/keman. I'd appreciate a code review from anyone who has a few minutes, especially of `internal/proxy`.

### r/devops or r/netsec

Lead with `keman scan . --history` and the threat model rather than the launch. Link the repo, not Product Hunt.

## Short blurb (Discord, Slack communities, newsletters)

> **Keman**: open-source protection from leaked API keys. A self-hosted proxy that gives apps virtual keys you can lock to IPs and countries, cap, expire, watch for abuse, and kill in one command, while the real key never leaves your box. Works with OpenAI, Anthropic, OpenRouter, Stripe, GitHub and any header-auth API. https://github.com/kirank55/keman
