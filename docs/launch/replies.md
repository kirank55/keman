# Replies

Starting points for the questions people will ask on launch day. Keep the answers short, honest about the beta's limits, and link to the docs for detail. Put each answer in your own words.

## "How is this different from…"

**…the provider's own key controls?**
Use them too. They differ from provider to provider, and many APIs have none. Keman gives every key the same address and country locks, expiry, caps, leak alerts, decoys and one-step rotation, across OpenAI, Anthropic, OpenRouter and header-auth APIs like Stripe and GitHub. The real key also never sits in the app, so a leak from the app can't expose it.

**…a secret scanner (GitHub secret scanning, gitleaks, trufflehog)?**
Scanners tell you a key leaked, after the fact. Keman limits what the leaked copy can do and gives you one command to kill it. They work well together. Keman's own `keman scan . --history` exists to find the keys to move behind it, and the `kmn_` prefix makes virtual keys easy for scanners to spot.

**…an LLM gateway (LiteLLM, Portkey, OpenRouter itself)?**
Gateways focus on routing and budgets across models. Keman focuses on what happens when a key leaks: where it may be used from, spotting a copy in use, decoys, and containment. It isn't a model router, and it covers non-LLM APIs too. You can put Keman in front of OpenRouter.

**…a secrets manager (Vault, Doppler, 1Password)?**
A secrets manager decides who can read the real key. Keman makes sure the apps never need it. They fit together: keep the provider key in your secrets manager and pass it to Keman with `--secret-env` or `--secret-file`.

## Security

**Isn't Keman a single point of compromise?**
It holds the real keys, so yes, it's the thing to protect. That trade is deliberate: one hardened place instead of a real key in every app, CI job and laptop. Real keys are encrypted at rest with a master key you can keep outside the data directory. Virtual keys and the admin token are stored only as hashes. The admin API listens on localhost by default. It does not help if someone can read the process memory. See [THREAT-MODEL.md](../THREAT-MODEL.md).

**Does it see my prompts or data?**
It forwards them, but doesn't keep them. For LLM APIs it reads only `model`, `stream`, `max_tokens` and `stream_options` from the request, and only the usage counts from the response. Bodies, headers and query strings are never logged, and it runs on your hardware.

**Does it phone home?**
No. There's no telemetry, no account and no license check.

**How do I know the binary is what's in the repo?**
Every release has SHA-256 sums, an SPDX SBOM and a keyless cosign signature from the GitHub Actions release workflow. See [SECURITY.md](../../SECURITY.md#verifying-a-release).

## Operations

**What happens if Keman goes down?**
Requests through it fail, like any proxy in the path. The beta is a single instance on SQLite. Run it next to the apps that use it, under a supervisor or as a container with a restart policy. High availability isn't in the beta.

**How much latency does it add?**
About 71 µs at p50 and 555 µs at p99 on loopback ([benchmark](../../benchmarks/RESULTS.md)). Streams are passed through unbuffered.

**Does streaming work?**
Yes, including SSE with the official OpenAI and Anthropic SDKs. WebSockets (and so the OpenAI Realtime API) are not supported yet.

**Will it alert on my normal traffic?**
A new key learns for 7 days or 500 requests before the spike and new-location rules can alert. To check what a policy would do before turning on auto-disable, run `keman policy dry-run <key>`. `keman detection test` replays abuse scenarios, or your own events.

**Do the country rules need anything?**
A GeoLite2 or DB-IP `.mmdb` file, which Keman doesn't bundle. Address locks and every other rule work without it.

**Can it run in Kubernetes?**
The image is distroless, multi-arch and non-root, so it runs anywhere containers do. There's no Helm chart yet. Run one replica, because it's SQLite.

**Does it work on Windows?**
Yes, there's a Windows amd64 binary on the release page. The install script covers macOS and Linux.

## The project

**Is it free? Will there be a paid version?**
It's free and Apache-2.0. [Say what's true for you about future plans, or that you haven't decided.]

**What's next?**
[Your roadmap. Candidates people will ask about: WebSockets, more provider profiles, high availability, a Helm chart, more alert destinations.] Ask them what they need most, and open issues for it.

**How can I help?**
Try it, open issues for anything that gets in your way, and see [CONTRIBUTING.md](../../CONTRIBUTING.md). Reports of false positives and false negatives from real traffic are the most useful thing right now.

**Why "beta"?**
The core works end to end and is tested, but the storage is single-node SQLite, a few protocols are missing, and the detection thresholds need tuning against more real traffic. [beta.md](../../beta.md) lists the full scope.
