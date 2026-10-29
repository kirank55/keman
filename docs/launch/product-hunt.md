# Product Hunt post

Copy each field as is. Product Hunt's limits are noted next to each field. The counts were checked when this was written.

## Name

Keman

## Tagline (60 characters max)

Pick one:

1. **Make leaked API keys worthless** (30), the recommended one
2. Open-source protection from leaked API keys (43)
3. Virtual API keys you can lock, watch, and kill (46)

## Description (260 characters max)

> Keman is a self-hosted proxy that keeps your real API keys and gives apps virtual ones. A leaked copy only works from addresses you allow, expires on its own, sets off an alert with the exact fix, and dies in one command. Free, open source, one Go binary.

(255 characters)

## Links

- Website: your hosted `website/`
- GitHub: https://github.com/kirank55/keman

## Topics

Developer Tools, Open Source, Security, Artificial Intelligence

## Pricing

Free. Open source (Apache-2.0).

## Thumbnail

[`docs/media/producthunt/thumbnail-240.png`](../media/producthunt/thumbnail-240.png)

## Gallery

Upload in this order. The first image is the one people see in the feed. The alt text describes each image for screen readers.

| # | File | Alt text |
| --- | --- | --- |
| 1 | `01-hero.png` | Keman: open-source protection from leaked API keys. The terminal UI lists nine virtual keys with their lock, alerts, expiry and where each was last seen. |
| 2 | `02-how-it-works.png` | How it works: apps send a virtual key, Keman checks address, country, expiry, paths and models, then forwards the request with the real key. A leaked copy is refused. |
| 3 | `03-stolen-key.png` | A stolen copy of the support-bot key burning Claude Opus credits from Brazil, with every request, address, and cost. |
| 4 | `04-alert.png` | A Slack alert for a spend spike that says who called, from where, and the exact command to rotate, disable or allow. |
| 5 | `05-detections.png` | Detections grouped into incidents: new countries, spend spikes, blocked probes, a disabled key in use and a decoy. |
| 6 | `06-contain.png` | keman key rotate issues a replacement with the same policy and revokes the leaked key in one command. |
| 7 | `07-canary.png` | A canary key planted in a .env file, and the critical alert its first use sets off. |
| 8 | `08-scan.png` | keman scan finds a Stripe and an OpenAI key in files and git history, and says how to move each behind Keman. |
| 9 | `09-exposure.png` | keman exposure lists keys that work from any address or never expire, with the command that fixes each. |

## Maker comment

Post this as the first comment as soon as the post is live. Replace the line in brackets with your own reason for building Keman. A specific story beats any pitch.

---

Hey Product Hunt 👋 I built Keman.

[One or two sentences on why: the leak you saw, the bill you got, or the rotation that took a whole afternoon.]

API keys leak all the time: committed to a repo, printed in a CI log, baked into an image, copied off a laptop. The usual advice is "rotate it", which means finding every app that uses the key, and in the meantime anyone who has it can use it from anywhere.

Keman is a small proxy you run yourself. Your apps get virtual keys (`kmn_…`) and the real key never leaves Keman. So when a virtual key leaks:

🔒 It may not work at all. Each key is locked to the addresses or countries it runs from, the endpoints and models it may call, and a dollar cap.
⏳ It stops on its own. New keys expire after 90 days.
🔔 You hear about it. A new country, a spend spike or a disabled key in use sets off a Slack or webhook alert, with the exact command to respond.
🪤 Decoys catch the thief. Canary keys look real and set off a critical alert on first use.
⚡ You kill it in one step. `keman key rotate <app> --grace 0`, and no other app notices.

It ships presets for 21 platforms, from OpenAI, Anthropic, OpenRouter, Gemini and Groq to Stripe, GitHub, Slack and Twilio, and works with any other API that takes a key in a header. It's a single Go binary, Apache-2.0, with no account and no telemetry.

Two things to try in the next five minutes:
• `keman scan . --history` finds the keys already sitting in your git history. No setup.
• `./scripts/demo.sh` plays a week in the life of a team, including a stolen key and the alerts it sets off, all locally.

It's a beta: one instance on SQLite, and HTTP only. I'd love to hear which APIs you'd want next, and what would stop you from putting your production keys behind it.

---

## Short replies for later in the day

- **To a thank-you:** "Thank you! If you try it, I'd love to hear what got in the way. Issues are open on GitHub."
- **To "does it work with X?":** check [`replies.md`](replies.md). If X is one of the 21 presets (`keman upstream presets`), it's one command. If it takes a key in a header or HTTP Basic, it works with a path allowlist you choose.
- **To a feature request:** "Good one, I've opened an issue for it: <link>." Then open it.
