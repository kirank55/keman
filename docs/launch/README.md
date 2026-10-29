# Launch kit: v0.1.0-beta on Product Hunt

Everything for the beta launch, in the order you need it.

| File | What it is |
| --- | --- |
| [`README.md`](README.md) | This checklist and the launch-day plan |
| [`product-hunt.md`](product-hunt.md) | Every field of the Product Hunt post, the gallery captions, and the maker comment |
| [`posts.md`](posts.md) | Show HN, X, LinkedIn, Reddit and a short blurb for chats |
| [`replies.md`](replies.md) | Answers to the questions people will ask, so replies are fast and consistent |

Assets:

| Asset | Path |
| --- | --- |
| Thumbnail (240×240) | [`docs/media/producthunt/thumbnail-240.png`](../media/producthunt/thumbnail-240.png) |
| Gallery (1270×760, rendered at 2×) | [`docs/media/producthunt/`](../media/producthunt/) `01-hero.png` … `09-exposure.png` |
| Logo (SVG) | [`docs/media/logo.svg`](../media/logo.svg) |
| Social card (1200×630, rendered at 2×) | [`website/og.png`](../../website/og.png) |
| Website | [`website/`](../../website/) (see its README before publishing) |
| Release notes | [`docs/releases/v0.1.0-beta.md`](../releases/v0.1.0-beta.md) |

## Before launch day

These block the launch. Every install path in the README, the website and the posts depends on them.

- [ ] **Make the repository public.** It is private now, so `install.sh`, `go install`, raw.githubusercontent.com links, the badges and the release downloads all return 404 to everyone else.
- [ ] Set the repo's About box: description `Open-source protection from leaked API keys`, the website URL, and topics `api-keys`, `security`, `proxy`, `secrets`, `llm`, `openai`, `anthropic`, `self-hosted`, `golang`, `devtools`.
- [ ] Upload `website/og.png` as the repo's social preview (Settings → General → Social preview).
- [ ] Tag the release and push it: `git tag v0.1.0-beta && git push origin v0.1.0-beta`. Watch the `release` workflow.
- [ ] Check the release has five binaries, each with `.sha256`, `.spdx.json` and `.bundle`, plus `checksums.txt` and `install.sh`. It should be marked as a prerelease.
- [ ] **Make the container image public.** New GHCR packages are private by default: open the `keman` package on GitHub → Package settings → Change visibility → Public.
- [ ] Test every install path on a machine that has never seen Keman:
  - [ ] `curl -fsSL https://raw.githubusercontent.com/kirank55/keman/main/scripts/install.sh | sh` on Linux and on macOS
  - [ ] `go install github.com/kirank55/keman/cmd/keman@v0.1.0-beta`
  - [ ] `docker pull ghcr.io/kirank55/keman:beta`, then `init` and `serve` as in the README
  - [ ] the Windows `.exe` from the release page
  - [ ] `cosign verify-blob` as in [SECURITY.md](../../SECURITY.md#verifying-a-release)
- [ ] From a fresh clone, run `./scripts/demo.sh` and open the UI with the command it prints.
- [ ] Publish `website/`, set the absolute `og:image` URL (see [`website/README.md`](../../website/README.md)), and check the link preview in Slack or with an Open Graph preview tool.
- [ ] Create the Product Hunt post from [`product-hunt.md`](product-hunt.md) and schedule it. Upload the thumbnail and gallery in order, and add the website and GitHub links.
- [ ] Tell the people who already know about Keman which day it launches, and ask them for honest feedback in the comments.

Nice to have:

- [ ] A 30–60 second demo video or GIF for the first gallery slot. The demo install is the script: `keman scan . --history`, then the key list, the stolen key, the alert, and `keman key rotate`.
- [ ] Pin an issue titled "Beta feedback" so feedback from the launch lands in one place.
- [ ] Enable GitHub Discussions for questions that aren't bugs.

## Launch day

Product Hunt's day runs from 12:01 AM to 11:59 PM Pacific time. Tuesday to Thursday get the most traffic and the most competition.

| When (PT) | What |
| --- | --- |
| 12:01 AM | The post goes live. Post the maker comment from [`product-hunt.md`](product-hunt.md) right away. |
| Morning | Post on X and LinkedIn ([`posts.md`](posts.md)) with the Product Hunt link. |
| 6–9 AM | Submit the Show HN. It is a separate audience. Link the GitHub repo there, not Product Hunt. |
| All day | Reply to every comment, on Product Hunt and HN, within the hour. Use [`replies.md`](replies.md) as a starting point, not a script. |
| Afternoon | Post to Reddit, one subreddit at a time and following each one's rules. |
| Evening | Thank the people who commented. Turn the bugs and requests you heard into issues. |

Product Hunt rules worth keeping in mind: ask people to check it out and leave feedback, not to upvote. Don't share a direct link that asks for votes, and don't use vote groups. Product Hunt discounts votes it thinks were coordinated.

## After launch

- [ ] Add the Product Hunt badge to the website (where `index.html` has the `Product Hunt badge` comment) and, if you like, to the README.
- [ ] Reply to issues opened during the launch.
- [ ] Write down what people asked for most, and update the roadmap in [`beta.md`](../../beta.md) or the README.
- [ ] Ship a `v0.1.1-beta` with the quick fixes, so the people who tried it see it move.
