# Website

The Keman landing page. It is static HTML, CSS and a little JavaScript, with no build step and no third-party requests: fonts are bundled, and there are no analytics or external scripts. Host this directory as is on any static host (GitHub Pages, Cloudflare Pages, Netlify, S3). The whole page, fonts included, is about 200 KB.

| File | What it is |
| --- | --- |
| `index.html` | The page. Every terminal, alert and HTTP exchange on it is real output from the demo install. |
| `style.css` | Flat black and white, matching the Product Hunt gallery |
| `main.js` | Copy buttons, tabs, the leaked-key simulator, the scroll-driven incident story, terminal fitting, and scroll reveals |
| `404.html` | Not-found page (GitHub Pages, Netlify and Cloudflare Pages serve it automatically) |
| `robots.txt` | Allows crawling |
| `fonts/` | Inter and JetBrains Mono, subset to Latin, arrows and box drawing, under the SIL Open Font License (license files alongside) |
| `logo.svg`, `favicon.svg`, `apple-touch-icon.png` | The logo and icons |
| `og.png` | The 1200×630 social card (rendered at 2×) |

The page works without JavaScript: the simulator shows its first exchange, the story shows each step with its visual inline, and nothing is hidden. It respects `prefers-reduced-motion`, and the tabs follow the WAI-ARIA tabs pattern (arrow keys, Home and End).

## Before you publish

1. Set the absolute URL of `og.png` in `index.html`. Link previews on X, LinkedIn and Slack need an absolute URL:

   ```html
   <meta property="og:image" content="https://YOUR-DOMAIN/og.png">
   ```

   Add `<meta property="og:url" content="https://YOUR-DOMAIN/">` and `<link rel="canonical" href="https://YOUR-DOMAIN/">` too, and a `Sitemap:` line in `robots.txt` if you add a sitemap.
2. `404.html` uses root-relative paths (`/style.css`). If the site lives under a subpath, such as `user.github.io/keman/`, change them to that path.
3. On launch day, paste the Product Hunt badge embed code where `index.html` has the `Product Hunt badge` comment.
4. Add the site URL to the GitHub repo's About box, and to the Product Hunt post.

## Regenerate the real output

The terminals, alert cards and HTTP exchanges come from the same captures as the gallery. After a change to the UI, CLI, alerts or proxy errors, from the repo root:

```sh
docs/media/src/capture.sh                       # seeds .demo/ and captures into .demo/shots (needs tmux)
python3 docs/media/src/website.py .demo/shots .media-cache/fonts .demo/og-html
node .media-cache/render/render.mjs .demo/og-html website 1200 630
```

`capture.sh` also runs `requests.py`, which sends one request per simulator scenario through the demo proxy (a valid key, a copy from another country, a disallowed model or path, a disabled, rotated and decoy key) and records the real responses in `requests.json`.

`website.py` then replaces the contents of every `<pre data-capture="NAME">` with `NAME.ans`, every `data-alert` element with that alert's Slack text, and every `<pre data-request="ID">` with that recorded exchange. Everything else in `index.html` is edited by hand. Running it twice changes nothing. See [`docs/media/src/README.md`](../docs/media/src/README.md) for the fonts and Playwright setup.

To regenerate the bundled fonts from the full ones in `.media-cache/fonts` (needs `pip install fonttools brotli`):

```sh
U="U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+2000-206F,U+2190-2199,U+2212,U+2318,U+2713,U+2715"
pyftsubset .media-cache/fonts/InterVariable.woff2 --unicodes="$U" \
  --layout-features='kern,liga,calt,ss01,cv11,tnum' --flavor=woff2 --output-file=website/fonts/inter.woff2
for w in Regular Bold; do
  pyftsubset .media-cache/fonts/JetBrainsMono-$w.woff2 --unicodes="$U,U+2500-25FF" --layout-features=kern \
    --flavor=woff2 --output-file=website/fonts/jetbrains-mono-$(echo $w | tr A-Z a-z).woff2
done
```

## Preview

Serve it over HTTP, so the font preloads work as they will in production:

```sh
python3 -m http.server -d website 8000
```

Then open http://localhost:8000.
