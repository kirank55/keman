# Website

The Keman landing page. It is plain static HTML, CSS and a few lines of JavaScript, with no build step and no third-party requests: no fonts, analytics or scripts are loaded from anywhere else. Host this directory as is on any static host (GitHub Pages, Cloudflare Pages, Netlify, S3).

| File | What it is |
| --- | --- |
| `index.html` | The page. The terminals and alert cards hold real output from the demo install. |
| `style.css` | Flat black and white, matching the Product Hunt gallery |
| `main.js` | Copy buttons, install tabs, and the nav border on scroll |
| `logo.svg`, `favicon.svg`, `apple-touch-icon.png` | The logo and icons |
| `og.png` | The 1200×630 social card (rendered at 2×) |

Fonts use the system stack (SF Pro on Apple devices, Segoe UI on Windows), with Inter and JetBrains Mono when they are installed locally.

## Before you publish

1. Set the absolute URL of `og.png` in `index.html`. Link previews on X, LinkedIn and Slack need an absolute URL:

   ```html
   <meta property="og:image" content="https://YOUR-DOMAIN/og.png">
   ```

   Add `<meta property="og:url" content="https://YOUR-DOMAIN/">` and `<link rel="canonical" href="https://YOUR-DOMAIN/">` too.
2. On launch day, paste the Product Hunt badge embed code where `index.html` has the `Product Hunt badge` comment.
3. Add the site URL to the GitHub repo's About box, and to the Product Hunt post.

## Regenerate the terminals

The terminals and alert cards come from the same captures as the gallery. After a UI change, from the repo root:

```sh
docs/media/src/capture.sh                       # seeds .demo/, captures into .demo/shots (needs tmux)
python3 docs/media/src/website.py .demo/shots .media-cache/fonts .demo/og-html
node .media-cache/render/render.mjs .demo/og-html website 1200 630
```

`website.py` replaces the contents of every `<pre data-capture="NAME">` with `NAME.ans`, and every `data-alert` element with that alert's Slack text. Everything else in `index.html` is edited by hand. See [`docs/media/src/README.md`](../docs/media/src/README.md) for the fonts and Playwright setup.

To preview locally, open `index.html` in a browser, or run `python3 -m http.server -d website` and visit http://localhost:8000.
