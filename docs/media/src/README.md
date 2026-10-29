# Gallery images

`docs/media/producthunt/` holds the Product Hunt gallery (1270×760, rendered at 2×) and the 240×240 thumbnail. Every terminal in them is a real capture of Keman running on the demo install from `scripts/demo.sh`. The alert cards show the exact text Keman sent to its Slack destination.

To make them again after a UI change, from the repo root:

```sh
docs/media/src/capture.sh                       # seeds .demo/, captures into .demo/shots (needs tmux)
python3 docs/media/src/build.py .demo/shots .media-cache/fonts .demo/gallery-html
mkdir -p .media-cache/render && cp docs/media/src/render.mjs .media-cache/render/ && (cd .media-cache/render && npm i playwright)
node .media-cache/render/render.mjs .demo/gallery-html docs/media/producthunt
```

The website uses the same captures. To refresh its terminals, alert cards and social card:

```sh
python3 docs/media/src/website.py .demo/shots .media-cache/fonts .demo/og-html
node .media-cache/render/render.mjs .demo/og-html website 1200 630
```

`.media-cache/fonts` must hold `JetBrainsMono-Regular.woff2` and `JetBrainsMono-Bold.woff2` ([JetBrains Mono](https://github.com/JetBrains/JetBrainsMono/releases)) and `InterVariable.woff2` ([Inter](https://github.com/rsms/inter/releases)). Both are under the SIL Open Font License.

| File | Shows |
| --- | --- |
| `capture.sh` | Seeds the demo and records the UI and CLI with `tmux capture-pane -e` |
| `ansi2html.py` | Turns the captures into HTML with the xterm-256 palette |
| `build.py` | Lays out each image: headline, explanation, terminal or alert card |
| `render.mjs` | Fits each terminal's font to its space and screenshots with Chromium |
| `website.py` | Fills the website's terminals and alert cards, and lays out its social card |
