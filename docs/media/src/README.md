# Gallery images

`docs/media/producthunt/` holds the Product Hunt gallery (1270×760, rendered at 2×) and the 240×240 thumbnail. Every terminal in them is a real capture of Keman running on the demo install from `scripts/demo.sh`. The alert cards show the exact text Keman sent to its Slack destination.

To make them again after a UI change, from the repo root:

```sh
docs/media/src/capture.sh                       # seeds .demo/, captures into .demo/shots (needs tmux)
python3 docs/media/src/build.py .demo/shots FONTS .demo/gallery-html
node docs/media/src/render.mjs .demo/gallery-html docs/media/producthunt   # needs: npm i playwright
```

`FONTS` is a directory with `JetBrainsMono-Regular.woff2` and `JetBrainsMono-Bold.woff2` ([JetBrains Mono](https://github.com/JetBrains/JetBrainsMono/releases)) and `InterVariable.woff2` ([Inter](https://github.com/rsms/inter/releases)). Both are under the SIL Open Font License.

| File | Shows |
| --- | --- |
| `capture.sh` | Seeds the demo and records the UI and CLI with `tmux capture-pane -e` |
| `ansi2html.py` | Turns the captures into HTML with the xterm-256 palette |
| `build.py` | Lays out each image: headline, explanation, terminal or alert card |
| `render.mjs` | Fits each terminal's font to its space and screenshots with Chromium |
