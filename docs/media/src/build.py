"""Compose the gallery images as HTML from the captures made by capture.sh.

Usage: python3 docs/media/src/build.py SHOTS_DIR FONTS_DIR OUT_DIR

SHOTS_DIR holds the .ans captures and alerts.jsonl. FONTS_DIR holds
JetBrainsMono-Regular.woff2, JetBrainsMono-Bold.woff2 and
InterVariable.woff2. Each image is 1270x760 CSS pixels, the size Product Hunt
recommends; render.mjs shoots them at 2x.

The style is flat and light: a centered headline and one-line subtitle over
a light background, and the app window centered below, cut off by the
bottom edge.
"""
import html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansi2html import convert  # noqa: E402

W, H = 1270, 760
SRC = os.path.dirname(os.path.abspath(__file__))
LOGO = open(os.path.join(SRC, "..", "logo.svg")).read()
ANSI = re.compile(r"\x1b\[[0-9;]*m")

CSS = """
@font-face { font-family: Mono; src: url('FONTS/JetBrainsMono-Regular.woff2'); font-weight: 400; }
@font-face { font-family: Mono; src: url('FONTS/JetBrainsMono-Bold.woff2'); font-weight: 700; }
@font-face { font-family: Inter; src: url('FONTS/InterVariable.woff2'); font-weight: 100 900; }
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --fg: #1f2328; --bg: #ffffff; }
html, body { width: WIDTHpx; height: HEIGHTpx; overflow: hidden; }
body {
  font-family: Inter, sans-serif; color: #111114; -webkit-font-smoothing: antialiased;
  background: #f6f5f9; display: flex; flex-direction: column; align-items: center;
  padding-top: 50px; text-align: center;
}
h1 { font-size: 46px; line-height: 1.1; font-weight: 680; letter-spacing: -.012em; }
.sub { margin-top: 14px; font-size: 20px; line-height: 1.4; color: #6c6b76; max-width: 1080px; }
.stage { flex: 1; min-height: 0; width: 100%; margin-top: 40px; display: flex; flex-direction: column;
  align-items: center; gap: 18px; text-align: left; }
.win { flex: none; background: var(--bg); border: 1px solid #e4e3ea; border-radius: 12px; overflow: hidden;
  box-shadow: 0 1px 2px rgba(17, 17, 40, .04), 0 18px 50px rgba(17, 17, 40, .09); }
.bar { height: 34px; display: flex; align-items: center; gap: 8px; padding: 0 14px;
  background: #fbfbfc; border-bottom: 1px solid #efeef3; }
.bar i { width: 12px; height: 12px; border-radius: 50%; display: block; }
.bar i:nth-child(1) { background: #ff5f57; } .bar i:nth-child(2) { background: #febc2e; } .bar i:nth-child(3) { background: #28c840; }
.bar span { flex: 1; text-align: center; margin-right: 52px; font-size: 13px; color: #8b8a94; }
pre { font-family: Mono, monospace; color: var(--fg); line-height: 1.34; padding: 16px 20px 18px; white-space: pre; }
"""

# fit() shrinks each terminal's font until it fits its width (data-maxw, or
# 1120px) and the height that stays visible (data-maxh, or down to the
# bottom edge). Then the last box in the stage is stretched past the bottom
# edge so the image cuts it off. render.mjs calls fit() after fonts load.
FIT_JS = """
<script>
window.fit = () => {
  const stage = document.querySelector('.stage');
  for (const win of document.querySelectorAll('.win')) {
    const pre = win.querySelector('pre');
    const maxW = +(win.dataset.maxw || 1120);
    let fs = +win.dataset.maxfont;
    for (let i = 0; i < 8; i++) {
      pre.style.fontSize = fs + 'px';
      const top = win.getBoundingClientRect().top;
      const maxH = +(win.dataset.maxh || (innerHeight - top - 26));
      const r = Math.min(1, maxW / win.offsetWidth, maxH / win.offsetHeight);
      if (r >= 0.999) break;
      fs = Math.floor(fs * r * 100) / 100 - 0.05;
    }
  }
  const last = stage.lastElementChild;
  if (last && !last.classList.contains('nobleed')) {
    last.style.minHeight = (innerHeight - last.getBoundingClientRect().top + 40) + 'px';
  }
};
</script>
"""


def page(body, extra_css=""):
    css = CSS.replace("WIDTH", str(W)).replace("HEIGHT", str(H)) + extra_css
    return (f"<!doctype html><html><head><meta charset='utf-8'><style>{css}</style>{FIT_JS}</head>"
            f"<body>{body}</body></html>")


def load(shots, name):
    """Read a capture, drop the trailing prompt and squeeze runs of blank lines."""
    lines = open(os.path.join(shots, name + ".ans"), encoding="utf-8").read().rstrip("\n").split("\n")
    plain = [ANSI.sub("", l).rstrip() for l in lines]
    while plain and (not plain[-1] or re.fullmatch(r"\S+ \$", plain[-1])):
        lines.pop()
        plain.pop()
    out, blank = [], False
    for raw, p in zip(lines, plain):
        if not p:
            if blank:
                continue
            blank = True
        else:
            blank = False
        out.append(raw)
    return "\n".join(out)


def terminal(shots, name, title, max_w=None, max_font=17.0, max_h=None):
    """A terminal window holding one capture."""
    limit = (f" data-maxw='{max_w}'" if max_w else "") + (f" data-maxh='{max_h}'" if max_h else "")
    return (
        f"<div class='win' data-maxfont='{max_font}'{limit}><div class='bar'><i></i><i></i><i></i>"
        f"<span>{html.escape(title)}</span></div>"
        f"<pre style='font-size:{max_font}px'>{convert(load(shots, name))}</pre></div>"
    )


SLACK_CSS = """
.slack { width: 1060px; background: #fff; border: 1px solid #e4e3ea; border-radius: 12px; overflow: hidden;
  box-shadow: 0 1px 2px rgba(17,17,40,.04), 0 18px 50px rgba(17,17,40,.09); font-family: Inter, sans-serif; }
.slack .chan { padding: 13px 20px; border-bottom: 1px solid #efeef3; color: #1d1c1d; font-weight: 700; font-size: 15px; }
.slack .chan small { color: #8b8a94; font-weight: 400; margin-left: 6px; }
.msg { display: flex; gap: 12px; padding: 16px 20px 20px; }
.msg svg { width: 38px; height: 38px; flex: none; border-radius: 8px; }
.who { font-size: 15px; font-weight: 800; color: #1d1c1d; }
.who b { font-size: 10px; font-weight: 700; color: #616061; background: #ececee; border-radius: 3px;
  padding: 1px 4px; margin-left: 5px; vertical-align: 2px; }
.who small { font-weight: 400; color: #8b8a94; font-size: 12px; margin-left: 6px; }
.text { margin-top: 4px; font-size: 15px; line-height: 1.55; color: #1d1c1d; white-space: pre-wrap; word-break: break-word; }
"""


def slack(alert_text, channel="security-alerts", when="4:31 PM"):
    return (
        f"<div class='slack'><div class='chan'># {channel}<small>Keman alerts</small></div>"
        f"<div class='msg'>{LOGO}<div><div class='who'>Keman<b>APP</b><small>{when}</small></div>"
        f"<div class='text'>{html.escape(alert_text)}</div></div></div></div>"
    )


def find_alert(shots, rule, key=None):
    for line in open(os.path.join(shots, "alerts.jsonl"), encoding="utf-8"):
        j = json.loads(line)
        if j["path"] != "/slack":
            continue
        text = j["body"]["text"]
        if f"] {rule} on virtual key" in text and (key is None or f"key {key} (" in text):
            return text.rstrip("\n")
    raise SystemExit(f"no {rule} alert in alerts.jsonl")


DIAGRAM_CSS = """
.stage { justify-content: center; padding-bottom: 60px; }
.flow { display: grid; grid-template-columns: 240px 120px 330px 120px 240px; align-items: center; }
.node { background: #fff; border: 1px solid #e4e3ea; border-radius: 14px; padding: 18px 20px;
  box-shadow: 0 1px 2px rgba(17,17,40,.04), 0 14px 40px rgba(17,17,40,.07); }
.node h3 { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
.node p { font-size: 14px; line-height: 1.5; color: #6c6b76; }
.node code { font-family: Mono, monospace; font-size: 13px; color: #1f2328; background: #f2f1f6; border-radius: 4px; padding: 1px 5px; }
.node.keman { border: 1.5px solid #111114; padding: 22px; }
.node.keman h3 { display: flex; align-items: center; gap: 10px; font-size: 22px; }
.node.keman svg { width: 32px; height: 32px; border-radius: 7px; }
.node.keman ul { list-style: none; margin-top: 8px; }
.node.keman li { font-size: 14px; line-height: 1.45; color: #3f3e48; padding: 7px 0; border-top: 1px solid #efeef3; }
.node.keman li:first-child { border-top: 0; }
.node.keman li b { color: #111114; font-weight: 650; }
.node.thief { border-color: #f3c4c0; }
.node.thief h3 { color: #c7372f; }
.arrow { position: relative; height: 1.5px; margin: 0 12px; background: #8b8a94; }
.arrow::after { content: ''; position: absolute; right: -1px; top: -5px; border: 6px solid transparent;
  border-left: 9px solid #8b8a94; border-right: 0; }
.arrow span { position: absolute; left: 50%; transform: translateX(-50%); bottom: 9px; white-space: nowrap;
  font-family: Mono, monospace; font-size: 12.5px; color: #3f3e48; }
.arrow.bad { background: #d9534f; }
.arrow.bad::after { border-left-color: #d9534f; }
.ups p { font-size: 14.5px; color: #3f3e48; padding: 3px 0; }
.stack { display: flex; flex-direction: column; gap: 64px; }
.blocked { margin-top: 12px; font-size: 13.5px; font-weight: 600; color: #c7372f; }
"""


def diagram():
    return f"""
<div class='flow nobleed'>
  <div class='stack'>
    <div class='node'><h3>Your app</h3><p>Holds a virtual key</p><p style='margin-top:6px'><code>kmn_x7Kq…</code></p></div>
    <div class='node thief'><h3>A leaked copy</h3><p>Used from a network or country you never allowed</p></div>
  </div>
  <div class='stack'>
    <div class='arrow'><span>kmn_ key</span></div>
    <div class='arrow bad'><span>kmn_ key</span></div>
  </div>
  <div class='node keman'>
    <h3>{LOGO}Keman</h3>
    <ul>
      <li><b>Checks</b> address, country, expiry, paths and models</li>
      <li><b>Limits</b> requests per minute and dollars per day</li>
      <li><b>Watches</b> for new countries, spikes and decoys</li>
      <li><b>Swaps in</b> the real key, encrypted at rest</li>
    </ul>
    <p class='blocked'>✕ Leaked copy refused, alert sent</p>
  </div>
  <div class='arrow'><span>real key</span></div>
  <div class='node ups'><h3>Provider</h3><p>OpenAI</p><p>Anthropic</p><p>OpenRouter</p><p>Stripe, GitHub</p><p>Any header-auth API</p></div>
</div>"""


def build(shots, fonts, out):
    for f in ("JetBrainsMono-Regular.woff2", "JetBrainsMono-Bold.woff2", "InterVariable.woff2"):
        if not os.path.isfile(os.path.join(fonts, f)):
            raise SystemExit(f"missing font {os.path.join(fonts, f)}")
    os.makedirs(out, exist_ok=True)

    def shot(name, title, sub, stage, css=""):
        body = f"<h1>{title}</h1><p class='sub'>{sub}</p><div class='stage'>{stage}</div>"
        doc = page(body, css).replace("FONTS/", "file://" + os.path.abspath(fonts) + "/")
        with open(os.path.join(out, name + ".html"), "w", encoding="utf-8") as f:
            f.write(doc)

    shot("01-hero", "Your apps never hold the real API key",
         "Keman keeps your provider keys and hands apps virtual ones you can lock, expire, watch, and kill.",
         terminal(shots, "keys", "keman"))
    shot("02-how-it-works", "A leaked key only works where you allow it",
         "Apps send a virtual key. Keman checks it, then forwards the request with the real key.",
         diagram(), DIAGRAM_CSS)
    shot("03-stolen-key", "See who used a key, from where, and what it cost",
         "A copy of support-bot is burning Opus credits from a new country. Keman shows every request.",
         terminal(shots, "detail-support-bot", "keman · support-bot"))
    shot("04-alert", "Every alert tells you what to do next",
         "Slack or a signed webhook, with who called, from where, and the exact command to respond.",
         slack(find_alert(shots, "spend_spike", "support-bot")), SLACK_CSS)
    shot("05-detections", "Notices the ways keys get abused",
         "New countries, spend spikes, blocked probes, disabled keys and decoys, grouped into incidents.",
         terminal(shots, "detections", "keman · detections"))
    shot("06-contain", "Kill a leaked key in one command",
         "The app gets a replacement with the same policy. The real provider key stays untouched.",
         terminal(shots, "rotate", "acme-api", max_font=16))
    shot("07-canary", "Plant a decoy, catch the thief",
         "Canary keys look real, never reach the provider, and raise a critical alert on first use.",
         terminal(shots, "canary", "acme-api", max_h=225) + slack(find_alert(shots, "canary_used"), when="4:32 PM"),
         SLACK_CSS + ".slack { width: 1000px; }")
    shot("08-scan", "Find the keys you already leaked",
         "keman scan checks files and every commit, offline, and exits 3 so it can gate CI.",
         terminal(shots, "scan", "acme-api"))
    shot("09-exposure", "Know which keys would hurt if they leaked",
         "keman exposure lists keys that work from anywhere or never expire, with the fix for each.",
         terminal(shots, "exposure", "acme-api"))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    build(*sys.argv[1:])
