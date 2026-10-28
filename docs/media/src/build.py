"""Compose the gallery images as HTML from the captures made by capture.sh.

Usage: python3 docs/media/src/build.py SHOTS_DIR FONTS_DIR OUT_DIR

SHOTS_DIR holds the .ans captures and alerts.jsonl. FONTS_DIR holds
JetBrainsMono-Regular.woff2, JetBrainsMono-Bold.woff2 and
InterVariable.woff2. Each image is 1270x760 CSS pixels, the size Product Hunt
recommends; render.mjs shoots them at 2x.
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
:root { --fg: #d7dde6; --bg: #0d1117; }
html, body { width: WIDTHpx; height: HEIGHTpx; overflow: hidden; }
body {
  font-family: Inter, sans-serif; color: #f8fafc; -webkit-font-smoothing: antialiased;
  background:
    radial-gradient(900px 500px at 0% 0%, rgba(94, 234, 212, .13), transparent 60%),
    radial-gradient(900px 600px at 100% 100%, rgba(129, 140, 248, .16), transparent 60%),
    #080c16;
  display: flex; flex-direction: column; padding: 34px 54px 30px;
}
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 17px; color: #cbd5e1; }
.brand svg { width: 28px; height: 28px; }
.brand .tag { margin-left: auto; font-size: 13px; font-weight: 500; color: #94a3b8;
  border: 1px solid rgba(148, 163, 184, .25); border-radius: 999px; padding: 4px 12px; }
h1 { margin-top: 20px; font-size: 38px; line-height: 1.12; font-weight: 750; letter-spacing: -.025em; }
h1 em { font-style: normal; background: linear-gradient(90deg, #5eead4, #818cf8);
  -webkit-background-clip: text; background-clip: text; color: transparent; }
.sub { margin-top: 10px; font-size: 18px; line-height: 1.45; color: #94a3b8; max-width: 1050px; }
.stage { flex: 1; min-height: 0; margin-top: 22px; display: flex; gap: 22px; align-items: center; justify-content: center; }
.win { flex: none; background: var(--bg); border: 1px solid rgba(255, 255, 255, .09); border-radius: 12px;
  box-shadow: 0 30px 80px rgba(0, 0, 0, .55), 0 0 0 1px rgba(0, 0, 0, .4); overflow: hidden; }
.bar { height: 34px; display: flex; align-items: center; gap: 8px; padding: 0 14px;
  background: #161b22; border-bottom: 1px solid rgba(255, 255, 255, .06); }
.bar i { width: 12px; height: 12px; border-radius: 50%; display: block; }
.bar i:nth-child(1) { background: #ff5f57; } .bar i:nth-child(2) { background: #febc2e; } .bar i:nth-child(3) { background: #28c840; }
.bar span { flex: 1; text-align: center; margin-right: 52px; font-size: 13px; color: #8b949e; }
pre { font-family: Mono, monospace; color: var(--fg); line-height: 1.32; padding: 14px 18px 16px; white-space: pre; }
"""


def page(body, extra_css=""):
    css = CSS.replace("WIDTH", str(W)).replace("HEIGHT", str(H)) + extra_css
    return f"<!doctype html><html><head><meta charset='utf-8'><style>{css}</style>{FIT_JS}</head><body>{body}</body></html>"


def header(title, sub):
    return (
        f"<div class='brand'>{LOGO}<span>Keman</span><span class='tag'>open source · self-hosted</span></div>"
        f"<h1>{title}</h1><p class='sub'>{sub}</p>"
    )


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
    cols = max(len(ANSI.sub("", l)) for l in out)
    return "\n".join(out), cols, len(out)


def terminal(shots, name, title, max_w=None, max_font=17.0, max_h=None):
    """A terminal window. fit() in the page sizes the font to the space."""
    text, _, _ = load(shots, name)
    limit = (f" data-maxw='{max_w}'" if max_w else "") + (f" data-maxh='{max_h}'" if max_h else "")
    return (
        f"<div class='win' data-maxfont='{max_font}'{limit}><div class='bar'><i></i><i></i><i></i>"
        f"<span>{html.escape(title)}</span></div>"
        f"<pre style='font-size:{max_font}px'>{convert(text)}</pre></div>"
    )


# Shrink each terminal's font until its window fits the stage (or its own
# data-maxw), measured with the real font after it loads. render.mjs calls
# fit() before each screenshot.
FIT_JS = """
<script>
window.fit = () => {
  const stage = document.querySelector('.stage');
  for (const win of document.querySelectorAll('.win')) {
    const pre = win.querySelector('pre');
    const maxW = +(win.dataset.maxw || stage.clientWidth);
    const maxH = +(win.dataset.maxh || stage.clientHeight);
    let fs = +win.dataset.maxfont;
    for (let i = 0; i < 6; i++) {
      pre.style.fontSize = fs + 'px';
      const r = Math.min(1, maxW / win.offsetWidth, maxH / win.offsetHeight);
      if (r >= 0.999) break;
      fs = Math.floor(fs * r * 100) / 100 - 0.05;
    }
  }
};
</script>
"""


SLACK_CSS = """
.slack { width: 560px; background: #1a1d21; border: 1px solid rgba(255,255,255,.08); border-radius: 12px;
  box-shadow: 0 30px 80px rgba(0,0,0,.55); overflow: hidden; font-family: Inter, sans-serif; }
.slack .chan { padding: 12px 18px; border-bottom: 1px solid rgba(255,255,255,.07); color: #d1d2d3; font-weight: 700; font-size: 15px; }
.slack .chan small { color: #8b8d90; font-weight: 400; margin-left: 6px; }
.msg { display: flex; gap: 12px; padding: 16px 18px 18px; }
.msg svg { width: 38px; height: 38px; flex: none; border-radius: 8px; }
.who { font-size: 15px; font-weight: 800; color: #f8f8f8; }
.who b { font-size: 10px; font-weight: 700; color: #b9bbbe; background: rgba(255,255,255,.1); border-radius: 3px; padding: 1px 4px; margin-left: 5px; vertical-align: 2px; }
.who small { font-weight: 400; color: #8b8d90; font-size: 12px; margin-left: 6px; }
.text { margin-top: 4px; font-size: 14px; line-height: 1.5; color: #d1d2d3; white-space: pre-wrap; word-break: break-word; }
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
.flow { display: grid; grid-template-columns: 250px 1fr 330px 1fr 250px; align-items: center; width: 100%; }
.node { background: #0f1522; border: 1px solid rgba(255,255,255,.1); border-radius: 14px; padding: 18px 20px; box-shadow: 0 20px 50px rgba(0,0,0,.45); }
.node h3 { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
.node p { font-size: 14px; line-height: 1.5; color: #94a3b8; }
.node code { font-family: Mono, monospace; font-size: 13px; color: #5eead4; }
.node.keman { border: 1px solid rgba(94,234,212,.45); background: linear-gradient(180deg, #111a2c, #0d1322); padding: 22px; }
.node.keman h3 { display: flex; align-items: center; gap: 10px; font-size: 22px; }
.node.keman svg { width: 34px; height: 34px; }
.node.keman ul { list-style: none; margin-top: 10px; }
.node.keman li { font-size: 14px; color: #cbd5e1; padding: 5px 0; border-top: 1px solid rgba(255,255,255,.06); }
.node.keman li:first-child { border-top: 0; }
.node.keman li b { color: #5eead4; font-weight: 600; }
.node.thief { border-color: rgba(255,107,107,.45); }
.node.thief h3 { color: #ff8a8a; }
.arrow { position: relative; height: 2px; margin: 0 14px; background: linear-gradient(90deg, rgba(94,234,212,.2), #5eead4); }
.arrow::after { content: ''; position: absolute; right: -2px; top: -5px; border: 6px solid transparent; border-left: 9px solid #5eead4; border-right: 0; }
.arrow span { position: absolute; left: 50%; transform: translateX(-50%); bottom: 10px; white-space: nowrap; font-family: Mono, monospace; font-size: 12.5px; color: #cbd5e1; }
.arrow.bad { background: linear-gradient(90deg, rgba(255,107,107,.2), #ff6b6b); }
.arrow.bad::after { border-left-color: #ff6b6b; }
.ups p { font-family: Mono, monospace; font-size: 13.5px; color: #cbd5e1; padding: 3px 0; }
.col { display: flex; flex-direction: column; gap: 26px; }
.stack { display: flex; flex-direction: column; gap: 70px; }
.blocked { margin-top: 10px; font-family: Mono, monospace; font-size: 12.5px; color: #ff8a8a; }
"""


def diagram():
    return f"""
<div class='flow'>
  <div class='stack'>
    <div class='node'><h3>Your app</h3><p>Holds a virtual key<br><code>kmn_x7Kq…</code></p></div>
    <div class='node thief'><h3>A leaked copy</h3><p>Used from a network or<br>country the key is not<br>locked to</p></div>
  </div>
  <div class='stack'>
    <div class='arrow'><span>kmn_ key</span></div>
    <div class='arrow bad'><span>kmn_ key</span></div>
  </div>
  <div class='node keman'>
    <h3>{LOGO}Keman</h3>
    <ul>
      <li><b>Checks</b> address, country, expiry, paths, models</li>
      <li><b>Limits</b> requests per minute and dollars per day</li>
      <li><b>Watches</b> for new countries, spikes, decoys</li>
      <li><b>Swaps in</b> the real key, encrypted at rest</li>
    </ul>
    <p class='blocked'>✗ leaked copy refused · alert sent</p>
  </div>
  <div class='arrow'><span>real key</span></div>
  <div class='node ups'><h3>Provider</h3><p>OpenAI</p><p>Anthropic</p><p>OpenRouter</p><p>Stripe, GitHub, any<br>header-auth API</p></div>
</div>"""


def build(shots, fonts, out):
    os.makedirs(out, exist_ok=True)
    def shot(name, title, sub, stage, css=""):
        body = header(title, sub) + f"<div class='stage'>{stage}</div>"
        doc = page(body, css).replace("FONTS/", "file://" + os.path.abspath(fonts) + "/")
        with open(os.path.join(out, name + ".html"), "w", encoding="utf-8") as f:
            f.write(doc)

    shot("01-hero", "Your apps never hold the <em>real API key</em>.",
         "Keman is a self-hosted proxy that keeps your provider keys and hands apps virtual ones you can lock to a network, expire, watch, and kill.",
         terminal(shots, "keys", "keman"))
    shot("02-how-it-works", "A leaked key is only as good as <em>where it works</em>.",
         "Apps send a kmn_ virtual key. Keman checks it, enforces its limits, and forwards the request with the real key, which never leaves Keman.",
         diagram(), DIAGRAM_CSS)
    shot("03-stolen-key", "See who used a key, <em>from where</em>, and what it cost.",
         "A copy of support-bot is burning Opus credits from a new country. Keman shows every client, every request, and the fix for each weakness.",
         terminal(shots, "detail-support-bot", "keman · support-bot"))
    shot("04-alert", "Every alert tells you <em>what to do next</em>.",
         "Alerts go to Slack or a signed webhook, with who called, from where, and the exact command to rotate, disable, or allow.",
         slack(find_alert(shots, "spend_spike", "support-bot")), SLACK_CSS)
    shot("05-detections", "Notices the ways keys <em>get abused</em>.",
         "New countries and networks, spend and rate spikes, blocked probes, disabled keys in use, provider auth failures, and decoys. Grouped into incidents.",
         terminal(shots, "detections", "keman · detections"))
    shot("06-contain", "Kill a leaked key in <em>one command</em>.",
         "The app gets a replacement with the same policy, and the leaked copy stops now. The real provider key, and every other app, stay untouched.",
         terminal(shots, "rotate", "acme-api"))
    shot("07-canary", "Plant a decoy. <em>Catch the thief.</em>",
         "Canary keys look real, never reach the provider, and raise a critical alert the first time anyone uses one.",
         terminal(shots, "canary", "acme-api", max_h=230) + slack(find_alert(shots, "canary_used"), when="4:32 PM"),
         SLACK_CSS + ".stage { flex-direction: column; gap: 18px; } .slack { width: 900px; }")
    shot("08-scan", "Find the keys you <em>already leaked</em>.",
         "keman scan checks files and every commit for OpenAI, Anthropic, Stripe, GitHub, AWS and more keys. Offline, no setup, and it exits 3 to gate CI.",
         terminal(shots, "scan", "acme-api"))
    shot("09-exposure", "Know which keys would hurt <em>if they leaked</em>.",
         "keman exposure lists keys that work from any address, never expire, or sit unused, with the command that fixes each. Lock keys by address, country, rate, and dollar caps.",
         terminal(shots, "exposure", "acme-api"))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    build(*sys.argv[1:])
