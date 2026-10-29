"""Compose the gallery images as HTML from the captures made by capture.sh.

Usage: python3 docs/media/src/build.py SHOTS_DIR FONTS_DIR OUT_DIR

SHOTS_DIR holds the .ans captures and alerts.jsonl. FONTS_DIR holds
JetBrainsMono-Regular.woff2, JetBrainsMono-Bold.woff2 and
InterVariable.woff2. Each image is 1270x760 CSS pixels, the size Product Hunt
recommends; render.mjs shoots them at 2x.

The style is flat black and white: the logo, headline and subtitle on the
left of a white page, and a black terminal (or a white alert card) floating
on the right, fully in frame.
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
:root { --fg: #e6e6e6; --bg: #000000; }
html, body { width: WIDTHpx; height: HEIGHTpx; overflow: hidden; }
body {
  font-family: Inter, sans-serif; color: #0a0a0a; -webkit-font-smoothing: antialiased; background: #fff;
  display: flex; align-items: center; gap: 40px; padding: 0 34px 0 58px;
}
.copy { flex: none; width: 360px; }
.copy.wide { width: 396px; }
.logo { display: flex; align-items: center; gap: 11px; font-weight: 800; font-size: 20px; letter-spacing: .2em; }
.logo svg { width: 36px; height: 36px; }
h1 { margin-top: 30px; font-size: 40px; line-height: 1.08; font-weight: 780; letter-spacing: -.03em; }
.sub { margin-top: 18px; font-size: 18px; line-height: 1.55; color: #525252; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 26px; }
.chip { display: flex; align-items: center; gap: 7px; padding: 6px 9px; border-radius: 9px; border: 1px solid #e5e5e5;
  font-size: 12px; font-weight: 600; white-space: nowrap; }
.cta-row { display: flex; align-items: center; gap: 16px; margin-top: 28px; }
.cta { padding: 14px 22px; border-radius: 10px; background: #0a0a0a; color: #fff; font-weight: 700; font-size: 16px; white-space: nowrap; }
.meta { color: #737373; font-size: 13px; font-weight: 500; white-space: nowrap; }
.stage { flex: 1; min-width: 0; height: 100%; display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 20px; }
.win { flex: none; background: var(--bg); border: 1px solid #262626; border-radius: 12px; overflow: hidden;
  box-shadow: 0 24px 60px rgba(0, 0, 0, .20), 0 2px 8px rgba(0, 0, 0, .10); }
.bar { height: 32px; display: flex; align-items: center; gap: 7px; padding: 0 13px;
  background: #111; border-bottom: 1px solid #262626; }
.bar i { width: 11px; height: 11px; border-radius: 50%; display: block; }
.bar i:nth-child(1) { background: #ff5f57; } .bar i:nth-child(2) { background: #febc2e; } .bar i:nth-child(3) { background: #28c840; }
.bar span { flex: 1; text-align: center; margin-right: 46px; font-size: 12px; color: #8a8a8a; }
pre { font-family: Mono, monospace; color: var(--fg); line-height: 1.24; padding: 14px 12px; white-space: pre;
  font-variant-ligatures: none; }
"""

# fit() shrinks each terminal's font until the window fits the stage's width
# and its share of the height (data-maxh, or what the other boxes leave).
# render.mjs calls fit() after fonts load.
FIT_JS = """
<script>
window.fit = () => {
  const stage = document.querySelector('.stage');
  const gap = parseFloat(getComputedStyle(stage).rowGap) || 0;
  for (const win of stage.querySelectorAll('.win')) {
    const pre = win.querySelector('pre');
    const others = [...stage.children].filter((c) => c !== win)
      .reduce((h, c) => h + c.offsetHeight + gap, 0);
    const maxW = stage.clientWidth;
    const maxH = +(win.dataset.maxh || (innerHeight - 96 - others));
    const fits = () => pre.scrollWidth + 2 <= maxW && win.offsetHeight <= maxH;
    let lo = 6, hi = +win.dataset.maxfont;
    pre.style.fontSize = hi + 'px';
    if (!fits()) {
      for (let i = 0; i < 14; i++) {
        const mid = (lo + hi) / 2;
        pre.style.fontSize = mid + 'px';
        if (fits()) lo = mid; else hi = mid;
      }
      pre.style.fontSize = lo + 'px';
    }
  }
};
</script>
"""

CHIP_ICONS = {
    "globe": "<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18'/>",
    "layers": "<path d='M12 2 3 7l9 5 9-5zM3 17l9 5 9-5M3 12l9 5 9-5'/>",
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
}


def chip(icon, label):
    return (f"<div class='chip'><svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
            f"stroke-width='2.2'>{CHIP_ICONS[icon]}</svg>{html.escape(label)}</div>")


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


def terminal(shots, name, title, max_font=15.0, max_h=None):
    """A terminal window holding one capture."""
    limit = f" data-maxh='{max_h}'" if max_h else ""
    return (
        f"<div class='win' data-maxfont='{max_font}'{limit}><div class='bar'><i></i><i></i><i></i>"
        f"<span>{html.escape(title)}</span></div>"
        f"<pre style='font-size:{max_font}px'>{convert(load(shots, name))}</pre></div>"
    )


SLACK_CSS = """
.slack { width: 100%; background: #fff; border: 1px solid #e5e5e5; border-radius: 12px; overflow: hidden;
  box-shadow: 0 24px 60px rgba(0, 0, 0, .12), 0 2px 8px rgba(0, 0, 0, .06); font-family: Inter, sans-serif; }
.slack .chan { padding: 12px 18px; border-bottom: 1px solid #eee; color: #0a0a0a; font-weight: 700; font-size: 14px; }
.slack .chan small { color: #8a8a8a; font-weight: 400; margin-left: 6px; }
.msg { display: flex; gap: 12px; padding: 14px 18px 18px; }
.msg svg { width: 36px; height: 36px; flex: none; border-radius: 8px; }
.who { font-size: 14px; font-weight: 800; color: #0a0a0a; }
.who b { font-size: 10px; font-weight: 700; color: #525252; background: #eee; border-radius: 3px;
  padding: 1px 4px; margin-left: 5px; vertical-align: 2px; }
.who small { font-weight: 400; color: #8a8a8a; font-size: 12px; margin-left: 6px; }
.text { margin-top: 4px; font-size: 13.5px; line-height: 1.5; color: #0a0a0a; white-space: pre-wrap; word-break: break-word; }
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
.flow { width: 100%; max-width: 680px; display: flex; flex-direction: column; align-items: stretch; }
.pair { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.node { background: #fff; border: 1px solid #e5e5e5; border-radius: 12px; padding: 16px 18px; }
.node h3 { font-size: 17px; font-weight: 700; margin-bottom: 6px; }
.node p { font-size: 14px; line-height: 1.5; color: #525252; }
.node code { font-family: Mono, monospace; font-size: 13px; color: #0a0a0a; background: #f5f5f5; border-radius: 4px; padding: 1px 5px; }
.node.keman { background: #000; border-color: #000; color: #fff; padding: 20px 22px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, .20), 0 2px 8px rgba(0, 0, 0, .10); }
.node.keman h3 { display: flex; align-items: center; gap: 10px; font-size: 20px; }
.node.keman h3 svg { width: 30px; height: 30px; border-radius: 7px; outline: 1px solid #333; }
.node.keman ul { list-style: none; margin-top: 6px; }
.node.keman li { font-size: 14px; line-height: 1.45; color: #a3a3a3; padding: 7px 0; border-top: 1px solid #262626; }
.node.keman li:first-child { border-top: 0; }
.node.keman li b { color: #fff; font-weight: 650; }
.node.thief h3 { color: #dc2626; }
.node .blocked { margin-top: 10px; font-size: 13.5px; font-weight: 600; color: #f87171; }
.down { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; height: 56px; }
.down.one { grid-template-columns: 1fr; }
.arrow { position: relative; justify-self: center; width: 1.5px; height: 100%; background: #0a0a0a; }
.arrow::after { content: ''; position: absolute; left: -5.25px; bottom: -1px; border: 6px solid transparent;
  border-top: 9px solid #0a0a0a; border-bottom: 0; }
.arrow span { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); white-space: nowrap;
  font-family: Mono, monospace; font-size: 12.5px; color: #525252; }
.arrow.bad { background: #dc2626; }
.arrow.bad::after { border-top-color: #dc2626; }
.ups { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
.ups h3 { margin: 0; }
.ups p { color: #0a0a0a; }
"""


def diagram():
    return f"""
<div class='flow'>
  <div class='pair'>
    <div class='node'><h3>Your app</h3><p>Holds a virtual key</p><p style='margin-top:6px'><code>kmn_x7Kq…</code></p></div>
    <div class='node thief'><h3>A leaked copy</h3><p>Used from a network or country you never allowed</p></div>
  </div>
  <div class='down'>
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
  <div class='down one'><div class='arrow'><span>real key</span></div></div>
  <div class='node ups'><h3>Provider</h3><p>OpenAI · Anthropic · OpenRouter · Stripe · GitHub · any header-auth API</p></div>
</div>"""


def build(shots, fonts, out):
    for f in ("JetBrainsMono-Regular.woff2", "JetBrainsMono-Bold.woff2", "InterVariable.woff2"):
        if not os.path.isfile(os.path.join(fonts, f)):
            raise SystemExit(f"missing font {os.path.join(fonts, f)}")
    os.makedirs(out, exist_ok=True)

    def shot(name, title, sub, stage, css="", extra=""):
        wide = " wide" if extra else ""
        body = (f"<div class='copy{wide}'><div class='logo'>{LOGO}KEMAN</div><h1>{title}</h1>"
                f"<p class='sub'>{sub}</p>{extra}</div><div class='stage'>{stage}</div>")
        doc = page(body, css).replace("FONTS/", "file://" + os.path.abspath(fonts) + "/")
        with open(os.path.join(out, name + ".html"), "w", encoding="utf-8") as f:
            f.write(doc)

    hero_extra = (
        "<div class='chips'>" + chip("globe", "IP & country locks") + chip("layers", "Canary keys")
        + chip("clock", "Auto-expiry") + "</div>"
        "<div class='cta-row'><div class='cta'>Get Keman on GitHub →</div>"
        "<div class='meta'>One Go binary · Apache-2.0</div></div>"
    )
    shot("01-hero", "OpenSource protection from leaked API keys",
         "Apps get virtual keys. The real key never leaves Keman, so a leaked copy is locked, watched, and killed in one command.",
         terminal(shots, "keys", "keman"), extra=hero_extra)
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
         terminal(shots, "rotate", "acme-api"))
    shot("07-canary", "Plant a decoy, catch the thief",
         "Canary keys look real, never reach the provider, and raise a critical alert on first use.",
         terminal(shots, "canary", "acme-api", max_h=200) + slack(find_alert(shots, "canary_used"), when="4:32 PM"),
         SLACK_CSS)
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
