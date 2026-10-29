"""Fill website/index.html with the captures made by capture.sh.

Usage: python3 docs/media/src/website.py SHOTS_DIR [FONTS_DIR OG_HTML_DIR]

Every <pre data-capture="NAME"> gets NAME.ans as colored HTML and --cols set
to its widest line. Every element with data-alert="RULE [KEY]" gets the text
of that Slack alert. Every <pre data-request="ID"> gets the HTTP exchange that
requests.py recorded for scenario ID in SHOTS_DIR/requests.json. The page
stays plain HTML, so website/ can be hosted as is. With FONTS_DIR and
OG_HTML_DIR (as for build.py), also write og.html there for render.mjs to
shoot as website/og.png.
"""
import html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansi2html import convert  # noqa: E402
from build import ANSI, LOGO, find_alert, load  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SITE = os.path.join(ROOT, "website")

PRE = re.compile(r'<pre class="term" data-capture="([\w-]+)"[^>]*>.*?</pre>', re.S)
ALERT = re.compile(r'(<div class="text" data-alert="([^"]+)">).*?(</div>)', re.S)
REQUEST = re.compile(r'(<pre class="term http" data-request="([\w-]+)">).*?(</pre>)', re.S)
REASONS = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 429: "Too Many Requests"}


def span(cls, text):
    return f'<span class="{cls}">{html.escape(text)}</span>'


def js(value, indent=0, inline=False):
    """JSON as colored HTML. Objects and arrays stay on one line when they fit in
    74 columns (and always when inline); the top-level object is always expanded."""
    flat = json.dumps(value, ensure_ascii=False)
    expand = not inline and (indent == 0 and isinstance(value, dict) or len(flat) + 2 * indent > 74)
    if isinstance(value, (dict, list)) and value and expand:
        pad = "  " * (indent + 1)
        if isinstance(value, dict):
            items = [f"{span('j-key', json.dumps(k))}: {js(v, indent + 1)}" for k, v in value.items()]
            o, c = "{", "}"
        else:
            items = [js(v, indent + 1) for v in value]
            o, c = "[", "]"
        return o + "\n" + ",\n".join(pad + i for i in items) + "\n" + "  " * indent + c
    if isinstance(value, dict):
        return "{" + ", ".join(f"{span('j-key', json.dumps(k))}: {js(v, inline=True)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(js(v, inline=True) for v in value) + "]"
    if isinstance(value, str):
        return span("j-str", json.dumps(value, ensure_ascii=False))
    if isinstance(value, bool) or value is None:
        return span("j-lit", json.dumps(value))
    return span("j-num", json.dumps(value))


def exchange(r):
    """One recorded request and Keman's response, as an HTTP transcript."""
    where = f"{r['ip']} ({r['country']}, AS{r['asn']})"
    auth = f"Bearer {r['token']}" if r["auth"] == "Authorization" else r["token"]
    status = r["status"]
    lines = [
        span("h-dim", f"# {r['key']}, called from {where}"),
        f"{span('h-method', r['method'])} {html.escape(r['path'])}",
        f"{span('h-hdr', r['auth'] + ':')} {html.escape(auth)}",
        "",
        js(r["body"], inline=True),
        "",
        span("h-ok" if status < 300 else "h-bad", f"HTTP/1.1 {status} {REASONS.get(status, '')}".rstrip()),
    ]
    if r["error_header"]:
        lines.append(f"{span('h-hdr', 'X-Keman-Error:')} {span('h-err', r['error_header'])}")
    lines += ["", js(r["response"])]
    return "\n".join(lines)


def fill(shots):
    path = os.path.join(SITE, "index.html")
    page = open(path, encoding="utf-8").read()

    def pre(m):
        text = load(shots, m.group(1))
        cols = max(len(ANSI.sub("", line)) for line in text.split("\n"))
        return (f'<pre class="term" data-capture="{m.group(1)}" style="--cols:{cols}">'
                f"{convert(text)}</pre>")

    def alert(m):
        rule, _, key = m.group(2).partition(" ")
        return m.group(1) + html.escape(find_alert(shots, rule, key or None)) + m.group(3)

    requests = json.load(open(os.path.join(shots, "requests.json"), encoding="utf-8"))

    def request(m):
        return m.group(1) + exchange(requests[m.group(2)]) + m.group(3)

    page, n = PRE.subn(pre, page)
    page, k = ALERT.subn(alert, page)
    page, r = REQUEST.subn(request, page)
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"{path}: {n} terminals, {k} alerts, {r} requests")


def og(shots, fonts, out):
    """A 1200x630 social card: the hero copy and the key list."""
    term = convert(load(shots, "keys"))
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><style>
@font-face {{ font-family: Mono; src: url('FONTS/JetBrainsMono-Regular.woff2'); font-weight: 400; }}
@font-face {{ font-family: Mono; src: url('FONTS/JetBrainsMono-Bold.woff2'); font-weight: 700; }}
@font-face {{ font-family: Inter; src: url('FONTS/InterVariable.woff2'); font-weight: 100 900; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ width: 1200px; height: 630px; overflow: hidden; }}
body {{ font-family: Inter, sans-serif; color: #0a0a0a; background: #fff; -webkit-font-smoothing: antialiased;
  padding: 64px 0 0 72px; position: relative; }}
.logo {{ display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 22px; letter-spacing: .2em; }}
.logo svg {{ width: 40px; height: 40px; }}
h1 {{ margin-top: 30px; width: 900px; font-size: 60px; line-height: 1.04; font-weight: 800; letter-spacing: -.035em; }}
.win {{ position: absolute; left: 72px; top: 330px; width: 1250px; background: #000; border: 1px solid #262626;
  border-radius: 14px; overflow: hidden; box-shadow: 0 24px 60px rgba(0,0,0,.2); }}
.bar {{ height: 36px; display: flex; align-items: center; gap: 8px; padding: 0 14px; background: #111;
  border-bottom: 1px solid #262626; }}
.bar i {{ width: 12px; height: 12px; border-radius: 50%; display: block; }}
.bar i:nth-child(1) {{ background: #ff5f57; }} .bar i:nth-child(2) {{ background: #febc2e; }}
.bar i:nth-child(3) {{ background: #28c840; }}
pre {{ --fg: #e6e6e6; --bg: #000; font-family: Mono, monospace; color: var(--fg); font-size: 15.5px;
  line-height: 1.3; padding: 16px 16px; white-space: pre; font-variant-ligatures: none; }}
</style></head><body>
<div class='logo'>{LOGO}KEMAN</div>
<h1>Open-source protection from leaked API keys</h1>
<div class='win'><div class='bar'><i></i><i></i><i></i></div><pre>{term}</pre></div>
</body></html>"""
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "og.html"), "w", encoding="utf-8") as f:
        f.write(doc.replace("FONTS/", "file://" + os.path.abspath(fonts) + "/"))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 4):
        raise SystemExit(__doc__)
    fill(sys.argv[1])
    if len(sys.argv) == 4:
        og(*sys.argv[1:])
