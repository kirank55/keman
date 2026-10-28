"""Convert an ANSI-colored terminal capture (tmux capture-pane -e) to HTML spans.

Usage: python3 ansi2html.py < capture.ans > capture.html
Only SGR sequences are interpreted; xterm-256 and truecolor are supported.
"""
import html
import re
import sys

BASE16 = [
    "#1b1f27", "#ff6b6b", "#3ddc84", "#ffb547", "#5aa9ff", "#d38aff", "#4fd1c5", "#c9d1d9",
    "#6e7681", "#ff8585", "#56e39f", "#ffcb6b", "#79bbff", "#e0a6ff", "#76e4d8", "#f0f6fc",
]


def xterm(n):
    if n < 16:
        return BASE16[n]
    if n < 232:
        n -= 16
        steps = [0, 95, 135, 175, 215, 255]
        r, g, b = steps[n // 36], steps[(n // 6) % 6], steps[n % 6]
        return f"#{r:02x}{g:02x}{b:02x}"
    v = 8 + (n - 232) * 10
    return f"#{v:02x}{v:02x}{v:02x}"


class Style:
    def __init__(self):
        self.reset()

    def reset(self):
        self.fg = self.bg = None
        self.bold = self.dim = self.italic = self.underline = self.reverse = False

    def apply(self, params):
        codes = [int(p) if p else 0 for p in params.split(";")] if params else [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.reset()
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.dim = True
            elif c == 3:
                self.italic = True
            elif c == 4:
                self.underline = True
            elif c == 7:
                self.reverse = True
            elif c == 22:
                self.bold = self.dim = False
            elif c == 23:
                self.italic = False
            elif c == 24:
                self.underline = False
            elif c == 27:
                self.reverse = False
            elif 30 <= c <= 37:
                self.fg = BASE16[c - 30]
            elif 90 <= c <= 97:
                self.fg = BASE16[c - 90 + 8]
            elif 40 <= c <= 47:
                self.bg = BASE16[c - 40]
            elif 100 <= c <= 107:
                self.bg = BASE16[c - 100 + 8]
            elif c == 39:
                self.fg = None
            elif c == 49:
                self.bg = None
            elif c in (38, 48) and i + 1 < len(codes):
                if codes[i + 1] == 5 and i + 2 < len(codes):
                    col = xterm(codes[i + 2])
                    i += 2
                elif codes[i + 1] == 2 and i + 4 < len(codes):
                    col = "#%02x%02x%02x" % tuple(codes[i + 2:i + 5])
                    i += 4
                else:
                    col = None
                if c == 38:
                    self.fg = col
                else:
                    self.bg = col
            i += 1

    def css(self):
        fg, bg = self.fg, self.bg
        if self.reverse:
            fg, bg = bg or "var(--bg)", fg or "var(--fg)"
        out = []
        if fg:
            out.append(f"color:{fg}")
        if bg:
            out.append(f"background:{bg}")
        if self.bold:
            out.append("font-weight:700")
        if self.dim:
            out.append("opacity:.6")
        if self.italic:
            out.append("font-style:italic")
        if self.underline:
            out.append("text-decoration:underline")
        return ";".join(out)


SEQ = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])")


def convert(text):
    st = Style()
    out = []
    for line in text.rstrip("\n").split("\n"):
        pos = 0
        parts = []
        for m in SEQ.finditer(line):
            if m.start() > pos:
                parts.append((st.css(), line[pos:m.start()]))
            if m.group(2) == "m":
                st.apply(m.group(1))
            pos = m.end()
        if pos < len(line):
            parts.append((st.css(), line[pos:]))
        spans = []
        for css, chunk in parts:
            chunk = html.escape(chunk)
            spans.append(f'<span style="{css}">{chunk}</span>' if css else chunk)
        out.append("".join(spans))
    return "\n".join(out)


if __name__ == "__main__":
    sys.stdout.write(convert(sys.stdin.read()))
