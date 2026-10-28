#!/bin/sh
# Capture the raw material for the gallery images: the terminal UI and CLI
# sessions as ANSI text (tmux capture-pane -e), and the alerts Keman sent.
# Run from the repo root. Needs tmux, git and python3. Seeds .demo/ again.
# COLORFGBG tells the UI the terminal is light, so it uses its light palette.
#
#   docs/media/src/capture.sh [OUT]     (default OUT: .demo/shots)
set -eu
cd "$(dirname "$0")/../../.."
ROOT="$(pwd)"
OUT="${1:-.demo/shots}"

./scripts/demo.sh > /dev/null
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
D="$ROOT/.demo"
TOKEN="$(cat "$D/admin.token")"
S=keman-shots

mkdir -p "$D/bin"
ln -sf "$D/keman" "$D/bin/keman"

wait_for() { # wait_for TEXT: until the pane shows TEXT
  i=0
  until tmux capture-pane -p -t "$S" | grep -qF -- "$1"; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
      echo "timed out waiting for: $1" >&2
      tmux capture-pane -p -t "$S" >&2
      exit 1
    fi
    sleep 0.25
  done
  sleep 0.4
}
grab() { # grab NAME, once no refresh is in progress
  i=0
  while tmux capture-pane -p -t "$S" | grep -q "loading" && [ "$i" -lt 40 ]; do
    i=$((i + 1))
    sleep 0.1
  done
  tmux capture-pane -e -p -t "$S" > "$OUT/$1.ans"
}
keys() { tmux send-keys -t "$S" "$@"; sleep 0.4; }

tui() { # tui COLS ROWS: a fresh UI session on the demo install
  tmux kill-session -t "$S" 2>/dev/null || true
  tmux new-session -d -s "$S" -x "$1" -y "$2" \
    "cd '$ROOT' && KEMAN_ADMIN_TOKEN='$TOKEN' TERM=xterm-256color COLORFGBG='0;15' '$D/keman' --config '$D/keman.yaml'"
  wait_for "q quit"
}
open_key() { # open_key NAME: filter the key list to NAME and open it
  keys /
  tmux send-keys -t "$S" -l "$1"
  keys Enter
  keys Enter
  wait_for "esc back"
}

tui 118 24
grab keys
keys 2
wait_for "enter open key"
grab detections

tui 124 26
open_key support-bot
grab detail-support-bot

# The CLI needs a server; the UI stops the one it started when it exits.
tmux kill-session -t "$S" 2>/dev/null || true
sleep 0.5
"$D/keman" --config "$D/keman.yaml" serve > "$D/shots-serve.log" 2>&1 &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2>/dev/null || true; tmux kill-session -t "$S" 2>/dev/null || true' EXIT INT TERM
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/metrics)" = 401 ]; do
  i=$((i + 1))
  [ "$i" -lt 100 ] || { echo "keman serve did not start" >&2; exit 1; }
  sleep 0.1
done

# CLI sessions run in a plain shell with a short prompt.
shell() { # shell DIR COLS ROWS
  tmux kill-session -t "$S" 2>/dev/null || true
  tmux new-session -d -s "$S" -x "$2" -y "$3" -c "$1" \
    "env -i HOME='$HOME' PATH='$D/bin:/usr/bin:/bin' TERM=xterm-256color COLORFGBG='0;15' KEMAN_ADMIN_TOKEN='$TOKEN' \
     PS1='\[\e[38;5;27m\]\W\[\e[0m\] \[\e[38;5;242m\]\$\[\e[0m\] ' bash --norc --noprofile"
  sleep 0.6
  tmux send-keys -t "$S" clear Enter
  sleep 0.3
}
run() { # run CMD: type it, then wait for the next prompt
  tmux send-keys -t "$S" -l "$1"
  tmux send-keys -t "$S" Enter
  sleep 1.2
}

# A small repo whose history still holds a deleted key.
R="$D/acme-api"
rm -rf "$R"
mkdir -p "$R/app" "$R/config"
rnd() { python3 -I -c "import secrets,string,sys;a=string.ascii_letters+string.digits;print(''.join(secrets.choice(a) for _ in range(int(sys.argv[1]))))" "$1"; }
(
  cd "$R"
  g() { git -c user.name=Dev -c user.email=dev@example.com "$@"; }
  git init -q -b main
  printf 'from openai import OpenAI\nclient = OpenAI()\n' > app/main.py
  printf 'OPENAI_API_KEY=sk-proj-%s\nDATABASE_URL=postgres://localhost/acme\n' "$(rnd 56)" > .env
  g add -A && g commit -qm "Initial API service"
  printf 'STRIPE_SECRET_KEY = "sk_live_%s"\nCURRENCY = "usd"\n' "$(rnd 34)" > config/settings.py
  g add -A && g commit -qm "Add billing settings"
  g rm -q --cached .env && rm .env && printf '.env\n' > .gitignore && g add -A && g commit -qm "Stop tracking .env"
  cp "$D/keman.yaml" keman.yaml
  printf 'keman.yaml\n' >> .gitignore
)

shell "$R" 128 24
run "keman scan . --history"
grab scan

shell "$R" 120 24
run "keman canary create --credential openai-main --name decoy --base-url https://keman.example.com >> .env.bak"
run "cat .env.bak"
grab canary

shell "$R" 86 24
run "keman exposure"
grab exposure

shell "$R" 128 30
run "keman key rotate support-bot --grace 0"
grab rotate

cp "$D/alerts.jsonl" "$OUT/alerts.jsonl"
echo "captured into $OUT"
