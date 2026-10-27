#!/bin/sh
# Local quickstart against a mock OpenAI-compatible server.
# A stranger-completes-this-unaided check was not run in the build environment.
set -eu
cd "$(dirname "$0")/.."
export KEMAN_MASTER_KEY="${KEMAN_MASTER_KEY:-$(python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())')}"
export KEMAN_DATABASE="${KEMAN_DATABASE:-./.quickstart/keman.db}"
export KEMAN_ADMIN_LISTEN="${KEMAN_ADMIN_LISTEN:-127.0.0.1:8081}"
export KEMAN_PROXY_LISTEN="${KEMAN_PROXY_LISTEN:-127.0.0.1:8080}"
mkdir -p .quickstart
CGO_ENABLED=0 go build -o .quickstart/keman ./cmd/keman
if [ ! -f .quickstart/keman.yaml ]; then
  .quickstart/keman --config .quickstart/keman.yaml init | tee .quickstart/init.out
fi
echo "Admin token is in .quickstart/init.out. Start the proxy with:"
echo "  KEMAN_MASTER_KEY=... KEMAN_DATABASE=$KEMAN_DATABASE .quickstart/keman --config .quickstart/keman.yaml serve"
