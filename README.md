# Keman

Keman is a self-hosted proxy that keeps your real API keys and hands out virtual ones. Apps send a `kmn_…` key. Keman checks it, applies that key's limits, and forwards the request upstream with the real credential. Each virtual key can be capped, watched, disabled or revoked without touching the real key.

It is one Go binary with pure-Go SQLite, and needs no CGO. It works with OpenAI-compatible APIs (including OpenRouter), Anthropic, and any HTTP API that authenticates with a header. Apache-2.0.

> **Beta.** The spec is [`beta.md`](beta.md). Decisions the spec left open are in [`docs/ASSUMPTIONS.md`](docs/ASSUMPTIONS.md).

## Quickstart

You need Go 1.22 or newer.

```sh
go build -o keman ./cmd/keman
./keman init    # prints the admin token once; writes keman.yaml and master.key here
./keman         # opens the terminal UI and starts the proxy
```

In the UI:

1. Paste the admin token from `init`. It is masked and kept only in memory. Set `KEMAN_ADMIN_TOKEN` to skip this prompt.
2. Press `a` to add an upstream. OpenRouter is filled in as a suggestion. Use ←/→ on **profile** to switch to `anthropic` or `generic`, or edit any field.
3. The credential form opens. Type the provider API key (masked), or read it from an environment variable. It is stored encrypted and never shown again.
4. The new-key form opens. The `kmn_…` virtual key is shown **once**. Copy it.

Leave the UI open: quitting it (`q`) stops the proxy it started. To keep the proxy running without the UI, run `keman serve`. When a server is already up, `keman` connects to it and leaves it running on exit.

Run `keman` from the directory where you ran `init`, or pass `--config path/to/keman.yaml`.

### Point an app at Keman

Send the virtual key wherever the app expects its API key, and change the base URL:

| Client | Base URL |
| --- | --- |
| OpenAI Python / Node SDK | `http://127.0.0.1:8080/v1` |
| OpenRouter through Keman | `http://127.0.0.1:8080/api/v1` |
| Anthropic SDK | `http://127.0.0.1:8080` |

```sh
curl http://127.0.0.1:8080/api/v1/chat/completions \
  -H "Authorization: Bearer $KEMAN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

Back in the UI, select the key and press Enter to see its requests, client IPs, models and spend.

### Try it without a provider key

```sh
./scripts/quickstart.sh
```

The script builds Keman, initializes `.quickstart/`, starts a mock OpenAI server, creates a virtual key, and sends one request through the proxy. It prints the command to open the UI on that install. Set `KEMAN_QUICKSTART_PROXY_PORT` and `KEMAN_QUICKSTART_ADMIN_PORT` if 8080 or 8081 is taken.

## The terminal UI

| Key | Does |
| --- | --- |
| `1`–`4`, `tab` | keys, detections, audit, setup |
| `j`/`k`, arrows | move or scroll |
| `enter` | open a key (also from a detection or an audit row) |
| `n` | new virtual key |
| `d` / `e` | disable / enable (reversible) |
| `x` | revoke (permanent; type the key's name to confirm) |
| `p` | policy: mode, requests per minute, daily and monthly caps in dollars |
| `a` / `c` | add an upstream / a credential |
| `/` | filter the current view |
| `?` | help |
| `q` | quit, except while typing in a field. `ctrl+c` always quits. |

Switching a key to `auto_disable` shows the 7-day dry run first and asks for confirmation. Credential rotation, `rekey`, admin-token rotation and alert destinations stay on the CLI.

## CLI

Every operation is also a one-shot command, for scripts:

```sh
export KEMAN_ADMIN_TOKEN=kma_...
./keman upstream add --name openai --profile openai --host api.openai.com --port 443 --tls
./keman credential add --upstream openai --name primary --secret-env OPENAI_API_KEY
./keman key create --credential primary --name laptop
./keman key revoke laptop
./keman key disable laptop
./keman key enable laptop
./keman credential rotate primary --secret-env OPENAI_API_KEY
./keman policy set laptop --daily-usd 1.50 --rpm 60
./keman policy set laptop --mode auto_disable --yes
./keman policy dry-run laptop
./keman alert add --kind webhook --url https://example.invalid/hook --secret-file ./hook.secret
./keman rekey --old-master-key-file ./old --new-master-key-file ./new
./keman help
```

Keys, credentials and upstreams can be named by name or id. Put secrets in `--secret-env` or `--secret-file`, never on the command line. Global flags (`--config`, `--admin-url`, `--admin-token`) work before or after the subcommand. Without `--admin-url`, the CLI uses `admin_listen` from the config, including `unix://` sockets. After `init`, every change goes through the admin API, so a running server never holds a stale copy.

The proxy listens on `0.0.0.0:8080`. The admin API and `/metrics` listen on `127.0.0.1:8081` and require the admin token. Server settings are in `keman.yaml`; see [`examples/keman.yaml`](examples/keman.yaml). `serve` and the UI flush spend and drain the event queue on Ctrl+C or SIGTERM.

## Spend, profiles, and detection

- Money is integer microdollars. Prices ship in `internal/price/prices.json` (snapshot 2026-10-27).
- A model that is not in the price table is recorded with no cost. If the key has a spend cap, the request is refused with `unknown_model_price`. That includes OpenRouter's `vendor/model` ids. To cap those keys, add prices with `prices_file`. Prices are microdollars per million tokens, and the key is the `model` string exactly as the app sends it:

  ```json
  {
    "version": "local",
    "models": {
      "openai/gpt-4o-mini": {"input": 150000, "output": 600000}
    }
  }
  ```

- OpenAI and Anthropic have built-in path allowlists. Generic HTTP requires one, and it does not support model allowlists or spend caps.
- Caps are reserved before the request and reconciled from usage. A missing usage object on a completed model response charges the reservation and marks it estimated. A dial failure, a blocked cross-host redirect, or a 3xx that is passed through releases the reservation.
- If spend flushes fail for 60 seconds, keys that have a cap get `503 store_unavailable`.
- Canary keys (`--kind canary`) answer with the profile's own 401 and raise a critical alert.
- A new key learns for 7 days or 500 requests before spike and new-location rules alert. Normal traffic does not create detections.
- `trusted_proxies` is empty by default. `X-Forwarded-For` from anyone else is ignored and is not sent upstream.

## Docker

```sh
docker build -t keman:beta .
docker volume create keman-data

docker run --rm -v keman-data:/home/nonroot keman:beta init
docker run --rm -p 8080:8080 -v keman-data:/home/nonroot keman:beta serve
```

`init` writes `keman.yaml`, `master.key` and the database to the volume, and prints the admin token. The admin listener stays on `127.0.0.1:8081` inside the container. Use `docker exec` for the CLI, bind a Unix socket on the volume, or set `KEMAN_ADMIN_LISTEN=0.0.0.0:8081` only on a private network. For production, keep the master key out of the data volume (see [`SECURITY.md`](SECURITY.md)).

## Develop

```sh
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o bin/keman ./cmd/keman
make fuzz
```

Tests use an injectable clock. Fuzz targets cover virtual-key parsing, header stripping and path matching. Proxy overhead is measured in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md). [`examples/sdk_stream.py`](examples/sdk_stream.py) and [`examples/sdk_stream.mjs`](examples/sdk_stream.mjs) stream through Keman with the official SDKs, and [`examples/mock-openai`](examples/mock-openai) is a local upstream for them.

## Security

Read [`SECURITY.md`](SECURITY.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before exposing the proxy. Encryption does not help if the process memory is readable. The admin listener should not be reachable from the network.

## Release

`.github/workflows/release.yml` builds static Linux amd64 and arm64 binaries, an SPDX SBOM of each binary (Syft), SHA-256 sums and keyless cosign signatures, and attaches them to one GitHub release. Pushing a `v*` tag runs it. No signed release has been published yet.

Background research from before the beta is in [`docs/archive/PLAN.md`](docs/archive/PLAN.md).
