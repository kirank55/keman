# Keman

Keman is a self-hosted HTTP proxy that issues virtual API keys in front of an upstream you already pay for. Callers send `kmn_<id>_<secret>`. Keman checks the key, enforces the policy, and swaps in the real credential. The real key stays on the host that you configured.

This is the beta described in [`beta.md`](beta.md). [`PLAN.md`](PLAN.md) is older research and is not the spec. Decisions that the spec left open are recorded in [`docs/ASSUMPTIONS.md`](docs/ASSUMPTIONS.md).

The proxy is Go, `net/http`, and pure-Go SQLite (`modernc.org/sqlite`, no CGO). The license is Apache-2.0.

## Quickstart

You need Go 1.22 and OpenSSL (for a master key).

The unaided path is one script. It builds the binary, initializes a database, starts a mock OpenAI-compatible server, creates a virtual key, and sends a sample request:

```sh
./scripts/quickstart.sh
```

Files land under `.quickstart/` (gitignored): `keman.yaml`, `master.key`, `admin.token`, `virtual.key`. The script stops the demo processes when it exits. To run the same install yourself:

```sh
.quickstart/keman --config .quickstart/keman.yaml serve
export KEMAN_ADMIN_TOKEN="$(cat .quickstart/admin.token)"
```

### Manual setup

```sh
export KEMAN_MASTER_KEY="$(openssl rand -base64 32)"
export KEMAN_DATABASE="$PWD/keman.db"
go build -o keman ./cmd/keman

./keman init
# prints admin_token: kma_... once. Store it.
# init also writes keman.yaml with the database path actually used.

# terminal A
export KEMAN_ADMIN_TOKEN=kma_...
./keman serve

# terminal B
export KEMAN_ADMIN_TOKEN=kma_...
./keman upstream add --name openai --profile openai --host api.openai.com --port 443 --tls
printf '%s' "$OPENAI_API_KEY" > /tmp/openai.key
./keman credential add --upstream openai --name primary --header "Authorization: Bearer {key}" --secret-file /tmp/openai.key
./keman key create --credential primary --name laptop
```

`key create` prints JSON with a `token` field once (`kmn_...`). Point an OpenAI-compatible client at Keman and send that token as the API key:

| Client | `base_url` / `baseURL` |
| --- | --- |
| Official OpenAI Python or Node SDK | `http://127.0.0.1:8080/v1` (the `/v1` is required) |
| Official Anthropic SDK | `http://127.0.0.1:8080` |
| Raw HTTP | `http://127.0.0.1:8080/v1/chat/completions` |

Examples: [`examples/sdk_stream.py`](examples/sdk_stream.py), [`examples/sdk_stream.mjs`](examples/sdk_stream.mjs). A local mock upstream is [`examples/mock-openai`](examples/mock-openai).

The admin API listens on `127.0.0.1:8081` by default. `/metrics` is on that same listener and also requires the admin token. Global CLI flags (`--config`, `--admin-url`, `--admin-token`) work before or after the subcommand. If you omit `--admin-url`, the CLI uses `admin_listen` from the config file, including `unix://` sockets.

A copy of the server settings is in [`examples/keman.yaml`](examples/keman.yaml). You can put the master key in `master_key_file` instead of exporting `KEMAN_MASTER_KEY` on every command.

## Common operations

```sh
./keman key revoke <id-or-name>
./keman key disable <id-or-name>
./keman key enable <id-or-name>
./keman credential rotate primary --secret-env OPENAI_API_KEY
./keman policy set laptop --daily-usd 1.50 --rpm 60
./keman policy set laptop --mode auto_disable --yes
./keman policy dry-run laptop
./keman alert add --kind webhook --url https://example.invalid/hook --secret-file ./hook.secret
./keman rekey --old-master-key-file ./old --new-master-key-file ./new
```

Put secrets in `--secret-env` or `--secret-file`. After `init`, the CLI writes through the admin API so a running process does not keep a stale copy. `serve` flushes spend and drains the event queue on Ctrl+C / SIGTERM.

## Spend, profiles, and detection

- Money is integer microdollars. Prices ship in `internal/price/prices.json` (snapshot 2026-10-27) and can be overlaid with `prices_file`.
- OpenAI and Anthropic have built-in path allowlists. Generic HTTP requires one, and it does not support model allowlists or spend caps.
- Caps are reserved before the request and reconciled from usage. A missing usage object on a completed model response charges the reservation and marks it estimated. A dial failure, a blocked cross-host redirect, or a 3xx that is passed through releases the reservation.
- If spend flushes fail for 60 seconds, keys that have a cap get `503 store_unavailable`.
- Canary keys (`--kind canary`) answer with the profile's own 401 and raise a critical alert.
- `trusted_proxies` is empty by default. `X-Forwarded-For` from anyone else is ignored and is not sent upstream.

## Docker

```sh
docker build -t keman:beta .
docker volume create keman-data
export KEMAN_MASTER_KEY="$(openssl rand -base64 32)"

docker run --rm \
  -e KEMAN_MASTER_KEY \
  -e KEMAN_DATABASE=/home/nonroot/keman.db \
  -v keman-data:/home/nonroot \
  keman:beta init

docker run --rm \
  -e KEMAN_MASTER_KEY \
  -e KEMAN_DATABASE=/home/nonroot/keman.db \
  -p 8080:8080 \
  -v keman-data:/home/nonroot \
  keman:beta serve
```

The admin listener stays on `127.0.0.1:8081` inside the container. Drive the CLI with `docker exec`, bind a Unix socket on the volume, or set `KEMAN_ADMIN_LISTEN=0.0.0.0:8081` only on a private network.

## Develop

```sh
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o bin/keman ./cmd/keman
make fuzz
```

Tests use an injectable clock. Fuzz targets cover virtual-key parsing, header stripping, and path matching. The proxy overhead measurement is in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md). Official SDK streaming is covered in Go against a mock upstream using the same SSE transcript the Python and Node SDKs consume; the examples above exercise those SDKs when they are installed.

```sh
docker build -t keman:beta .
```

## Security

Read [`SECURITY.md`](SECURITY.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before exposing the proxy. Encryption does not help if the process memory is readable. The admin listener should not be reachable from the network.

## Release

`.github/workflows/release.yml` builds a static Linux amd64/arm64 binary, an SPDX SBOM of that binary (Syft), a SHA-256 sum, and a keyless cosign signature, then attaches them to one GitHub release. No signed release has been published yet; pushing a `v*` tag is what runs it.
