# Keman

Keman is a self-hosted HTTP proxy that issues virtual API keys in front of an upstream you already pay for. Callers send `kmn_<id>_<secret>`. Keman checks the key, enforces the policy, and swaps in the real credential. The real key stays on the host that you configured.

This is the beta described in [`beta.md`](beta.md). [`PLAN.md`](PLAN.md) is older research and is not the spec. Decisions that the spec left open are recorded in [`docs/ASSUMPTIONS.md`](docs/ASSUMPTIONS.md).

The proxy is Go, `net/http`, and pure-Go SQLite (`modernc.org/sqlite`, no CGO). The license is Apache-2.0.

## Quickstart

You need Go 1.22.

```sh
export KEMAN_MASTER_KEY="$(openssl rand -base64 32)"
export KEMAN_DATABASE="$PWD/keman.db"
go build -o keman ./cmd/keman

./keman init
# prints admin_token: kma_... once. Store it.

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

`key create` prints the virtual key once. Point an OpenAI-compatible client at `http://127.0.0.1:8080` and send that key as the bearer token.

`scripts/quickstart.sh` builds a binary and initializes a database under `.quickstart/`. The admin API listens on `127.0.0.1:8081` by default. `/metrics` is on that same listener and also requires the admin token.

A copy of the server settings is in [`examples/keman.yaml`](examples/keman.yaml).

## Common operations

```sh
./keman key revoke <id>
./keman key disable <id>
./keman key enable <id>
./keman credential rotate <id> --secret-env OPENAI_API_KEY
./keman policy set <id> --daily-usd 1.50 --rpm 60
./keman policy set <id> --mode auto_disable --yes
./keman policy dry-run <id>
./keman alert add --kind webhook --url https://example.invalid/hook --secret-file ./hook.secret
./keman rekey --old-master-key-file ./old --new-master-key-file ./new
```

Put secrets in `--secret-env` or `--secret-file`. After `init`, the CLI writes through the admin API so a running process does not keep a stale copy.

## Spend, profiles, and detection

- Money is integer microdollars. Prices ship in `internal/price/prices.json` (snapshot 2026-10-27) and can be overlaid with `prices_file`.
- OpenAI and Anthropic have built-in path allowlists. Generic HTTP requires one, and it does not support model allowlists or spend caps.
- Caps are reserved before the request and reconciled from usage. A missing usage object charges the reservation and marks it estimated. A dial failure releases the reservation.
- If spend flushes fail for 60 seconds, keys that have a cap get `503 store_unavailable`.
- Canary keys (`--kind canary`) answer with the profile's own 401 and raise a critical alert.
- `trusted_proxies` is empty by default. `X-Forwarded-For` from anyone else is ignored and is not sent upstream.

## Develop

```sh
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o bin/keman ./cmd/keman
make fuzz
```

Tests use an injectable clock. Fuzz targets cover virtual-key parsing, header stripping, and path matching. The proxy overhead measurement is in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md).

```sh
docker build -t keman:beta .
```

## Security

Read [`SECURITY.md`](SECURITY.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before exposing the proxy. Encryption does not help if the process memory is readable. The admin listener should not be reachable from the network.

## Not done in this beta build

- No stranger ran the quickstart unaided.
- The official Python and Node SDK streaming checks were not run here. The test suite covers the same streaming transcript against a mock upstream.
- `.github/workflows/release.yml` can build a static binary, an SPDX SBOM (Syft), and a keyless cosign signature, but no signed release has been published.
