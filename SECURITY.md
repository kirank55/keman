# Security

Keman is a self-hosted proxy. It is not a hosted service, and it does not phone home.

## Reporting

Open a private security advisory on the GitHub repository, or contact the maintainers out of band if an advisory is not available. Please include a way to reproduce the issue and the version (`keman version`).

## Supported versions

| Version | Status |
| --- | --- |
| 0.1.0-beta | Current beta. |

## What you must protect

- The master key (`KEMAN_MASTER_KEY` or `master_key_file`). Anyone with the master key and the database can unwrap credential secrets.
- The admin token. It is shown once by `init` and by `admin-token rotate`. The admin listener must stay on localhost or a Unix socket.
- The SQLite file. It holds ciphertext, spend counters, events, and the wrapped data key.
- The process memory. Plaintext credentials are cached so the proxy can swap them onto requests. A memory dump defeats the encryption. Run the process as a non-root user, on a read-only root filesystem where you can, and with egress only to the upstream hosts you configured.

## What the proxy refuses to do

- Forward a virtual key, `Authorization`, `X-Api-Key`, `X-Forwarded-*`, or `Forwarded` to the upstream.
- Honor `X-Forwarded-For` from a peer that is not in `trusted_proxies` (empty by default).
- Follow a redirect whose host or port is not the configured upstream.
- Use `HTTP_PROXY` for upstream connections.
- Serve the admin API or `/metrics` without the admin token.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).

## Releases

The release workflow in `.github/workflows/release.yml` is a scaffold for a static binary, a Syft SPDX SBOM, and a keyless cosign signature. No signed release or SBOM has been published yet.
