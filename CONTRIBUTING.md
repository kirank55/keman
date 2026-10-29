# Contributing

Thanks for helping. Keman is a beta, so bug reports from real setups are the most useful thing you can send.

## Report a bug

Open an issue with `keman version`, your OS, the upstream profile (`openai`, `anthropic`, or `generic`), what you ran, and what happened. Remove keys and tokens from logs first. Keman redacts secrets it knows about, but check anyway.

Security issues go through a private advisory instead. See [SECURITY.md](SECURITY.md).

## Propose a change

Open an issue first for anything larger than a fix, so we can agree on the shape before you write it. [`beta.md`](beta.md) is the spec: it lists what is in and out of the beta. A change that moves something across that line needs the spec updated too.

## Build and test

You need Go 1.22 or newer. CGO stays off.

```sh
make test     # CGO_ENABLED=0 go test ./...
make build    # bin/keman
make fuzz     # short fuzz campaigns
go vet ./...
./scripts/quickstart.sh   # end-to-end run against a mock OpenAI upstream
```

## Conventions

- Time comes from the injectable clock in `internal/clock`, never `time.Now()` in logic, so tests can replay history.
- Money is integer microdollars. No floats.
- Every mutation goes through the admin API ([ADR 0004](docs/adr/0004-admin-api-is-the-mutation-path.md)).
- Secrets never go on a command line, in a log line, or in an error message.
- Words used in code and docs are defined in [`GLOSSARY.md`](GLOSSARY.md).
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) under the unreleased version for anything a user would notice.

By contributing, you agree that your work is licensed under the [Apache-2.0](LICENSE) license.
