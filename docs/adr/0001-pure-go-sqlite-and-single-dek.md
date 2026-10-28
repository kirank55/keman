# Pure-Go SQLite and a single data key

The beta is one static binary, so the database is `modernc.org/sqlite` with `CGO_ENABLED=0` rather than the C SQLite driver. Postgres and a second instance are out of scope.

There is one data key per install. The master key wraps it, and each credential is AES-256-GCM with the credential id as associated data. `rekey` re-wraps that data key instead of rewriting every credential. A per-tenant key and a cloud KMS would be a different product.
