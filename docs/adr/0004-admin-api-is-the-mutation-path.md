# The admin API is the only mutation path once the process is up

Virtual keys and policies live in memory as well as SQLite. The request path never reads SQLite. If the CLI wrote the database on its own, a running process would keep serving a revoked key until restart.

`init` creates the database before anything is listening. Every later change goes through the admin API, which commits SQLite and then updates memory, and leaves memory alone when the commit fails.
