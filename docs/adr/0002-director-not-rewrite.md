# Director, and no forwarded client headers

`httputil.ReverseProxy.Rewrite` deletes the raw query and replaces it with a parsed one. Virtual keys are often used in front of APIs that depend on the exact query string, and the beta says query strings are forwarded as-is, so the proxy uses `Director`.

Go’s `Director` path appends the peer to `X-Forwarded-For` unless that header is present and nil. The Director sets it to nil and also strips `Forwarded`, `X-Forwarded-Host`, and the client’s auth headers. Keman never tells the upstream who the client is.
