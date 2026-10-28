# Proxy overhead

Measured on the beta build machine (loopback, Go 1.22, `CGO_ENABLED=0`) by `TestProxyOverheadDistribution` in `internal/proxy/bench_test.go`.

Each sample is one HTTP POST of a small JSON body to an in-process upstream that answers immediately. "Direct" is the client talking to that upstream. "Proxy" is the same client talking to Keman, which then talks to the upstream. Overhead is the proxy percentile minus the direct percentile. 200 samples each.

| Path | p50 | p99 |
| --- | --- | --- |
| Direct | 48 µs | 159 µs |
| Through Keman | 119 µs | 714 µs |
| Overhead | 71 µs | 555 µs |

The beta targets are p50 under 3 ms and p99 under 10 ms. This run is inside both. It is a loopback measurement, not a saturated production host. Re-run with:

```sh
CGO_ENABLED=0 go test ./internal/proxy/ -run TestProxyOverheadDistribution -v
CGO_ENABLED=0 go test -bench=BenchmarkProxyOverhead -benchtime=200ms ./internal/proxy
```

The benchmark is not a CI failure gate. Latency on a busy machine will be higher than the table above.
