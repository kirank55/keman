.PHONY: build test fuzz bench

build:
	CGO_ENABLED=0 go build -trimpath -o bin/keman ./cmd/keman

test:
	CGO_ENABLED=0 go test ./...

fuzz:
	CGO_ENABLED=0 go test -fuzz=FuzzParse -fuzztime=10s ./internal/keyfmt
	CGO_ENABLED=0 go test -fuzz=FuzzSanitize -fuzztime=10s ./internal/headers
	CGO_ENABLED=0 go test -fuzz=FuzzMatch -fuzztime=10s ./internal/pathmatch

bench:
	CGO_ENABLED=0 go test -bench=BenchmarkProxyOverhead -benchtime=200ms -count=1 ./internal/proxy
