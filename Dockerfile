# Build a static binary. SQLite is pure Go, so CGO stays off, and buildx
# cross-compiles on the build host instead of emulating the target.
FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.0-beta
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X github.com/kirank55/keman/internal/cli.Version=$VERSION" \
    -o /out/keman ./cmd/keman

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/kirank55/keman" \
      org.opencontainers.image.description="Self-hosted proxy that keeps real API keys out of your apps" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/keman /keman
USER nonroot:nonroot
# init writes keman.yaml and master.key to the working directory, so it
# must be the writable volume, not /.
WORKDIR /home/nonroot
ENV KEMAN_DATABASE=/home/nonroot/keman.db
EXPOSE 8080
ENTRYPOINT ["/keman"]
# The image has no database or master key. Initialize a volume first;
# see README.md (Docker). Admin stays on 127.0.0.1:8081 inside the
# container unless you set KEMAN_ADMIN_LISTEN.
CMD ["serve"]
