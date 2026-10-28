# Build a static binary. SQLite is pure Go, so CGO stays off.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keman ./cmd/keman

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keman /keman
USER nonroot:nonroot
ENV KEMAN_DATABASE=/home/nonroot/keman.db
EXPOSE 8080
ENTRYPOINT ["/keman"]
# The image has no database or master key. Initialize a volume first;
# see README.md (Docker). Admin stays on 127.0.0.1:8081 inside the
# container unless you set KEMAN_ADMIN_LISTEN.
CMD ["serve"]
