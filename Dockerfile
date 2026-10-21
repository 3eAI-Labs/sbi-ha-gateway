# Build Stage
# Base must satisfy go.mod's `go 1.26.10`: the image sets GOTOOLCHAIN=local and will not
# fetch a newer toolchain. Module downloads are a cached layer: go.mod and go.sum are
# copied before the sources.
FROM golang:1.26.10-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o sbi-gateway ./cmd/sbi-gateway

# Licence texts (and NOTICE files) of every third-party module compiled into the binary, for
# redistribution of the image (Apache-2.0 §4(d), MIT/BSD notice clauses). Saved here because
# the final image has no shell. The gateway's own packages are skipped (its LICENSE/NOTICE
# are copied below); the trailing slash keeps the Apache-2.0 client module in the saved set.
RUN go install github.com/google/go-licenses/v2@v2.0.1 && \
    go-licenses save ./cmd/sbi-gateway --save_path=/app/third_party_licenses \
        --ignore github.com/3eAI-Labs/sbi-ha-gateway/

# Final Stage (Distroless). The tag names the Debian release, so a base-image change is visible
# in this file.
FROM gcr.io/distroless/static-debian13:nonroot

LABEL org.opencontainers.image.title="sbi-ha-gateway" \
      org.opencontainers.image.vendor="3eAI Labs Ltd" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/3eAI-Labs/sbi-ha-gateway"

WORKDIR /
COPY --from=builder /app/sbi-gateway .

# Licences: the gateway's own, and those of the Go modules built into it
COPY LICENSE NOTICE /usr/share/licenses/sbi-ha-gateway/
COPY --from=builder /app/third_party_licenses /usr/share/licenses/sbi-ha-gateway/third_party/go/

# Expose ports (SBI and Admin)
EXPOSE 8080 9090

USER nonroot:nonroot

ENTRYPOINT ["/sbi-gateway"]
