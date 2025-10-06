# Multi-stage build for echo-server
# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT

# Install git for go tools and ensure certificates available for downloads
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy the source code
COPY . .

# Build the binary for the requested target platform
RUN set -eux; \
    export CGO_ENABLED=0; \
    export GOOS="${TARGETOS}"; \
    export GOARCH="${TARGETARCH}"; \
    if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
      export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    go build -trimpath -ldflags "-s -w" -o echo-server .

# Stage 2: Create minimal runtime image
FROM scratch

# Copy CA certificates for HTTPS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder
COPY --from=builder /build/echo-server /usr/local/bin/echo-server

# Expose default port
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/echo-server"]

# Default arguments (can be overridden)
CMD ["-addr", ":8080"]
