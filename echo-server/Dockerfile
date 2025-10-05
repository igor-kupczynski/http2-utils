# Multi-stage build for echo-server
# Stage 1: Build the Go binary
FROM golang:1.20-alpine AS builder

# Install git for go get (if needed)
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy the source code
COPY . .

# Build the binary with static linking
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=off \
    go build -a -installsuffix cgo -ldflags '-extldflags "-static"' \
    -o echo-server .

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
