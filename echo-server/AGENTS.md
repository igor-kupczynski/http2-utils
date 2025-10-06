# echo-server - Agent Guide

This document provides automation-friendly guidance for coding agents and CI scripts to build, run, and test the echo-server utility. All commands are non-interactive and idempotent where possible.

## Build and Install

### Install from source (Go 1.20+)

```bash
# Install latest version
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/echo-server@latest

# Verify installation
echo-server -h
```

### Build locally

```bash
# From repository root
cd echo-server
GO111MODULE=off go build

# Or with modules (if go.mod exists in repo root)
go build ./echo-server

# Or using Makefile
make build
```

## Makefile Targets

The project includes a Makefile for automation-friendly builds and tests:

```bash
# Build
make build             # Build the echo-server binary
make install           # Install to GOPATH/bin

# Testing
make test              # Run all tests (unit + integration)
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
make coverage          # Generate unit + integration coverage summaries

# Code quality
make fmt               # Format Go code
make vet               # Run go vet
make lint              # Run all linters (fmt + vet)

# Development
make run               # Build and run in plain HTTP mode on :8080
make run-tls           # Build and run in TLS mode on :8443 (requires certs in /tmp)
make run-mtls          # Build and run in mTLS mode on :8443 (requires certs in /tmp)
make dev-certs         # Generate test certificates in /tmp using selfsigned-gen
make dev-test          # Quick test cycle: build, start server, test, stop

# Cleanup
make clean             # Remove binaries, coverage files, and test certificates

# Help
make help              # Display all available targets
```

### Makefile Examples

```bash
# Complete development workflow
cd echo-server
make clean
make build
make test
make coverage

# Quick iteration
make dev-certs         # Generate certs once
make dev-test          # Quick test cycle

# Run different modes
make run               # Plain HTTP
make run-tls           # TLS mode
make run-mtls          # mTLS mode
```

## Quick Reference

### Modes

| Mode | Flags Required | Description |
|------|---------------|-------------|
| Plain HTTP | None | Standard HTTP server |
| TLS | `-tlsCert`, `-tlsKey` | HTTPS with server authentication |
| mTLS | `-tlsCert`, `-tlsKey`, `-mtlsMode` | HTTPS with mutual authentication |

### Flags

```
-addr string          Address to listen on (default ":8080")
-healthCheck string   Optional health check address (default "")
-tlsCert string       Path to server cert PEM (default "")
-tlsKey string        Path to server key PEM (default "")
-mtlsMode string      Client auth mode: request, verify_if_given, require_any, require_and_verify (default "")
-clientCAs string     Path to PEM bundle of client CAs (default "")
```

### Endpoints

- `GET /` - Echo handler (returns path and random number)
- `GET /client-certs` - Client certificate inspector
- `GET /` (health check address) - Health check endpoint (returns "OK")

## Non-Interactive Commands

### Plain HTTP Mode

```bash
# Start server
echo-server -addr :8080 -healthCheck :8081

# Test in another terminal
curl http://localhost:8080/test
curl http://localhost:8081/  # health check

# Stop server
pkill echo-server
```

### TLS Mode

```bash
# Generate certificates
cd /tmp
selfsigned-gen -domains "localhost,127.0.0.1"

# Start server with TLS
echo-server -addr :8443 -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key

# Test with curl
curl --cacert /tmp/ca.pem https://localhost:8443/test
curl --cacert /tmp/ca.pem https://localhost:8443/client-certs

# Stop server
pkill echo-server
```

### TLS Mode with Health Check

```bash
# Start server with TLS and separate health check
echo-server \
  -addr :8443 \
  -healthCheck :8444 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key

# Test main endpoint (TLS)
curl --cacert /tmp/ca.pem https://localhost:8443/test

# Test health check (TLS, no client cert required)
curl --cacert /tmp/ca.pem https://localhost:8444/

# Stop server
pkill echo-server
```

### mTLS Mode - Request (Optional Client Cert)

```bash
# Start server requesting but not requiring client certs
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode request

# Works without client cert
curl --cacert /tmp/ca.pem https://localhost:8443/test

# Also works with client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs

# Stop server
pkill echo-server
```

### mTLS Mode - Require and Verify

```bash
# Start server requiring verified client certs
echo-server \
  -addr :8443 \
  -healthCheck :8444 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode require_and_verify \
  -clientCAs /tmp/ca.pem

# Health check works without client cert (TLS only)
curl --cacert /tmp/ca.pem https://localhost:8444/

# Main endpoint requires client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/test

# Inspect client certificate details
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs

# Stop server
pkill echo-server
```

### mTLS Mode - Verify If Given

```bash
# Start server verifying client certs only if provided
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode verify_if_given \
  -clientCAs /tmp/ca.pem

# Works without client cert
curl --cacert /tmp/ca.pem https://localhost:8443/test

# Works with valid client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/test

# Fails with invalid client cert (not signed by CA)
# curl --cacert /tmp/ca.pem --cert /path/to/invalid.pem --key /path/to/invalid.key https://localhost:8443/test

# Stop server
pkill echo-server
```

### mTLS Mode - Require Any

```bash
# Start server requiring any client cert (no verification)
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode require_any

# Fails without client cert
# curl --cacert /tmp/ca.pem https://localhost:8443/test

# Works with any client cert (even self-signed)
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/test

# Stop server
pkill echo-server
```

## Background Execution

For CI/testing scenarios where the server needs to run in the background:

```bash
# Start in background
echo-server -addr :8080 > /tmp/echo-server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
sleep 1

# Run tests
curl http://localhost:8080/test

# Stop server
kill $SERVER_PID
```

## Docker Example

```dockerfile
FROM golang:1.20-alpine AS builder
WORKDIR /build
COPY . .
RUN GO111MODULE=off go build -o echo-server ./echo-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/echo-server /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["echo-server"]
CMD ["-addr", ":8080"]
```

Build and run:

```bash
# Build image
docker build -t echo-server .

# Run plain HTTP
docker run -p 8080:8080 echo-server

# Run with TLS (mount certs)
docker run -p 8443:8443 \
  -v /tmp/domain.pem:/certs/domain.pem:ro \
  -v /tmp/domain.key:/certs/domain.key:ro \
  echo-server \
  -addr :8443 \
  -tlsCert /certs/domain.pem \
  -tlsKey /certs/domain.key
```

## Testing Scenarios

### Verify HTTP/2 Support

```bash
# Start TLS server
echo-server -addr :8443 -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key &
sleep 1

# Check ALPN negotiation
curl -v --cacert /tmp/ca.pem https://localhost:8443/ 2>&1 | grep -E "(ALPN|HTTP/2)"
# Expected: "ALPN: server accepted h2" and "using HTTP/2"

pkill echo-server
```

### Verify Client Certificate Inspection

```bash
# Start mTLS server
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode request &
sleep 1

# Without client cert
curl --cacert /tmp/ca.pem https://localhost:8443/client-certs
# Expected: "no client certificate"

# With client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs
# Expected: certificate details (subject_cn, issuer_cn, serial, dates, SANs)

pkill echo-server
```

### Verify Health Check Behavior

```bash
# Start mTLS server with health check
echo-server \
  -addr :8443 \
  -healthCheck :8444 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode require_and_verify \
  -clientCAs /tmp/ca.pem &
sleep 1

# Health check should work without client cert
curl --cacert /tmp/ca.pem https://localhost:8444/
# Expected: "OK"

# Main endpoint should require client cert
curl --cacert /tmp/ca.pem https://localhost:8443/test 2>&1
# Expected: TLS handshake error

# Main endpoint with client cert should work
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/test
# Expected: "Hello, test! Here's your random number: ..."

pkill echo-server
```

## Validation Testing

Test error conditions:

```bash
# Missing tlsKey
echo-server -tlsCert /tmp/domain.pem
# Expected: "Error: both -tlsCert and -tlsKey must be provided together"

# Invalid mtlsMode
echo-server -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key -mtlsMode invalid
# Expected: "Error: invalid -mtlsMode=\"invalid\". Allowed values: ..."

# Missing clientCAs for verifying mode
echo-server -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key -mtlsMode verify_if_given
# Expected: "Error: -mtlsMode=verify_if_given requires -clientCAs"

# Invalid cert file
echo-server -tlsCert /nonexistent.pem -tlsKey /tmp/domain.key
# Expected: "Error loading server certificate: ..."
```

## Startup Log Format

The server logs its configuration on startup:

**Plain HTTP:**
```
Main server: addr=:8080 mode=plain
```

**TLS:**
```
Main server: addr=:8443 mode=tls tlsCert=/tmp/domain.pem tlsKey=/tmp/domain.key
```

**mTLS:**
```
Main server: addr=:8443 mode=mtls tlsCert=/tmp/domain.pem tlsKey=/tmp/domain.key mtlsMode=require_and_verify clientCAs=/tmp/ca.pem caCount=1
Health server: addr=:8444 mode=tls
```

## Response Formats

### Echo Endpoint (`GET /`)

```
Hello, <path>! Here's your random number: <random_int>
```

Example:
```bash
$ curl http://localhost:8080/test
Hello, test! Here's your random number: 5577006791947779410
```

### Client Certs Endpoint (`GET /client-certs`)

**Without client certificate:**
```
no client certificate
```

**With client certificate:**
```
subject_cn: localhost
issuer_cn: Example CA
serial: 07e3
not_before: 2025-10-05T19:39:17Z
not_after: 2035-10-05T19:39:17Z
dns: localhost
ip: 127.0.0.1
```

**With certificate but no SANs:**
```
subject_cn: example.com
issuer_cn: Example CA
serial: 0a1b2c3d
not_before: 2025-01-01T00:00:00Z
not_after: 2026-01-01T00:00:00Z
no SANs on client certificate
```

### Health Check Endpoint (`GET /` on health check address)

```
OK
```

## Notes for Agents

### Certificate Generation

Always use `selfsigned-gen` for test certificates:

```bash
cd /tmp
selfsigned-gen -domains "localhost,127.0.0.1,example.local"
# Creates: ca.pem, ca.key, domain.pem, domain.key
```

### Port Selection

- Use high ports (>1024) to avoid requiring root
- Suggested ports: 8080 (HTTP), 8443 (HTTPS), 8444 (health check)
- For parallel testing, use unique ports per test

### Process Management

```bash
# Start with explicit PID tracking
echo-server -addr :8080 &
PID=$!

# Or find by command
PID=$(pgrep -f "echo-server -addr :8080")

# Stop gracefully
kill $PID

# Force stop if needed
kill -9 $PID
```

### Health Check Usage

The health check endpoint is designed for:
- Load balancer health probes
- Kubernetes liveness/readiness probes
- Monitoring systems

It uses the same TLS settings as the main server but never requires client certificates, making it suitable for automated health checks.

### Idempotency

- Starting the server on an already-bound port will fail
- Certificate generation with `selfsigned-gen` overwrites existing files
- Multiple servers can run simultaneously on different ports

### Security Considerations

- All examples use self-signed certificates for local testing only
- Do not use these certificates or configurations in production
- The server logs TLS handshake errors, which is useful for debugging but may be verbose in production
