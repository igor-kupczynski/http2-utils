# echo-server

A minimal HTTP/HTTPS server that echoes the request path with a random number. Supports plain HTTP, TLS, and mutual TLS (mTLS) modes.

## Installation

### Install from source

```bash
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/echo-server@latest
```

### Build locally

```bash
cd echo-server
make build
# or
go build
```

### Docker

Build and run using Docker:

```bash
# Build Docker image (tagged with git SHA)
make docker-build

# Run in plain HTTP mode
make docker-run

# Or use docker directly
docker run -p 8080:8080 docker.io/$(whoami)/echo-server:latest

# Run with TLS (requires certificates in /tmp)
make docker-run-tls

# Push to registry
make docker-push

# Customize registry and image name
make docker-build DOCKER_REGISTRY=ghcr.io DOCKER_IMAGE_NAME=ghcr.io/myuser/echo-server
make docker-push DOCKER_REGISTRY=ghcr.io DOCKER_IMAGE_NAME=ghcr.io/myuser/echo-server
```

The Docker image is built using a multi-stage build with a scratch base image, resulting in a minimal ~7MB image.

## Makefile Targets

The project includes a Makefile for common development tasks:

```bash
make help              # Show all available targets
make build             # Build the binary
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
make coverage          # Generate unit + integration coverage summaries
make fmt               # Format code
make vet               # Run go vet
make lint              # Run all linters
make clean             # Remove build artifacts
make run               # Build and run in HTTP mode
make run-tls           # Build and run in TLS mode
make run-mtls          # Build and run in mTLS mode
make dev-certs         # Generate test certificates

# Docker targets
make docker-info       # Display Docker image configuration
make docker-build      # Build Docker image tagged with git SHA
make docker-push       # Build and push Docker image to registry
make docker-run        # Build and run Docker container in HTTP mode
make docker-run-tls    # Build and run Docker container in TLS mode
make docker-clean      # Remove locally built Docker images
```

## Quickstart

### Plain HTTP

```bash
echo-server -addr :8080
curl http://localhost:8080/hello
```

### TLS

Generate self-signed certificates:

```bash
cd /tmp
selfsigned-gen -domains "localhost,127.0.0.1"
```

Start server with TLS:

```bash
echo-server -addr :8443 -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key
curl --cacert /tmp/ca.pem https://localhost:8443/hello
```

### mTLS (Mutual TLS)

Using the same certificates from above:

```bash
# Start server requiring client certificates
echo-server -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode require_and_verify \
  -clientCAs /tmp/ca.pem

# Request with client certificate (use domain.pem/key as client cert for demo)
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/hello
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Address to listen on for main server |
| `-healthCheck` | `""` | Optional address for health check endpoint |
| `-tlsCert` | `""` | Path to server certificate PEM file |
| `-tlsKey` | `""` | Path to server private key PEM file |
| `-mtlsMode` | `""` | Client authentication mode (see below) |
| `-clientCAs` | `""` | Path to PEM bundle of client CA certificates |

### mTLS Modes

When TLS is enabled (`-tlsCert` and `-tlsKey` provided), you can optionally enable mTLS by setting `-mtlsMode`:

| Mode | Description | Requires `-clientCAs` |
|------|-------------|----------------------|
| `request` | Request client cert but don't verify | No |
| `verify_if_given` | Verify client cert if provided | Yes |
| `require_any` | Require client cert but don't verify | No |
| `require_and_verify` | Require and verify client cert | Yes |

**Note:** If `-mtlsMode` is empty or `"none"`, the server runs in TLS-only mode (no client authentication).

## Mode Matrix

### Main Server

| `-tlsCert`/`-tlsKey` | `-mtlsMode` | Result |
|---------------------|-------------|---------|
| Not provided | Any | Plain HTTP |
| Provided | Empty/`none` | TLS only |
| Provided | Valid mode | mTLS |

### Health Check Server

The health check server follows the main server's TLS setting but **never** uses mTLS:

| Main Server Mode | Health Check Mode |
|-----------------|-------------------|
| Plain HTTP | Plain HTTP |
| TLS | TLS (no client auth) |
| mTLS | TLS (no client auth) |

## Endpoints

### `GET /`

Echo endpoint that returns a greeting with the request path and a random number.

**Example:**

```bash
$ curl http://localhost:8080/world
Hello, world! Here's your random number: 5577006791947779410
```

### `GET /client-certs`

Returns client certificate details if a client certificate was presented during the TLS handshake.

**Response format (text/plain):**

When no client certificate is present:
```
no client certificate
```

When a client certificate is present:
```
subject_cn: <Common Name or empty>
issuer_cn: <Issuer Common Name or empty>
serial: <hex-encoded serial number>
not_before: <RFC3339 timestamp>
not_after: <RFC3339 timestamp>
dns: <DNS SAN>
dns: <another DNS SAN>
ip: <IP SAN>
uri: <URI SAN>
```

If the certificate has no SANs:
```
subject_cn: example.com
issuer_cn: Example CA
serial: 0a1b2c3d
not_before: 2025-01-01T00:00:00Z
not_after: 2026-01-01T00:00:00Z
no SANs on client certificate
```

**Examples:**

```bash
# Without client cert (TLS mode)
$ curl --cacert /tmp/ca.pem https://localhost:8443/client-certs
no client certificate

# With client cert (mTLS mode)
$ curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs
subject_cn: localhost
issuer_cn: localhost
serial: 5c9d5e5f5a5b5c5d
not_before: 2025-10-05T12:00:00Z
not_after: 2026-10-05T12:00:00Z
dns: localhost
ip: 127.0.0.1
```

### Health Check Endpoint

When `-healthCheck` is specified, a separate server runs on that address with a single endpoint:

**`GET /` (health check)**

Returns `OK` with HTTP 200 status.

```bash
# Plain HTTP health check
$ curl http://localhost:8081/
OK

# TLS health check (when main server uses TLS)
$ curl --cacert /tmp/ca.pem https://localhost:8444/
OK
```

## Validation and Errors

The server validates flags at startup and exits with clear error messages:

- **Missing TLS key or cert:** Both `-tlsCert` and `-tlsKey` must be provided together
  ```
  Error: both -tlsCert and -tlsKey must be provided together
  ```

- **Invalid mTLS mode:**
  ```
  Error: invalid -mtlsMode="invalid". Allowed values: request, verify_if_given, require_any, require_and_verify
  ```

- **Missing client CAs for verifying modes:**
  ```
  Error: -mtlsMode=verify_if_given requires -clientCAs
  Error: -mtlsMode=require_and_verify requires -clientCAs
  ```

- **Certificate file errors:**
  ```
  Error loading server certificate: open /path/to/cert.pem: no such file or directory
  Error reading client CAs: open /path/to/ca.pem: no such file or directory
  Error: failed to parse any CA certificates from -clientCAs
  ```

## Startup Logging

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

## Troubleshooting

### CA Bundle Issues

**Problem:** `Error: failed to parse any CA certificates from -clientCAs`

**Solution:** Ensure the `-clientCAs` file contains valid PEM-encoded certificates. The file can contain multiple certificates concatenated together:

```bash
# Verify PEM format
openssl x509 -in /tmp/ca.pem -text -noout

# Multiple CAs in one file
cat ca1.pem ca2.pem > bundle.pem
```

### Handshake Failures

**Problem:** `curl: (35) error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure`

**Possible causes:**

1. **Client cert required but not provided:**
   ```bash
   # Server requires client cert
   echo-server -mtlsMode require_any ...
   
   # Add client cert to curl
   curl --cert client.pem --key client.key ...
   ```

2. **Client cert not trusted:**
   ```bash
   # Server verifies client certs
   echo-server -mtlsMode require_and_verify -clientCAs ca.pem ...
   
   # Ensure client cert is signed by a CA in ca.pem
   openssl verify -CAfile ca.pem client.pem
   ```

3. **Server cert not trusted by client:**
   ```bash
   # Add server CA to curl
   curl --cacert ca.pem https://...
   ```

### Connection Refused

**Problem:** `curl: (7) Failed to connect to localhost port 8443: Connection refused`

**Solution:** Check that the server started successfully and is listening on the expected address. Review startup logs for errors.

### HTTP/2 Support

The server automatically enables HTTP/2 when TLS is enabled. Verify with:

```bash
curl -v --cacert /tmp/ca.pem https://localhost:8443/ 2>&1 | grep ALPN
# Should show: ALPN, server accepted to use h2
```

## Examples

### Development Server with Health Check

```bash
# Plain HTTP with separate health check port
echo-server -addr :8080 -healthCheck :8081

# In another terminal
curl http://localhost:8080/api/users
curl http://localhost:8081/  # health check
```

### Production-like TLS Setup

```bash
# Generate certs
cd /tmp
selfsigned-gen -domains "myapp.local,localhost,127.0.0.1"

# Start with TLS and health check
echo-server \
  -addr :8443 \
  -healthCheck :8444 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key

# Test
curl --cacert /tmp/ca.pem https://localhost:8443/test
curl --cacert /tmp/ca.pem https://localhost:8444/  # health
```

### mTLS with Client Verification

```bash
# Start server requiring verified client certs
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode require_and_verify \
  -clientCAs /tmp/ca.pem

# Request with client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/secure

# Check client cert details
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs
```

### Optional Client Certificates

```bash
# Request but don't require client certs
echo-server \
  -addr :8443 \
  -tlsCert /tmp/domain.pem \
  -tlsKey /tmp/domain.key \
  -mtlsMode request

# Works without client cert
curl --cacert /tmp/ca.pem https://localhost:8443/

# Also works with client cert
curl --cacert /tmp/ca.pem \
  --cert /tmp/domain.pem \
  --key /tmp/domain.key \
  https://localhost:8443/client-certs
```

## Backward Compatibility

When no TLS flags are provided, the server behaves exactly as before:
- Main server listens on `-addr` with plain HTTP
- Health check (if enabled) uses plain HTTP
- No breaking changes to existing deployments
