# AGENTS

This document provides automation-friendly guidance for coding agents and CI scripts to build and run the utilities in this repo. All commands are non-interactive and idempotent where possible.

## Build and install (Go 1.20+)

```bash
# Ensure GOPATH/bin is on PATH for local installs
# macOS (zsh): echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.zshrc

# Install latest versions of all binaries
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/echo-server@latest
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/http2-cli@latest
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/selfsigned-gen@latest
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/too-many-requests@latest
GO111MODULE=on go install github.com/igor-kupczynski/http2-utils/http-client-stats@latest
```

## Binaries and flags

- echo-server
  - Purpose: Minimal HTTP server that echoes path with a random number; optional healthcheck port.
  - Flags:
    - `-addr string` (default ":8080"): address to listen on
    - `-healthCheck string` (default ""): optional extra address for health checks
  - Example:
    ```bash
    echo-server -addr :8080 -healthCheck localhost:8081
    # health: curl http://localhost:8081/
    curl http://localhost:8080/foo
    ```

- http2-cli
  - Purpose: Simple HTTP/2 client using `golang.org/x/net/http2`.
  - Flags:
    - `-url string` (default "https://localhost"): URL to request
    - `-method string` (default "GET"): HTTP method (note: request body is always nil in current implementation)
    - `-auth string` (default ""): `username:password` for Basic Auth
  - Example:
    ```bash
    http2-cli -url https://example.com -auth "user:pass"
    ```

- selfsigned-gen
  - Purpose: Generate a local CA and a server/client certificate for given DNS/IPs.
  - Output: `ca.pem`, `ca.key`, `domain.pem`, `domain.key` in current directory.
  - Flags:
    - `-domains string` (comma-separated) (default "https://example.local"): list of SANs; first DNS becomes CN
  - Example:
    ```bash
    selfsigned-gen -domains "example.com,*.example.com,127.0.0.1,localhost"
    ```

- too-many-requests
  - Purpose: Test harness that optionally closes all incoming connections immediately.
  - Flags:
    - `-addr string` (default "localhost:8080"): address to listen on
    - `-healthCheck string` (default ""): optional extra address for health checks
    - `-close` (default false): if set, server closes all incoming connections without replying
  - Example:
    ```bash
    too-many-requests -addr localhost:8080 -close -healthCheck localhost:8081
    curl -v http://localhost:8080/
    ```

- http-client-stats
  - Purpose: Demonstrate/trace HTTP client connection lifecycle using `net/http/httptrace`.
  - Behavior: Issues 10 GET requests to `https://golang.org/`, logs connection events, drains bodies, then sleeps briefly.
  - Example:
    ```bash
    http-client-stats
    ```

## mTLS demo (client-auth)

- Server (TLS, optional client certs requested):
  ```bash
  go run client-auth/server.go
  ```
- Example requests:
  ```bash
  # Without client cert
  curl --cacert client-auth/certs/ca.pem https://localhost:8443

  # With client cert
  curl --cacert client-auth/certs/ca.pem \
    --cert client-auth/certs/client.pem \
    --key client-auth/certs/client.key \
    https://localhost:8443
  ```

## Notes for agents

- Networking
  - Health endpoints, where available, are root path `/` on the specified `-healthCheck` address and return `OK`.
  - The echo endpoints reply on `/` with a greeting; some include a random number in the body.
- Idempotency
  - Generating certs with `selfsigned-gen` overwrites existing output files in the working directory.
- Security
  - The examples are for local testing only; keys and certs are intentionally insecure for production use.
