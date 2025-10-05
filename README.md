# http2-utils

## Echo server for these random tests

A minimal HTTP/HTTPS server that echoes the request path with a random number. Supports plain HTTP, TLS, and mutual TLS (mTLS) modes.

**📖 [Full documentation](echo-server/README.md)**

Install:

    ❯  go install github.com/igor-kupczynski/http2-utils/echo-server@latest

Quick start:

    ❯ echo-server -addr :8080 -healthCheck localhost:8081
    
    # In a different terminal (or a web browser)
    ❯ curl localhost:8080/foo

With TLS:

    ❯ cd /tmp && selfsigned-gen -domains "localhost,127.0.0.1"
    ❯ echo-server -addr :8443 -tlsCert /tmp/domain.pem -tlsKey /tmp/domain.key
    ❯ curl --cacert /tmp/ca.pem https://localhost:8443/hello

## HTTP v2 CLI

Install:

    ❯  go install github.com/igor-kupczynski/http2-utils/http2-cli@latest

Profit:

    ❯ http2-cli -url "https://host" -auth "username:pass"
    Got response 200 over HTTP/2.0
    (...)


## Self-signed cert generator

Install:

    ❯  go install github.com/igor-kupczynski/http2-utils/selfsigned-gen@latest

Profit:

    ❯ selfsigned-gen -domains "example.com,*.example.com"
    ❯ openssl x509 -subject -enddate -ext subjectAltName  -noout -in domain.pem
      subject=O = "Example, Inc.", CN = example.com 
      notAfter=Oct 21 14:44:26 2029 GMT
      X509v3 Subject Alternative Name: 
          DNS:example.com, DNS:*.example.com


## Too many requests

Always close an incoming connection

Install:

    ❯  go install github.com/igor-kupczynski/http2-utils/too-many-requests@latest

Profit:

    ❯ too-many-requests -addr localhost:8080 -close -healthCheck localhost:8081
    
    # In a different terminal (or a web browser)
    ❯ curl localhost:8080/foo


## HTTP client stats

Simple demo that logs client connection lifecycle events using `net/http/httptrace`.

Install:

    ❯  go install github.com/igor-kupczynski/http2-utils/http-client-stats@latest

Profit:

    ❯ http-client-stats


## Client TLS (mTLS)

A simple server to experiment with mTLS.

We have a set of certs in client-auth/certs:
  * CA
  * client  (`DNSName: client.local`), signed by _CA_
  * server  (`DNSName: localhost`), signed by _CA_


### Server

```sh
go run client-auth/server.go
```

### Client

Without mTLS:
```sh
curl --cacert client-auth/certs/ca.pem https://localhost:8443
```

```
Hello, stranger! Here's your random number: 8674665223082153551
```

With mTLS:
```sh
curl --cacert client-auth/certs/ca.pem \
  --cert client-auth/certs/client.pem  \
  --key client-auth/certs/client.key \
  https://localhost:8443
```

```
Hello, client.local! Here's your random number: 3916589616287113937
```
