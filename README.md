# http2-utils

## HTTP v2 CLI

Install:

    $  go get github.com/igor-kupczynski/http2-utils/http2-cli

Profit:

    $ http2-cli -url "https://host" -auth "username:pass"
    Got response 200 over HTTP/2.0
    (...)


## Self-signed cert generator

Install:

    $  go get github.com/igor-kupczynski/http2-utils/selfsigned-gen

Profit:

    $ selfsigned-gen -domains "example.com,*.example.com"
    $ openssl x509 -subject -enddate -ext subjectAltName  -noout -in domain.pem
      subject=O = "Example, Inc."
      notAfter=Oct 21 14:44:26 2029 GMT
      X509v3 Subject Alternative Name: 
          DNS:example.com, DNS:*.example.com


## Too many requests

Always close an incoming connection

Install:

    $  go get github.com/igor-kupczynski/http2-utils/too-many-requests

Profit:

    $ too-many-requests -addr localhost:8080 -close -healthcheck localhost:8081
    
    # In a different terminal (or a web browser)
    $ curl localhost:8080/foo
