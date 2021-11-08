package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
)

func main() {
	var addr = flag.String("addr", ":8443", "address to listen on")
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	config := &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}

	server := http.Server{
		Handler:   mux,
		TLSConfig: config,
	}
	log.Printf("Listening on %s", *addr)
	log.Fatal(server.ServeTLS(listener, "client-auth/certs/server.pem", "client-auth/certs/server.key"))
}

func newEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientName := "stranger"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientName = r.TLS.PeerCertificates[0].DNSNames[0]
		}
		_, err := fmt.Fprintf(w, "Hello, %s! Here's your random number: %d\n", clientName, rand.Int())
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}
