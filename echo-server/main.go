package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
)

func main() {
	var addr = flag.String("addr", ":8080", "address to listen on")
	var healthCheck = flag.String("healthCheck", "", "extra address to listen on for health checks")
	flag.Parse()

	if *healthCheck != "" {
		go serveHealthCheck(*healthCheck)
	}

	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	server := http.Server{
		Handler: mux,
	}
	log.Printf("Listening on %s", *addr)
	log.Fatal(server.Serve(listener))
}

func newEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, "Hello, %s! Here's your random number: %d\n", r.URL.Path[1:], rand.Int())
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}

func newHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Health check OK")
		_, err := fmt.Fprintf(w, "OK")
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}

func serveHealthCheck(hcAddr string) {
	mux := http.NewServeMux()
	mux.Handle("/", newHealthCheckHandler())

	listener, err := net.Listen("tcp4", hcAddr)
	if err != nil {
		log.Fatalf("Error creating health check listener: %v", err)
	}

	server := http.Server{
		Handler: mux,
	}
	log.Printf("Health check on %s", hcAddr)
	log.Fatal(server.Serve(listener))
}
