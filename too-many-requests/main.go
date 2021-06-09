package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

func main() {
	var addr = flag.String("addr", "localhost:8080", "address to listen on")
	var healthCheck = flag.String("healthCheck", "", "extra address to listen on for health checks")
	var modeClose = flag.Bool("close", false, "should the server always close the incoming connection without a reply")
	flag.Parse()

	if *healthCheck != "" {
		go serveHealthCheck(*healthCheck)
	}

	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())

	listener, err := net.Listen("tcp4", *addr)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}
	if *modeClose {
		log.Printf("Close the incoming connections")
		listener = alwaysClose(listener)
	}

	server := http.Server{
		Handler: mux,
	}
	log.Printf("Listening on %s", *addr)
	log.Fatal(server.Serve(listener))
}

func newEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}

func newHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, "OK")
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}

type alwaysCloseListener struct {
	delegate net.Listener
}

func alwaysClose(l net.Listener) *alwaysCloseListener {
	return &alwaysCloseListener{l}
}

func (a *alwaysCloseListener) Accept() (net.Conn, error) {
	for {
		conn, err := a.delegate.Accept()
		if err != nil {
			return nil, err
		}
		log.Printf("Closing the connection from %s", conn.RemoteAddr())
		_ = conn.Close()
	}
}

func (a *alwaysCloseListener) Close() error {
	return a.delegate.Close()
}

func (a *alwaysCloseListener) Addr() net.Addr {
	return a.delegate.Addr()
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
