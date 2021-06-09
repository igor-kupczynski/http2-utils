package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

var addr = flag.String("addr", "localhost:8080", "address to listen on")

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())

	listener, err := net.Listen("tcp4", *addr)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	server := http.Server{
		Handler: mux,
	}
	log.Printf("Listening on %s", *addr)
	log.Fatal(server.Serve(alwaysClose(listener)))
}

func newEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
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