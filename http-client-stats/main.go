package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"time"
)

func main() {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			log.Printf("GotConn(%+v)", info)
		},
		PutIdleConn: func(err error) {
			log.Printf("PutIdleConn(%+v)", err)
		},
	}

	client := http.DefaultClient

	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", "https://golang.org/", nil)
		if err != nil {
			log.Fatal(err)
		}

		ctx := httptrace.WithClientTrace(req.Context(), trace)
		req = req.WithContext(ctx)

		res, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := io.Copy(ioutil.Discard, res.Body); err != nil {
			log.Fatal(err)
		}
		res.Body.Close()

		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(1000 * time.Millisecond)
}
