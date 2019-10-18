package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
)

var url = flag.String("url", "https://localhost", "url to connect to")
var method = flag.String("method", "GET", "HTTP method to use")
var auth = flag.String("auth", "", "username:password to be used for basic auth")


func main() {
	flag.Parse()

	client := &http.Client{}
	client.Transport = &http2.Transport{}

	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		log.Fatalf("Can't create a request: %s", err)
	}
	if *auth != "" {
		items := strings.SplitN(*auth, ":", 2)
		if len(items) < 2 {
			items = append(items, "")
		}
		req.SetBasicAuth(items[0], items[1])
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed get: %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed reading response body: %s", err)
	}
	fmt.Printf("Got response %d over %s\n%s\n", resp.StatusCode, resp.Proto, string(body))
}
