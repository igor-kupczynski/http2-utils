package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	var addr = flag.String("addr", ":8080", "address to listen on")
	var healthCheck = flag.String("healthCheck", "", "extra address to listen on for health checks")
	var tlsCert = flag.String("tlsCert", "", "path to server cert PEM")
	var tlsKey = flag.String("tlsKey", "", "path to server key PEM")
	var mtlsMode = flag.String("mtlsMode", "", "mTLS client-auth mode: request, verify_if_given, require_any, require_and_verify")
	var clientCAs = flag.String("clientCAs", "", "path to PEM bundle of client CAs")
	flag.Parse()

	// Validate TLS flags
	if (*tlsCert != "" && *tlsKey == "") || (*tlsCert == "" && *tlsKey != "") {
		log.Fatal("Error: both -tlsCert and -tlsKey must be provided together")
	}

	tlsEnabled := *tlsCert != "" && *tlsKey != ""

	// Validate mTLS mode
	var clientAuthType tls.ClientAuthType
	var mtlsModeNormalized string
	if *mtlsMode != "" && *mtlsMode != "none" {
		if !tlsEnabled {
			log.Fatal("Error: -mtlsMode requires -tlsCert and -tlsKey to be set")
		}
		switch *mtlsMode {
		case "request":
			clientAuthType = tls.RequestClientCert
			mtlsModeNormalized = "request"
		case "verify_if_given":
			clientAuthType = tls.VerifyClientCertIfGiven
			mtlsModeNormalized = "verify_if_given"
			if *clientCAs == "" {
				log.Fatal("Error: -mtlsMode=verify_if_given requires -clientCAs")
			}
		case "require_any":
			clientAuthType = tls.RequireAnyClientCert
			mtlsModeNormalized = "require_any"
		case "require_and_verify":
			clientAuthType = tls.RequireAndVerifyClientCert
			mtlsModeNormalized = "require_and_verify"
			if *clientCAs == "" {
				log.Fatal("Error: -mtlsMode=require_and_verify requires -clientCAs")
			}
		default:
			log.Fatalf("Error: invalid -mtlsMode=%q. Allowed values: request, verify_if_given, require_any, require_and_verify", *mtlsMode)
		}
	}

	mtlsEnabled := mtlsModeNormalized != ""

	// Build TLS config for main server
	var mainTLSConfig *tls.Config
	var caCount int
	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("Error loading server certificate: %v", err)
		}

		mainTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		if mtlsEnabled {
			mainTLSConfig.ClientAuth = clientAuthType

			// Load client CAs for verifying modes
			if *clientCAs != "" {
				caPEM, err := os.ReadFile(*clientCAs)
				if err != nil {
					log.Fatalf("Error reading client CAs: %v", err)
				}
				caPool := x509.NewCertPool()
				if !caPool.AppendCertsFromPEM(caPEM) {
					log.Fatal("Error: failed to parse any CA certificates from -clientCAs")
				}
				mainTLSConfig.ClientCAs = caPool

				// Count CAs for logging
				block := caPEM
				for len(block) > 0 {
					var derBlock []byte
					derBlock, block = extractNextPEM(block)
					if derBlock != nil {
						caCount++
					}
				}
			}
		}
	}

	// Build TLS config for health check (TLS but never mTLS)
	var healthTLSConfig *tls.Config
	if tlsEnabled && *healthCheck != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("Error loading server certificate for health check: %v", err)
		}

		healthTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	// Start health check server
	if *healthCheck != "" {
		go serveHealthCheck(*healthCheck, healthTLSConfig)
	}

	// Setup main server
	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())
	mux.Handle("/client-certs", newClientCertsHandler())

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	// Wrap with TLS if enabled
	if mainTLSConfig != nil {
		listener = tls.NewListener(listener, mainTLSConfig)
	}

	server := http.Server{
		Handler: mux,
	}

	// Log startup configuration
	logMainServerConfig(*addr, tlsEnabled, mtlsEnabled, mtlsModeNormalized, *tlsCert, *tlsKey, *clientCAs, caCount)
	if *healthCheck != "" {
		logHealthServerConfig(*healthCheck, tlsEnabled)
	}

	log.Fatal(server.Serve(listener))
}

func logMainServerConfig(addr string, tlsEnabled, mtlsEnabled bool, mtlsMode, tlsCert, tlsKey, clientCAs string, caCount int) {
	mode := "plain"
	if mtlsEnabled {
		mode = "mtls"
	} else if tlsEnabled {
		mode = "tls"
	}

	parts := []string{fmt.Sprintf("Main server: addr=%s mode=%s", addr, mode)}
	if tlsEnabled {
		parts = append(parts, fmt.Sprintf("tlsCert=%s tlsKey=%s", tlsCert, tlsKey))
	}
	if mtlsEnabled {
		parts = append(parts, fmt.Sprintf("mtlsMode=%s", mtlsMode))
		if clientCAs != "" {
			parts = append(parts, fmt.Sprintf("clientCAs=%s caCount=%d", clientCAs, caCount))
		}
	}
	log.Println(strings.Join(parts, " "))
}

func logHealthServerConfig(addr string, tlsEnabled bool) {
	mode := "plain"
	if tlsEnabled {
		mode = "tls"
	}
	log.Printf("Health server: addr=%s mode=%s", addr, mode)
}

func newEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, "Hello, %s! Here's your random number: %d\n", r.URL.Path[1:], rand.Int())
		if err != nil {
			log.Printf("Can't write to response body: %v", err)
		}
	})
}

func newClientCertsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			fmt.Fprint(w, "no client certificate\n")
			return
		}

		cert := r.TLS.PeerCertificates[0]

		// Subject CN
		subjectCN := ""
		if cert.Subject.CommonName != "" {
			subjectCN = cert.Subject.CommonName
		}
		fmt.Fprintf(w, "subject_cn: %s\n", subjectCN)

		// Issuer CN
		issuerCN := ""
		if cert.Issuer.CommonName != "" {
			issuerCN = cert.Issuer.CommonName
		}
		fmt.Fprintf(w, "issuer_cn: %s\n", issuerCN)

		// Serial number
		fmt.Fprintf(w, "serial: %s\n", hex.EncodeToString(cert.SerialNumber.Bytes()))

		// Validity dates
		fmt.Fprintf(w, "not_before: %s\n", cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"))
		fmt.Fprintf(w, "not_after: %s\n", cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"))

		// SANs
		hasSANs := false
		for _, dns := range cert.DNSNames {
			fmt.Fprintf(w, "dns: %s\n", dns)
			hasSANs = true
		}
		for _, ip := range cert.IPAddresses {
			fmt.Fprintf(w, "ip: %s\n", ip.String())
			hasSANs = true
		}
		for _, uri := range cert.URIs {
			fmt.Fprintf(w, "uri: %s\n", uri.String())
			hasSANs = true
		}

		if !hasSANs {
			fmt.Fprint(w, "no SANs on client certificate\n")
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

func serveHealthCheck(hcAddr string, tlsConfig *tls.Config) {
	mux := http.NewServeMux()
	mux.Handle("/", newHealthCheckHandler())

	listener, err := net.Listen("tcp4", hcAddr)
	if err != nil {
		log.Fatalf("Error creating health check listener: %v", err)
	}

	// Wrap with TLS if config provided
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	server := http.Server{
		Handler: mux,
	}
	log.Fatal(server.Serve(listener))
}

// extractNextPEM extracts the next PEM block from the input and returns it along with the remaining data
func extractNextPEM(data []byte) ([]byte, []byte) {
	// Simple PEM block detection
	start := []byte("-----BEGIN")
	end := []byte("-----END")

	startIdx := indexOf(data, start)
	if startIdx == -1 {
		return nil, nil
	}

	endIdx := indexOf(data[startIdx:], end)
	if endIdx == -1 {
		return nil, nil
	}

	// Find the end of the END line
	endLineEnd := indexOf(data[startIdx+endIdx:], []byte("\n"))
	if endLineEnd == -1 {
		endLineEnd = len(data[startIdx+endIdx:])
	} else {
		endLineEnd++ // Include the newline
	}

	blockEnd := startIdx + endIdx + endLineEnd
	return data[startIdx:blockEnd], data[blockEnd:]
}

func indexOf(data []byte, pattern []byte) int {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
