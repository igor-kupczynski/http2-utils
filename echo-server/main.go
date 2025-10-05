package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
)

// Config holds the server configuration
type Config struct {
	Addr        string
	HealthCheck string
	TLSCert     string
	TLSKey      string
	MTLSMode    string
	ClientCAs   string
}

// Server represents the echo server
type Server struct {
	config       Config
	mainServer   *http.Server
	healthServer *http.Server
	logger       *log.Logger
}

func main() {
	var addr = flag.String("addr", ":8080", "address to listen on")
	var healthCheck = flag.String("healthCheck", "", "extra address to listen on for health checks")
	var tlsCert = flag.String("tlsCert", "", "path to server cert PEM")
	var tlsKey = flag.String("tlsKey", "", "path to server key PEM")
	var mtlsMode = flag.String("mtlsMode", "", "mTLS client-auth mode: request, verify_if_given, require_any, require_and_verify")
	var clientCAs = flag.String("clientCAs", "", "path to PEM bundle of client CAs")
	flag.Parse()

	config := Config{
		Addr:        *addr,
		HealthCheck: *healthCheck,
		TLSCert:     *tlsCert,
		TLSKey:      *tlsKey,
		MTLSMode:    *mtlsMode,
		ClientCAs:   *clientCAs,
	}

	srv, err := NewServer(config, log.Default())
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// NewServer creates a new server with the given configuration
func NewServer(config Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	// Validate TLS flags
	if (config.TLSCert != "" && config.TLSKey == "") || (config.TLSCert == "" && config.TLSKey != "") {
		return nil, fmt.Errorf("Error: both -tlsCert and -tlsKey must be provided together")
	}

	tlsEnabled := config.TLSCert != "" && config.TLSKey != ""

	// Validate mTLS mode
	var clientAuthType tls.ClientAuthType
	var mtlsModeNormalized string
	if config.MTLSMode != "" && config.MTLSMode != "none" {
		if !tlsEnabled {
			return nil, fmt.Errorf("Error: -mtlsMode requires -tlsCert and -tlsKey to be set")
		}
		switch config.MTLSMode {
		case "request":
			clientAuthType = tls.RequestClientCert
			mtlsModeNormalized = "request"
		case "verify_if_given":
			clientAuthType = tls.VerifyClientCertIfGiven
			mtlsModeNormalized = "verify_if_given"
			if config.ClientCAs == "" {
				return nil, fmt.Errorf("Error: -mtlsMode=verify_if_given requires -clientCAs")
			}
		case "require_any":
			clientAuthType = tls.RequireAnyClientCert
			mtlsModeNormalized = "require_any"
		case "require_and_verify":
			clientAuthType = tls.RequireAndVerifyClientCert
			mtlsModeNormalized = "require_and_verify"
			if config.ClientCAs == "" {
				return nil, fmt.Errorf("Error: -mtlsMode=require_and_verify requires -clientCAs")
			}
		default:
			return nil, fmt.Errorf("Error: invalid -mtlsMode=%q. Allowed values: request, verify_if_given, require_any, require_and_verify", config.MTLSMode)
		}
	}

	mtlsEnabled := mtlsModeNormalized != ""

	// Build TLS config for main server
	var mainTLSConfig *tls.Config
	var caCount int
	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("Error loading server certificate: %v", err)
		}

		mainTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		if mtlsEnabled {
			mainTLSConfig.ClientAuth = clientAuthType

			// Load client CAs for verifying modes
			if config.ClientCAs != "" {
				caPEM, err := os.ReadFile(config.ClientCAs)
				if err != nil {
					return nil, fmt.Errorf("Error reading client CAs: %v", err)
				}
				caPool := x509.NewCertPool()
				if !caPool.AppendCertsFromPEM(caPEM) {
					return nil, fmt.Errorf("Error: failed to parse any CA certificates from -clientCAs")
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
	if tlsEnabled && config.HealthCheck != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("Error loading server certificate for health check: %v", err)
		}

		healthTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	// Setup main server
	mux := http.NewServeMux()
	mux.Handle("/", newEchoHandler())
	mux.Handle("/client-certs", newClientCertsHandler())

	mainServer := &http.Server{
		Addr:      config.Addr,
		Handler:   mux,
		TLSConfig: mainTLSConfig,
	}

	// Setup health check server
	var healthServer *http.Server
	if config.HealthCheck != "" {
		healthMux := http.NewServeMux()
		healthMux.Handle("/", newHealthCheckHandler(logger))

		healthServer = &http.Server{
			Addr:      config.HealthCheck,
			Handler:   healthMux,
			TLSConfig: healthTLSConfig,
		}
	}

	// Log startup configuration
	logMainServerConfig(logger, config.Addr, tlsEnabled, mtlsEnabled, mtlsModeNormalized, config.TLSCert, config.TLSKey, config.ClientCAs, caCount)
	if config.HealthCheck != "" {
		logHealthServerConfig(logger, config.HealthCheck, tlsEnabled)
	}

	return &Server{
		config:       config,
		mainServer:   mainServer,
		healthServer: healthServer,
		logger:       logger,
	}, nil
}

// ListenAndServe starts the server and blocks until an error occurs
func (s *Server) ListenAndServe() error {
	// Start health check server in background if configured
	if s.healthServer != nil {
		go func() {
			var err error
			if s.healthServer.TLSConfig != nil {
				err = s.healthServer.ListenAndServeTLS("", "")
			} else {
				err = s.healthServer.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				s.logger.Printf("Health check server error: %v", err)
			}
		}()
	}

	// Start main server
	var err error
	if s.mainServer.TLSConfig != nil {
		err = s.mainServer.ListenAndServeTLS("", "")
	} else {
		err = s.mainServer.ListenAndServe()
	}
	return err
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	if s.healthServer != nil {
		s.healthServer.Close()
	}
	if s.mainServer != nil {
		return s.mainServer.Close()
	}
	return nil
}

// Addr returns the address the main server is listening on
func (s *Server) Addr() string {
	return s.mainServer.Addr
}

// HealthAddr returns the address the health check server is listening on
func (s *Server) HealthAddr() string {
	if s.healthServer != nil {
		return s.healthServer.Addr
	}
	return ""
}

func logMainServerConfig(logger *log.Logger, addr string, tlsEnabled, mtlsEnabled bool, mtlsMode, tlsCert, tlsKey, clientCAs string, caCount int) {
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
	logger.Println(strings.Join(parts, " "))
}

func logHealthServerConfig(logger *log.Logger, addr string, tlsEnabled bool) {
	mode := "plain"
	if tlsEnabled {
		mode = "tls"
	}
	logger.Printf("Health server: addr=%s mode=%s", addr, mode)
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

func newHealthCheckHandler(logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("Health check OK")
		_, err := fmt.Fprintf(w, "OK")
		if err != nil {
			logger.Printf("Can't write to response body: %v", err)
		}
	})
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
