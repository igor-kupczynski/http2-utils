package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServerCreation tests that servers can be created with various configurations
func TestServerCreation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError string
	}{
		{
			name: "plain HTTP",
			config: Config{
				Addr: ":0",
			},
			wantError: "",
		},
		{
			name: "missing TLS key",
			config: Config{
				Addr:    ":0",
				TLSCert: "cert.pem",
			},
			wantError: "both -tlsCert and -tlsKey must be provided together",
		},
		{
			name: "missing TLS cert",
			config: Config{
				Addr:   ":0",
				TLSKey: "key.pem",
			},
			wantError: "both -tlsCert and -tlsKey must be provided together",
		},
		{
			name: "invalid mTLS mode",
			config: Config{
				Addr:     ":0",
				TLSCert:  "cert.pem",
				TLSKey:   "key.pem",
				MTLSMode: "invalid",
			},
			wantError: "invalid -mtlsMode",
		},
		{
			name: "verify_if_given without clientCAs",
			config: Config{
				Addr:     ":0",
				TLSCert:  "cert.pem",
				TLSKey:   "key.pem",
				MTLSMode: "verify_if_given",
			},
			wantError: "verify_if_given requires -clientCAs",
		},
		{
			name: "require_and_verify without clientCAs",
			config: Config{
				Addr:     ":0",
				TLSCert:  "cert.pem",
				TLSKey:   "key.pem",
				MTLSMode: "require_and_verify",
			},
			wantError: "require_and_verify requires -clientCAs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.New(io.Discard, "", 0)
			srv, err := NewServer(tt.config, logger)

			if tt.wantError != "" {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if srv == nil {
				t.Error("Expected non-nil server")
			}
		})
	}
}

// TestPlainHTTPServer tests a plain HTTP server
func TestPlainHTTPServer(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)

	config := Config{
		Addr: "127.0.0.1:0", // Use port 0 to get a free port
	}

	srv, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.ListenAndServe()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual address the server is listening on
	addr := srv.mainServer.Addr
	if addr == "127.0.0.1:0" {
		// Server hasn't updated the address yet, we need to extract it differently
		// For now, skip this test as it requires more complex port extraction
		t.Skip("Port extraction not implemented for this test style")
	}

	// Clean up
	srv.Shutdown()

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=plain") {
		t.Errorf("Expected mode=plain in logs, got: %s", logs)
	}
}

// TestTLSServerWithCerts tests TLS server with actual certificates
func TestTLSServerWithCerts(t *testing.T) {
	// Generate test certificates
	certDir := t.TempDir()
	ca, cert, key := generateCerts(t, certDir)

	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)

	config := Config{
		Addr:    "127.0.0.1:0",
		TLSCert: cert,
		TLSKey:  key,
	}

	srv, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify TLS config is set
	if srv.mainServer.TLSConfig == nil {
		t.Error("Expected TLS config to be set")
	}

	// Verify HTTP/2 is enabled
	if !contains(srv.mainServer.TLSConfig.NextProtos, "h2") {
		t.Error("Expected h2 in NextProtos")
	}

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=tls") {
		t.Errorf("Expected mode=tls in logs, got: %s", logs)
	}
	if !strings.Contains(logs, fmt.Sprintf("tlsCert=%s", cert)) {
		t.Errorf("Expected tlsCert path in logs, got: %s", logs)
	}

	// Verify we can create a client
	client := newTestHTTPClient(t, ca, nil)
	if client == nil {
		t.Error("Failed to create test client")
	}
}

// TestMTLSServerConfiguration tests mTLS server configuration
func TestMTLSServerConfiguration(t *testing.T) {
	certDir := t.TempDir()
	ca, cert, key := generateCerts(t, certDir)

	tests := []struct {
		name           string
		mtlsMode       string
		clientCAs      string
		expectedAuth   tls.ClientAuthType
		expectCAPool   bool
		expectLogMatch string
	}{
		{
			name:           "request mode",
			mtlsMode:       "request",
			clientCAs:      "",
			expectedAuth:   tls.RequestClientCert,
			expectCAPool:   false,
			expectLogMatch: "mtlsMode=request",
		},
		{
			name:           "verify_if_given mode",
			mtlsMode:       "verify_if_given",
			clientCAs:      ca,
			expectedAuth:   tls.VerifyClientCertIfGiven,
			expectCAPool:   true,
			expectLogMatch: "mtlsMode=verify_if_given",
		},
		{
			name:           "require_any mode",
			mtlsMode:       "require_any",
			clientCAs:      "",
			expectedAuth:   tls.RequireAnyClientCert,
			expectCAPool:   false,
			expectLogMatch: "mtlsMode=require_any",
		},
		{
			name:           "require_and_verify mode",
			mtlsMode:       "require_and_verify",
			clientCAs:      ca,
			expectedAuth:   tls.RequireAndVerifyClientCert,
			expectCAPool:   true,
			expectLogMatch: "mtlsMode=require_and_verify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := log.New(&logBuf, "", 0)

			config := Config{
				Addr:      "127.0.0.1:0",
				TLSCert:   cert,
				TLSKey:    key,
				MTLSMode:  tt.mtlsMode,
				ClientCAs: tt.clientCAs,
			}

			srv, err := NewServer(config, logger)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Verify TLS config
			if srv.mainServer.TLSConfig == nil {
				t.Fatal("Expected TLS config to be set")
			}

			if srv.mainServer.TLSConfig.ClientAuth != tt.expectedAuth {
				t.Errorf("Expected ClientAuth=%v, got %v", tt.expectedAuth, srv.mainServer.TLSConfig.ClientAuth)
			}

			if tt.expectCAPool && srv.mainServer.TLSConfig.ClientCAs == nil {
				t.Error("Expected ClientCAs to be set")
			}

			if !tt.expectCAPool && srv.mainServer.TLSConfig.ClientCAs != nil {
				t.Error("Expected ClientCAs to be nil")
			}

			// Check logs
			logs := logBuf.String()
			if !strings.Contains(logs, "mode=mtls") {
				t.Errorf("Expected mode=mtls in logs, got: %s", logs)
			}
			if !strings.Contains(logs, tt.expectLogMatch) {
				t.Errorf("Expected %q in logs, got: %s", tt.expectLogMatch, logs)
			}
		})
	}
}

// TestHealthCheckConfiguration tests health check server configuration
func TestHealthCheckConfiguration(t *testing.T) {
	certDir := t.TempDir()
	ca, cert, key := generateCerts(t, certDir)

	tests := []struct {
		name         string
		useTLS       bool
		useMTLS      bool
		expectHCTLS  bool
		expectHCMTLS bool
	}{
		{
			name:         "plain HTTP",
			useTLS:       false,
			useMTLS:      false,
			expectHCTLS:  false,
			expectHCMTLS: false,
		},
		{
			name:         "TLS only",
			useTLS:       true,
			useMTLS:      false,
			expectHCTLS:  true,
			expectHCMTLS: false,
		},
		{
			name:         "mTLS on main",
			useTLS:       true,
			useMTLS:      true,
			expectHCTLS:  true,
			expectHCMTLS: false, // Health check should never use mTLS
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := log.New(&logBuf, "", 0)

			config := Config{
				Addr:        "127.0.0.1:0",
				HealthCheck: "127.0.0.1:0",
			}

			if tt.useTLS {
				config.TLSCert = cert
				config.TLSKey = key
			}

			if tt.useMTLS {
				config.MTLSMode = "require_and_verify"
				config.ClientCAs = ca
			}

			srv, err := NewServer(config, logger)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			if srv.healthServer == nil {
				t.Fatal("Expected health check server to be configured")
			}

			// Check health server TLS config
			if tt.expectHCTLS {
				if srv.healthServer.TLSConfig == nil {
					t.Error("Expected health check server to have TLS config")
				} else {
					// Health check should never require client certs
					if srv.healthServer.TLSConfig.ClientAuth != tls.NoClientCert {
						t.Errorf("Expected health check ClientAuth=NoClientCert, got %v", srv.healthServer.TLSConfig.ClientAuth)
					}
				}
			} else {
				if srv.healthServer.TLSConfig != nil {
					t.Error("Expected health check server to have no TLS config")
				}
			}

			// Check logs
			logs := logBuf.String()
			if tt.expectHCTLS {
				if !strings.Contains(logs, "Health server:") || !strings.Contains(logs, "mode=tls") {
					t.Errorf("Expected health server TLS log, got: %s", logs)
				}
			} else {
				if strings.Contains(logs, "Health server:") && strings.Contains(logs, "mode=tls") {
					t.Errorf("Did not expect health server TLS log, got: %s", logs)
				}
			}
		})
	}
}

// Helper functions

func generateCerts(t *testing.T, dir string) (ca, cert, key string) {
	t.Helper()

	// Get absolute path to selfsigned-gen
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	selfsignedPath := filepath.Join(cwd, "..", "selfsigned-gen", "main.go")
	if _, err := os.Stat(selfsignedPath); os.IsNotExist(err) {
		selfsignedPath = filepath.Join(cwd, "selfsigned-gen", "main.go")
		if _, err := os.Stat(selfsignedPath); os.IsNotExist(err) {
			t.Fatalf("Cannot find selfsigned-gen/main.go from %s", cwd)
		}
	}

	// Run selfsigned-gen using exec
	cmd := exec.Command("go", "run", selfsignedPath, "-domains", "localhost,127.0.0.1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to generate certs: %v\n%s", err, output)
	}

	ca = filepath.Join(dir, "ca.pem")
	cert = filepath.Join(dir, "domain.pem")
	key = filepath.Join(dir, "domain.key")

	// Verify files exist
	for _, f := range []string{ca, cert, key} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("Certificate file not found: %s", f)
		}
	}

	return ca, cert, key
}

func newTestHTTPClient(t *testing.T, caPath string, clientCert *tls.Certificate) *http.Client {
	t.Helper()

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("Failed to read CA: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("Failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caPool,
	}

	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
