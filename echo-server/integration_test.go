package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test helpers

func genCerts(t *testing.T, dir string) (ca, cert, key string) {
	t.Helper()

	// Get absolute path to selfsigned-gen from current working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	selfsignedPath := filepath.Join(cwd, "..", "selfsigned-gen", "main.go")
	if _, err := os.Stat(selfsignedPath); os.IsNotExist(err) {
		// Try from repo root if we're already there
		selfsignedPath = filepath.Join(cwd, "selfsigned-gen", "main.go")
		if _, err := os.Stat(selfsignedPath); os.IsNotExist(err) {
			t.Fatalf("Cannot find selfsigned-gen/main.go from %s", cwd)
		}
	}

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

func getFreePorts(t *testing.T, count int) []string {
	t.Helper()
	ports := make([]string, count)
	listeners := make([]net.Listener, count)

	// Reserve ports
	for i := 0; i < count; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to reserve port: %v", err)
		}
		listeners[i] = l
		ports[i] = l.Addr().String()
	}

	// Close listeners to free ports
	for _, l := range listeners {
		l.Close()
	}

	// Small delay to ensure ports are fully released
	time.Sleep(10 * time.Millisecond)

	return ports
}

func startServer(t *testing.T, config Config) (*Server, *strings.Builder) {
	t.Helper()

	var logBuf strings.Builder
	logger := log.New(&logBuf, "", log.LstdFlags)

	srv, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(150 * time.Millisecond)

	t.Cleanup(func() {
		srv.Shutdown()
	})

	return srv, &logBuf
}

func waitForServer(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Server did not start listening on %s within %v", addr, timeout)
}

func newHTTPClient(t *testing.T, caPath string, clientCert *tls.Certificate) *http.Client {
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

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func loadClientCert(t *testing.T, certPath, keyPath string) *tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load client cert: %v", err)
	}
	return &cert
}

func doGet(t *testing.T, client *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return resp, string(body)
}

func tryGet(client *http.Client, url string) (*http.Response, string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

// Integration Tests

func TestPlainHTTP(t *testing.T) {
	ports := getFreePorts(t, 1)

	config := Config{
		Addr: ports[0],
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=plain") {
		t.Errorf("Expected startup log with mode=plain, got: %s", logs)
	}

	// Test echo endpoint
	resp, body := doGet(t, http.DefaultClient, "http://"+addr+"/test")
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Expected body to start with 'Hello, test!', got: %q", body)
	}

	// Test client-certs endpoint
	_, body = doGet(t, http.DefaultClient, "http://"+addr+"/client-certs")
	if strings.TrimSpace(body) != "no client certificate" {
		t.Errorf("Expected 'no client certificate', got: %q", body)
	}
}

func TestPlainHTTPWithHealthCheck(t *testing.T) {
	ports := getFreePorts(t, 2)

	config := Config{
		Addr:        ports[0],
		HealthCheck: ports[1],
	}

	srv, logBuf := startServer(t, config)
	mainAddr := srv.Addr()
	healthAddr := srv.HealthAddr()

	waitForServer(t, mainAddr, 3*time.Second)
	waitForServer(t, healthAddr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "Main server:") || !strings.Contains(logs, "mode=plain") {
		t.Errorf("Expected main server log, got: %s", logs)
	}

	// Test main endpoint
	resp, body := doGet(t, http.DefaultClient, "http://"+mainAddr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Main endpoint failed: %d %q", resp.StatusCode, body)
	}

	// Test health check endpoint
	resp, body = doGet(t, http.DefaultClient, "http://"+healthAddr+"/")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "OK" {
		t.Errorf("Health check failed: %d %q", resp.StatusCode, body)
	}
}

func TestTLS_NoClientCert(t *testing.T) {
	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:    "127.0.0.1:19999",
		TLSCert: cert,
		TLSKey:  key,
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=tls") {
		t.Errorf("Expected mode=tls in logs, got: %s", logs)
	}

	client := newHTTPClient(t, ca, nil)

	// Test echo endpoint
	resp, body := doGet(t, client, "https://"+addr+"/test")
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Expected body to start with 'Hello, test!', got: %q", body)
	}

	// Test client-certs endpoint
	_, body = doGet(t, client, "https://"+addr+"/client-certs")
	if strings.TrimSpace(body) != "no client certificate" {
		t.Errorf("Expected 'no client certificate', got: %q", body)
	}
}

func TestTLSWithHealthCheck(t *testing.T) {
	ports := getFreePorts(t, 2)
	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:        ports[0],
		HealthCheck: ports[1],
		TLSCert:     cert,
		TLSKey:      key,
	}

	srv, logBuf := startServer(t, config)
	mainAddr := srv.Addr()
	healthAddr := srv.HealthAddr()

	waitForServer(t, mainAddr, 3*time.Second)
	waitForServer(t, healthAddr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "Main server:") || !strings.Contains(logs, "mode=tls") {
		t.Errorf("Expected main server TLS log, got: %s", logs)
	}
	if !strings.Contains(logs, "Health server:") || !strings.Contains(logs, "mode=tls") {
		t.Errorf("Expected health server TLS log, got: %s", logs)
	}

	client := newHTTPClient(t, ca, nil)

	// Test main endpoint
	resp, body := doGet(t, client, "https://"+mainAddr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Main endpoint failed: %d %q", resp.StatusCode, body)
	}

	// Test health check endpoint (TLS but no client cert required)
	resp, body = doGet(t, client, "https://"+healthAddr+"/")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "OK" {
		t.Errorf("Health check failed: %d %q", resp.StatusCode, body)
	}
}

func TestMTLS_Request_OptionalClientCert(t *testing.T) {
	ports := getFreePorts(t, 1)

	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:     ports[0],
		TLSCert:  cert,
		TLSKey:   key,
		MTLSMode: "request",
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=mtls") || !strings.Contains(logs, "mtlsMode=request") {
		t.Errorf("Expected mode=mtls mtlsMode=request in logs, got: %s", logs)
	}

	// Test without client cert
	clientNoAuth := newHTTPClient(t, ca, nil)
	resp, body := doGet(t, clientNoAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request without client cert failed: %d %q", resp.StatusCode, body)
	}

	_, body = doGet(t, clientNoAuth, "https://"+addr+"/client-certs")
	if strings.TrimSpace(body) != "no client certificate" {
		t.Errorf("Expected 'no client certificate', got: %q", body)
	}

	// Test with client cert
	clientCert := loadClientCert(t, cert, key)
	clientWithAuth := newHTTPClient(t, ca, clientCert)
	resp, body = doGet(t, clientWithAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request with client cert failed: %d %q", resp.StatusCode, body)
	}

	_, body = doGet(t, clientWithAuth, "https://"+addr+"/client-certs")
	if !strings.Contains(body, "subject_cn:") {
		t.Errorf("Expected certificate details, got: %q", body)
	}
	if !strings.Contains(body, "serial:") {
		t.Errorf("Expected serial in certificate details, got: %q", body)
	}
	if !strings.Contains(body, "not_before:") || !strings.Contains(body, "not_after:") {
		t.Errorf("Expected validity dates in certificate details, got: %q", body)
	}
}

func TestMTLS_RequireAny(t *testing.T) {
	ports := getFreePorts(t, 1)

	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:     ports[0],
		TLSCert:  cert,
		TLSKey:   key,
		MTLSMode: "require_any",
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=mtls") || !strings.Contains(logs, "mtlsMode=require_any") {
		t.Errorf("Expected mode=mtls mtlsMode=require_any in logs, got: %s", logs)
	}

	// Test without client cert (should fail)
	clientNoAuth := newHTTPClient(t, ca, nil)
	_, _, err := tryGet(clientNoAuth, "https://"+addr+"/test")
	if err == nil {
		t.Error("Expected handshake error without client cert, but request succeeded")
	}

	// Test with client cert (should work)
	clientCert := loadClientCert(t, cert, key)
	clientWithAuth := newHTTPClient(t, ca, clientCert)
	resp, body := doGet(t, clientWithAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request with client cert failed: %d %q", resp.StatusCode, body)
	}
}

func TestMTLS_VerifyIfGiven(t *testing.T) {
	ports := getFreePorts(t, 1)

	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	// Generate a second CA and cert for invalid client test
	invalidCertDir := t.TempDir()
	_, invalidCert, invalidKey := genCerts(t, invalidCertDir)

	config := Config{
		Addr:      ports[0],
		TLSCert:   cert,
		TLSKey:    key,
		MTLSMode:  "verify_if_given",
		ClientCAs: ca,
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=mtls") || !strings.Contains(logs, "mtlsMode=verify_if_given") {
		t.Errorf("Expected mode=mtls mtlsMode=verify_if_given in logs, got: %s", logs)
	}
	if !strings.Contains(logs, "caCount=1") {
		t.Errorf("Expected caCount=1 in logs, got: %s", logs)
	}

	// Test without client cert (should work)
	clientNoAuth := newHTTPClient(t, ca, nil)
	resp, body := doGet(t, clientNoAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request without client cert failed: %d %q", resp.StatusCode, body)
	}

	// Test with valid client cert (should work)
	clientCert := loadClientCert(t, cert, key)
	clientWithAuth := newHTTPClient(t, ca, clientCert)
	resp, body = doGet(t, clientWithAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request with valid client cert failed: %d %q", resp.StatusCode, body)
	}

	// Test with invalid client cert (different CA, should fail)
	invalidClientCert := loadClientCert(t, invalidCert, invalidKey)
	clientWithInvalidAuth := newHTTPClient(t, ca, invalidClientCert)
	_, _, err := tryGet(clientWithInvalidAuth, "https://"+addr+"/test")
	if err == nil {
		t.Error("Expected handshake error with invalid client cert, but request succeeded")
	}
}

func TestMTLS_RequireAndVerify(t *testing.T) {
	ports := getFreePorts(t, 1)

	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:      ports[0],
		TLSCert:   cert,
		TLSKey:    key,
		MTLSMode:  "require_and_verify",
		ClientCAs: ca,
	}

	srv, logBuf := startServer(t, config)
	addr := srv.Addr()

	waitForServer(t, addr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "mode=mtls") || !strings.Contains(logs, "mtlsMode=require_and_verify") {
		t.Errorf("Expected mode=mtls mtlsMode=require_and_verify in logs, got: %s", logs)
	}
	if !strings.Contains(logs, "caCount=1") {
		t.Errorf("Expected caCount=1 in logs, got: %s", logs)
	}

	// Test without client cert (should fail)
	clientNoAuth := newHTTPClient(t, ca, nil)
	_, _, err := tryGet(clientNoAuth, "https://"+addr+"/test")
	if err == nil {
		t.Error("Expected handshake error without client cert, but request succeeded")
	}

	// Test with valid client cert (should work)
	clientCert := loadClientCert(t, cert, key)
	clientWithAuth := newHTTPClient(t, ca, clientCert)
	resp, body := doGet(t, clientWithAuth, "https://"+addr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Request with client cert failed: %d %q", resp.StatusCode, body)
	}

	// Test client-certs endpoint
	_, body = doGet(t, clientWithAuth, "https://"+addr+"/client-certs")
	if !strings.Contains(body, "subject_cn:") {
		t.Errorf("Expected certificate details, got: %q", body)
	}
	if !strings.Contains(body, "issuer_cn:") {
		t.Errorf("Expected issuer_cn in certificate details, got: %q", body)
	}
	if !strings.Contains(body, "serial:") {
		t.Errorf("Expected serial in certificate details, got: %q", body)
	}
	if !strings.Contains(body, "not_before:") || !strings.Contains(body, "not_after:") {
		t.Errorf("Expected validity dates in certificate details, got: %q", body)
	}
	// Check for SANs (our test certs have localhost and 127.0.0.1)
	if !strings.Contains(body, "dns:") && !strings.Contains(body, "ip:") {
		t.Errorf("Expected SANs in certificate details, got: %q", body)
	}
}

func TestMTLS_RequireAndVerify_WithHealthCheck(t *testing.T) {
	ports := getFreePorts(t, 2)
	certDir := t.TempDir()
	ca, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:        ports[0],
		HealthCheck: ports[1],
		TLSCert:     cert,
		TLSKey:      key,
		MTLSMode:    "require_and_verify",
		ClientCAs:   ca,
	}

	srv, logBuf := startServer(t, config)
	mainAddr := srv.Addr()
	healthAddr := srv.HealthAddr()

	waitForServer(t, mainAddr, 3*time.Second)
	waitForServer(t, healthAddr, 3*time.Second)

	// Check logs
	logs := logBuf.String()
	if !strings.Contains(logs, "Main server:") || !strings.Contains(logs, "mode=mtls") {
		t.Errorf("Expected main server mTLS log, got: %s", logs)
	}
	if !strings.Contains(logs, "Health server:") || !strings.Contains(logs, "mode=tls") {
		t.Errorf("Expected health server TLS (not mTLS) log, got: %s", logs)
	}

	clientNoAuth := newHTTPClient(t, ca, nil)
	clientCert := loadClientCert(t, cert, key)
	clientWithAuth := newHTTPClient(t, ca, clientCert)

	// Health check should work without client cert (TLS only, not mTLS)
	resp, body := doGet(t, clientNoAuth, "https://"+healthAddr+"/")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "OK" {
		t.Errorf("Health check failed: %d %q", resp.StatusCode, body)
	}

	// Main endpoint should fail without client cert
	_, _, err := tryGet(clientNoAuth, "https://"+mainAddr+"/test")
	if err == nil {
		t.Error("Expected handshake error on main endpoint without client cert, but request succeeded")
	}

	// Main endpoint should work with client cert
	resp, body = doGet(t, clientWithAuth, "https://"+mainAddr+"/test")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "Hello, test!") {
		t.Errorf("Main endpoint with client cert failed: %d %q", resp.StatusCode, body)
	}
}

// Validation tests

func TestValidation_MissingTLSKey(t *testing.T) {
	certDir := t.TempDir()
	_, cert, _ := genCerts(t, certDir)

	config := Config{
		Addr:    "127.0.0.1:19999",
		TLSCert: cert,
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "both -tlsCert and -tlsKey must be provided together") {
		t.Errorf("Expected error message about missing tlsKey, got: %v", err)
	}
}

func TestValidation_MissingTLSCert(t *testing.T) {
	certDir := t.TempDir()
	_, _, key := genCerts(t, certDir)

	config := Config{
		Addr:   "127.0.0.1:19999",
		TLSKey: key,
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "both -tlsCert and -tlsKey must be provided together") {
		t.Errorf("Expected error message about missing tlsCert, got: %v", err)
	}
}

func TestValidation_InvalidMTLSMode(t *testing.T) {
	ports := getFreePorts(t, 1)

	certDir := t.TempDir()
	_, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:     ports[0],
		TLSCert:  cert,
		TLSKey:   key,
		MTLSMode: "invalid_mode",
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "invalid -mtlsMode=") {
		t.Errorf("Expected error message about invalid mtlsMode, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Allowed values:") {
		t.Errorf("Expected allowed values in error message, got: %v", err)
	}
}

func TestValidation_VerifyIfGivenWithoutClientCAs(t *testing.T) {
	certDir := t.TempDir()
	_, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:     "127.0.0.1:19999",
		TLSCert:  cert,
		TLSKey:   key,
		MTLSMode: "verify_if_given",
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "verify_if_given requires -clientCAs") {
		t.Errorf("Expected error message about missing clientCAs, got: %v", err)
	}
}

func TestValidation_RequireAndVerifyWithoutClientCAs(t *testing.T) {
	certDir := t.TempDir()
	_, cert, key := genCerts(t, certDir)

	config := Config{
		Addr:     "127.0.0.1:19999",
		TLSCert:  cert,
		TLSKey:   key,
		MTLSMode: "require_and_verify",
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "require_and_verify requires -clientCAs") {
		t.Errorf("Expected error message about missing clientCAs, got: %v", err)
	}
}

func TestValidation_NonexistentCertFile(t *testing.T) {
	config := Config{
		Addr:    "127.0.0.1:19999",
		TLSCert: "/nonexistent/cert.pem",
		TLSKey:  "/nonexistent/key.pem",
	}

	logger := log.New(io.Discard, "", 0)
	_, err := NewServer(config, logger)
	if err == nil {
		t.Error("Expected error, but server creation succeeded")
	}
	if !strings.Contains(err.Error(), "Error loading server certificate:") {
		t.Errorf("Expected error message about loading certificate, got: %v", err)
	}
}
