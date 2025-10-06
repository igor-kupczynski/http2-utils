package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCertificates struct {
	dir                   string
	caPath                string
	serverCertPath        string
	serverKeyPath         string
	clientCertPath        string
	clientKeyPath         string
	invalidClientCertPath string
	invalidClientKeyPath  string
	clientCertificate     tls.Certificate
	invalidClientCert     tls.Certificate
}

func newTestCertificates(t *testing.T) *testCertificates {
	t.Helper()

	dir := t.TempDir()

	caCert, caKey := newTestCA(t, "Test CA")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caPath := filepath.Join(dir, "ca.pem")
	mustWriteFile(t, caPath, caPEM)

	serverKey, serverCert := issueServerCert(t, caCert, caKey)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	serverKeyPEM := encodeECPrivateKey(t, serverKey)
	serverCertPath := filepath.Join(dir, "server.pem")
	serverKeyPath := filepath.Join(dir, "server.key")
	mustWriteFile(t, serverCertPath, serverCertPEM)
	mustWriteFile(t, serverKeyPath, serverKeyPEM)

	clientKey, clientCert := issueClientCert(t, caCert, caKey, "Test Client")
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	clientKeyPEM := encodeECPrivateKey(t, clientKey)
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")
	mustWriteFile(t, clientCertPath, clientCertPEM)
	mustWriteFile(t, clientKeyPath, clientKeyPEM)
	clientTLSCert := mustLoadKeyPair(t, clientCertPath, clientKeyPath)

	invalidNotBefore := time.Now().Add(-48 * time.Hour)
	invalidNotAfter := time.Now().Add(-24 * time.Hour)
	invalidKey, invalidCert := issueClientCertWithValidity(t, caCert, caKey, "Expired Client", invalidNotBefore, invalidNotAfter)
	invalidCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: invalidCert.Raw})
	invalidKeyPEM := encodeECPrivateKey(t, invalidKey)
	invalidClientCertPath := filepath.Join(dir, "invalid-client.pem")
	invalidClientKeyPath := filepath.Join(dir, "invalid-client.key")
	mustWriteFile(t, invalidClientCertPath, invalidCertPEM)
	mustWriteFile(t, invalidClientKeyPath, invalidKeyPEM)
	invalidTLSCert := mustLoadKeyPair(t, invalidClientCertPath, invalidClientKeyPath)

	return &testCertificates{
		dir:                   dir,
		caPath:                caPath,
		serverCertPath:        serverCertPath,
		serverKeyPath:         serverKeyPath,
		clientCertPath:        clientCertPath,
		clientKeyPath:         clientKeyPath,
		invalidClientCertPath: invalidClientCertPath,
		invalidClientKeyPath:  invalidClientKeyPath,
		clientCertificate:     clientTLSCert,
		invalidClientCert:     invalidTLSCert,
	}
}

func (c *testCertificates) CAPath() string {
	return c.caPath
}

func (c *testCertificates) ServerCertPath() string {
	return c.serverCertPath
}

func (c *testCertificates) ServerKeyPath() string {
	return c.serverKeyPath
}

func (c *testCertificates) ClientCert() *tls.Certificate {
	return &c.clientCertificate
}

func (c *testCertificates) ClientCertPath() string {
	return c.clientCertPath
}

func (c *testCertificates) ClientKeyPath() string {
	return c.clientKeyPath
}

func (c *testCertificates) InvalidClientCert() *tls.Certificate {
	return &c.invalidClientCert
}

func (c *testCertificates) InvalidClientCertPath() string {
	return c.invalidClientCertPath
}

func (c *testCertificates) InvalidClientKeyPath() string {
	return c.invalidClientKeyPath
}

func newTestCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	serial := randomSerialNumber(t)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return cert, key
}

func issueServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serial := randomSerialNumber(t)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}

	return key, cert
}

func issueClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	return issueClientCertWithValidity(t, ca, caKey, commonName, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

func issueClientCertWithValidity(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, notBefore, notAfter time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	serial := randomSerialNumber(t)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	return key, cert
}

func encodeECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write file %s: %v", path, err)
	}
}

func mustLoadKeyPair(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to load key pair %s/%s: %v", certPath, keyPath, err)
	}
	return cert
}

func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}
	return serial
}

func newTestHTTPClient(t *testing.T, caPath string, clientCert *tls.Certificate) *http.Client {
	t.Helper()
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		t.Fatal("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{RootCAs: caPool}
	if clientCert != nil {
		// Copy to avoid sharing mutable state between tests.
		dup := tls.Certificate{
			Certificate: append([][]byte(nil), clientCert.Certificate...),
			PrivateKey:  clientCert.PrivateKey,
			Leaf:        clientCert.Leaf,
		}
		tlsConfig.Certificates = []tls.Certificate{dup}
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func startTestServer(t *testing.T, config Config) (*Server, *strings.Builder) {
	t.Helper()

	var logBuf strings.Builder
	logger := log.New(&logBuf, "", log.LstdFlags)

	srv, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	errCh := make(chan error, 1)

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			errCh <- err
		}
	}()

	waitForAddress(t, config.Addr, 3*time.Second)
	if config.HealthCheck != "" {
		waitForAddress(t, config.HealthCheck, 3*time.Second)
	}

	select {
	case err := <-errCh:
		if err != http.ErrServerClosed {
			t.Fatalf("server failed to start: %v", err)
		}
	default:
	}

	t.Cleanup(func() {
		_ = srv.Shutdown()
		select {
		case err := <-errCh:
			if err != http.ErrServerClosed {
				t.Fatalf("server returned error: %v", err)
			}
		case <-time.After(500 * time.Millisecond):
		}
	})

	return srv, &logBuf
}

func waitForAddress(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s within %v", addr, timeout)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("failed to release port %s: %v", addr, err)
	}
	return addr
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
		t.Fatalf("failed to read response body: %v", err)
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
