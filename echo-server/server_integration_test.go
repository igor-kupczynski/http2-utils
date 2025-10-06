//go:build integration
// +build integration

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestIntegrationPlainHTTP(t *testing.T) {
	tests := []struct {
		name       string
		withHealth bool
	}{
		{name: "main only"},
		{name: "with health", withHealth: true},
	}

	for _, tt := range tests {
		caseData := tt

		t.Run(caseData.name, func(t *testing.T) {
			cfg := Config{Addr: freePort(t)}
			if caseData.withHealth {
				cfg.HealthCheck = freePort(t)
			}

			srv, logs := startTestServer(t, cfg)

			baseURL := fmt.Sprintf("http://%s", srv.Addr())
			resp, body := doGet(t, http.DefaultClient, baseURL+"/test")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected status 200, got %d", resp.StatusCode)
			}
			if !strings.HasPrefix(body, "Hello, test!") {
				t.Fatalf("unexpected body: %q", body)
			}

			_, certBody := doGet(t, http.DefaultClient, baseURL+"/client-certs")
			if strings.TrimSpace(certBody) != "no client certificate" {
				t.Fatalf("expected 'no client certificate', got %q", certBody)
			}

			if caseData.withHealth {
				healthURL := fmt.Sprintf("http://%s", srv.HealthAddr())
				resp, body := doGet(t, http.DefaultClient, healthURL+"/")
				if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "OK" {
					t.Fatalf("expected health OK response, got %d %q", resp.StatusCode, body)
				}
			}

			if !strings.Contains(logs.String(), "mode=plain") {
				t.Fatalf("expected plain mode log, got: %s", logs.String())
			}
			if caseData.withHealth {
				if !strings.Contains(logs.String(), "Health server:") {
					t.Fatalf("expected health server log, got: %s", logs.String())
				}
				if !strings.Contains(logs.String(), "mode=plain") {
					t.Fatalf("expected health server plain mode log, got: %s", logs.String())
				}
			}
		})
	}
}

func TestIntegrationTLSAndMTLSModes(t *testing.T) {
	tests := []struct {
		name                   string
		mtlsMode               string
		withHealth             bool
		useClientCAs           bool
		expectWithoutCertOK    bool
		expectWithCertOK       bool
		expectNoClientCertLog  bool
		expectClientDetails    bool
		checkInvalidClient     bool
		expectInvalidCertError bool
		logContains            []string
	}{
		{
			name:                  "tls",
			expectWithoutCertOK:   true,
			expectWithCertOK:      true,
			expectNoClientCertLog: true,
			logContains:           []string{"mode=tls"},
		},
		{
			name:                  "tls with health",
			withHealth:            true,
			expectWithoutCertOK:   true,
			expectWithCertOK:      true,
			expectNoClientCertLog: true,
			logContains:           []string{"mode=tls"},
		},
		{
			name:                  "mtls request",
			mtlsMode:              "request",
			expectWithoutCertOK:   true,
			expectWithCertOK:      true,
			expectClientDetails:   true,
			expectNoClientCertLog: true,
			logContains:           []string{"mode=mtls", "mtlsMode=request"},
		},
		{
			name:                   "mtls verify_if_given",
			mtlsMode:               "verify_if_given",
			useClientCAs:           true,
			expectWithoutCertOK:    true,
			expectWithCertOK:       true,
			expectClientDetails:    true,
			expectNoClientCertLog:  true,
			checkInvalidClient:     true,
			expectInvalidCertError: true,
			logContains:            []string{"mode=mtls", "mtlsMode=verify_if_given", "caCount=1"},
		},
		{
			name:                   "mtls require_any",
			mtlsMode:               "require_any",
			expectWithCertOK:       true,
			expectClientDetails:    true,
			checkInvalidClient:     true,
			expectInvalidCertError: false,
			logContains:            []string{"mode=mtls", "mtlsMode=require_any"},
		},
		{
			name:                   "mtls require_and_verify",
			mtlsMode:               "require_and_verify",
			useClientCAs:           true,
			expectWithCertOK:       true,
			expectClientDetails:    true,
			checkInvalidClient:     true,
			expectInvalidCertError: true,
			logContains:            []string{"mode=mtls", "mtlsMode=require_and_verify", "caCount=1"},
		},
		{
			name:                   "mtls require_and_verify with health",
			mtlsMode:               "require_and_verify",
			useClientCAs:           true,
			withHealth:             true,
			expectWithCertOK:       true,
			expectClientDetails:    true,
			checkInvalidClient:     true,
			expectInvalidCertError: true,
			logContains:            []string{"mode=mtls", "mtlsMode=require_and_verify", "caCount=1"},
		},
	}

	for _, tt := range tests {
		caseData := tt

		t.Run(caseData.name, func(t *testing.T) {
			certs := newTestCertificates(t)

			cfg := Config{
				Addr:    freePort(t),
				TLSCert: certs.ServerCertPath(),
				TLSKey:  certs.ServerKeyPath(),
			}
			if caseData.withHealth {
				cfg.HealthCheck = freePort(t)
			}
			if caseData.mtlsMode != "" {
				cfg.MTLSMode = caseData.mtlsMode
				if caseData.useClientCAs {
					cfg.ClientCAs = certs.CAPath()
				}
			}

			srv, logs := startTestServer(t, cfg)

			baseURL := fmt.Sprintf("https://%s", srv.Addr())
			clientNoCert := newTestHTTPClient(t, certs.CAPath(), nil)
			clientWithCert := newTestHTTPClient(t, certs.CAPath(), certs.ClientCert())
			clientInvalid := newTestHTTPClient(t, certs.CAPath(), certs.InvalidClientCert())

			if caseData.expectWithoutCertOK {
				resp, body := doGet(t, clientNoCert, baseURL+"/test")
				if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "Hello, test!") {
					t.Fatalf("request without client cert failed: %d %q", resp.StatusCode, body)
				}
				if caseData.expectNoClientCertLog {
					_, certBody := doGet(t, clientNoCert, baseURL+"/client-certs")
					if strings.TrimSpace(certBody) != "no client certificate" {
						t.Fatalf("expected 'no client certificate', got %q", certBody)
					}
				}
			} else {
				if _, _, err := tryGet(clientNoCert, baseURL+"/test"); err == nil {
					t.Fatalf("expected handshake error without client certificate")
				}
			}

			if caseData.expectWithCertOK {
				resp, body := doGet(t, clientWithCert, baseURL+"/test")
				if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "Hello, test!") {
					t.Fatalf("request with client cert failed: %d %q", resp.StatusCode, body)
				}

				_, certBody := doGet(t, clientWithCert, baseURL+"/client-certs")
				if caseData.expectClientDetails {
					if !strings.Contains(certBody, "subject_cn:") || !strings.Contains(certBody, "issuer_cn:") {
						t.Fatalf("expected certificate details, got: %q", certBody)
					}
					if !strings.Contains(certBody, "serial:") || !strings.Contains(certBody, "not_before:") || !strings.Contains(certBody, "not_after:") {
						t.Fatalf("expected validity details, got: %q", certBody)
					}
				} else {
					if strings.TrimSpace(certBody) != "no client certificate" {
						t.Fatalf("expected 'no client certificate', got %q", certBody)
					}
				}
			} else {
				if _, _, err := tryGet(clientWithCert, baseURL+"/test"); err == nil {
					t.Fatalf("expected handshake error even with valid client certificate")
				}
			}

			if caseData.checkInvalidClient {
				if caseData.expectInvalidCertError {
					if _, _, err := tryGet(clientInvalid, baseURL+"/test"); err == nil {
						t.Fatalf("expected handshake error with invalid client cert")
					}
				} else {
					resp, body := doGet(t, clientInvalid, baseURL+"/test")
					if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "Hello, test!") {
						t.Fatalf("request with invalid client cert failed unexpectedly: %d %q", resp.StatusCode, body)
					}
				}
			}

			if caseData.withHealth {
				healthURL := fmt.Sprintf("https://%s", srv.HealthAddr())
				resp, body := doGet(t, clientNoCert, healthURL+"/")
				if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "OK" {
					t.Fatalf("expected health OK response, got %d %q", resp.StatusCode, body)
				}
			}

			for _, want := range caseData.logContains {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("expected log containing %q, got: %s", want, logs.String())
				}
			}
			if caseData.withHealth {
				if !strings.Contains(logs.String(), "Health server:") || !strings.Contains(logs.String(), "mode=tls") {
					t.Fatalf("expected TLS health server log, got: %s", logs.String())
				}
			}
		})
	}
}
