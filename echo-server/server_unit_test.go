package main

import (
	"crypto/tls"
	"io"
	"log"
	"strings"
	"testing"
)

func TestNewServerValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		substring string
	}{
		{
			name: "missing tls key",
			config: Config{
				Addr:    "127.0.0.1:0",
				TLSCert: "cert.pem",
			},
			substring: "both -tlsCert and -tlsKey must be provided together",
		},
		{
			name: "missing tls cert",
			config: Config{
				Addr:   "127.0.0.1:0",
				TLSKey: "key.pem",
			},
			substring: "both -tlsCert and -tlsKey must be provided together",
		},
		{
			name: "mtls requires tls",
			config: Config{
				Addr:     "127.0.0.1:0",
				MTLSMode: "request",
			},
			substring: "-mtlsMode requires -tlsCert and -tlsKey",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			logr := log.New(io.Discard, "", 0)
			_, err := NewServer(tc.config, logr)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.substring)
			}
			if !strings.Contains(err.Error(), tc.substring) {
				t.Fatalf("expected error containing %q, got %q", tc.substring, err.Error())
			}
		})
	}
}

func TestNewServerValidationRequiresClientCAs(t *testing.T) {
	certs := newTestCertificates(t)
	logr := log.New(io.Discard, "", 0)

	_, err := NewServer(Config{
		Addr:     "127.0.0.1:0",
		TLSCert:  certs.ServerCertPath(),
		TLSKey:   certs.ServerKeyPath(),
		MTLSMode: "verify_if_given",
	}, logr)
	if err == nil {
		t.Fatalf("expected error about missing client CAs")
	}
	if !strings.Contains(err.Error(), "verify_if_given requires -clientCAs") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = NewServer(Config{
		Addr:     "127.0.0.1:0",
		TLSCert:  certs.ServerCertPath(),
		TLSKey:   certs.ServerKeyPath(),
		MTLSMode: "require_and_verify",
	}, logr)
	if err == nil {
		t.Fatalf("expected error about missing client CAs")
	}
	if !strings.Contains(err.Error(), "require_and_verify requires -clientCAs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewServerTLSConfigIncludesHTTP2(t *testing.T) {
	certs := newTestCertificates(t)
	logr := log.New(io.Discard, "", 0)

	srv, err := NewServer(Config{
		Addr:    "127.0.0.1:0",
		TLSCert: certs.ServerCertPath(),
		TLSKey:  certs.ServerKeyPath(),
	}, logr)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if srv.mainServer.TLSConfig == nil {
		t.Fatal("expected TLS config to be set")
	}

	if !containsString(srv.mainServer.TLSConfig.NextProtos, "h2") {
		t.Fatalf("expected NextProtos to include h2, got %v", srv.mainServer.TLSConfig.NextProtos)
	}
}

func TestNewServerMTLSConfig(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		requiresCA   bool
		expectedAuth tls.ClientAuthType
	}{
		{
			name:         "request",
			mode:         "request",
			requiresCA:   false,
			expectedAuth: tls.RequestClientCert,
		},
		{
			name:         "verify_if_given",
			mode:         "verify_if_given",
			requiresCA:   true,
			expectedAuth: tls.VerifyClientCertIfGiven,
		},
		{
			name:         "require_any",
			mode:         "require_any",
			requiresCA:   false,
			expectedAuth: tls.RequireAnyClientCert,
		},
		{
			name:         "require_and_verify",
			mode:         "require_and_verify",
			requiresCA:   true,
			expectedAuth: tls.RequireAndVerifyClientCert,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			certs := newTestCertificates(t)
			logr := log.New(io.Discard, "", 0)

			cfg := Config{
				Addr:     "127.0.0.1:0",
				TLSCert:  certs.ServerCertPath(),
				TLSKey:   certs.ServerKeyPath(),
				MTLSMode: tc.mode,
			}
			if tc.requiresCA {
				cfg.ClientCAs = certs.CAPath()
			}

			srv, err := NewServer(cfg, logr)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}

			if srv.mainServer.TLSConfig == nil {
				t.Fatalf("expected TLS config to be set")
			}

			if srv.mainServer.TLSConfig.ClientAuth != tc.expectedAuth {
				t.Fatalf("expected ClientAuth %v, got %v", tc.expectedAuth, srv.mainServer.TLSConfig.ClientAuth)
			}

			if tc.requiresCA {
				if srv.mainServer.TLSConfig.ClientCAs == nil {
					t.Fatal("expected ClientCAs to be configured")
				}
			} else {
				if srv.mainServer.TLSConfig.ClientCAs != nil {
					t.Fatal("expected ClientCAs to be nil")
				}
			}
		})
	}
}

func TestNewServerHealthCheckNeverUsesMTLS(t *testing.T) {
	certs := newTestCertificates(t)
	logr := log.New(io.Discard, "", 0)

	srv, err := NewServer(Config{
		Addr:        "127.0.0.1:0",
		HealthCheck: "127.0.0.1:0",
		TLSCert:     certs.ServerCertPath(),
		TLSKey:      certs.ServerKeyPath(),
		MTLSMode:    "require_and_verify",
		ClientCAs:   certs.CAPath(),
	}, logr)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if srv.healthServer == nil {
		t.Fatal("expected health server to be configured")
	}

	if srv.healthServer.TLSConfig == nil {
		t.Fatal("expected health server to use TLS")
	}

	if srv.healthServer.TLSConfig.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected health server ClientAuth to be NoClientCert, got %v", srv.healthServer.TLSConfig.ClientAuth)
	}
}
