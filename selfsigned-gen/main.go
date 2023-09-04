package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var domains = flag.String("domains", "https://example.local", "domains to create the certificate for")

func main() {
	flag.Parse()
	hosts := strings.Split(*domains, ",")

	caTemplate, caCert, caKey, err := generateCA()
	if err != nil {
		log.Fatal(err)
	}

	cert, key, err := generateCertForDomain(caTemplate, caKey, hosts)
	if err != nil {
		log.Fatal(err)
	}

	if err := writeCert("ca.pem", caCert); err != nil {
		log.Fatal(err)
	}
	if err := writeKey("ca.key", caKey); err != nil {
		log.Fatal(err)
	}
	if err := writeCert("domain.pem", cert); err != nil {
		log.Fatal(err)
	}
	if err := writeKey("domain.key", key); err != nil {
		log.Fatal(err)
	}
}

func generateCA() (template *x509.Certificate, cert []byte, key *rsa.PrivateKey, err error) {
	template = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Example, Inc."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	key, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

func generateCertForDomain(caTemplate *x509.Certificate, caKey *rsa.PrivateKey, hosts []string) (cert []byte, key *rsa.PrivateKey, err error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Example, Inc."},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	gotCN := false
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			if !gotCN {
				template.Subject.CommonName = h
				gotCN = true
			}
		}
	}

	key, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, caTemplate, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	return
}

func writeCert(fname string, cert []byte) error {
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Error closing %s: %s", fname, err)
	}
	return nil
}

func writeKey(fname string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Error closing %s: %s", fname, err)
	}
	return nil
}
