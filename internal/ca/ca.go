// Package ca manages Interlace's local root certificate authority and mints
// short-lived leaf certificates for each host the proxy intercepts.
//
// The root CA is generated once and stored on disk. The user installs the
// root certificate into their OS/browser trust store so that intercepted
// HTTPS connections validate cleanly. Leaf certs are generated on demand and
// cached in memory.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootCertFile = "interlace-root-ca.pem"
	rootKeyFile  = "interlace-root-ca.key.pem"
	orgName      = "Interlace Proxy"
	rootCN       = "Interlace Root CA"
)

// CA holds the root certificate/key and a cache of minted leaf certificates.
type CA struct {
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey
	rootPEM  []byte

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate loads the root CA from dir, generating and persisting a new one
// if it does not yet exist.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, rootCertFile)
	keyPath := filepath.Join(dir, rootKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		return load(certPath, keyPath)
	}
	return create(certPath, keyPath)
}

func load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("root cert PEM is invalid")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("root key PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	return &CA{
		rootCert: cert,
		rootKey:  key,
		rootPEM:  certPEM,
		cache:    make(map[string]*tls.Certificate),
	}, nil
}

func create(certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   rootCN,
			Organization: []string{orgName},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse created root cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write root cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write root key: %w", err)
	}
	return &CA{
		rootCert: cert,
		rootKey:  key,
		rootPEM:  certPEM,
		cache:    make(map[string]*tls.Certificate),
	}, nil
}

// CertForHost returns a leaf certificate valid for the given host, minting and
// caching one if necessary. host may include a port, which is stripped.
func (c *CA) CertForHost(host string) (*tls.Certificate, error) {
	host = stripPort(host)

	c.mu.RLock()
	if cert, ok := c.cache[host]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check: another goroutine may have minted it while we waited.
	if cert, ok := c.cache[host]; ok {
		return cert, nil
	}

	leaf, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	c.cache[host] = leaf
	return leaf, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{orgName},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.rootCert.Raw},
		PrivateKey:  key,
		Leaf:        mustParse(der),
	}, nil
}

// RootPEM returns the PEM-encoded root certificate for the user to install.
func (c *CA) RootPEM() []byte { return c.rootPEM }

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func mustParse(der []byte) *x509.Certificate {
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
