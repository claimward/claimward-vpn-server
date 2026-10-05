package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// With a certificate the RouteService is TLS; without, it is not, and says so.
func TestTheRouteServiceIsTLSWhenTheServerHasACertificate(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn.example.org"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"vpn.example.org"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)

	opts, secure, err := grpcOptions(certFile, keyFile)
	if err != nil || !secure || len(opts) != 1 {
		t.Errorf("with a certificate: %d options, secure %v, %v", len(opts), secure, err)
	}
	if _, secure, err := grpcOptions("", ""); secure || err != nil {
		t.Errorf("without one: secure %v, %v", secure, err)
	}
	if _, _, err := grpcOptions(certFile, filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a key that is not there was taken")
	}
}
