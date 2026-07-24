package tdxtrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestIntelSGXRootCAPool(t *testing.T) {
	pool, err := IntelSGXRootCAPool()
	if err != nil {
		t.Fatalf("IntelSGXRootCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("IntelSGXRootCAPool returned nil")
	}

	block, _ := pem.Decode(intelSGXRootCAPEM)
	if block == nil {
		t.Fatal("embedded Intel root is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse embedded Intel root: %v", err)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	if got := hex.EncodeToString(fingerprint[:]); got != IntelSGXRootCAFingerprintSHA256 {
		t.Fatalf("fingerprint = %s, want %s", got, IntelSGXRootCAFingerprintSHA256)
	}
}

func TestParseIntelSGXRootCARejectsUnexpectedCertificate(t *testing.T) {
	if _, err := parseIntelSGXRootCA([]byte("not a certificate")); err == nil {
		t.Fatal("invalid PEM should be rejected")
	}
}
