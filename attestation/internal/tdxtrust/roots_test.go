package tdxtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
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

func selfSignedCAPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseIntelSGXRootCARejections(t *testing.T) {
	wrongIdentity := selfSignedCAPEM(t, "Not Intel SGX Root CA")
	wrongKey := selfSignedCAPEM(t, "Intel SGX Root CA")

	cases := []struct {
		name    string
		certPEM []byte
		wantErr string
	}{
		{"not PEM", []byte("not a certificate"), "not a PEM CERTIFICATE"},
		{"trailing PEM data", append(append([]byte{}, intelSGXRootCAPEM...), wrongIdentity...), "trailing PEM data"},
		{"unexpected identity", wrongIdentity, "unexpected identity"},
		{"fingerprint mismatch", wrongKey, "fingerprint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseIntelSGXRootCA(tc.certPEM)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
