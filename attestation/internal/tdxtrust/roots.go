// Package tdxtrust owns the explicit root of trust used by the TDX
// verifiers. Keeping it here lets both the legacy GCE entry point and the
// evidence-envelope API pass a non-nil root pool to go-tdx-guest.
package tdxtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

const (
	// IntelSGXRootCAFingerprintSHA256 is SHA-256 over the certificate's DER.
	// Intel PCS publishes this root in the SGX-Enclave-Identity-Issuer-Chain
	// response header:
	// https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity
	IntelSGXRootCAFingerprintSHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
)

//go:embed intel_sgx_root_ca.pem
var intelSGXRootCAPEM []byte

var (
	intelSGXRootPool, intelSGXRootPoolErr = parseIntelSGXRootCA(intelSGXRootCAPEM)
)

// IntelSGXRootCAPool returns the certificate pool explicitly pinned by this
// module. Each call returns a clone so callers cannot mutate the pinned pool.
func IntelSGXRootCAPool() (*x509.CertPool, error) {
	if intelSGXRootPoolErr != nil {
		return nil, intelSGXRootPoolErr
	}
	return intelSGXRootPool.Clone(), nil
}

func parseIntelSGXRootCA(certPEM []byte) (*x509.CertPool, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("embedded Intel SGX root is not a PEM CERTIFICATE")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("embedded Intel SGX root contains trailing PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded Intel SGX root: %w", err)
	}
	if cert.Subject.CommonName != "Intel SGX Root CA" || !cert.IsCA {
		return nil, fmt.Errorf(
			"embedded Intel SGX root has unexpected identity: CN=%q IsCA=%t",
			cert.Subject.CommonName, cert.IsCA,
		)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("embedded Intel SGX root is not self-signed: %w", err)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	if got := hex.EncodeToString(fingerprint[:]); got != IntelSGXRootCAFingerprintSHA256 {
		return nil, fmt.Errorf(
			"embedded Intel SGX root fingerprint = %s, want %s",
			got, IntelSGXRootCAFingerprintSHA256,
		)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}
