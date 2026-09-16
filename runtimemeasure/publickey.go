package runtimemeasure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParsePublicKeyPEM accepts exactly one headerless PEM PUBLIC KEY containing an
// ECDSA P-256 key, allowing only whitespace around it. Parsing never rewrites
// the input: launch bindings hash the caller's exact bytes, including whitespace.
func ParsePublicKeyPEM(key []byte) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("want one PEM PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("want an ECDSA P-256 key")
	}
	return ec, nil
}
