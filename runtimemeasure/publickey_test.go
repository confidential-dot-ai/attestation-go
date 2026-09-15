package runtimemeasure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func publicKeyPEM(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestParsePublicKeyPEMRequiresOneP256Key(t *testing.T) {
	valid := publicKeyPEM(t, elliptic.P256())
	withSpace := append(bytes.Clone(valid), '\n')
	if _, err := ParsePublicKeyPEM(withSpace); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withSpace, append(bytes.Clone(valid), '\n')) {
		t.Fatal("parsing changed the anchor bytes")
	}
	block, _ := pem.Decode(valid)
	headered := *block
	headered.Headers = map[string]string{"extra": "ignored"}
	for name, key := range map[string][]byte{
		"empty": {}, "garbage": []byte("not a key"),
		"wrong curve":    publicKeyPEM(t, elliptic.P384()),
		"multiple keys":  append(bytes.Clone(valid), valid...),
		"prefix garbage": append([]byte("garbage\n"), valid...),
		"suffix garbage": append(bytes.Clone(valid), []byte("garbage")...),
		"headers":        pem.EncodeToMemory(&headered),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"bad DER":        pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKeyPEM(key); err == nil {
				t.Fatal("accepted malformed key")
			}
		})
	}
}
