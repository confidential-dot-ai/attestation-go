package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// fakeSNPReport builds a structurally valid but unsigned 1184-byte SEV-SNP
// report with reportData at REPORTDATA's offset. Field offsets are from the AMD
// SEV-SNP ABI Specification, table 21.
func fakeSNPReport(reportData [64]byte) []byte {
	report := make([]byte, SNPReportSize)
	report[0] = 0x02                                  // VERSION, >= 2 for SNP
	report[0x0A] = 0x03                               // POLICY: SMT allowed + reserved bit
	copy(report[snpReportDataOffset:], reportData[:]) // REPORTDATA, 64 bytes at 0x50
	for i := range 48 {
		report[0x90+i] = byte(i) // MEASUREMENT, deterministic
	}
	return report
}

// fakeHCLEnvelope wraps report in the Hyper-V HCL envelope an Azure vTPM
// returns: header(32) + report + var-data header(20) + var data, with trailing
// padding after the var data.
func fakeHCLEnvelope(report []byte, trailing int) []byte {
	varData := []byte(`{"keys":[]}`)
	env := make([]byte, 32+len(report)+20+len(varData)+trailing)
	copy(env[:4], "HCLA")
	binary.LittleEndian.PutUint32(env[4:8], 1)
	copy(env[32:], report)
	hdr := env[32+len(report):]
	binary.LittleEndian.PutUint32(hdr[8:12], tpmcommon.HCLReportTypeSNP)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(varData)+trailing))
	copy(hdr[20:], varData)
	return env
}

// marshalASN1 encodes an extension body directly, so a test can build shapes
// [Attestation.MarshalExtension] would refuse to produce.
func marshalASN1(t *testing.T, v attestationASN1) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshal attestationASN1: %v", err)
	}
	return der
}

// testKey returns a fresh P-256 key.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// certWithExtension self-signs a certificate carrying the RA-TLS extension for
// att, and returns it with the key it binds.
// testOID is the extension identifier the tests embed under; the package claims
// none of its own.
var testOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}

func certWithExtension(t *testing.T, att *Attestation) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if att != nil {
		ext, err := att.MarshalExtension(testOID)
		if err != nil {
			t.Fatalf("MarshalExtension: %v", err)
		}
		template.ExtraExtensions = []pkix.Extension{ext}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}
