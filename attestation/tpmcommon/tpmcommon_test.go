package tpmcommon

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

//go:embed testdata/hcl-report.bin
var hclReportFixture []byte

func buildTPMSAttest(nonce, pcrSelect, pcrDigest []byte) []byte {
	var msg []byte
	msg = append(msg, 0xFF, 0x54, 0x43, 0x47) // magic
	msg = append(msg, 0x80, 0x18)             // type TPM_ST_ATTEST_QUOTE
	msg = append(msg, 0x00, 0x00)             // qualifiedSigner size 0
	var nlen [2]byte
	binary.BigEndian.PutUint16(nlen[:], uint16(len(nonce)))
	msg = append(msg, nlen[:]...)
	msg = append(msg, nonce...)
	msg = append(msg, make([]byte, 17)...)    // clockInfo
	msg = append(msg, make([]byte, 8)...)     // firmwareVersion
	msg = append(msg, 0x00, 0x00, 0x00, 0x01) // TPML_PCR_SELECTION count = 1
	msg = append(msg, 0x00, 0x0B)             // hashAlg SHA-256
	msg = append(msg, pcrSelect...)
	var dlen [2]byte
	binary.BigEndian.PutUint16(dlen[:], uint16(len(pcrDigest)))
	msg = append(msg, dlen[:]...)
	msg = append(msg, pcrDigest...)
	return msg
}

func jwkVarData(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	doc := map[string]any{"keys": []any{map[string]any{
		"kid": "HCLAkPub", "kty": "RSA",
		"e": base64.RawURLEncoding.EncodeToString(eBytes[i:]),
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signTPM(t *testing.T, key *rsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func zeroPCRs() [][]byte {
	p := make([][]byte, 24)
	for i := range p {
		p[i] = make([]byte, 32)
	}
	return p
}

func TestVerifyTPMSignatureAndNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	varData := jwkVarData(t, &key.PublicKey)
	nonce := []byte("hello world test nonce")
	msg := buildTPMSAttest(nonce, []byte{3, 0xFF, 0xFF, 0xFF}, make([]byte, 32))
	sig := signTPM(t, key, msg)

	if err := VerifyTPMSignature(sig, msg, varData); err != nil {
		t.Fatalf("signature should verify: %v", err)
	}
	if err := VerifyTPMNonce(msg, nonce); err != nil {
		t.Fatalf("nonce should match: %v", err)
	}
	if err := VerifyTPMNonce(msg, []byte("different nonce value!")); err == nil {
		t.Fatal("wrong nonce should fail")
	}
	// Tampered message breaks the signature.
	bad := append([]byte(nil), msg...)
	bad[6] ^= 0xFF
	if err := VerifyTPMSignature(sig, bad, varData); err == nil {
		t.Fatal("tampered message should fail signature")
	}
}

func TestVerifyTPMPCRs(t *testing.T) {
	pcrs := zeroPCRs()
	var concat []byte
	for i := 0; i < 8; i++ {
		concat = append(concat, pcrs[i]...)
	}
	good := sha256.Sum256(concat)
	if err := VerifyTPMPCRs(buildTPMSAttest(make([]byte, 32), []byte{3, 0xFF, 0x00, 0x00}, good[:]), pcrs); err != nil {
		t.Fatalf("valid PCR digest should verify: %v", err)
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0xAA
	}
	if err := VerifyTPMPCRs(buildTPMSAttest(make([]byte, 32), []byte{3, 0xFF, 0x00, 0x00}, wrong), pcrs); err == nil {
		t.Fatal("wrong PCR digest should fail")
	}
}

func TestCheckReportDataAndInitData(t *testing.T) {
	nonce := []byte("nonce-value")
	msg := buildTPMSAttest(nonce, []byte{3, 0xFF, 0xFF, 0xFF}, make([]byte, 32))
	if m, err := CheckReportData(msg, nil); err != nil || m != nil {
		t.Fatalf("nil expected → nil match, no error; got %v %v", m, err)
	}
	if m, err := CheckReportData(msg, nonce); err != nil || m == nil || !*m {
		t.Fatalf("matching nonce → true; got %v %v", m, err)
	}
	// PCR[8] init-data extend.
	pcrs := zeroPCRs()
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = 0xAB
	}
	h := sha256.New()
	h.Write(make([]byte, 32))
	h.Write(hash)
	pcrs[8] = h.Sum(nil)
	if m, err := CheckInitData(pcrs, hash); err != nil || m == nil || !*m {
		t.Fatalf("init-data extend should match: %v %v", m, err)
	}
	if _, err := CheckInitData(pcrs, make([]byte, 32)); err == nil {
		t.Fatal("wrong init-data should fail")
	}
}

func TestExtractAKPub_TPM2BPublic(t *testing.T) {
	modulus := make([]byte, 256)
	for i := range modulus {
		modulus[i] = 0xAB
	}
	var c []byte
	c = append(c, 0x00, 0x01, 0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x00, 0x10, 0x00, 0x10, 0x08, 0x00, 0, 0, 0, 0)
	var ml [2]byte
	binary.BigEndian.PutUint16(ml[:], uint16(len(modulus)))
	c = append(c, ml[:]...)
	c = append(c, modulus...)
	var sz [2]byte
	binary.BigEndian.PutUint16(sz[:], uint16(len(c)))
	varData := append(sz[:], c...)
	pub, err := ExtractAKPub(varData)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if pub.E != 65537 || len(pub.N.Bytes()) != 256 {
		t.Fatalf("unexpected key E=%d N=%d", pub.E, len(pub.N.Bytes()))
	}
}

// TestParseHCLReport_Fixture exercises the HCL parser + AK extraction + var_data
// binding against the real CoCo az-snp HCL report fixture.
func TestParseHCLReport_Fixture(t *testing.T) {
	hcl, err := ParseHCLReport(hclReportFixture)
	if err != nil {
		t.Fatalf("ParseHCLReport: %v", err)
	}
	if hcl.ReportType != HCLReportTypeSNP {
		t.Fatalf("report_type = %d, want %d (SNP)", hcl.ReportType, HCLReportTypeSNP)
	}
	if len(hcl.TEEReport) != 1184 {
		t.Fatalf("tee_report = %d bytes, want 1184", len(hcl.TEEReport))
	}
	pub, err := ExtractAKPub(hcl.VarData)
	if err != nil {
		t.Fatalf("ExtractAKPub: %v", err)
	}
	if len(pub.N.Bytes()) != 256 {
		t.Fatalf("AK modulus = %d bytes, want 256", len(pub.N.Bytes()))
	}
	// report_data lives at offset 0x50 of the SNP report and binds SHA-256(var_data).
	reportData := hcl.TEEReport[0x50 : 0x50+64]
	if err := VerifyHCLVarDataBinding(reportData, hcl.VarData); err != nil {
		t.Fatalf("var_data binding should hold on real evidence: %v", err)
	}
}
