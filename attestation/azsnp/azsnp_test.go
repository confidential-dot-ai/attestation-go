package azsnp

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

//go:embed testdata/attestation.json
var attestationFixture []byte

// TestVerify_Fixture verifies a real recorded az-snp envelope through the
// back-compat API (hardware verify) and the vTPM components.
func TestVerify_Fixture(t *testing.T) {
	res, err := Verify(attestationFixture)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Measurement == "" || len(res.ReportData) != 64 {
		t.Fatalf("unexpected result: measurement=%q reportData=%d", res.Measurement, len(res.ReportData))
	}
	if len(res.VarData) == 0 || res.TPMQuote == nil {
		t.Fatal("expected var_data + tpm_quote to be surfaced")
	}

	// vTPM components verify against real evidence.
	if err := tpmcommon.VerifyHCLVarDataBinding(res.ReportData, res.VarData); err != nil {
		t.Fatalf("var_data binding: %v", err)
	}
	if err := tpmcommon.VerifyTPMSignature(res.TPMQuote.Signature, res.TPMQuote.Message, res.VarData); err != nil {
		t.Fatalf("AK signature: %v", err)
	}
	pub, err := tpmcommon.ExtractAKPub(res.VarData)
	if err != nil || len(pub.N.Bytes()) != 256 || pub.E != 65537 {
		t.Fatalf("AK pub: %v (N=%d E=%d)", err, len(pub.N.Bytes()), pub.E)
	}

	// Recorded evidence has empty qualifyingData → a fresh nonce fails closed.
	if err := res.VerifyVTPMFreshness(make([]byte, 32)); err == nil {
		t.Fatal("recorded evidence must fail freshness against a fresh nonce")
	}
}

// TestVerifyEvidence_FailClosed runs the hardened unified path on the inner
// evidence and confirms a fresh nonce is rejected (recorded quote isn't bound).
func TestVerifyEvidence_FailClosed(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(attestationFixture, &env); err != nil {
		t.Fatal(err)
	}

	// No nonce: hardware + vTPM-AK chain verify; result carries az-snp claims.
	res, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{})
	if err != nil {
		t.Fatalf("VerifyEvidence (no nonce): %v", err)
	}
	if res.Platform != teetypes.PlatformAzSNP || res.Claims.LaunchDigest == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Claims.PlatformData["tpm"] == nil {
		t.Fatal("expected tpm claims to be overlaid")
	}

	// Fresh nonce: recorded quote isn't bound to it → fail closed.
	if _, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedReportData: make([]byte, 32)}); err == nil {
		t.Fatal("fresh nonce must be rejected on recorded evidence")
	}
}

func TestVerify_Errors(t *testing.T) {
	if err := VerifyAttestation([]byte("not json")); err == nil {
		t.Fatal("garbage should fail")
	}
	if err := VerifyAttestation([]byte(`{"platform":"snp","evidence":{}}`)); err == nil {
		t.Fatal("wrong platform should fail")
	}
}
