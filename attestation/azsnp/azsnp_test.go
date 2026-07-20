package azsnp

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

//go:embed testdata/attestation.json
var attestationFixture []byte

// TestDecode_AKPub decodes the real recorded az-snp fixture and checks the HCL
// var_data carries a well-formed RSA-2048 vTPM AK.
func TestDecode_AKPub(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(attestationFixture, &env); err != nil {
		t.Fatal(err)
	}
	var ev azSnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	d, err := decode(ev)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(d.hcl.VarData) == 0 || d.quote == nil {
		t.Fatal("expected var_data + tpm_quote to be surfaced")
	}
	pub, err := tpmcommon.ExtractAKPub(d.hcl.VarData)
	if err != nil || len(pub.N.Bytes()) != 256 || pub.E != 65537 {
		t.Fatalf("AK pub: %v (N=%d E=%d)", err, len(pub.N.Bytes()), pub.E)
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
	res, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{}, snp.Options{})
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
	if _, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedReportData: make([]byte, 32)}, snp.Options{}); err == nil {
		t.Fatal("fresh nonce must be rejected on recorded evidence")
	}
}

// TestVerifyEvidence_LaunchDigestForwarded proves ExpectedLaunchDigest is
// forwarded into the SNP hardware layer on the Azure path: the report's own
// MEASUREMENT verifies and sets LaunchDigestMatch, and a wrong digest fails
// closed. Guards the hwParams-forwarding fix (a dropped forward would make the
// wrong-digest case pass).
func TestVerifyEvidence_LaunchDigestForwarded(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(attestationFixture, &env); err != nil {
		t.Fatal(err)
	}

	base, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{}, snp.Options{})
	if err != nil {
		t.Fatalf("baseline VerifyEvidence: %v", err)
	}
	md, err := hex.DecodeString(base.Claims.LaunchDigest)
	if err != nil {
		t.Fatalf("decoding launch digest: %v", err)
	}

	res, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedLaunchDigest: md}, snp.Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence with launch digest: %v", err)
	}
	if res.LaunchDigestMatch == nil || !*res.LaunchDigestMatch {
		t.Errorf("LaunchDigestMatch = %v, want true", res.LaunchDigestMatch)
	}

	wrong := append([]byte(nil), md...)
	wrong[0] ^= 0xFF
	if _, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedLaunchDigest: wrong}, snp.Options{}); err == nil {
		t.Fatal("wrong launch digest must be rejected on the az-snp path")
	}
}

func TestVerifyEvidence_Errors(t *testing.T) {
	if _, err := VerifyEvidence([]byte("not json"), teetypes.VerifyParams{}, snp.Options{}); err == nil {
		t.Fatal("garbage should fail")
	}
	if _, err := VerifyEvidence([]byte(`{"version":99}`), teetypes.VerifyParams{}, snp.Options{}); err == nil {
		t.Fatal("unsupported evidence version should fail")
	}
}
