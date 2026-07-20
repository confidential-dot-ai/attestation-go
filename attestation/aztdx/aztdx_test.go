package aztdx

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/evidence-v1.json
var azTdxFixture []byte

// TestVerifyEvidence_Fixture verifies a real recorded az-tdx envelope end to
// end: the Intel DCAP TD quote, the HCL var_data binding, and the vTPM AK quote
// (signature + PCR digest). A fresh nonce must fail closed since the recorded
// quote is not bound to it.
func TestVerifyEvidence_Fixture(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(azTdxFixture, &env); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{}, tdx.Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if res.Platform != teetypes.PlatformAzTDX {
		t.Fatalf("platform = %s, want az-tdx", res.Platform)
	}
	if res.Claims.TCB.Type != "Tdx" || res.Claims.LaunchDigest == "" {
		t.Fatalf("unexpected claims: %+v", res.Claims.TCB)
	}
	if res.Claims.PlatformData["tpm"] == nil {
		t.Fatal("expected tpm claims overlaid")
	}

	if _, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedReportData: make([]byte, 32)}, tdx.Options{}); err == nil {
		t.Fatal("fresh nonce must be rejected on recorded evidence")
	}
}

func TestVerifyEvidence_Errors(t *testing.T) {
	if _, err := VerifyEvidence([]byte(`{"version":99}`), teetypes.VerifyParams{}, tdx.Options{}); err == nil {
		t.Fatal("bad version should fail")
	}
}

// TestVerify_LightweightAPI exercises the back-compat Verify/Result surface that
// TEErminator's Flow A consumes: it takes the full {platform, evidence} envelope,
// verifies the TD quote, and exposes the MRTD + a nonce-binding freshness check.
func TestVerify_LightweightAPI(t *testing.T) {
	res, err := Verify(azTdxFixture)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Measurement == "" {
		t.Fatal("expected an MRTD launch measurement")
	}
	if len(res.ReportData) == 0 || len(res.VarData) == 0 || res.TPMQuote == nil {
		t.Fatalf("incomplete result: %+v", res)
	}

	// A fresh (unbound) nonce must fail closed: the recorded quote's extraData
	// binds a different value.
	if err := res.VerifyVTPMFreshness(make([]byte, 32)); err == nil {
		t.Fatal("fresh nonce must be rejected on recorded evidence")
	}

	// A platform-tagged non-TDX envelope is rejected by the envelope guard.
	if _, err := Verify([]byte(`{"platform":"az-snp","evidence":{}}`)); err == nil {
		t.Fatal("az-snp envelope must be rejected by aztdx.Verify")
	}
}
