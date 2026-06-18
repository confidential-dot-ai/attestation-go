package teeverify

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// TestVerify_Dispatch drives the unified entry point across platforms using real
// envelope fixtures, confirming auto-detection routes to the right verifier and
// tags the result platform.
func TestVerify_Dispatch(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		params teetypes.VerifyParams
		want   teetypes.PlatformType
	}{
		{"az-snp", "../azsnp/testdata/attestation.json", teetypes.VerifyParams{}, teetypes.PlatformAzSNP},
		{"az-tdx", "../aztdx/testdata/evidence-v1.json", teetypes.VerifyParams{}, teetypes.PlatformAzTDX},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Skipf("fixture missing: %v", err)
			}
			res, err := Verify(raw, tc.params)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Platform != tc.want {
				t.Fatalf("platform = %s, want %s", res.Platform, tc.want)
			}
			if res.Claims.LaunchDigest == "" {
				t.Fatal("expected a launch digest")
			}
		})
	}
}

// TestVerify_TDXEnvelope dispatches a bare-metal TDX envelope (synthesized from a
// real DCAP quote) and a gcp-tdx re-tag of the same evidence.
func TestVerify_TDXEnvelope(t *testing.T) {
	quote, err := os.ReadFile("../tdx/testdata/tdx_quote_4.dat")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	mkEnvelope := func(platform teetypes.PlatformType) []byte {
		inner, _ := json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(quote)})
		env, _ := json.Marshal(teetypes.AttestationEvidence{Platform: platform, Evidence: inner})
		return env
	}

	res, err := Verify(mkEnvelope(teetypes.PlatformTDX), teetypes.VerifyParams{AllowDebug: true})
	if err != nil {
		t.Fatalf("tdx Verify: %v", err)
	}
	if res.Platform != teetypes.PlatformTDX || res.Claims.TCB.Type != "Tdx" {
		t.Fatalf("unexpected tdx result: %+v", res)
	}

	gcp, err := Verify(mkEnvelope(teetypes.PlatformGcpTDX), teetypes.VerifyParams{AllowDebug: true})
	if err != nil {
		t.Fatalf("gcp-tdx Verify: %v", err)
	}
	if gcp.Platform != teetypes.PlatformGcpTDX {
		t.Fatalf("platform = %s, want gcp-tdx", gcp.Platform)
	}
}

func TestVerify_UnsupportedPlatform(t *testing.T) {
	if _, err := Verify([]byte(`{"platform":"dstack","evidence":{}}`), teetypes.VerifyParams{}); err == nil {
		t.Fatal("unsupported platform should error")
	}
	if _, err := Verify([]byte(`{"platform":"snp"`), teetypes.VerifyParams{}); err == nil {
		t.Fatal("malformed JSON should error")
	}
	big := make([]byte, MaxEvidenceSize+1)
	if _, err := Verify(big, teetypes.VerifyParams{}); err == nil {
		t.Fatal("oversized evidence should error")
	}
}
