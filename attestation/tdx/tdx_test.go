package tdx

import (
	_ "embed"
	"encoding/base64"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/tdx_quote_4.dat
var tdxQuoteV4 []byte

// TestVerifyQuoteBytes_Fixture verifies a real DCAP TDX quote (v4) offline:
// signature + PCK chain against the embedded Intel root, plus claims. The v4
// fixture has the debug attribute set, so AllowDebug is required.
func TestVerifyQuoteBytes_Fixture(t *testing.T) {
	quote := tdxQuoteV4

	// Without AllowDebug the debug TD must be rejected.
	if _, err := VerifyQuoteBytes(quote, teetypes.VerifyParams{}, teetypes.PlatformTDX, Options{}); err == nil {
		t.Fatal("debug TD without AllowDebug should fail")
	}

	res, err := VerifyQuoteBytes(quote, teetypes.VerifyParams{AllowDebug: true}, teetypes.PlatformTDX, Options{})
	if err != nil {
		t.Fatalf("VerifyQuoteBytes: %v", err)
	}
	if !res.SignatureValid || res.Platform != teetypes.PlatformTDX {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Claims.TCB.Type != "Tdx" || len(res.Claims.TCB.TCBSvn) != 16 {
		t.Fatalf("expected Tdx TCB info, got %+v", res.Claims.TCB)
	}
	// mr_td of the v4 fixture begins 705e...
	if got := res.Claims.LaunchDigest[:4]; got != "705e" {
		t.Fatalf("launch_digest prefix = %q, want 705e", got)
	}

	// Wrong expected report_data must fail closed.
	bad := make([]byte, 64)
	bad[0] = 1
	if _, err := VerifyQuoteBytes(quote, teetypes.VerifyParams{AllowDebug: true, ExpectedReportData: bad}, teetypes.PlatformTDX, Options{}); err == nil {
		t.Fatal("wrong report_data should fail")
	}
}

// TestVerifyEvidence_Envelope drives the envelope-shaped entry point.
func TestVerifyEvidence_Envelope(t *testing.T) {
	ev := TdxEvidence{Quote: base64.StdEncoding.EncodeToString(tdxQuoteV4)}
	res, err := VerifyEvidence(ev, teetypes.VerifyParams{AllowDebug: true}, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if res.Claims.PlatformData["rtmr_0"] == "" {
		t.Fatal("expected rtmr_0 in claims")
	}
}
