package teeverify

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Real envelope fixtures embedded so the dispatcher test is self-contained (no
// fragile cross-package paths).
var (
	//go:embed testdata/az-snp.json
	azSnpEnvelope []byte
	//go:embed testdata/az-tdx.json
	azTdxEnvelope []byte
	//go:embed testdata/tdx-quote.dat
	tdxQuote []byte
)

// TestVerify_Dispatch drives the unified entry point across platforms, confirming
// auto-detection routes to the right verifier and tags the result platform.
func TestVerify_Dispatch(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want teetypes.PlatformType
	}{
		{"az-snp", azSnpEnvelope, teetypes.PlatformAzSNP},
		{"az-tdx", azTdxEnvelope, teetypes.PlatformAzTDX},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Verify(tc.raw, teetypes.VerifyParams{})
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
	mkEnvelope := func(platform teetypes.PlatformType) []byte {
		inner, _ := json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(tdxQuote)})
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

// TestDispatchMatchesFamily keeps the dispatcher and teetypes.Family in
// lockstep. Downstream consumers gate hardware-specific policy (TDX RTMR pins,
// SNP TCB floors) on Family, so a tag this package routes but Family calls
// FamilyUnknown would be verified with that policy silently dropped — and a tag
// Family claims but this package rejects would let a policy report itself as
// enforceable against evidence no verifier accepts.
func TestDispatchMatchesFamily(t *testing.T) {
	for _, p := range []teetypes.PlatformType{
		teetypes.PlatformSNP, teetypes.PlatformTDX,
		teetypes.PlatformAzSNP, teetypes.PlatformAzTDX,
		teetypes.PlatformGcpSNP, teetypes.PlatformGcpTDX,
		teetypes.PlatformDstack,
		" AZ-TDX ", "nitro", "",
	} {
		env, err := json.Marshal(teetypes.AttestationEvidence{Platform: p, Evidence: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatalf("marshal envelope for %q: %v", p, err)
		}
		// Empty inner evidence never verifies; what matters is whether the
		// dispatcher recognized the tag at all, which precedes any parsing.
		_, err = Verify(env, teetypes.VerifyParams{})
		if err == nil {
			t.Fatalf("platform %q: empty evidence unexpectedly verified", p)
		}
		routed := !strings.Contains(err.Error(), "unsupported platform")
		if want := p.Family() != teetypes.FamilyUnknown; routed != want {
			t.Errorf("platform %q: dispatcher routed = %v, Family()=%q implies %v (err: %v)",
				p, routed, p.Family(), want, err)
		}
	}
}
