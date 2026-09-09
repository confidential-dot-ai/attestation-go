package teeverify

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
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
	//go:embed testdata/snp-genoa.json
	snpEnvelope []byte
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

// TestVerifyWithOptionsContext_SNPKDSFallback drives the dispatcher's snp arm
// with the VCEK stripped from the envelope — the shape a bare RA-TLS serving
// cert produces. The dispatcher must refuse it offline and accept it once a
// Getter can supply the VCEK, so callers stop reaching past this package to
// snp.VerifyReportContext for that one case.
func TestVerifyWithOptionsContext_SNPKDSFallback(t *testing.T) {
	report, vcek := snpGenoaFixture(t)
	inner, err := json.Marshal(snp.SnpEvidence{AttestationReport: base64.StdEncoding.EncodeToString(report)})
	if err != nil {
		t.Fatal(err)
	}

	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformGcpSNP} {
		t.Run(string(platform), func(t *testing.T) {
			env, err := json.Marshal(teetypes.AttestationEvidence{Platform: platform, Evidence: inner})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(env, teetypes.VerifyParams{}); err == nil {
				t.Fatal("a VCEK-less envelope must not verify offline")
			}

			rp, err := abi.ReportToProto(report)
			if err != nil {
				t.Fatal(err)
			}
			url := kds.VCEKCertURL("Genoa", rp.GetChipId(), kds.TCBVersion(rp.GetReportedTcb()))
			opts := Options{SNP: snp.Options{Getter: test.SimpleGetter(map[string][]byte{url: vcek})}}

			res, err := VerifyWithOptionsContext(context.Background(), env, teetypes.VerifyParams{}, opts)
			if err != nil {
				t.Fatalf("VerifyWithOptionsContext with a KDS getter: %v", err)
			}
			if res.Platform != platform || !res.SignatureValid {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
}

// TestVerifyWithOptionsContext_CancelledContextBoundsTheFetch: the ctx must
// reach the KDS fetch, or a caller's deadline buys nothing.
func TestVerifyWithOptionsContext_CancelledContextBoundsTheFetch(t *testing.T) {
	report, _ := snpGenoaFixture(t)
	inner, _ := json.Marshal(snp.SnpEvidence{AttestationReport: base64.StdEncoding.EncodeToString(report)})
	env, _ := json.Marshal(teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: inner})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := Options{SNP: snp.Options{Getter: &trust.RetryHTTPSGetter{
		MaxRetryDelay: time.Minute,
		Getter:        test.SimpleGetter(nil),
	}}}
	start := time.Now()
	_, err := VerifyWithOptionsContext(ctx, env, teetypes.VerifyParams{}, opts)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancelled ctx took %v, want prompt return", elapsed)
	}
	if !errors.Is(err, snp.ErrCollateralUnavailable) {
		t.Fatalf("err = %v, want ErrCollateralUnavailable", err)
	}
}

// snpGenoaFixture returns the raw report and paired VCEK from the bare-metal
// SNP envelope fixture.
func snpGenoaFixture(t *testing.T) (report, vcek []byte) {
	t.Helper()
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(snpEnvelope, &env); err != nil {
		t.Fatal(err)
	}
	var ev snp.SnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	report, err := base64.StdEncoding.DecodeString(ev.AttestationReport)
	if err != nil {
		t.Fatal(err)
	}
	if vcek, err = base64.StdEncoding.DecodeString(ev.CertChain.Vcek); err != nil {
		t.Fatal(err)
	}
	return report, vcek
}
