package tdx

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/tdx_quote_4.dat
var tdxQuoteV4 []byte

//go:embed testdata/tdx-evidence-batch.json
var tdxEvidenceBatch []byte

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

func TestVerifyQuoteBytesRejectsUntrustedRoot(t *testing.T) {
	if _, err := VerifyQuoteBytes(
		tdxQuoteV4,
		teetypes.VerifyParams{AllowDebug: true},
		teetypes.PlatformTDX,
		Options{TrustedRoots: x509.NewCertPool()},
	); err == nil {
		t.Fatal("empty caller-supplied trust pool should reject the PCK chain")
	}
}

// TestVerifyQuoteBytes_LaunchDigestAndRTMRs pins MR_TD and RTMRs on the real v4
// fixture: feeding the quote's own values back must verify and set
// LaunchDigestMatch; wrong values must fail closed.
func TestVerifyQuoteBytes_LaunchDigestAndRTMRs(t *testing.T) {
	base, err := VerifyQuoteBytes(tdxQuoteV4, teetypes.VerifyParams{AllowDebug: true}, teetypes.PlatformTDX, Options{})
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	mrTd, err := hex.DecodeString(base.Claims.LaunchDigest)
	if err != nil {
		t.Fatalf("decoding mr_td: %v", err)
	}
	rtmr0Hex, ok := base.Claims.PlatformData["rtmr_0"].(string)
	if !ok {
		t.Fatal("rtmr_0 claim missing or not a string")
	}
	rtmr0, err := hex.DecodeString(rtmr0Hex)
	if err != nil {
		t.Fatalf("decoding rtmr_0: %v", err)
	}

	// Correct MR_TD + RTMR[0] (others left unpinned) must verify.
	params := teetypes.VerifyParams{
		AllowDebug:           true,
		ExpectedLaunchDigest: mrTd,
		ExpectedRTMRs:        [][]byte{rtmr0},
	}
	res, err := VerifyQuoteBytes(tdxQuoteV4, params, teetypes.PlatformTDX, Options{})
	if err != nil {
		t.Fatalf("VerifyQuoteBytes with mr_td+rtmr: %v", err)
	}
	if res.LaunchDigestMatch == nil || !*res.LaunchDigestMatch {
		t.Errorf("LaunchDigestMatch = %v, want true", res.LaunchDigestMatch)
	}

	// Wrong MR_TD fails closed.
	badMrTd := append([]byte(nil), mrTd...)
	badMrTd[0] ^= 0xFF
	if _, err := VerifyQuoteBytes(tdxQuoteV4, teetypes.VerifyParams{AllowDebug: true, ExpectedLaunchDigest: badMrTd}, teetypes.PlatformTDX, Options{}); err == nil {
		t.Fatal("wrong mr_td must be rejected")
	}

	// Wrong RTMR[0] fails closed. Pass an explicit 4-slot slice so the rejection
	// is unambiguously a digest mismatch (RTMR[0]) and not a slice-length error —
	// this stays a genuine fail-closed assertion even if validateOptions' 4-slot
	// expansion were to regress.
	badRtmr := append([]byte(nil), rtmr0...)
	badRtmr[0] ^= 0xFF
	if _, err := VerifyQuoteBytes(tdxQuoteV4, teetypes.VerifyParams{AllowDebug: true, ExpectedRTMRs: [][]byte{badRtmr, nil, nil, nil}}, teetypes.PlatformTDX, Options{}); err == nil {
		t.Fatal("wrong rtmr[0] must be rejected")
	}
}

// TestValidateOptions_LaunchDigestAndRTMRs covers the VerifyParams -> validate
// mapping for the launch digest and the 4-slot positional RTMR slice.
func TestValidateOptions_LaunchDigestAndRTMRs(t *testing.T) {
	mrTd := make([]byte, 48)
	mrTd[0] = 0x70
	r2 := make([]byte, 48)
	r2[0] = 0x22
	opts, err := validateOptions(teetypes.VerifyParams{
		ExpectedLaunchDigest: mrTd,
		ExpectedRTMRs:        [][]byte{nil, nil, r2}, // pin only RTMR[2]
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(opts.TdQuoteBodyOptions.MrTd) != string(mrTd) {
		t.Errorf("MrTd = %x, want %x", opts.TdQuoteBodyOptions.MrTd, mrTd)
	}
	// go-tdx-guest requires exactly 4 slots; unpinned entries stay nil.
	got := opts.TdQuoteBodyOptions.Rtmrs
	if len(got) != 4 {
		t.Fatalf("Rtmrs has %d slots, want 4", len(got))
	}
	if got[0] != nil || got[1] != nil || string(got[2]) != string(r2) || got[3] != nil {
		t.Errorf("unexpected RTMR slice: %v", got)
	}

	// Size violations rejected.
	if _, err := validateOptions(teetypes.VerifyParams{ExpectedLaunchDigest: make([]byte, 32)}); err == nil {
		t.Error("launch_digest != 48 should error")
	}
	if _, err := validateOptions(teetypes.VerifyParams{ExpectedRTMRs: [][]byte{make([]byte, 47)}}); err == nil {
		t.Error("rtmr != 48 should error")
	}
	if _, err := validateOptions(teetypes.VerifyParams{ExpectedRTMRs: make([][]byte, 5)}); err == nil {
		t.Error(">4 rtmrs should error")
	}
}

// TestVerifyEvidence_BatchFixtures verifies real, non-debug TDX v4 evidence
// captured from a live TD (each entry carries a DCAP quote plus a CCEL
// eventlog). Every entry must verify offline, expose TDX claims, honor
// launch-digest pinning against its own MR_TD, and fail closed on a wrong nonce.
func TestVerifyEvidence_BatchFixtures(t *testing.T) {
	var batch []struct {
		Platform string      `json:"platform"`
		Evidence TdxEvidence `json:"evidence"`
	}
	if err := json.Unmarshal(tdxEvidenceBatch, &batch); err != nil {
		t.Fatalf("parsing batch fixture: %v", err)
	}
	if len(batch) == 0 {
		t.Fatal("batch fixture is empty")
	}

	for i, e := range batch {
		t.Run(fmt.Sprintf("entry-%d", i), func(t *testing.T) {
			if e.Platform != string(teetypes.PlatformTDX) {
				t.Fatalf("platform = %q, want %q", e.Platform, teetypes.PlatformTDX)
			}
			if e.Evidence.CCEventlog == "" {
				t.Error("expected cc_eventlog to be present in the fixture")
			}

			// Real non-debug TD: verifies offline without AllowDebug.
			res, err := VerifyEvidence(e.Evidence, teetypes.VerifyParams{}, Options{})
			if err != nil {
				t.Fatalf("VerifyEvidence: %v", err)
			}
			if !res.SignatureValid || res.Platform != teetypes.PlatformTDX {
				t.Fatalf("unexpected result: %+v", res)
			}
			if res.Claims.TCB.Type != "Tdx" || len(res.Claims.TCB.TCBSvn) != 16 {
				t.Fatalf("expected Tdx TCB info, got %+v", res.Claims.TCB)
			}
			if s, _ := res.Claims.PlatformData["rtmr_0"].(string); s == "" {
				t.Fatal("expected rtmr_0 in claims")
			}

			// Launch-digest pinning against the fixture's own MR_TD verifies.
			mrTd, err := hex.DecodeString(res.Claims.LaunchDigest)
			if err != nil {
				t.Fatalf("decoding mr_td: %v", err)
			}
			if _, err := VerifyEvidence(e.Evidence, teetypes.VerifyParams{ExpectedLaunchDigest: mrTd}, Options{}); err != nil {
				t.Fatalf("pinning the fixture's own MR_TD should verify: %v", err)
			}

			// Wrong nonce (report_data) fails closed.
			bad := make([]byte, 64)
			bad[0] = 1
			if _, err := VerifyEvidence(e.Evidence, teetypes.VerifyParams{ExpectedReportData: bad}, Options{}); err == nil {
				t.Fatal("wrong report_data must be rejected")
			}
		})
	}
}

// TestVerificationTime pins Options.Now and checks it actually reaches
// go-tdx-guest's certificate-validity evaluation.
//
// go-tdx-guest v0.3.2-20250814 replaced Options.Now (time.Time) with a
// *TimeSet carrying one instant per collateral artifact. verificationTimeSet
// maps our single time onto all five fields; this test would fail if it
// populated the wrong field or dropped the value, since PckCertChain is what
// gates the offline chain check.
func TestVerificationTime(t *testing.T) {
	ev := batchEvidence(t)[0]

	// An explicitly pinned "now" must behave like the zero value. If
	// verificationTimeSet left PckCertChain unset, this would fail with the
	// zero time reading as "certificate not yet valid".
	if _, err := VerifyEvidence(ev, teetypes.VerifyParams{}, Options{Now: time.Now()}); err != nil {
		t.Fatalf("pinning Now to the present should verify: %v", err)
	}

	// Before the PCK certificate was issued.
	if _, err := VerifyEvidence(ev, teetypes.VerifyParams{},
		Options{Now: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("a verification time before the PCK cert was issued must fail")
	}

	// After the PCK certificate expired.
	if _, err := VerifyEvidence(ev, teetypes.VerifyParams{},
		Options{Now: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("a verification time after the PCK cert expired must fail")
	}
}

// TestVerificationTimeSet covers the mapping itself.
func TestVerificationTimeSet(t *testing.T) {
	if ts := verificationTimeSet(time.Time{}); ts != nil {
		t.Fatalf("zero time must map to nil (upstream then defaults to now), got %+v", ts)
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	ts := verificationTimeSet(now)
	if ts == nil {
		t.Fatal("non-zero time must produce a TimeSet")
	}
	for name, got := range map[string]time.Time{
		"PckCertChain": ts.PckCertChain,
		"TcbInfo":      ts.TcbInfo,
		"QeIdentity":   ts.QeIdentity,
		"PckCrl":       ts.PckCrl,
		"RootCaCrl":    ts.RootCaCrl,
	} {
		if !got.Equal(now) {
			t.Errorf("%s = %v, want %v", name, got, now)
		}
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
