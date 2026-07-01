package tdx

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
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
	rtmr0, err := hex.DecodeString(base.Claims.PlatformData["rtmr_0"].(string))
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

	// Wrong RTMR[0] fails closed.
	badRtmr := append([]byte(nil), rtmr0...)
	badRtmr[0] ^= 0xFF
	if _, err := VerifyQuoteBytes(tdxQuoteV4, teetypes.VerifyParams{AllowDebug: true, ExpectedRTMRs: [][]byte{badRtmr}}, teetypes.PlatformTDX, Options{}); err == nil {
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
