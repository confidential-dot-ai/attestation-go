package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// verifyServer records the last /verify request and answers with resp.
type verifyServer struct {
	got  VerifyRequest
	resp VerifyResponse
}

func (s *verifyServer) start(t *testing.T) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&s.got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if err := json.NewEncoder(w).Encode(s.resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL)
}

func okResult(platform teetypes.PlatformType, launchDigest string) VerifyResponse {
	match := true
	return VerifyResponse{Result: teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        platform,
		ReportDataMatch: &match,
		Claims:          teetypes.Claims{LaunchDigest: launchDigest},
	}}
}

// A 48-byte SHA-384-shaped value, as hex.
const digestHex = "aabbccddeeff00112233445566778899" +
	"aabbccddeeff00112233445566778899" +
	"aabbccddeeff00112233445566778899"

// The expected report data is the value sent to /attest and travels verbatim:
// native verifiers zero-pad it to the hardware field, vTPM verifiers compare
// it with the quote nonce as attested. An empty value pins nothing.
func TestVerifyEvidenceSendsReportDataVerbatim(t *testing.T) {
	digest := measurement(0x5a)
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformSNP, teetypes.PlatformTDX,
		teetypes.PlatformGcpSNP, teetypes.PlatformGcpTDX,
		teetypes.PlatformAzSNP, teetypes.PlatformAzTDX,
	} {
		t.Run(string(platform), func(t *testing.T) {
			s := &verifyServer{resp: okResult(platform, digestHex)}
			c := s.start(t)
			ev := teetypes.AttestationEvidence{Platform: platform, Evidence: json.RawMessage(`{}`)}

			if _, err := c.VerifyEvidence(context.Background(), ev, Policy{ExpectedReportData: digest}); err != nil {
				t.Fatalf("VerifyEvidence: %v", err)
			}
			if got := s.got.Params.ExpectedReportData; !bytes.Equal(got, digest) {
				t.Errorf("expected_report_data = %x, want %x", got, digest)
			}

			s.got, s.resp.Result.ReportDataMatch = VerifyRequest{}, nil
			if _, err := c.VerifyEvidence(context.Background(), ev, Policy{}); err != nil {
				t.Fatalf("VerifyEvidence(zero policy): %v", err)
			}
			if got := s.got.Params.ExpectedReportData; got != nil {
				t.Errorf("zero policy sent expected_report_data %x, want none", got)
			}
		})
	}
}

// MinTcb names SEV-SNP components. On any other family it is refused rather
// than dropped, so a caller never verifies under no floor while believing one
// was applied.
func TestVerifyEvidenceRefusesMinTcbOffSNP(t *testing.T) {
	floor := &teetypes.SnpTcb{Bootloader: 10, Tee: 0, Snp: 27, Microcode: 28}
	for _, tc := range []struct {
		platform teetypes.PlatformType
		want     error
	}{
		{teetypes.PlatformSNP, nil},
		{teetypes.PlatformAzSNP, nil},
		{teetypes.PlatformTDX, ErrMinTcbNotAllowed},
		{teetypes.PlatformAzTDX, ErrMinTcbNotAllowed},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			s := &verifyServer{resp: okResult(tc.platform, digestHex)}
			c := s.start(t)
			ev := teetypes.AttestationEvidence{Platform: tc.platform, Evidence: json.RawMessage(`{}`)}
			_, err := c.VerifyEvidence(context.Background(), ev, Policy{MinTcb: floor})
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyEvidence(MinTcb) = %v, want %v", err, tc.want)
			}
			if tc.want == nil && s.got.Params.MinTcb == nil {
				t.Error("min_tcb was not sent")
			}
			if tc.want != nil && s.got.Platform != "" {
				t.Error("evidence was sent to the service despite the refused floor")
			}
		})
	}
}

func TestVerifyEvidenceUnknownPlatformFailsClosed(t *testing.T) {
	s := &verifyServer{resp: okResult("nonsense", digestHex)}
	c := s.start(t)
	ev := teetypes.AttestationEvidence{Platform: "nonsense", Evidence: json.RawMessage(`{}`)}
	_, err := c.VerifyEvidence(context.Background(), ev, Policy{})
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("VerifyEvidence(nonsense) = %v, want ErrUnsupportedPlatform", err)
	}
	if s.got.Platform != "" {
		t.Error("an unsupported platform was still sent to the service")
	}
}

func TestEnforceVerdict(t *testing.T) {
	yes, no := true, false
	withRD := VerifyRequest{Params: &VerifyParams{ExpectedReportData: []byte("x")}}

	for _, tc := range []struct {
		name string
		req  VerifyRequest
		resp VerifyResponse
		want error
	}{
		{"bad signature", VerifyRequest{}, VerifyResponse{}, ErrSignatureInvalid},
		{"no pins", VerifyRequest{}, VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true}}, nil},
		{"report data absent", withRD, VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true}}, ErrReportDataMismatch},
		{"report data false", withRD, VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &no}}, ErrReportDataMismatch},
		{"report data true", withRD, VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &yes}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceVerdict(tc.req, tc.resp)
			if tc.want == nil && err != nil {
				t.Fatalf("EnforceVerdict() = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("EnforceVerdict() = %v, want %v", err, tc.want)
			}
		})
	}
}

// An init-data pin the caller asked for must be affirmatively matched, not
// tolerated when the service omits the verdict.
func TestEnforceVerdictInitDataFailsClosed(t *testing.T) {
	req := VerifyRequest{Params: &VerifyParams{ExpectedInitDataHash: []byte("x")}}

	resp := VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true}}
	if err := EnforceVerdict(req, resp); !errors.Is(err, ErrInitDataMismatch) {
		t.Fatalf("EnforceVerdict with an unanswered init-data pin = %v, want ErrInitDataMismatch", err)
	}
}

// A service that predates the expected-measurement request fields ignores
// them and returns a clean report. The pins are enforced against the returned
// claims, so a report for one image is refused when another was requested.
func TestVerifyEnforcedChecksExpectedMeasurementsAgainstClaims(t *testing.T) {
	reported, _ := hex.DecodeString(digestHex)
	other := measurement(0xbb)
	claims := teetypes.Claims{LaunchDigest: digestHex, PlatformData: map[string]any{"rtmr_1": digestHex}}

	for _, tc := range []struct {
		name   string
		launch []byte
		rtmrs  map[int][]byte
		want   error
	}{
		{"launch digest differs", other, nil, ErrMeasurementNotAllowed},
		{"register differs", reported, map[int][]byte{1: other}, ErrRTMRNotAllowed},
		{"register not reported", reported, map[int][]byte{2: reported}, ErrRTMRNotAllowed},
		{"both match", reported, map[int][]byte{1: reported}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &verifyServer{resp: okResult(teetypes.PlatformTDX, digestHex)}
			s.resp.Result.Claims = claims
			c := s.start(t)

			var params VerifyParams
			if err := params.SetExpectedMeasurements(teetypes.PlatformTDX, tc.launch, tc.rtmrs); err != nil {
				t.Fatal(err)
			}
			ev := teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}
			_, err := c.VerifyEnforced(context.Background(), NewVerifyRequest(ev, &params, false))
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyEnforced() = %v, want %v", err, tc.want)
			}
		})
	}
}

func claimsWithRTMR(idx int, hexVal string) teetypes.Claims {
	return teetypes.Claims{PlatformData: map[string]any{"rtmr_" + string(rune('0'+idx)): hexVal}}
}

func TestEnforceRTMRs(t *testing.T) {
	val, _ := hex.DecodeString(digestHex)
	resp := VerifyResponse{Result: teetypes.VerificationResult{Claims: claimsWithRTMR(1, digestHex)}}

	if err := EnforceRTMRs(resp, nil); err != nil {
		t.Errorf("EnforceRTMRs(no pins) = %v, want nil", err)
	}
	if err := EnforceRTMRs(resp, map[int][]byte{1: val}); err != nil {
		t.Errorf("EnforceRTMRs(matching) = %v, want nil", err)
	}
	if err := EnforceRTMRs(resp, map[int][]byte{1: make([]byte, 48)}); !errors.Is(err, ErrRTMRNotAllowed) {
		t.Errorf("EnforceRTMRs(mismatch) = %v, want ErrRTMRNotAllowed", err)
	}
	// A pinned register the evidence does not carry is a refusal, not a pass.
	if err := EnforceRTMRs(resp, map[int][]byte{2: val}); !errors.Is(err, ErrRTMRNotAllowed) {
		t.Errorf("EnforceRTMRs(unreported) = %v, want ErrRTMRNotAllowed", err)
	}
}

// Registers pinned against a platform that has none must be refused: silently
// skipping the pin would report a policy as enforced when it was not.
func TestEnforcePinsRefusesRTMRPinsOnSNP(t *testing.T) {
	resp := VerifyResponse{Result: teetypes.VerificationResult{Claims: teetypes.Claims{LaunchDigest: digestHex}}}
	policy := Policy{RTMRs: map[int][]byte{1: make([]byte, 48)}}
	snp := teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP}
	if err := EnforcePins(resp, policy, snp); !errors.Is(err, ErrRTMRNotAllowed) {
		t.Fatalf("EnforcePins(snp with RTMR pins) = %v, want ErrRTMRNotAllowed", err)
	}
	if err := EnforcePins(resp, Policy{}, snp); err != nil {
		t.Fatalf("EnforcePins(snp, no pins) = %v, want nil", err)
	}
}

func TestEnforceImagesMatchesWholeImages(t *testing.T) {
	digest, _ := hex.DecodeString(digestHex)
	other := make([]byte, 48)
	rtmr, _ := hex.DecodeString(digestHex)

	resp := VerifyResponse{Result: teetypes.VerificationResult{
		Claims: teetypes.Claims{LaunchDigest: digestHex, PlatformData: map[string]any{"rtmr_1": digestHex}},
	}}

	for _, tc := range []struct {
		name     string
		images   []ImagePin
		platform teetypes.PlatformType
		wantErr  bool
	}{
		{"digest only, snp", []ImagePin{{Name: "a", Digest: digest}}, teetypes.PlatformSNP, false},
		{"wrong digest", []ImagePin{{Name: "a", Digest: other}}, teetypes.PlatformSNP, true},
		// A register pin the platform cannot answer is a non-match, not a pass
		// on the digest alone.
		{"registers pinned, snp", []ImagePin{{Name: "a", Digest: digest, RTMRs: map[int][]byte{3: rtmr}}}, teetypes.PlatformSNP, true},
		{"registers pinned, unknown platform", []ImagePin{{Name: "a", Digest: digest, RTMRs: map[int][]byte{3: rtmr}}}, "dstack", true},
		{"mixed set, digest-only candidate matches", []ImagePin{
			{Name: "tdx", Digest: digest, RTMRs: map[int][]byte{1: rtmr}},
			{Name: "snp", Digest: digest},
		}, teetypes.PlatformSNP, false},
		{"digest and register", []ImagePin{{Name: "a", Digest: digest, RTMRs: map[int][]byte{1: rtmr}}}, teetypes.PlatformTDX, false},
		{"right digest, wrong register", []ImagePin{{Name: "a", Digest: digest, RTMRs: map[int][]byte{1: other}}}, teetypes.PlatformTDX, true},
		// The crossed pairing an image pin exists to refuse.
		{"digest of one, registers of another", []ImagePin{
			{Name: "a", Digest: other, RTMRs: map[int][]byte{1: rtmr}},
			{Name: "b", Digest: digest, RTMRs: map[int][]byte{1: other}},
		}, teetypes.PlatformTDX, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceImages(resp, tc.images, tc.platform)
			if (err != nil) != tc.wantErr {
				t.Fatalf("EnforceImages() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestEnforceLaunchMeasurement(t *testing.T) {
	digest, _ := hex.DecodeString(digestHex)
	resp := func(d string) VerifyResponse {
		return VerifyResponse{Result: teetypes.VerificationResult{Claims: teetypes.Claims{LaunchDigest: d}}}
	}
	if err := EnforceLaunchMeasurement(resp(""), nil); err != nil {
		t.Errorf("no digest, no pins = %v, want nil", err)
	}
	if err := EnforceLaunchMeasurement(resp(""), [][]byte{digest}); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Errorf("no digest, pinned = %v, want ErrMeasurementNotAllowed", err)
	}
	if err := EnforceLaunchMeasurement(resp("zz"), nil); !errors.Is(err, ErrInvalidLaunchDigest) {
		t.Errorf("non-hex digest = %v, want ErrInvalidLaunchDigest", err)
	}
	if err := EnforceLaunchMeasurement(resp(strings.Repeat("ab", 16)), nil); !errors.Is(err, ErrInvalidLaunchDigest) {
		t.Errorf("short digest = %v, want ErrInvalidLaunchDigest", err)
	}
	if err := EnforceLaunchMeasurement(resp(digestHex), [][]byte{digest}); err != nil {
		t.Errorf("matching digest = %v, want nil", err)
	}
	if err := EnforceLaunchMeasurement(resp(digestHex), [][]byte{make([]byte, 48)}); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Errorf("non-matching digest = %v, want ErrMeasurementNotAllowed", err)
	}
}
