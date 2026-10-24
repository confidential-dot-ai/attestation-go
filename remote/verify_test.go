package remote

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
	return VerifyResponse{Passed: true, Result: teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        platform,
		ReportDataMatch: &match,
		Claims:          teetypes.Claims{LaunchDigest: launchDigest},
	}}
}

// sent is the platform-neutral view of the pins a recorded request carried.
func sent(req VerifyRequest) Pins {
	pins, _ := req.Policies.Pins(req.Platform)
	return pins
}

// sentSNP and sentTDX return the params a recorded request carried for its
// platform, whichever tag it used.
func sentSNP(req VerifyRequest) *SNPParams {
	switch p := req.Policies; req.Platform {
	case teetypes.PlatformSNP:
		return p.SNP
	case teetypes.PlatformGcpSNP:
		return p.GcpSNP
	case teetypes.PlatformAzSNP:
		if p.AzSNP != nil {
			return &p.AzSNP.SNPParams
		}
	}
	return nil
}

func sentTDX(req VerifyRequest) *TDXParams {
	switch p := req.Policies; req.Platform {
	case teetypes.PlatformTDX:
		return p.TDX
	case teetypes.PlatformGcpTDX:
		return p.GcpTDX
	case teetypes.PlatformAzTDX:
		if p.AzTDX != nil {
			return &p.AzTDX.TDXParams
		}
	}
	return nil
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
			if got := sent(s.got).ReportData; !bytes.Equal(got, digest) {
				t.Errorf("report_data = %x, want %x", got, digest)
			}

			s.got, s.resp.Result.ReportDataMatch = VerifyRequest{}, nil
			if _, err := c.VerifyEvidence(context.Background(), ev, Policy{}); err != nil {
				t.Fatalf("VerifyEvidence(zero policy): %v", err)
			}
			if got := sent(s.got).ReportData; got != nil {
				t.Errorf("zero policy sent report_data %x, want none", got)
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
			if tc.want == nil && (sentSNP(s.got) == nil || sentSNP(s.got).MinTcb == nil) {
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
	snpReq := func(p SNPParams) VerifyRequest {
		return VerifyRequest{Platform: teetypes.PlatformSNP, Policies: Policies{SNP: &p}}
	}
	tdxReq := func(p TDXParams) VerifyRequest {
		return VerifyRequest{Platform: teetypes.PlatformAzTDX, Policies: Policies{AzTDX: &AzTDXParams{TDXParams: p, PCRs: map[int][]byte{4: pcr(1)}}}}
	}
	withRD := snpReq(SNPParams{ReportData: []byte("x")})
	genuine := func(mutate func(*VerifyResponse)) VerifyResponse {
		resp := VerifyResponse{Passed: true, Result: teetypes.VerificationResult{SignatureValid: true}}
		mutate(&resp)
		return resp
	}
	none := func(*VerifyResponse) {}

	for _, tc := range []struct {
		name string
		req  VerifyRequest
		resp VerifyResponse
		want error
	}{
		{"bad signature", VerifyRequest{}, VerifyResponse{Passed: true}, ErrSignatureInvalid},
		{"no pins", snpReq(SNPParams{}), genuine(none), nil},
		{"not passed", snpReq(SNPParams{}), genuine(func(r *VerifyResponse) { r.Passed = false; r.Checks.Debug = true }), ErrRejected},
		{"report data absent", withRD, genuine(none), ErrReportDataMismatch},
		{"report data false", withRD, genuine(func(r *VerifyResponse) { r.Result.ReportDataMatch = &no; r.Passed = false }), ErrReportDataMismatch},
		{"report data true", withRD, genuine(func(r *VerifyResponse) { r.Result.ReportDataMatch = &yes }), nil},
		{"launch digest false", snpReq(SNPParams{LaunchDigest: [][]byte{measurement(1)}}),
			genuine(func(r *VerifyResponse) { r.Result.LaunchDigestMatch = &no; r.Passed = false }), ErrMeasurementNotAllowed},
		{"launch digest unanswered", snpReq(SNPParams{LaunchDigest: [][]byte{measurement(1)}}), genuine(none), ErrMeasurementNotAllowed},
		{"measurement registers false", snpReq(SNPParams{MeasurementRegisters: &[][]byte{}}),
			genuine(func(r *VerifyResponse) { r.Result.MeasurementRegistersMatch = &no; r.Passed = false }), ErrRegistersNotAllowed},
		{"measurement registers unanswered", snpReq(SNPParams{MeasurementRegisters: &[][]byte{}}), genuine(none), ErrRegistersNotAllowed},
		{"host data false", snpReq(SNPParams{HostData: []byte("x")}),
			genuine(func(r *VerifyResponse) { r.Result.InitDataMatch = &no; r.Passed = false }), ErrInitDataMismatch},
		{"rtmr false", tdxReq(TDXParams{RTMR2: [][]byte{measurement(1)}}),
			genuine(func(r *VerifyResponse) { r.Result.RTMR2Match = &no; r.Checks.PCRsMatch = &yes; r.Passed = false }), ErrRegistersNotAllowed},
		{"pcr false", tdxReq(TDXParams{}),
			genuine(func(r *VerifyResponse) { r.Checks.PCRsMatch = &no; r.Passed = false }), ErrPCRNotAllowed},
		{"pcr unanswered", tdxReq(TDXParams{}), genuine(none), ErrPCRNotAllowed},
		{"tdx all held", tdxReq(TDXParams{ReportData: []byte("x"), MRTD: [][]byte{measurement(1)}, RTMR1: [][]byte{measurement(2)}}),
			genuine(func(r *VerifyResponse) {
				r.Result.ReportDataMatch, r.Result.LaunchDigestMatch, r.Result.RTMR1Match, r.Checks.PCRsMatch = &yes, &yes, &yes, &yes
			}), nil},
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
	for _, req := range []VerifyRequest{
		{Platform: teetypes.PlatformSNP, Policies: Policies{SNP: &SNPParams{HostData: []byte("x")}}},
		{Platform: teetypes.PlatformTDX, Policies: Policies{TDX: &TDXParams{InitData: []byte("x")}}},
	} {
		resp := VerifyResponse{Passed: true, Result: teetypes.VerificationResult{SignatureValid: true}}
		if err := EnforceVerdict(req, resp); !errors.Is(err, ErrInitDataMismatch) {
			t.Fatalf("EnforceVerdict(%s) with an unanswered init-data pin = %v, want ErrInitDataMismatch", req.Platform, err)
		}
	}
}

// The pins reach the service, which answers each; the client then re-checks
// them against the returned claims, so a service that answered true for a
// claim that does not match is still refused.
func TestVerifyEvidenceSendsPinsAndRechecksClaims(t *testing.T) {
	reported, _ := hex.DecodeString(digestHex)
	other := measurement(0xbb)
	yes := true
	claims := teetypes.Claims{LaunchDigest: digestHex, PlatformData: map[string]any{"rtmr_1": digestHex}}

	for _, tc := range []struct {
		name   string
		policy Policy
		want   error
	}{
		{"launch digest differs", Policy{Measurements: [][]byte{other}}, ErrMeasurementNotAllowed},
		{"register differs", Policy{Measurements: [][]byte{reported}, Registers: map[int][]byte{1: other}}, ErrRegistersNotAllowed},
		{"register not reported", Policy{Measurements: [][]byte{reported}, Registers: map[int][]byte{2: reported}}, ErrRegistersNotAllowed},
		{"both match", Policy{Measurements: [][]byte{reported}, Registers: map[int][]byte{1: reported}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The server says every pin held, whatever the claims say.
			s := &verifyServer{resp: okResult(teetypes.PlatformTDX, digestHex)}
			s.resp.Result.Claims = claims
			s.resp.Result.LaunchDigestMatch, s.resp.Result.RTMR1Match, s.resp.Result.RTMR2Match = &yes, &yes, &yes
			c := s.start(t)

			ev := teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}
			_, err := c.VerifyEvidence(context.Background(), ev, tc.policy)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyEvidence() = %v, want %v", err, tc.want)
			}
			sent := sentTDX(s.got)
			if sent == nil || !slices.EqualFunc(sent.MRTD, tc.policy.Measurements, bytes.Equal) {
				t.Fatalf("mrtd sent = %+v, want %x", sent, tc.policy.Measurements)
			}
			for idx, pin := range tc.policy.Registers {
				got := [][][]byte{sent.RTMR0, sent.RTMR1, sent.RTMR2, sent.RTMR3}[idx]
				if len(got) != 1 || !bytes.Equal(got[0], pin) {
					t.Fatalf("rtmr%d sent = %x, want [%x]", idx, got, pin)
				}
			}
		})
	}
}

// Register mode end to end: the pin travels as the service's list, the
// service's verdict is required, and the registers it reports must be the
// pinned ones.
func TestVerifyEvidenceMeasurementRegisters(t *testing.T) {
	reported, _ := hex.DecodeString(digestHex)
	yes, no := true, false
	zero := make([]byte, measurementSize)
	registers := make([][]byte, teetypes.MeasurementRegisterCount)
	for i := range registers {
		registers[i] = zero
	}
	registers[0] = measurement(0x0a)
	policy := Policy{
		ExpectedReportData:   measurement(0x5a),
		Images:               []ImagePin{{Name: "node", Digest: reported}},
		MeasurementRegisters: [][]byte{measurement(0x0a)},
	}
	ev := teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)}

	passing := okResult(teetypes.PlatformSNP, digestHex)
	passing.Result.LaunchDigestMatch = &yes
	passing.Result.MeasurementRegistersMatch = &yes
	passing.Result.MeasurementRegisters = &teetypes.MeasurementRegisters{EventCount: 1, Registers: registers}

	s := &verifyServer{resp: passing}
	c := s.start(t)
	if _, err := c.VerifyEvidence(context.Background(), ev, policy); err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	sent := sentSNP(s.got)
	if sent == nil || sent.MeasurementRegisters == nil || len(*sent.MeasurementRegisters) != 1 || len(sent.ReportData) != reportDataSize {
		t.Fatalf("sent = %+v", sent)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*VerifyResponse)
		want   error
	}{
		{"service says mismatch", func(r *VerifyResponse) { r.Result.MeasurementRegistersMatch = &no; r.Passed = false }, ErrRegistersNotAllowed},
		{"service did not check", func(r *VerifyResponse) { r.Result.MeasurementRegistersMatch = nil }, ErrRegistersNotAllowed},
		{"registers withheld", func(r *VerifyResponse) { r.Result.MeasurementRegisters = nil }, ErrRegistersNotAllowed},
		{"other registers", func(r *VerifyResponse) {
			other := slices.Clone(registers)
			other[0] = measurement(0x0b)
			r.Result.MeasurementRegisters = &teetypes.MeasurementRegisters{EventCount: 1, Registers: other}
		}, ErrRegistersNotAllowed},
		{"register past the pin set", func(r *VerifyResponse) {
			other := slices.Clone(registers)
			other[5] = measurement(0x0b)
			r.Result.MeasurementRegisters = &teetypes.MeasurementRegisters{EventCount: 2, Registers: other}
		}, ErrRegistersNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := passing
			resp.Result.MeasurementRegisters = &teetypes.MeasurementRegisters{EventCount: 1, Registers: slices.Clone(registers)}
			tc.mutate(&resp)
			s := &verifyServer{resp: resp}
			if _, err := s.start(t).VerifyEvidence(context.Background(), ev, policy); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyEvidence = %v, want %v", err, tc.want)
			}
		})
	}

	// Off bare-metal snp the pin is refused before any request.
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformAzSNP, teetypes.PlatformGcpSNP, teetypes.PlatformTDX} {
		s := &verifyServer{resp: okResult(platform, digestHex)}
		_, err := s.start(t).VerifyEvidence(context.Background(), teetypes.AttestationEvidence{Platform: platform, Evidence: json.RawMessage(`{}`)}, policy)
		if !errors.Is(err, ErrRegistersNotAllowed) {
			t.Fatalf("VerifyEvidence(%s) = %v, want ErrRegistersNotAllowed", platform, err)
		}
		if s.got.Platform != "" {
			t.Fatalf("%s: evidence was sent despite the refused pin", platform)
		}
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
	if err := EnforceRTMRs(resp, map[int][]byte{1: make([]byte, 48)}); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Errorf("EnforceRTMRs(mismatch) = %v, want ErrRegistersNotAllowed", err)
	}
	// A pinned register the evidence does not carry is a refusal, not a pass.
	if err := EnforceRTMRs(resp, map[int][]byte{2: val}); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Errorf("EnforceRTMRs(unreported) = %v, want ErrRegistersNotAllowed", err)
	}
}

// Registers pinned against a platform that has none must be refused: silently
// skipping the pin would report a policy as enforced when it was not.
func TestEnforcePinsRefusesRTMRPinsOnSNP(t *testing.T) {
	resp := VerifyResponse{Result: teetypes.VerificationResult{Claims: teetypes.Claims{LaunchDigest: digestHex}}}
	policy := Policy{Registers: map[int][]byte{1: make([]byte, 48)}}
	snp := teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP}
	if err := EnforcePins(resp, policy, snp); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Fatalf("EnforcePins(snp with RTMR pins) = %v, want ErrRegistersNotAllowed", err)
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
		{"registers pinned, snp", []ImagePin{{Name: "a", Digest: digest, Registers: map[int][]byte{3: rtmr}}}, teetypes.PlatformSNP, true},
		{"registers pinned, unknown platform", []ImagePin{{Name: "a", Digest: digest, Registers: map[int][]byte{3: rtmr}}}, "dstack", true},
		{"mixed set, digest-only candidate matches", []ImagePin{
			{Name: "tdx", Digest: digest, Registers: map[int][]byte{1: rtmr}},
			{Name: "snp", Digest: digest},
		}, teetypes.PlatformSNP, false},
		{"digest and register", []ImagePin{{Name: "a", Digest: digest, Registers: map[int][]byte{1: rtmr}}}, teetypes.PlatformTDX, false},
		{"right digest, wrong register", []ImagePin{{Name: "a", Digest: digest, Registers: map[int][]byte{1: other}}}, teetypes.PlatformTDX, true},
		// The crossed pairing an image pin exists to refuse.
		{"digest of one, registers of another", []ImagePin{
			{Name: "a", Digest: other, Registers: map[int][]byte{1: rtmr}},
			{Name: "b", Digest: digest, Registers: map[int][]byte{1: other}},
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

const (
	digestA = "aa11" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	digestB = "bb22" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	regA1   = "1111" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// evidence builds a response carrying a launch digest and, unlike the
// single-register claimsWithRTMR, any number of registers at once.
func evidence(t *testing.T, digest string, rtmrs map[string]string) VerifyResponse {
	t.Helper()
	var resp VerifyResponse
	resp.Result.Claims.LaunchDigest = digest
	if rtmrs != nil {
		pd := make(map[string]any, len(rtmrs))
		for k, v := range rtmrs {
			pd[k] = v
		}
		resp.Result.Claims.PlatformData = pd
	}
	return resp
}

// An agent on the same image must never satisfy the server-only CDS policy.
func TestEnforceImagesPinsAnchorWithImage(t *testing.T) {
	server := []byte("server launch key")
	agent := []byte("agent launch key")
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
		t.Run(string(platform), func(t *testing.T) {
			bound := func(digest string, key []byte) VerifyResponse {
				r := evidence(t, digest, map[string]string{"rtmr_1": regA1})
				r.Result.SignatureValid = true
				r.Result.Platform = platform
				if platform == teetypes.PlatformTDX {
					seed := runtimemeasure.Seed(key)
					r.Result.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])
				} else {
					hostData := runtimemeasure.HostData(key)
					r.Result.Claims.InitData = hostData[:]
				}
				return r
			}
			entry := ImagePin{
				Name:      "server",
				Digest:    mustHex(t, digestA),
				Registers: map[int][]byte{1: mustHex(t, regA1)},
				Anchor:    server,
			}
			if platform == teetypes.PlatformSNP {
				entry.Registers = nil
			}
			policy := []ImagePin{entry}
			if err := EnforceImages(bound(digestA, server), policy, platform); err != nil {
				t.Fatalf("server refused: %v", err)
			}
			if err := EnforceImages(bound(digestA, agent), policy, platform); !errors.Is(err, ErrAnchorNotAllowed) {
				t.Fatalf("agent with same image: %v", err)
			}
			missing := bound(digestA, server)
			missing.Result.Claims.InitData = nil
			delete(missing.Result.Claims.PlatformData, "rtmr_3")
			if err := EnforceImages(missing, policy, platform); !errors.Is(err, ErrAnchorNotAllowed) {
				t.Fatalf("missing operator binding: %v", err)
			}
			unverified := bound(digestA, server)
			unverified.Result.SignatureValid = false
			if err := EnforceImages(unverified, policy, platform); !errors.Is(err, ErrAnchorNotAllowed) {
				t.Fatalf("unverified claims accepted: %v", err)
			}
			// Neither key matching a different image nor the shared image
			// matching a different role may satisfy half of a tuple.
			other := entry
			other.Name, other.Digest, other.Anchor = "other", mustHex(t, digestB), agent
			if err := EnforceImages(bound(digestA, agent), append(policy, other), platform); err == nil {
				t.Fatal("crossed image/operator tuple accepted")
			}
			// Mesh may explicitly allow both roles on the same image.
			other.Digest = entry.Digest
			if err := EnforceImages(bound(digestA, agent), append(policy, other), platform); err != nil {
				t.Fatalf("authorized agent refused: %v", err)
			}
		})
	}
}

// Cloud overlays cannot borrow another platform's binding semantics. Azure SNP
// HOSTDATA is set by the paravisor, even when it happens to equal our anchor.
func TestEnforceImagesRefusesUnsupportedAnchorBinding(t *testing.T) {
	anchor := []byte("operator")
	hd := runtimemeasure.HostData(anchor)
	r := evidence(t, digestA, nil)
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformAzSNP
	r.Result.Claims.InitData = hd[:]
	images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}}
	if err := EnforceImages(r, images, teetypes.PlatformAzSNP); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("Azure SNP launcher binding accepted: %v", err)
	}
	r.Result.Platform = teetypes.PlatformSNP
	images[0].Anchor = []byte{}
	if err := EnforceImages(r, images, teetypes.PlatformSNP); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("explicit empty anchor accepted: %v", err)
	}
}

// A verifier that attested one platform while the evidence was submitted for
// another answers a different question than the policy asked, whatever pin
// form is configured. EnforcePins settles that before any pin runs.
func TestEnforcePinsRefusesMismatchedVerifiedPlatform(t *testing.T) {
	r := evidence(t, digestA, nil)
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformSNP
	policy := Policy{Images: []ImagePin{{Name: "image", Digest: mustHex(t, digestA)}}}
	err := EnforcePins(r, policy, teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX})
	if !errors.Is(err, ErrPlatformMismatch) {
		t.Fatalf("mismatched verified platform accepted: %v", err)
	}
	// A result naming no platform contradicts nothing.
	r.Result.Platform = ""
	if err := EnforcePins(r, policy, teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP}); err != nil {
		t.Fatalf("unstated verified platform refused: %v", err)
	}
}

// tdxBoundTo returns TDX evidence of image digestA whose RTMR[3] is anchor's
// seed extended with extended.
func tdxBoundTo(t *testing.T, anchor []byte, extended []string) VerifyResponse {
	t.Helper()
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), extended)
	r := evidence(t, digestA, map[string]string{"rtmr_3": hex.EncodeToString(reg[:])})
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformTDX
	return r
}

func TestEnforceImagesWithRuntimeLog(t *testing.T) {
	anchor := []byte("operator")
	d := func(b string) string { return "sha256:" + strings.Repeat(b, 32) }
	log := []string{d("01"), d("02"), d("03")}
	acceptAll := func(string) error { return nil }
	refuse := func(bad string) func(string) error {
		return func(digest string) error {
			if digest == bad {
				return errors.New("not allowlisted")
			}
			return nil
		}
	}
	for _, tc := range []struct {
		name     string
		extended []string
		claimed  []string
		accept   func(string) error
		wantErr  bool
	}{
		{name: "bare seed, nil list", extended: nil, claimed: nil},
		{name: "bare seed, list without hook", extended: nil, claimed: log},
		{name: "exact list", extended: log, claimed: log, accept: acceptAll},
		{name: "list ahead of the quote", extended: log[:2], claimed: log, accept: acceptAll},
		{name: "extended without hook", extended: log[:2], claimed: log, wantErr: true},
		{name: "tail mismatch", extended: log[:2], claimed: []string{log[0], d("ff")}, wantErr: true},
		{name: "extended but nil list", extended: log[:1], claimed: nil, wantErr: true},
		{name: "refused inside the prefix", extended: log[:2], claimed: log, accept: refuse(log[1]), wantErr: true},
		{name: "refused beyond the prefix", extended: log[:2], claimed: log, accept: refuse(log[2])},
		{name: "non-canonical entry", extended: log[:1], claimed: []string{strings.ToUpper(log[0])}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor, AcceptExtension: tc.accept}}
			err := EnforceImagesWithRuntimeLog(tdxBoundTo(t, anchor, tc.extended), images, teetypes.PlatformTDX, tc.claimed)
			if tc.wantErr {
				if !errors.Is(err, ErrAnchorNotAllowed) {
					t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want ErrAnchorNotAllowed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want nil", err)
			}
		})
	}
}

// EnforceImages keeps requiring the bare seed: a measuring guest is refused
// unless its list is passed.
func TestEnforceImagesRequiresBareSeed(t *testing.T) {
	anchor := []byte("operator")
	extended := []string{"sha256:" + strings.Repeat("01", 32)}
	images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}}
	if err := EnforceImages(tdxBoundTo(t, anchor, nil), images, teetypes.PlatformTDX); err != nil {
		t.Fatalf("EnforceImages(bare seed) = %v, want nil", err)
	}
	if err := EnforceImages(tdxBoundTo(t, anchor, extended), images, teetypes.PlatformTDX); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("EnforceImages(extended) = %v, want ErrAnchorNotAllowed", err)
	}
}

// SNP has no runtime extends, so a claimed list proves nothing there and
// AcceptExtension never runs.
func TestEnforceImagesWithRuntimeLogOnSNP(t *testing.T) {
	anchor := []byte("operator")
	hd := runtimemeasure.HostData(anchor)
	r := evidence(t, digestA, nil)
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformSNP
	r.Result.Claims.InitData = hd[:]
	images := []ImagePin{{
		Name: "image", Digest: mustHex(t, digestA), Anchor: anchor,
		AcceptExtension: func(string) error { return errors.New("refuse everything") },
	}}
	for _, claimed := range [][]string{nil, {}, {"sha256:" + strings.Repeat("01", 32)}} {
		if err := EnforceImagesWithRuntimeLog(r, images, teetypes.PlatformSNP, claimed); err != nil {
			t.Fatalf("EnforceImagesWithRuntimeLog(snp, %q) = %v, want nil", claimed, err)
		}
	}
	claimed := []string{"img:latest"}
	if err := EnforceImagesWithRuntimeLog(r, images, teetypes.PlatformSNP, claimed); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("EnforceImagesWithRuntimeLog(snp, %q) = %v, want ErrAnchorNotAllowed", claimed, err)
	}
}

// AcceptExtension judges exactly the proven prefix, in extend order.
func TestEnforceImagesAcceptsProvenPrefixOnly(t *testing.T) {
	anchor := []byte("operator")
	log := []string{"sha256:" + strings.Repeat("01", 32), "sha256:" + strings.Repeat("02", 32), "sha256:" + strings.Repeat("03", 32)}
	var judged []string
	images := []ImagePin{{
		Name: "image", Digest: mustHex(t, digestA), Anchor: anchor,
		AcceptExtension: func(d string) error { judged = append(judged, d); return nil },
	}}
	if err := EnforceImagesWithRuntimeLog(tdxBoundTo(t, anchor, log[:2]), images, teetypes.PlatformTDX, log); err != nil {
		t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want nil", err)
	}
	if !slices.Equal(judged, log[:2]) {
		t.Fatalf("AcceptExtension called with %q, want %q", judged, log[:2])
	}
}

// A refusal carries the hook's own error, so a caller tells a disallowed
// extension from a wrong anchor.
func TestEnforceImagesWrapsAcceptExtensionError(t *testing.T) {
	anchor := []byte("operator")
	log := []string{"sha256:" + strings.Repeat("01", 32)}
	errDenied := errors.New("not allowlisted")
	images := []ImagePin{{
		Name: "image", Digest: mustHex(t, digestA), Anchor: anchor,
		AcceptExtension: func(string) error { return errDenied },
	}}
	err := EnforceImagesWithRuntimeLog(tdxBoundTo(t, anchor, log), images, teetypes.PlatformTDX, log)
	if !errors.Is(err, ErrAnchorNotAllowed) || !errors.Is(err, errDenied) {
		t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want ErrAnchorNotAllowed wrapping the hook's error", err)
	}
}

func TestEnforcePinsWithRuntimeLog(t *testing.T) {
	anchor := []byte("operator")
	log := []string{"sha256:" + strings.Repeat("01", 32), "sha256:" + strings.Repeat("02", 32)}
	r := tdxBoundTo(t, anchor, log)
	pin := ImagePin{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}
	policy := Policy{Images: []ImagePin{pin}}
	tdx := teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX}
	if err := EnforcePinsWithRuntimeLog(r, policy, tdx, log); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("EnforcePinsWithRuntimeLog(no hook) = %v, want ErrAnchorNotAllowed", err)
	}
	pin.AcceptExtension = func(string) error { return nil }
	policy.Images = []ImagePin{pin}
	if err := EnforcePinsWithRuntimeLog(r, policy, tdx, log); err != nil {
		t.Fatalf("EnforcePinsWithRuntimeLog(full list) = %v, want nil", err)
	}
	if err := EnforcePins(r, policy, tdx); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("EnforcePins(no list) = %v, want ErrAnchorNotAllowed", err)
	}
	measured := Policy{Measurements: [][]byte{mustHex(t, digestA)}}
	bogus := []string{"img:latest"}
	if err := EnforcePinsWithRuntimeLog(r, measured, tdx, bogus); err != nil {
		t.Fatalf("EnforcePinsWithRuntimeLog(measurements only, %q) = %v, want nil", bogus, err)
	}
}
