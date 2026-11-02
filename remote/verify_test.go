package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
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
		{"register differs", reported, map[int][]byte{1: other}, ErrRegistersNotAllowed},
		{"register not reported", reported, map[int][]byte{2: reported}, ErrRegistersNotAllowed},
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
			_, err := c.VerifyEnforced(context.Background(), NewVerifyRequestNoToken(ev, &params))
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
					r.Result.Claims.InitData = mustLaunchFileDigest(t, teetypes.FamilyTDX, key)
					r.Result.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(runtimemeasure.Zero[:])
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

// Azure sets HOSTDATA and MRCONFIGID itself, even when they happen to equal
// our anchor's digest; GCP carries the bare-metal report.
func TestEnforceImagesCloudOverlays(t *testing.T) {
	anchor := []byte("operator")
	images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}}
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		want     error
	}{
		{"az-snp is refused", teetypes.PlatformAzSNP, ErrAnchorNotAllowed},
		{"az-tdx is refused", teetypes.PlatformAzTDX, ErrAnchorNotAllowed},
		{"gcp-snp binds as snp", teetypes.PlatformGcpSNP, nil},
		{"gcp-tdx binds as tdx", teetypes.PlatformGcpTDX, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceImages(boundOn(t, tc.platform, anchor, nil), images, tc.platform)
			if !errors.Is(err, tc.want) {
				t.Fatalf("EnforceImages() = %v, want %v", err, tc.want)
			}
		})
	}
}

// An az-tdx guest satisfies no launch binding pin, even with evidence that
// satisfies the same pin on bare-metal tdx.
func TestEnforceImagesRefusesAzureTDXOnEveryBindingPin(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	digest := digestOfAnchor(t, teetypes.FamilyTDX, file)
	log := []string{"sha256:" + strings.Repeat("01", 32)}
	acceptAll := func(string) error { return nil }
	for _, tc := range []struct {
		name     string
		pin      ImagePin
		claimed  []string
		sentinel error
	}{
		{"anchor", ImagePin{Anchor: file}, nil, ErrAnchorNotAllowed},
		{"anchor with replayed extensions", ImagePin{Anchor: file, AcceptExtension: acceptAll}, log, ErrAnchorNotAllowed},
		{"launch file", ImagePin{LaunchFile: file}, nil, ErrLaunchFileNotAllowed},
		{"launch file digest", ImagePin{LaunchFileDigest: digest}, nil, ErrLaunchFileNotAllowed},
		{"launch file digest with replayed extensions", ImagePin{LaunchFileDigest: digest, AcceptExtension: acceptAll}, log, ErrLaunchFileNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin := tc.pin
			pin.Name, pin.Digest = "image", mustHex(t, digestA)
			images := []ImagePin{pin}
			if err := EnforceImagesWithRuntimeLog(boundOn(t, teetypes.PlatformTDX, file, tc.claimed), images, teetypes.PlatformTDX, tc.claimed); err != nil {
				t.Fatalf("tdx = %v, want nil", err)
			}
			err := EnforceImagesWithRuntimeLog(boundOn(t, teetypes.PlatformAzTDX, file, tc.claimed), images, teetypes.PlatformAzTDX, tc.claimed)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("az-tdx = %v, want %v", err, tc.sentinel)
			}
		})
	}
}

func TestEnforceImagesRefusesEmptyAnchor(t *testing.T) {
	images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: []byte{}}}
	if err := EnforceImages(snpBoundTo(t, []byte("operator")), images, teetypes.PlatformSNP); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("explicit empty anchor = %v, want ErrAnchorNotAllowed", err)
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

// snpBoundTo returns SNP evidence of image digestA whose HOSTDATA is anchor's
// digest.
func snpBoundTo(t *testing.T, anchor []byte) VerifyResponse {
	t.Helper()
	hostData := runtimemeasure.HostData(anchor)
	r := evidence(t, digestA, nil)
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformSNP
	r.Result.Claims.InitData = hostData[:]
	return r
}

// tdxBoundTo returns TDX evidence of image digestA whose MRCONFIGID is
// anchor's SHA-384 and whose RTMR[3] is zero extended with extended.
func tdxBoundTo(t *testing.T, anchor []byte, extended []string) VerifyResponse {
	t.Helper()
	reg := runtimemeasure.FromDigests(extended)
	r := evidence(t, digestA, map[string]string{"rtmr_3": hex.EncodeToString(reg[:])})
	r.Result.SignatureValid = true
	r.Result.Platform = teetypes.PlatformTDX
	r.Result.Claims.InitData = mustLaunchFileDigest(t, teetypes.FamilyTDX, anchor)
	return r
}

// boundOn returns evidence from platform of image digestA bound to file, as
// tdxBoundTo or snpBoundTo builds it for platform's family.
func boundOn(t *testing.T, platform teetypes.PlatformType, file []byte, extended []string) VerifyResponse {
	t.Helper()
	var r VerifyResponse
	switch platform.Family() {
	case teetypes.FamilyTDX:
		r = tdxBoundTo(t, file, extended)
	case teetypes.FamilySNP:
		r = snpBoundTo(t, file)
	default:
		t.Fatalf("no evidence builder for platform %q", platform)
	}
	r.Result.Platform = platform
	return r
}

// A launch file digest pin replays the runtime log exactly as an anchor pin of
// the same file does.
func TestEnforceImagesWithRuntimeLog(t *testing.T) {
	anchor := []byte("operator")
	pins := []struct {
		kind     string
		pin      ImagePin
		sentinel error
	}{
		{"anchor", ImagePin{Anchor: anchor}, ErrAnchorNotAllowed},
		{"launch file digest", ImagePin{LaunchFileDigest: digestOfAnchor(t, teetypes.FamilyTDX, anchor)}, ErrLaunchFileNotAllowed},
	}
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
		{name: "zero RTMR[3], nil list", extended: nil, claimed: nil},
		{name: "zero RTMR[3], list without hook", extended: nil, claimed: log},
		{name: "exact list", extended: log, claimed: log, accept: acceptAll},
		{name: "list ahead of the quote", extended: log[:2], claimed: log, accept: acceptAll},
		{name: "extended without hook", extended: log[:2], claimed: log, wantErr: true},
		{name: "tail mismatch", extended: log[:2], claimed: []string{log[0], d("ff")}, wantErr: true},
		{name: "extended but nil list", extended: log[:1], claimed: nil, wantErr: true},
		{name: "refused inside the prefix", extended: log[:2], claimed: log, accept: refuse(log[1]), wantErr: true},
		{name: "refused beyond the prefix", extended: log[:2], claimed: log, accept: refuse(log[2])},
		{name: "non-canonical entry", extended: log[:1], claimed: []string{strings.ToUpper(log[0])}, wantErr: true},
	} {
		for _, p := range pins {
			t.Run(p.kind+"/"+tc.name, func(t *testing.T) {
				pin := p.pin
				pin.Name, pin.Digest, pin.AcceptExtension = "image", mustHex(t, digestA), tc.accept
				err := EnforceImagesWithRuntimeLog(tdxBoundTo(t, anchor, tc.extended), []ImagePin{pin}, teetypes.PlatformTDX, tc.claimed)
				if tc.wantErr {
					if !errors.Is(err, p.sentinel) {
						t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want %v", err, p.sentinel)
					}
					return
				}
				if err != nil {
					t.Fatalf("EnforceImagesWithRuntimeLog() = %v, want nil", err)
				}
			})
		}
	}
}

// EnforceImages requires RTMR[3] to be zero: a measuring guest is refused
// unless its list is passed.
func TestEnforceImagesRequiresZeroRuntimeLog(t *testing.T) {
	anchor := []byte("operator")
	extended := []string{"sha256:" + strings.Repeat("01", 32)}
	images := []ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}}
	if err := EnforceImages(tdxBoundTo(t, anchor, nil), images, teetypes.PlatformTDX); err != nil {
		t.Fatalf("EnforceImages(zero RTMR[3]) = %v, want nil", err)
	}
	if err := EnforceImages(tdxBoundTo(t, anchor, extended), images, teetypes.PlatformTDX); !errors.Is(err, ErrAnchorNotAllowed) {
		t.Fatalf("EnforceImages(extended) = %v, want ErrAnchorNotAllowed", err)
	}
}

// A CDS pin names the exact launch file its VM was started with, and nothing
// in such a guest extends the binding afterwards.
func TestEnforceImagesPinsLaunchFile(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	other := []byte("clusterID: beta\n")
	images := []ImagePin{{Name: "cds", Digest: mustHex(t, digestA), LaunchFile: file}}

	t.Run("tdx", func(t *testing.T) {
		if err := EnforceImages(tdxBoundTo(t, file, nil), images, teetypes.PlatformTDX); err != nil {
			t.Fatalf("the pinned launch file was refused: %v", err)
		}
		if err := EnforceImages(tdxBoundTo(t, other, nil), images, teetypes.PlatformTDX); !errors.Is(err, ErrLaunchFileNotAllowed) {
			t.Fatalf("another launch file = %v, want ErrLaunchFileNotAllowed", err)
		}
		extended := []string{"sha256:" + strings.Repeat("01", 32)}
		for _, claimed := range [][]string{nil, extended} {
			err := EnforceImagesWithRuntimeLog(tdxBoundTo(t, file, extended), images, teetypes.PlatformTDX, claimed)
			if !errors.Is(err, ErrLaunchFileNotAllowed) {
				t.Fatalf("extended RTMR[3] with claimed %q = %v, want ErrLaunchFileNotAllowed", claimed, err)
			}
		}
	})

	t.Run("snp", func(t *testing.T) {
		if err := EnforceImages(snpBoundTo(t, file), images, teetypes.PlatformSNP); err != nil {
			t.Fatalf("the pinned launch file was refused: %v", err)
		}
		if err := EnforceImages(snpBoundTo(t, other), images, teetypes.PlatformSNP); !errors.Is(err, ErrLaunchFileNotAllowed) {
			t.Fatalf("another launch file = %v, want ErrLaunchFileNotAllowed", err)
		}
	})
}

// bindingPin is a launch binding pin and the sentinel its refusals wrap.
type bindingPin struct {
	kind     string
	pin      ImagePin
	sentinel error
}

// tdxBindingPins returns one pin of each launch binding kind for file.
func tdxBindingPins(t *testing.T, file []byte) []bindingPin {
	t.Helper()
	return []bindingPin{
		{"anchor", ImagePin{Name: "image", Digest: mustHex(t, digestA), Anchor: file}, ErrAnchorNotAllowed},
		{"launch file", ImagePin{Name: "image", Digest: mustHex(t, digestA), LaunchFile: file}, ErrLaunchFileNotAllowed},
		{"launch file digest", ImagePin{Name: "image", Digest: mustHex(t, digestA), LaunchFileDigest: digestOfAnchor(t, teetypes.FamilyTDX, file)}, ErrLaunchFileNotAllowed},
	}
}

// TDX evidence whose MRCONFIGID is not SHA-384(file), or whose RTMR[3] is not
// zero, satisfies no launch binding pin. Each case changes one claim of
// evidence that does.
func TestEnforceImagesRefusesOtherTDXBindings(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	hostData := runtimemeasure.HostData(file)
	extendedWithFileDigest := runtimemeasure.Extend(runtimemeasure.Zero, sha512.Sum384(file))
	for _, tc := range []struct {
		name   string
		mutate func(*VerifyResponse)
	}{
		{"RTMR[3] extended with the file digest", func(r *VerifyResponse) {
			r.Result.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(extendedWithFileDigest[:])
		}},
		{"no RTMR[3]", func(r *VerifyResponse) { delete(r.Result.Claims.PlatformData, "rtmr_3") }},
		{"zero MRCONFIGID", func(r *VerifyResponse) { r.Result.Claims.InitData = make([]byte, runtimemeasure.Size) }},
		{"zero-padded SHA-256 MRCONFIGID", func(r *VerifyResponse) {
			r.Result.Claims.InitData = append(hostData[:], make([]byte, runtimemeasure.Size-runtimemeasure.HostDataSize)...)
		}},
		{"SHA-256 MRCONFIGID", func(r *VerifyResponse) { r.Result.Claims.InitData = hostData[:] }},
	} {
		for _, p := range tdxBindingPins(t, file) {
			t.Run(tc.name+"/"+p.kind, func(t *testing.T) {
				if err := EnforceImages(tdxBoundTo(t, file, nil), []ImagePin{p.pin}, teetypes.PlatformTDX); err != nil {
					t.Fatalf("the bound guest = %v, want nil", err)
				}
				r := tdxBoundTo(t, file, nil)
				tc.mutate(&r)
				if err := EnforceImages(r, []ImagePin{p.pin}, teetypes.PlatformTDX); !errors.Is(err, p.sentinel) {
					t.Fatalf("EnforceImages() = %v, want %v", err, p.sentinel)
				}
			})
		}
	}
}

// A guest of an image that extended RTMR[3] with its file digest and left
// MRCONFIGID zero satisfies no launch binding pin.
func TestEnforceImagesRefusesOldImageGuest(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	extendedWithFileDigest := runtimemeasure.Extend(runtimemeasure.Zero, sha512.Sum384(file))
	r := tdxBoundTo(t, file, nil)
	r.Result.Claims.InitData = make([]byte, runtimemeasure.Size)
	r.Result.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(extendedWithFileDigest[:])
	for _, p := range tdxBindingPins(t, file) {
		t.Run(p.kind, func(t *testing.T) {
			if err := EnforceImages(r, []ImagePin{p.pin}, teetypes.PlatformTDX); !errors.Is(err, p.sentinel) {
				t.Fatalf("EnforceImages() = %v, want %v", err, p.sentinel)
			}
		})
	}
}

// A launch-file pin that cannot mean what it says is a policy the caller never
// meant, so it is refused rather than half applied.
func TestEnforceImagesRefusesContradictoryLaunchFilePin(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	for name, mutate := range map[string]func(*ImagePin){
		"an empty launch file": func(p *ImagePin) { p.LaunchFile = []byte{} },
		"anchor as well":       func(p *ImagePin) { p.Anchor = file },
		"an extension hook":    func(p *ImagePin) { p.AcceptExtension = func(string) error { return nil } },
	} {
		t.Run(name, func(t *testing.T) {
			pin := ImagePin{Name: "cds", Digest: mustHex(t, digestA), LaunchFile: file}
			mutate(&pin)
			if err := EnforceImages(snpBoundTo(t, file), []ImagePin{pin}, teetypes.PlatformSNP); !errors.Is(err, ErrLaunchFileNotAllowed) {
				t.Fatalf("pin with %s = %v, want ErrLaunchFileNotAllowed", name, err)
			}
		})
	}
}

func mustLaunchFileDigest(t *testing.T, f teetypes.Family, file []byte) []byte {
	t.Helper()
	d, err := runtimemeasure.LaunchFileDigest(f, file)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// digestOfAnchor returns the LaunchFileDigest pin that tdxBoundTo and
// snpBoundTo evidence for anchor satisfies, having checked that it is:
// MRCONFIGID is SHA-384(anchor), and HostData is SHA-256(anchor).
func digestOfAnchor(t *testing.T, f teetypes.Family, anchor []byte) []byte {
	t.Helper()
	d := mustLaunchFileDigest(t, f, anchor)
	switch f {
	case teetypes.FamilyTDX:
		if want := sha512.Sum384(anchor); !bytes.Equal(d, want[:]) {
			t.Fatal("a TDX launch file digest is not its anchor's SHA-384")
		}
	case teetypes.FamilySNP:
		if hostData := runtimemeasure.HostData(anchor); !bytes.Equal(d, hostData[:]) {
			t.Fatal("an SEV-SNP launch file digest is not its anchor's HOSTDATA")
		}
	default:
		t.Fatalf("no evidence builder for family %s", f)
	}
	return d
}

// A worker pin names its launch file by digest alone.
func TestEnforceImagesPinsLaunchFileDigest(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	other := []byte("clusterID: beta\n")
	for _, tc := range []struct {
		name     string
		resp     VerifyResponse
		platform teetypes.PlatformType
		digest   []byte
		wantErr  bool
	}{
		{"tdx", tdxBoundTo(t, file, nil), teetypes.PlatformTDX, digestOfAnchor(t, teetypes.FamilyTDX, file), false},
		{"tdx other file", tdxBoundTo(t, other, nil), teetypes.PlatformTDX, digestOfAnchor(t, teetypes.FamilyTDX, file), true},
		{"snp", snpBoundTo(t, file), teetypes.PlatformSNP, digestOfAnchor(t, teetypes.FamilySNP, file), false},
		{"snp other file", snpBoundTo(t, other), teetypes.PlatformSNP, digestOfAnchor(t, teetypes.FamilySNP, file), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images := []ImagePin{{Name: "worker", Digest: mustHex(t, digestA), LaunchFileDigest: tc.digest}}
			err := EnforceImages(tc.resp, images, tc.platform)
			if tc.wantErr {
				if !errors.Is(err, ErrLaunchFileNotAllowed) {
					t.Fatalf("EnforceImages() = %v, want ErrLaunchFileNotAllowed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("EnforceImages() = %v, want nil", err)
			}
		})
	}
}

// A launch binding pin that cannot mean what it says fails the whole policy
// before any evidence is matched, even beside a pin that matches.
func TestEnforceImagesRefusesInvalidLaunchBindingPin(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	snp := digestOfAnchor(t, teetypes.FamilySNP, file)
	tdx := digestOfAnchor(t, teetypes.FamilyTDX, file)
	emptyFile := sha256.Sum256(nil)
	for name, tc := range map[string]struct {
		resp     VerifyResponse
		platform teetypes.PlatformType
		valid    []byte
		invalid  ImagePin
	}{
		"anchor and launch file":        {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{Anchor: file, LaunchFile: file}},
		"anchor and launch file digest": {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{Anchor: file, LaunchFileDigest: snp}},
		"launch file and its digest":    {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{LaunchFile: file, LaunchFileDigest: snp}},
		"empty digest":                  {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{LaunchFileDigest: []byte{}}},
		"tdx width on sev-snp":          {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{LaunchFileDigest: tdx}},
		"sev-snp width on tdx":          {tdxBoundTo(t, file, nil), teetypes.PlatformTDX, tdx, ImagePin{LaunchFileDigest: snp}},
		"all-zero digest":               {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{LaunchFileDigest: make([]byte, runtimemeasure.HostDataSize)}},
		"empty file's digest":           {snpBoundTo(t, file), teetypes.PlatformSNP, snp, ImagePin{LaunchFileDigest: emptyFile[:]}},
	} {
		t.Run(name, func(t *testing.T) {
			valid := ImagePin{Name: "valid", Digest: mustHex(t, digestA), LaunchFileDigest: tc.valid}
			if err := EnforceImages(tc.resp, []ImagePin{valid}, tc.platform); err != nil {
				t.Fatalf("the valid pin alone = %v, want nil", err)
			}
			invalid := tc.invalid
			invalid.Name, invalid.Digest = "invalid", mustHex(t, digestA)
			if err := EnforceImages(tc.resp, []ImagePin{valid, invalid}, tc.platform); !errors.Is(err, ErrLaunchFileNotAllowed) {
				t.Fatalf("EnforceImages() = %v, want ErrLaunchFileNotAllowed", err)
			}
		})
	}
}

// SNP has no runtime extends, so a claimed list proves nothing there and
// AcceptExtension never runs.
func TestEnforceImagesWithRuntimeLogOnSNP(t *testing.T) {
	anchor := []byte("operator")
	r := snpBoundTo(t, anchor)
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
