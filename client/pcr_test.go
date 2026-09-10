package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func pcr(b byte) []byte { return bytes.Repeat([]byte{b}, sha256.Size) }

func claimsWithPCRs(vals map[int][]byte) teetypes.Claims {
	tpm := map[string]any{}
	for i, v := range vals {
		tpm[pcrKey(i)] = hex.EncodeToString(v)
	}
	return teetypes.Claims{LaunchDigest: digestHex, PlatformData: map[string]any{"tpm": tpm}}
}

func pcrKey(i int) string {
	if i < 10 {
		return "pcr0" + string(rune('0'+i))
	}
	return "pcr" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// azEvidence builds Azure-shaped evidence whose tpm_quote selects exactly the
// given PCRs. The digest is not checked here; the service does that.
func azEvidence(platform teetypes.PlatformType, selected ...int) teetypes.AttestationEvidence {
	var bitmap [3]byte
	for _, i := range selected {
		bitmap[i/8] |= 1 << (i % 8)
	}
	var msg []byte
	msg = append(msg, 0xFF, 0x54, 0x43, 0x47) // magic
	msg = append(msg, 0x80, 0x18)             // TPM_ST_ATTEST_QUOTE
	msg = append(msg, 0x00, 0x00)             // qualifiedSigner size 0
	msg = append(msg, 0x00, 0x05, 'n', 'o', 'n', 'c', 'e')
	msg = append(msg, make([]byte, 17)...)    // clockInfo
	msg = append(msg, make([]byte, 8)...)     // firmwareVersion
	msg = append(msg, 0x00, 0x00, 0x00, 0x01) // one TPMS_PCR_SELECTION
	msg = append(msg, 0x00, 0x0B, 0x03)       // SHA-256, 3-byte bitmap
	msg = append(msg, bitmap[:]...)
	msg = append(msg, 0x00, 0x20)
	msg = append(msg, make([]byte, 32)...) // pcrDigest
	body, _ := json.Marshal(map[string]any{"tpm_quote": map[string]any{
		"message": hex.EncodeToString(msg), "signature": "", "pcrs": []string{},
	}})
	return teetypes.AttestationEvidence{Platform: platform, Evidence: body}
}

func TestEnforcePCRs(t *testing.T) {
	claims := claimsWithPCRs(map[int][]byte{4: pcr(4), 11: pcr(11)})
	ev := azEvidence(teetypes.PlatformAzSNP, 4, 11)

	for _, tc := range []struct {
		name     string
		evidence teetypes.AttestationEvidence
		pinned   map[int][]byte
		want     error
	}{
		{"no pins", ev, nil, nil},
		{"matching", azEvidence(teetypes.PlatformAzTDX, 4, 11), map[int][]byte{4: pcr(4), 11: pcr(11)}, nil},
		{"mismatch", ev, map[int][]byte{4: pcr(9)}, ErrPCRNotAllowed},
		// A pinned register the evidence does not carry is a refusal.
		{"unreported", azEvidence(teetypes.PlatformAzSNP, 4, 7, 11), map[int][]byte{7: pcr(7)}, ErrPCRNotAllowed},
		// The bypass: the report carries the pinned value, but the quote's
		// signed selection excludes that register, so the value is the
		// attester's word rather than the AK's.
		{"reported but not signed", azEvidence(teetypes.PlatformAzSNP, 11), map[int][]byte{4: pcr(4)}, ErrPCRNotAllowed},
		{"no tpm_quote in evidence", teetypes.AttestationEvidence{Platform: teetypes.PlatformAzSNP, Evidence: json.RawMessage(`{}`)}, map[int][]byte{4: pcr(4)}, ErrPCRNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforcePCRs(tc.evidence, claims, tc.pinned)
			if !errors.Is(err, tc.want) {
				t.Fatalf("EnforcePCRs() = %v, want %v", err, tc.want)
			}
		})
	}
}

// A pin against a platform with no vTPM asked for a check that can never run.
// Skipping it quietly would report the policy as enforced when it was not.
func TestEnforcePCRsRefusesPinsWithoutAVTPM(t *testing.T) {
	claims := claimsWithPCRs(map[int][]byte{4: pcr(4)})
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformSNP, teetypes.PlatformTDX,
		teetypes.PlatformGcpSNP, teetypes.PlatformGcpTDX, "nonsense",
	} {
		err := EnforcePCRs(azEvidence(platform, 4), claims, map[int][]byte{4: pcr(4)})
		if !errors.Is(err, ErrPCRNotAllowed) {
			t.Errorf("EnforcePCRs(pins, %q) = %v, want ErrPCRNotAllowed", platform, err)
		}
	}
}

// On Azure the launch measurement identifies the paravisor and the PCRs
// identify the guest OS, so a matching launch measurement must not excuse a
// wrong PCR.
func TestEnforcePinsChecksPCRsAlongsideTheLaunchMeasurement(t *testing.T) {
	digest, _ := hex.DecodeString(digestHex)
	resp := VerifyResponse{Result: teetypes.VerificationResult{Claims: claimsWithPCRs(map[int][]byte{4: pcr(4)})}}
	ev := azEvidence(teetypes.PlatformAzSNP, 4)

	policy := Policy{Measurements: [][]byte{digest}, PCRs: map[int][]byte{4: pcr(4)}}
	if err := EnforcePins(resp, policy, ev); err != nil {
		t.Fatalf("EnforcePins(both matching) = %v, want nil", err)
	}

	policy.PCRs = map[int][]byte{4: pcr(0xff)}
	if err := EnforcePins(resp, policy, ev); !errors.Is(err, ErrPCRNotAllowed) {
		t.Fatalf("EnforcePins(good measurement, bad PCR) = %v, want ErrPCRNotAllowed", err)
	}

	// Image pins take the same treatment.
	policy = Policy{Images: []ImagePin{{Name: "a", Digest: digest}}, PCRs: map[int][]byte{4: pcr(0xff)}}
	if err := EnforcePins(resp, policy, ev); !errors.Is(err, ErrPCRNotAllowed) {
		t.Fatalf("EnforcePins(image pin, bad PCR) = %v, want ErrPCRNotAllowed", err)
	}
}

func TestVerifyEvidenceForwardsInitDataHash(t *testing.T) {
	s := &verifyServer{resp: okResult(teetypes.PlatformAzSNP, digestHex)}
	yes := true
	s.resp.Result.InitDataMatch = &yes
	c := s.start(t)

	hash := pcr(0x42)
	ev := teetypes.AttestationEvidence{Platform: teetypes.PlatformAzSNP, Evidence: json.RawMessage(`{}`)}
	if _, err := c.VerifyEvidence(context.Background(), ev, Policy{ExpectedInitDataHash: hash}); err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if !bytes.Equal(s.got.Params.ExpectedInitDataHash, hash) {
		t.Errorf("expected_init_data_hash = %x, want %x", s.got.Params.ExpectedInitDataHash, hash)
	}
}

// An init-data pin the caller asked for must come back affirmatively matched.
func TestVerifyEvidenceRefusesUnansweredInitDataPin(t *testing.T) {
	s := &verifyServer{resp: okResult(teetypes.PlatformAzSNP, digestHex)} // InitDataMatch nil
	c := s.start(t)

	ev := teetypes.AttestationEvidence{Platform: teetypes.PlatformAzSNP, Evidence: json.RawMessage(`{}`)}
	_, err := c.VerifyEvidence(context.Background(), ev, Policy{ExpectedInitDataHash: pcr(0x42)})
	if !errors.Is(err, ErrInitDataMismatch) {
		t.Fatalf("VerifyEvidence = %v, want ErrInitDataMismatch", err)
	}
}
