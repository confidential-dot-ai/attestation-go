package apiclient

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

func TestEnforcePCRs(t *testing.T) {
	claims := claimsWithPCRs(map[int][]byte{4: pcr(4), 11: pcr(11)})

	if err := EnforcePCRs(claims, nil, teetypes.PlatformAzSNP); err != nil {
		t.Errorf("EnforcePCRs(no pins) = %v, want nil", err)
	}
	if err := EnforcePCRs(claims, map[int][]byte{4: pcr(4), 11: pcr(11)}, teetypes.PlatformAzTDX); err != nil {
		t.Errorf("EnforcePCRs(matching) = %v, want nil", err)
	}
	if err := EnforcePCRs(claims, map[int][]byte{4: pcr(9)}, teetypes.PlatformAzSNP); !errors.Is(err, ErrPCRNotAllowed) {
		t.Errorf("EnforcePCRs(mismatch) = %v, want ErrPCRNotAllowed", err)
	}
	// A pinned register the evidence does not carry is a refusal.
	if err := EnforcePCRs(claims, map[int][]byte{7: pcr(7)}, teetypes.PlatformAzSNP); !errors.Is(err, ErrPCRNotAllowed) {
		t.Errorf("EnforcePCRs(unreported) = %v, want ErrPCRNotAllowed", err)
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
		err := EnforcePCRs(claims, map[int][]byte{4: pcr(4)}, platform)
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

	policy := Policy{Measurements: [][]byte{digest}, PCRs: map[int][]byte{4: pcr(4)}}
	if err := EnforcePins(resp, policy, teetypes.PlatformAzSNP); err != nil {
		t.Fatalf("EnforcePins(both matching) = %v, want nil", err)
	}

	policy.PCRs = map[int][]byte{4: pcr(0xff)}
	if err := EnforcePins(resp, policy, teetypes.PlatformAzSNP); !errors.Is(err, ErrPCRNotAllowed) {
		t.Fatalf("EnforcePins(good measurement, bad PCR) = %v, want ErrPCRNotAllowed", err)
	}

	// Image pins take the same treatment.
	policy = Policy{Images: []ImagePin{{Name: "a", Digest: digest}}, PCRs: map[int][]byte{4: pcr(0xff)}}
	if err := EnforcePins(resp, policy, teetypes.PlatformAzSNP); !errors.Is(err, ErrPCRNotAllowed) {
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
