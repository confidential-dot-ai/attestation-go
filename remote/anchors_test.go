package remote

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

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
				Name:   "server",
				Digest: mustHex(t, digestA),
				RTMRs:  map[int][]byte{1: mustHex(t, regA1)},
				Anchor: server,
			}
			if platform == teetypes.PlatformSNP {
				entry.RTMRs = nil
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
