package remote_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
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

func evidence(t *testing.T, digest string, rtmrs map[string]string) remote.VerifyResponse {
	t.Helper()
	var resp remote.VerifyResponse
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

func entryTDX(t *testing.T, name, digest string, r1, r2 string) remote.ImagePin {
	t.Helper()
	e := remote.ImagePin{Name: name, Digest: mustHex(t, digest), RTMRs: map[int][]byte{}}
	if r1 != "" {
		e.RTMRs[1] = mustHex(t, r1)
	}
	if r2 != "" {
		e.RTMRs[2] = mustHex(t, r2)
	}
	return e
}

// An agent on the same image must never satisfy the server-only CDS policy.
func TestEnforceImagesPinsAnchorWithImage(t *testing.T) {
	server := []byte("server launch key")
	agent := []byte("agent launch key")
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
		t.Run(string(platform), func(t *testing.T) {
			bound := func(digest string, key []byte) remote.VerifyResponse {
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
			entry := entryTDX(t, "server", digestA, regA1, "")
			entry.Anchor = server
			if platform == teetypes.PlatformSNP {
				entry.RTMRs = nil
			}
			policy := []remote.ImagePin{entry}
			if err := remote.EnforceImages(bound(digestA, server), policy, platform); err != nil {
				t.Fatalf("server refused: %v", err)
			}
			if err := remote.EnforceImages(bound(digestA, agent), policy, platform); !errors.Is(err, remote.ErrAnchorNotAllowed) {
				t.Fatalf("agent with same image: %v", err)
			}
			missing := bound(digestA, server)
			missing.Result.Claims.InitData = nil
			delete(missing.Result.Claims.PlatformData, "rtmr_3")
			if err := remote.EnforceImages(missing, policy, platform); !errors.Is(err, remote.ErrAnchorNotAllowed) {
				t.Fatalf("missing operator binding: %v", err)
			}
			unverified := bound(digestA, server)
			unverified.Result.SignatureValid = false
			if err := remote.EnforceImages(unverified, policy, platform); !errors.Is(err, remote.ErrAnchorNotAllowed) {
				t.Fatalf("unverified claims accepted: %v", err)
			}
			if err := remote.EnforceImages(bound(digestA, server), policy, "different-platform"); err == nil {
				t.Fatalf("inconsistent verified platform accepted: %v", err)
			}
			// Neither key matching a different image nor the shared image
			// matching a different role may satisfy half of a tuple.
			other := entry
			other.Name, other.Digest, other.Anchor = "other", mustHex(t, digestB), agent
			if err := remote.EnforceImages(bound(digestA, agent), append(policy, other), platform); err == nil {
				t.Fatal("crossed image/operator tuple accepted")
			}
			// Mesh may explicitly allow both roles on the same image.
			other.Digest = entry.Digest
			if err := remote.EnforceImages(bound(digestA, agent), append(policy, other), platform); err != nil {
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
	images := []remote.ImagePin{{Name: "image", Digest: mustHex(t, digestA), Anchor: anchor}}
	if err := remote.EnforceImages(r, images, teetypes.PlatformAzSNP); !errors.Is(err, remote.ErrAnchorNotAllowed) {
		t.Fatalf("Azure SNP launcher binding accepted: %v", err)
	}
	r.Result.Platform = teetypes.PlatformSNP
	if err := remote.EnforceImages(r, images, teetypes.PlatformAzSNP); !errors.Is(err, remote.ErrAnchorNotAllowed) {
		t.Fatalf("mismatched verified platform accepted: %v", err)
	}
	images[0].Anchor = []byte{}
	if err := remote.EnforceImages(r, images, teetypes.PlatformSNP); !errors.Is(err, remote.ErrAnchorNotAllowed) {
		t.Fatalf("explicit empty anchor accepted: %v", err)
	}
}
