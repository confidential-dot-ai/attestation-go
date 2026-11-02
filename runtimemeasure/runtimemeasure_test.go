package runtimemeasure

import (
	"encoding/hex"
	"strings"
	"testing"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Golden vectors pin the convention. If any of these change, the measurer
// and every verifier disagree on RTMR[3] — treat a failure here as a
// breaking change to the attestation contract, not a test to update.
func TestConventionGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  [Size]byte
		want string
	}{
		{"Event(A)", Event(digestA),
			"a3f24413601f0cebf6316f0e499927cbf4adae24d5421f94abdc135fa464bbbb2afb7075b075976eff5379cd25c3f8f2"},
		{"FromDigests[A]", FromDigests([]string{digestA}),
			"c22e78b178c845f91bdc8f575cd3e3b058a7903892807f81129f878df35bdf6566bd18dbcc5dce9177963b1d0e2889f3"},
		{"FromDigests[A,B]", FromDigests([]string{digestA, digestB}),
			"6e06070a4178ba9617ce1598f0e749a05c2e0b9c59e74236265f04d505348e203204ff3a7f920009b87ab272b34c3146"},
	} {
		if got := hex.EncodeToString(tc.got[:]); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestFromDigestsEmptyIsZero(t *testing.T) {
	if FromDigests(nil) != Zero {
		t.Error("FromDigests(nil) must equal the boot value Zero")
	}
}

func TestExtendMatchesFold(t *testing.T) {
	step := Extend(Extend(Zero, Event(digestA)), Event(digestB))
	if step != FromDigests([]string{digestA, digestB}) {
		t.Error("Extend composition disagrees with FromDigests")
	}
}

func TestExtendMatchesHardware(t *testing.T) {
	const (
		event     = "0c06aa4f364e480ece13c58b1585dab43d7222fa331ccc9ff05ea18fdd39a4d9d75e87d711ac6aeda2782c2e339de7c1"
		wantRTMR3 = "db479dfe6333f8d3a2761494b6004bc4332688c6d5b72577b48ecfc0409e4cb53988dcd26b89ec605a81b00e7f0e0863"
	)
	ev, err := hex.DecodeString(event)
	if err != nil {
		t.Fatal(err)
	}
	got := Extend(Zero, [Size]byte(ev))
	if hex.EncodeToString(got[:]) != wantRTMR3 {
		t.Errorf("Extend(Zero, event) = %x, want %s (hardware-confirmed)", got, wantRTMR3)
	}
}

func TestCanonicalDigest(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		ref  string
		want string // "" = must be rejected
	}{
		{"bare canonical digest", "sha256:" + hex64, "sha256:" + hex64},
		{"digest-pinned ref", "ghcr.io/acme/api@sha256:" + hex64, "sha256:" + hex64},
		{"digest-pinned ref with ignored tag", "ghcr.io/acme/api:v1@sha256:" + hex64, "sha256:" + hex64},
		{"tag ref", "ghcr.io/acme/api:v1", ""},
		{"floating tag", "nginx:latest", ""},
		{"bare name", "nginx", ""},
		{"uppercase hex", "sha256:" + strings.ToUpper(hex64), ""},
		{"mixed-case hex in ref", "acme/api@sha256:AB" + strings.Repeat("ab", 31), ""},
		{"too short", "sha256:" + hex64[:62], ""},
		{"too long", "sha256:" + hex64 + "ab", ""},
		{"wrong algorithm", "sha512:" + strings.Repeat("ab", 64), ""},
		{"wrong algorithm in ref", "acme/api@sha512:" + strings.Repeat("ab", 64), ""},
		{"empty name before @", "@sha256:" + hex64, ""},
		{"non-hex chars", "sha256:" + strings.Repeat("zz", 32), ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalDigest(tc.ref)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("CanonicalDigest(%q) = %q, want rejection", tc.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalDigest(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalDigest(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// TestHostDataGolden pins the SNP binding formula: a changed
// vector here breaks the launcher, the guest initrd, and every verifier at
// once, exactly like the RTMR[3] vectors above.
func TestHostDataGolden(t *testing.T) {
	anchor := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	const want = "f61b347fbb8e6469f294c1faa146d37688e5c1c8a6b1b25653ee85ad10b7447a"
	if got := hex.EncodeToString(hostDataSlice(HostData(anchor))); got != want {
		t.Errorf("HostData = %s, want %s", got, want)
	}
}

// A trailing newline changes the binding.
func TestHostDataIsByteExact(t *testing.T) {
	withNewline := []byte("anchor bytes\n")
	withoutNewline := withNewline[:len(withNewline)-1]
	if HostData(withNewline) == HostData(withoutNewline) {
		t.Error("HostData must not normalize its input; a trailing newline changes the binding")
	}
}

func hostDataSlice(v [HostDataSize]byte) []byte { return v[:] }
