package teetypes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func pcrClaims(entries map[string]any) Claims {
	return Claims{PlatformData: map[string]any{"tpm": entries}}
}

func TestClaimsPCR(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, sha256.Size)
	c := pcrClaims(map[string]any{
		"pcr00": hex.EncodeToString(want),
		"pcr08": hex.EncodeToString(want),
		"pcr23": hex.EncodeToString(want),
	})

	for _, i := range []int{0, 8, 23} {
		got, err := c.PCR(i)
		if err != nil {
			t.Fatalf("PCR(%d) = _, %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("PCR(%d) = %x, want %x", i, got, want)
		}
	}
}

// Every failure is a refusal: a caller pinning a register must never read an
// unreported or malformed value as a pass.
func TestClaimsPCRFailsClosed(t *testing.T) {
	good := hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size))

	for _, tc := range []struct {
		name   string
		claims Claims
		index  int
		want   string
	}{
		{"index below range", pcrClaims(map[string]any{"pcr00": good}), -1, "out of range"},
		{"index above range", pcrClaims(map[string]any{"pcr00": good}), 24, "out of range"},
		{"no vTPM data", Claims{PlatformData: map[string]any{"rtmr_1": good}}, 1, "no vTPM data"},
		{"nil platform data", Claims{}, 1, "no vTPM data"},
		{"register not reported", pcrClaims(map[string]any{"pcr00": good}), 1, "no pcr01"},
		{"empty value", pcrClaims(map[string]any{"pcr01": ""}), 1, "no pcr01"},
		{"non-string value", pcrClaims(map[string]any{"pcr01": 7}), 1, "no pcr01"},
		{"not hex", pcrClaims(map[string]any{"pcr01": "zz"}), 1, "pcr01"},
		{"wrong width", pcrClaims(map[string]any{"pcr01": hex.EncodeToString([]byte{1, 2, 3})}), 1, "want 32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.claims.PCR(tc.index)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PCR(%d) = _, %v, want an error containing %q", tc.index, err, tc.want)
			}
		})
	}
}

// A 48-byte RTMR value must not satisfy a PCR read, and vice versa: the two
// banks use different hashes and are never interchangeable.
func TestPCRAndRTMRWidthsDoNotCross(t *testing.T) {
	sha384 := hex.EncodeToString(bytes.Repeat([]byte{1}, 48))
	if _, err := pcrClaims(map[string]any{"pcr01": sha384}).PCR(1); err == nil {
		t.Error("a 48-byte value satisfied a PCR read")
	}
	sha256Hex := hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size))
	if _, err := (Claims{PlatformData: map[string]any{"rtmr_1": sha256Hex}}).RTMR(1); err == nil {
		t.Error("a 32-byte value satisfied an RTMR read")
	}
}

func TestHasVTPMQuote(t *testing.T) {
	for _, tc := range []struct {
		platform PlatformType
		want     bool
	}{
		{PlatformAzSNP, true},
		{PlatformAzTDX, true},
		{" AZ-TDX ", true},
		{PlatformSNP, false},
		{PlatformTDX, false},
		{PlatformGcpSNP, false},
		{PlatformGcpTDX, false},
		{PlatformDstack, false},
		{"nonsense", false},
	} {
		if got := tc.platform.HasVTPMQuote(); got != tc.want {
			t.Errorf("PlatformType(%q).HasVTPMQuote() = %v, want %v", tc.platform, got, tc.want)
		}
	}
}
