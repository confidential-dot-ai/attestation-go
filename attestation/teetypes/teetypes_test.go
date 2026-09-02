package teetypes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPlatformTypeFamily(t *testing.T) {
	tests := []struct {
		platform PlatformType
		family   Family
		known    bool
	}{
		{PlatformSNP, FamilySNP, true},
		{PlatformAzSNP, FamilySNP, true},
		{PlatformGcpSNP, FamilySNP, true},
		{PlatformTDX, FamilyTDX, true},
		{PlatformAzTDX, FamilyTDX, true},
		{PlatformGcpTDX, FamilyTDX, true},
		{PlatformDstack, FamilyTDX, true},
		{PlatformType("sev-snp"), "", false},
		{PlatformType(""), "", false},
	}
	for _, tc := range tests {
		t.Run(string(tc.platform), func(t *testing.T) {
			family, known := tc.platform.Family()
			if family != tc.family || known != tc.known {
				t.Errorf("Family(%q) = %q, %v, want %q, %v", tc.platform, family, known, tc.family, tc.known)
			}
			if got := tc.platform.IsSNP(); got != (tc.family == FamilySNP && tc.known) {
				t.Errorf("IsSNP(%q) = %v", tc.platform, got)
			}
			if got := tc.platform.IsTDX(); got != (tc.family == FamilyTDX && tc.known) {
				t.Errorf("IsTDX(%q) = %v", tc.platform, got)
			}
		})
	}
}

func tdxClaims() Claims {
	return Claims{
		PlatformData: map[string]any{
			"rtmr_0":               strings.Repeat("aa", 48),
			"rtmr_1":               strings.Repeat("bb", 48),
			"rtmr_2":               strings.Repeat("cc", 48),
			"rtmr_3":               strings.Repeat("dd", 48),
			"td_attributes_parsed": map[string]any{"debug": true},
		},
	}
}

func snpClaims() Claims {
	return Claims{
		PlatformData: map[string]any{
			"policy":        map[string]any{"debug_allowed": false},
			"platform_info": map[string]any{"smt_enabled": true},
		},
	}
}

// jsonRoundTrip re-encodes claims the way a caller receiving a serialized
// VerificationResult sees them, so the accessors must work on both shapes.
func jsonRoundTrip(t *testing.T, c Claims) Claims {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out Claims
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestClaimsRTMR(t *testing.T) {
	for name, claims := range map[string]Claims{"in-process": tdxClaims(), "json round-trip": jsonRoundTrip(t, tdxClaims())} {
		t.Run(name, func(t *testing.T) {
			got, err := claims.RTMR(2)
			if err != nil {
				t.Fatalf("RTMR(2): %v", err)
			}
			if want := bytes.Repeat([]byte{0xcc}, 48); !bytes.Equal(got, want) {
				t.Fatalf("RTMR(2) = %x, want %x", got, want)
			}
		})
	}

	t.Run("SNP claims fail closed", func(t *testing.T) {
		if _, err := snpClaims().RTMR(0); err == nil || !strings.Contains(err.Error(), "no rtmr_0") {
			t.Fatalf("RTMR(0) on SNP claims = %v, want a no-claim error", err)
		}
	})

	for name, claims := range map[string]Claims{
		"index out of range": tdxClaims(),
		"not hex":            {PlatformData: map[string]any{"rtmr_1": "zz"}},
		"wrong length":       {PlatformData: map[string]any{"rtmr_1": "aabb"}},
		"wrong type":         {PlatformData: map[string]any{"rtmr_1": 7}},
	} {
		t.Run(name, func(t *testing.T) {
			idx := 1
			if name == "index out of range" {
				idx = 4
			}
			if _, err := claims.RTMR(idx); err == nil {
				t.Fatalf("RTMR(%d) accepted %s", idx, name)
			}
		})
	}
}

func TestClaimsDebugEnabled(t *testing.T) {
	tests := []struct {
		name   string
		claims Claims
		want   bool
	}{
		{"SNP policy bit", snpClaims(), false},
		{"TDX attribute bit", tdxClaims(), true},
		{"SNP after JSON round-trip", jsonRoundTrip(t, snpClaims()), false},
		{"TDX after JSON round-trip", jsonRoundTrip(t, tdxClaims()), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.claims.DebugEnabled()
			if err != nil || got != tc.want {
				t.Fatalf("DebugEnabled() = %v, %v, want %v, nil", got, err, tc.want)
			}
		})
	}

	t.Run("no flag fails closed", func(t *testing.T) {
		if _, err := (Claims{}).DebugEnabled(); err == nil {
			t.Fatal("DebugEnabled() on empty claims accepted, want error")
		}
	})
}

func TestClaimsSMTEnabled(t *testing.T) {
	got, err := snpClaims().SMTEnabled()
	if err != nil || !got {
		t.Fatalf("SMTEnabled() = %v, %v, want true, nil", got, err)
	}
	if _, err := tdxClaims().SMTEnabled(); err == nil {
		t.Fatal("SMTEnabled() on TDX claims accepted, want error")
	}
}
