package teetypes

import "testing"

// The width of an expected report-data value follows this predicate, so a tag
// landing in the wrong arm fails verification against correct evidence.
func TestUsesTPMNonce(t *testing.T) {
	for _, tc := range []struct {
		platform PlatformType
		want     bool
	}{
		{PlatformAzSNP, true},
		{PlatformAzTDX, true},
		{"AZ-TDX", true},
		{" az-snp ", true},
		{PlatformSNP, false},
		{PlatformTDX, false},
		{PlatformGcpSNP, false},
		{PlatformGcpTDX, false},
		{PlatformDstack, false},
		{"nonsense", false},
	} {
		if got := tc.platform.UsesTPMNonce(); got != tc.want {
			t.Errorf("PlatformType(%q).UsesTPMNonce() = %v, want %v", tc.platform, got, tc.want)
		}
	}
}
