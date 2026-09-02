package teetypes

import "testing"

func TestFamily(t *testing.T) {
	for _, tc := range []struct {
		in   PlatformType
		want Family
	}{
		{PlatformSNP, FamilySNP},
		{PlatformAzSNP, FamilySNP},
		{PlatformGcpSNP, FamilySNP},
		{PlatformTDX, FamilyTDX},
		{PlatformAzTDX, FamilyTDX},
		{PlatformGcpTDX, FamilyTDX},
		// No dstack verifier exists, so the tag must not claim a family a
		// hardware-specific policy would then believe it enforced.
		{PlatformDstack, FamilyUnknown},
		{"", FamilyUnknown},
		{"sev-snp", FamilyUnknown}, // not a tag this module emits or accepts
		{"nitro", FamilyUnknown},
		// Case and surrounding space are the same tag.
		{" AZ-TDX ", FamilyTDX},
		{"GCP-SNP", FamilySNP},
	} {
		if got := tc.in.Family(); got != tc.want {
			t.Errorf("PlatformType(%q).Family() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsTDXAndIsSNPAreExclusiveAndFailClosed(t *testing.T) {
	for _, p := range []PlatformType{
		PlatformSNP, PlatformTDX, PlatformAzSNP, PlatformAzTDX,
		PlatformGcpSNP, PlatformGcpTDX, PlatformDstack, "nitro", "",
	} {
		tdx, snp := p.IsTDX(), p.IsSNP()
		if tdx && snp {
			t.Errorf("PlatformType(%q) is both TDX and SNP", p)
		}
		if want := p.Family() == FamilyTDX; tdx != want {
			t.Errorf("PlatformType(%q).IsTDX() = %v, want %v", p, tdx, want)
		}
		if want := p.Family() == FamilySNP; snp != want {
			t.Errorf("PlatformType(%q).IsSNP() = %v, want %v", p, snp, want)
		}
	}
	// An unroutable tag answers no to both, so a TDX-only and an SNP-only
	// policy both refuse it rather than one of them silently applying.
	if PlatformType("nitro").IsTDX() || PlatformType("nitro").IsSNP() {
		t.Fatal("unknown platform must not satisfy either family")
	}
}

func TestNormalizePlatform(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want PlatformType
	}{
		{"tdx", PlatformTDX},
		{"  TDX\n", PlatformTDX},
		{"Az-Snp", PlatformAzSNP},
		{"", ""},
		// Unrecognized input survives verbatim (modulo trim/fold) so callers
		// can quote what was supplied.
		{" Bogus ", "bogus"},
	} {
		if got := NormalizePlatform(tc.in); got != tc.want {
			t.Errorf("NormalizePlatform(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
