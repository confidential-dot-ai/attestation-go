package teetypes

import (
	"strings"
	"testing"
)

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

// TestParseFamily tables every spelling a config or an evidence envelope can
// carry, in both vocabularies.
func TestParseFamily(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Family
	}{
		{"sev-snp", FamilySNP}, // family name, as configs write it
		{"snp", FamilySNP},     // common alias, and the bare-metal tag
		{"az-snp", FamilySNP},
		{"gcp-snp", FamilySNP},
		{"tdx", FamilyTDX}, // family name and bare-metal tag are the same word
		{"az-tdx", FamilyTDX},
		{"gcp-tdx", FamilyTDX},
		{"  SEV-SNP\n", FamilySNP},
		{"Az-Tdx", FamilyTDX},
	} {
		got, err := ParseFamily(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseFamily(%q) = %q, %v, want %q, nil", tc.in, got, err, tc.want)
		}
	}
}

// TestParseFamily_Unknown pins the fail-closed contract: no input yields
// FamilyUnknown with a nil error, and the error quotes what was supplied.
func TestParseFamily_Unknown(t *testing.T) {
	for _, in := range []string{"", "dstack", "nitro", "sev", "snp-sev", "tdx1"} {
		got, err := ParseFamily(in)
		if err == nil {
			t.Errorf("ParseFamily(%q) = %q, nil; want an error", in, got)
			continue
		}
		if got != FamilyUnknown {
			t.Errorf("ParseFamily(%q) = %q on error, want FamilyUnknown", in, got)
		}
		if in != "" && !strings.Contains(err.Error(), in) {
			t.Errorf("ParseFamily(%q) error %q does not quote the input", in, err)
		}
	}
}

// TestParseFamily_ErrorListsWhatItAccepts keeps the error's list of spellings
// in lockstep with what ParseFamily takes: an operator retyping a value from
// the message must land on one that parses.
func TestParseFamily_ErrorListsWhatItAccepts(t *testing.T) {
	_, err := ParseFamily("nope")
	if err == nil {
		t.Fatal("ParseFamily(\"nope\") must fail")
	}
	for _, spelling := range familySpellings {
		if _, err := ParseFamily(spelling); err != nil {
			t.Errorf("error lists %q but ParseFamily rejects it: %v", spelling, err)
		}
		if !strings.Contains(err.Error(), spelling) {
			t.Errorf("error %q omits accepted spelling %q", err, spelling)
		}
	}
}

func TestFamilyDefaultPlatform(t *testing.T) {
	for _, tc := range []struct {
		f    Family
		want PlatformType
	}{
		{FamilySNP, PlatformSNP},
		{FamilyTDX, PlatformTDX},
		{FamilyUnknown, ""},
	} {
		got := tc.f.DefaultPlatform()
		if got != tc.want {
			t.Errorf("Family(%q).DefaultPlatform() = %q, want %q", tc.f, got, tc.want)
		}
		// A default tag must round-trip: whatever it names verifies under the
		// family it came from, so a config that only knows a family cannot
		// build a request no verifier accepts.
		if tc.want != "" && got.Family() != tc.f {
			t.Errorf("Family(%q).DefaultPlatform() = %q, whose Family() is %q", tc.f, got, got.Family())
		}
	}
}

func TestFamilyString(t *testing.T) {
	for _, tc := range []struct {
		f    Family
		want string
	}{
		{FamilySNP, "sev-snp"},
		{FamilyTDX, "tdx"},
		{FamilyUnknown, "unknown"},
	} {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("Family(%q).String() = %q, want %q", string(tc.f), got, tc.want)
		}
	}
}
