package runtimemeasure

import (
	"encoding/hex"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// multiManifest is a build manifest for an image built for both families: it
// declares "multi" and carries a TDX tuple next to the SNP variants.
const multiManifest = `{
	"version": 3,
	"build": {"platform": "multi"},
	"tdx": {"mrtd": "` + mrtdRepeat + `", "rtmr1": "` + rtmr1Repeat + `", "rtmr2": "` + rtmr2Repeat + `"},
	"snp_variants": [
		{"smp": 2, "measurement": {"algorithm": "sha384", "snp_launch_digest": "` + mrtdRepeat + `"}}
	]
}`

// The register hex the loaders accept, held as constants so multiManifest is
// built at compile time.
const (
	mrtdRepeat  = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	rtmr1Repeat = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	rtmr2Repeat = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"
)

func TestManifestFamilies(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want []teetypes.Family
	}{
		{"tdx build", "testdata/confos-tdx-manifest.json", []teetypes.Family{teetypes.FamilyTDX}},
		{"snp build", "testdata/confos-snp-manifest.json", []teetypes.Family{teetypes.FamilySNP}},
		{"multi build", writeManifest(t, multiManifest), []teetypes.Family{teetypes.FamilyTDX, teetypes.FamilySNP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ManifestFamilies(tc.path)
			if err != nil {
				t.Fatalf("ManifestFamilies = _, %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ManifestFamilies = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestManifestFamiliesRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent.json")},
		{"not JSON", writeManifest(t, "not json")},
		{"older schema", writeManifest(t, `{"version": 2, "build": {"platform": "tdx"}}`)},
		{"no version", writeManifest(t, `{"build": {"platform": "tdx"}}`)},
		{"unknown platform", writeManifest(t, `{"version": 3, "build": {"platform": "sgx"}}`)},
		{"no platform", writeManifest(t, `{"version": 3, "build": {}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ManifestFamilies(tc.path); err == nil {
				t.Fatalf("ManifestFamilies = %v, nil; want an error", got)
			}
		})
	}
}

func TestLoadImageManifest(t *testing.T) {
	tdx, err := LoadImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatalf("LoadImageManifest(tdx) = _, %v", err)
	}
	if got := tdx.Family(); got != teetypes.FamilyTDX {
		t.Errorf("Family() = %q, want %q", got, teetypes.FamilyTDX)
	}
	want, err := loadTDXImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if tdx != ImageIdentity(want) {
		t.Error("LoadImageManifest did not return the pins loadTDXImageManifest loads")
	}

	snp, err := LoadImageManifest("testdata/confos-snp-manifest.json")
	if err != nil {
		t.Fatalf("LoadImageManifest(snp) = _, %v", err)
	}
	if got := snp.Family(); got != teetypes.FamilySNP {
		t.Errorf("Family() = %q, want %q", got, teetypes.FamilySNP)
	}

	// A multi manifest carries both pins; the TDX tuple wins.
	multi, err := LoadImageManifest(writeManifest(t, multiManifest))
	if err != nil {
		t.Fatalf("LoadImageManifest(multi) = _, %v", err)
	}
	if got := multi.Family(); got != teetypes.FamilyTDX {
		t.Errorf("Family() = %q, want %q for a multi-platform image", got, teetypes.FamilyTDX)
	}
}

// A file that is neither pin keeps the TDX loader's error text, which names
// the tuple a caller most often meant to supply.
func TestLoadImageManifestRejectsNeither(t *testing.T) {
	_, err := LoadImageManifest(writeManifest(t, `{"version": 3, "build": {"platform": "tdx"}}`))
	if err == nil {
		t.Fatal("LoadImageManifest = _, nil; want an error")
	}
	if !strings.Contains(err.Error(), "mrtd") {
		t.Errorf("LoadImageManifest = _, %v; want the TDX pin error text", err)
	}
}

// A multi manifest carries both shapes, so the shape alone cannot pick one:
// the named family must decide which half loads.
func TestLoadImageManifestForPicksTheNamedHalf(t *testing.T) {
	path := writeManifest(t, multiManifest)
	for _, want := range []teetypes.Family{teetypes.FamilyTDX, teetypes.FamilySNP} {
		identity, err := LoadImageManifestFor(path, want)
		if err != nil {
			t.Fatalf("LoadImageManifestFor(%q) = _, %v", want, err)
		}
		if got := identity.Family(); got != want {
			t.Errorf("LoadImageManifestFor(%q).Family() = %q", want, got)
		}
	}
}

func TestLoadImageManifestForRefusals(t *testing.T) {
	tdxPath := "testdata/confos-tdx-manifest.json"
	// An unknown family must not fall back to a shape guess: the caller asked
	// for a pin this package cannot build.
	_, err := LoadImageManifestFor(tdxPath, teetypes.FamilyUnknown)
	if err == nil {
		t.Fatal("LoadImageManifestFor(unknown) = _, nil; want an error")
	}
	for _, want := range []string{"tee family", string(teetypes.FamilySNP), string(teetypes.FamilyTDX)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	// A TDX manifest read as SNP must fail rather than yield an empty set.
	if _, err := LoadImageManifestFor(tdxPath, teetypes.FamilySNP); err == nil {
		t.Error("LoadImageManifestFor read a TDX manifest as SNP")
	}
}

// The accessors are what a caller reads a pin out through, so their values and
// their order are part of the contract.
func TestImageIdentityAccessors(t *testing.T) {
	tdx, err := LoadImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	const wantMRTD = "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1"
	variants := tdx.LaunchDigests()
	if len(variants) != 1 || variants[0].Label != "" {
		t.Fatalf("TDX LaunchDigests() = %+v, want one unlabelled variant", variants)
	}
	if got := hex.EncodeToString(variants[0].Digest[:]); got != wantMRTD {
		t.Errorf("TDX launch digest = %s, want %s", got, wantMRTD)
	}
	regs := tdx.RTMRs()
	if got := slices.Sorted(maps.Keys(regs)); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("TDX RTMRs() pins %v, want RTMR[1] and RTMR[2]", got)
	}
	var zero [Size]byte
	if regs[1] == zero || regs[2] == zero {
		t.Error("TDX RTMRs() returned an unset register")
	}

	snp, err := LoadImageManifest("testdata/confos-snp-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	// One IGVM per supported vCPU count, ascending.
	var labels []string
	for _, v := range snp.LaunchDigests() {
		labels = append(labels, v.Label)
	}
	if want := []string{"smp2", "smp4", "smp8", "smp16"}; !slices.Equal(labels, want) {
		t.Errorf("SNP LaunchDigests() labels = %v, want %v", labels, want)
	}
	const wantSMP2 = "e7df3a8f1dbe619607154ce994c1f4d7299c539b120b5560e137f7787e4ece304f270c1444b47c863fde54bc863291d7"
	if got := hex.EncodeToString(snp.LaunchDigests()[0].Digest[:]); got != wantSMP2 {
		t.Errorf("SNP smp2 digest = %s, want %s", got, wantSMP2)
	}
	if regs := snp.RTMRs(); len(regs) != 0 {
		t.Errorf("SNP RTMRs() = %v, want none", regs)
	}
}
