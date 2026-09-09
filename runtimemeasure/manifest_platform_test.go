package runtimemeasure

import (
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

// The register hex the loaders accept, spelled as constants so they can build
// the manifest above at compile time.
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

func TestLoadAnyImageManifest(t *testing.T) {
	tdx, err := LoadAnyImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatalf("LoadAnyImageManifest(tdx) = _, %v", err)
	}
	if got := tdx.Family(); got != teetypes.FamilyTDX {
		t.Errorf("Family() = %q, want %q", got, teetypes.FamilyTDX)
	}
	want, err := LoadImageManifest("testdata/confos-tdx-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if tdx != ImageIdentity(want) {
		t.Error("LoadAnyImageManifest did not return the pins LoadImageManifest loads")
	}

	snp, err := LoadAnyImageManifest("testdata/confos-snp-manifest.json")
	if err != nil {
		t.Fatalf("LoadAnyImageManifest(snp) = _, %v", err)
	}
	if got := snp.Family(); got != teetypes.FamilySNP {
		t.Errorf("Family() = %q, want %q", got, teetypes.FamilySNP)
	}

	// A multi manifest carries both pins; the TDX tuple wins.
	multi, err := LoadAnyImageManifest(writeManifest(t, multiManifest))
	if err != nil {
		t.Fatalf("LoadAnyImageManifest(multi) = _, %v", err)
	}
	if got := multi.Family(); got != teetypes.FamilyTDX {
		t.Errorf("Family() = %q, want %q for a multi-platform image", got, teetypes.FamilyTDX)
	}
}

// A file that is neither pin keeps the TDX loader's error text, which names
// the tuple a caller most often meant to supply.
func TestLoadAnyImageManifestRejectsNeither(t *testing.T) {
	_, err := LoadAnyImageManifest(writeManifest(t, `{"version": 3, "build": {"platform": "tdx"}}`))
	if err == nil {
		t.Fatal("LoadAnyImageManifest = _, nil; want an error")
	}
	if !strings.Contains(err.Error(), "mrtd") {
		t.Errorf("LoadAnyImageManifest = _, %v; want the TDX pin error text", err)
	}
}
