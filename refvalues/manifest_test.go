package refvalues

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An SNP launch measurement covers the initial vCPU state, so one image is one
// pin per SMP variant, in ascending order.
func TestFromImageManifestSNP(t *testing.T) {
	path := writeManifest(t, `{"snp_variants":[
		{"smp":4,"measurement":{"snp_launch_digest":"`+d2+`","algorithm":"sha384"}},
		{"smp":2,"measurement":{"snp_launch_digest":"`+d1+`","algorithm":"sha384"}}]}`)

	pins, err := FromImageManifest(path, "worker", teetypes.FamilySNP)
	if err != nil {
		t.Fatalf("FromImageManifest: %v", err)
	}
	if len(pins) != 2 {
		t.Fatalf("got %d pins, want 2", len(pins))
	}
	if pins[0].Name != "worker-smp2" || pins[1].Name != "worker-smp4" {
		t.Errorf("names = %q, %q; want worker-smp2, worker-smp4", pins[0].Name, pins[1].Name)
	}
	if got := hex.EncodeToString(pins[0].Digest); got != d1 {
		t.Errorf("smp2 digest = %s, want %s", got, d1)
	}
	for _, p := range pins {
		if len(p.RTMRs) != 0 {
			t.Errorf("%s pins registers, but SNP reports none: %v", p.Name, p.RTMRs)
		}
	}
}

// A TDX image pins MRTD with RTMR[1] and RTMR[2] and nothing else: RTMR[0]
// varies with the VM shape and RTMR[3] is extended at runtime.
func TestFromImageManifestTDX(t *testing.T) {
	path := writeManifest(t, `{"tdx":{"mrtd":"`+d1+`","rtmr1":"`+r1+`","rtmr2":"`+r2+`"}}`)

	pins, err := FromImageManifest(path, "worker", teetypes.FamilyTDX)
	if err != nil {
		t.Fatalf("FromImageManifest: %v", err)
	}
	if len(pins) != 1 || pins[0].Name != "worker" {
		t.Fatalf("pins = %+v, want one named worker", pins)
	}
	if got := hex.EncodeToString(pins[0].Digest); got != d1 {
		t.Errorf("mrtd = %s, want %s", got, d1)
	}
	if !bytes.Equal(pins[0].RTMRs[1], mustHex(t, r1)) || !bytes.Equal(pins[0].RTMRs[2], mustHex(t, r2)) {
		t.Errorf("registers = %v, want RTMR[1]=%s RTMR[2]=%s", pins[0].RTMRs, r1, r2)
	}
	for _, idx := range []int{0, 3} {
		if _, pinned := pins[0].RTMRs[idx]; pinned {
			t.Errorf("RTMR[%d] pinned from a manifest", idx)
		}
	}
}

// The pins a manifest yields must be a set every component loads.
func TestFromImageManifestFormats(t *testing.T) {
	path := writeManifest(t, `{"tdx":{"mrtd":"`+d1+`","rtmr1":"`+r1+`","rtmr2":"`+r2+`"}}`)
	pins, err := FromImageManifest(path, "worker", teetypes.FamilyTDX)
	if err != nil {
		t.Fatalf("FromImageManifest: %v", err)
	}
	doc, err := Format(ReferenceValues{Family: teetypes.FamilyTDX, Images: pins})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if _, err := Parse(doc); err != nil {
		t.Fatalf("Parse(Format(pins)): %v\n%s", err, doc)
	}
}

func TestFromImageManifestRejects(t *testing.T) {
	tdx := writeManifest(t, `{"tdx":{"mrtd":"`+d1+`","rtmr1":"`+r1+`","rtmr2":"`+r2+`"}}`)

	if _, err := FromImageManifest(tdx, "worker", teetypes.FamilyUnknown); err == nil {
		t.Error("FromImageManifest accepted an unknown family")
	} else if !strings.Contains(err.Error(), "tee family") {
		t.Errorf("error %q does not name the family", err)
	}
	// A TDX tuple carries no snp_variants, so reading it as SNP must fail
	// rather than yield an empty, silently unpinned set.
	if _, err := FromImageManifest(tdx, "worker", teetypes.FamilySNP); err == nil {
		t.Error("FromImageManifest read a TDX manifest as SNP")
	}
	if _, err := FromImageManifest(filepath.Join(t.TempDir(), "absent.json"), "worker", teetypes.FamilyTDX); err == nil {
		t.Error("FromImageManifest accepted a missing manifest")
	}
}
