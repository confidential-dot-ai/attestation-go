package refvalues

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/client"
)

const (
	d1 = "c1e0a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009"
	d2 = "9f2c1a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"
	r1 = "77df02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
	r2 = "3e90ac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005"
)

func snpFile(images string) string {
	return `{"schema_version":"1","tee":"sev-snp","measurements":[` + images + `]}`
}

func tdxFile(images string) string {
	return `{"schema_version":"1","tee":"tdx","measurements":[` + images + `]}`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func TestParseValidSNP(t *testing.T) {
	rv, err := Parse([]byte(snpFile(
		`{"name":"worker-smp2","measurement":"` + d1 + `"},` +
			`{"name":"worker-smp4","measurement":"` + d2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rv.Family != teetypes.FamilySNP {
		t.Errorf("Family = %q, want %q", rv.Family, teetypes.FamilySNP)
	}
	if len(rv.Images) != 2 {
		t.Fatalf("got %d images, want 2", len(rv.Images))
	}
	if got := hex.EncodeToString(rv.Images[0].Digest); got != d1 {
		t.Errorf("digest = %s, want %s", got, d1)
	}
	if rv.Images[0].RTMRs != nil {
		t.Errorf("SNP image carries RTMRs: %v", rv.Images[0].RTMRs)
	}
	if rv.Empty() {
		t.Error("Empty() = true for a populated set")
	}
}

// An empty rtmr slot pins the register to all zeros; a null slot leaves it
// unchecked. The two must not collapse into each other.
func TestParseTDXRTMRSlots(t *testing.T) {
	rv, err := Parse([]byte(tdxFile(
		`{"name":"worker","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `",null,""]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := rv.Images[0].RTMRs
	if _, pinned := got[0]; pinned {
		t.Error("rtmr[0] pinned from a null slot")
	}
	if _, pinned := got[2]; pinned {
		t.Error("rtmr[2] pinned from a null slot")
	}
	if want := mustHex(t, r1); !bytes.Equal(got[1], want) {
		t.Errorf("rtmr[1] = %x, want %s", got[1], r1)
	}
	if !bytes.Equal(got[3], make([]byte, DigestSize)) {
		t.Errorf("rtmr[3] = %x, want %d zero bytes", got[3], DigestSize)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"wrong schema version", `{"schema_version":"2","tee":"tdx","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "schema_version"},
		{"missing schema version", `{"tee":"tdx","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "schema_version"},
		{"unknown tee", `{"schema_version":"1","tee":"sev","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "tee"},
		{"empty measurements", `{"schema_version":"1","tee":"tdx","measurements":[]}`, "empty"},
		{"missing measurements", `{"schema_version":"1","tee":"tdx"}`, "empty"},
		{"unknown field", snpFile(`{"name":"a","measurement":"` + d1 + `","host_data":"ab"}`), "host_data"},
		{"unknown top-level field", `{"schema_version":"1","tee":"tdx","extra":1,"measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "extra"},
		{"duplicate top-level key", `{"schema_version":"1","tee":"tdx","tee":"sev-snp","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "duplicate key"},
		{"duplicate key inside an image", tdxFile(`{"name":"a","mrtd":"` + d1 + `","mrtd":"` + d2 + `"}`), "duplicate key"},
		{"uppercase hex", snpFile(`{"name":"a","measurement":"` + strings.ToUpper(d1) + `"}`), "lowercase"},
		{"short digest", snpFile(`{"name":"a","measurement":"c1e0a7"}`), "hex chars"},
		{"non-hex digest", snpFile(`{"name":"a","measurement":"` + strings.Repeat("z", 96) + `"}`), "not hex"},
		{"missing name", snpFile(`{"measurement":"` + d1 + `"}`), "name is required"},
		{"blank name", snpFile(`{"name":"  ","measurement":"` + d1 + `"}`), "name is required"},
		{"missing measurement", snpFile(`{"name":"a"}`), "measurement is required"},
		{"missing mrtd", tdxFile(`{"name":"a"}`), "mrtd is required"},
		{"snp image with mrtd", snpFile(`{"name":"a","measurement":"` + d1 + `","mrtd":"` + d2 + `"}`), "tdx fields"},
		{"snp image with rtmr", snpFile(`{"name":"a","measurement":"` + d1 + `","rtmr":[null,"` + r1 + `"]}`), "tdx fields"},
		{"tdx image with measurement", tdxFile(`{"name":"a","mrtd":"` + d1 + `","measurement":"` + d2 + `"}`), "sev-snp field"},
		{"pinned rtmr0", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":["` + r1 + `"]}`), "rtmr[0]"},
		{"zero-pinned rtmr0", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[""]}`), "rtmr[0]"},
		{"too many rtmrs", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `","` + r2 + `","` + r1 + `","` + r2 + `"]}`), "at most"},
		{"duplicate name", snpFile(`{"name":"a","measurement":"` + d1 + `"},{"name":"a","measurement":"` + d2 + `"}`), "duplicate name"},
		{"duplicate tuple", snpFile(`{"name":"a","measurement":"` + d1 + `"},{"name":"b","measurement":"` + d1 + `"}`), "same tuple"},
		{"not an object", `[]`, "decode"},
		{"trailing data", snpFile(`{"name":"a","measurement":"`+d1+`"}`) + `{}`, "trailing data"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The error names the JSON path, so lint output points at the offending line.
func TestParseErrorNamesTheJSONPath(t *testing.T) {
	_, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `"},{"name":"b","mrtd":"` + d2 + `"},{"name":"c","mrtd":"beef"}`)))
	if err == nil || !strings.Contains(err.Error(), "measurements[2].mrtd:") {
		t.Fatalf("err = %v, want a measurements[2].mrtd path", err)
	}
}

// Two images differing only in RTMRs are distinct images, not a duplicate.
func TestParseAllowsSameMRTDDifferentRTMRs(t *testing.T) {
	if _, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]},` +
			`{"name":"b","mrtd":"` + d1 + `","rtmr":[null,"` + r2 + `"]}`))); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// Format must produce exactly what Parse read back, or a config a component
// writes is not the config it loads.
func TestFormatParseRoundTrip(t *testing.T) {
	docs := []string{
		snpFile(`{"name":"worker-smp2","measurement":"` + d1 + `"},{"name":"worker-smp4","measurement":"` + d2 + `"}`),
		tdxFile(`{"name":"worker","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `","` + r2 + `",""]}`),
		tdxFile(`{"name":"worker","mrtd":"` + d1 + `"}`),
	}
	for _, doc := range docs {
		want, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		out, err := Format(want)
		if err != nil {
			t.Fatalf("Format: %v", err)
		}
		got, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse(Format(x)): %v\n%s", err, out)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip changed the set:\ngot  %+v\nwant %+v", got, want)
		}
	}
}

// The rendered field names are what existing config files use, so an existing
// deployment's file keeps loading and keeps being written back the same way.
func TestFormatFieldNames(t *testing.T) {
	snp, err := Format(ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []client.ImagePin{{Name: "a", Digest: mustHex(t, d1)}},
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	for _, want := range []string{`"schema_version": "1"`, `"tee": "sev-snp"`, `"measurement": "` + d1 + `"`} {
		if !strings.Contains(string(snp), want) {
			t.Errorf("SNP document does not contain %s:\n%s", want, snp)
		}
	}
	tdx, err := Format(ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []client.ImagePin{{Name: "a", Digest: mustHex(t, d1), RTMRs: map[int][]byte{1: mustHex(t, r1)}}},
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	for _, want := range []string{`"tee": "tdx"`, `"mrtd": "` + d1 + `"`, `"rtmr": [`, `null,`} {
		if !strings.Contains(string(tdx), want) {
			t.Errorf("TDX document does not contain %s:\n%s", want, tdx)
		}
	}
}

// Format must refuse a set it cannot render, rather than emitting a document
// that would not load or silently dropping a pin.
func TestFormatRejects(t *testing.T) {
	tests := []struct {
		name string
		rv   ReferenceValues
		want string
	}{
		{"unknown tee", ReferenceValues{Family: "sev", Images: []client.ImagePin{{Name: "a", Digest: make([]byte, DigestSize)}}}, "tee"},
		{"rtmr on an snp image", ReferenceValues{Family: teetypes.FamilySNP, Images: []client.ImagePin{
			{Name: "a", Digest: make([]byte, DigestSize), RTMRs: map[int][]byte{1: make([]byte, DigestSize)}},
		}}, "rtmr"},
		{"rtmr index out of range", ReferenceValues{Family: teetypes.FamilyTDX, Images: []client.ImagePin{
			{Name: "a", Digest: make([]byte, DigestSize), RTMRs: map[int][]byte{7: make([]byte, DigestSize)}},
		}}, "rtmr[7]"},
		{"rtmr zero pinned", ReferenceValues{Family: teetypes.FamilyTDX, Images: []client.ImagePin{
			{Name: "a", Digest: make([]byte, DigestSize), RTMRs: map[int][]byte{0: make([]byte, DigestSize)}},
		}}, "rtmr[0]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Format(tc.rv)
			if err == nil {
				t.Fatalf("Format accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Serve accepts what Format refuses — a component enforcing nothing — and
// ParseServed reads it back without demanding a pin.
func TestServeEmptySet(t *testing.T) {
	doc, err := Serve(ReferenceValues{Family: teetypes.FamilyTDX})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if _, err := Parse(doc); err == nil {
		t.Error("Parse accepted an empty served document")
	}
	rv, err := ParseServed(doc)
	if err != nil {
		t.Fatalf("ParseServed: %v", err)
	}
	if rv.Family != teetypes.FamilyTDX || !rv.Empty() {
		t.Errorf("ParseServed = %+v, want an empty tdx set", rv)
	}
}

func TestDiff(t *testing.T) {
	want, err := Parse([]byte(snpFile(
		`{"name":"a","measurement":"` + d1 + `"},{"name":"b","measurement":"` + d2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Same pin as want's first image under another name, plus one it lacks.
	got, err := Parse([]byte(snpFile(
		`{"name":"renamed","measurement":"` + d1 + `"},{"name":"c","measurement":"` + r2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	missing, extra := Diff(want, got)
	if len(missing) != 1 || hex.EncodeToString(missing[0].Digest) != d2 {
		t.Errorf("missing = %+v, want the %s pin", missing, d2)
	}
	if len(extra) != 1 || hex.EncodeToString(extra[0].Digest) != r2 {
		t.Errorf("extra = %+v, want the %s pin", extra, r2)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.json")
	if err := os.WriteFile(path, []byte(snpFile(`{"name":"a","measurement":"`+d1+`"}`)), 0o600); err != nil {
		t.Fatal(err)
	}
	rv, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rv.Images) != 1 {
		t.Errorf("got %d images, want 1", len(rv.Images))
	}
	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("Load accepted a missing file")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(snpFile(`{"name":"a","measurement":"` + d1 + `"}`))
	f.Add(tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `","` + r2 + `",""]}`))
	f.Fuzz(func(t *testing.T, doc string) {
		rv, err := Parse([]byte(doc))
		if err != nil {
			return
		}
		// Anything that parses must be usable as a policy without panicking
		// and must actually pin something.
		if rv.Empty() {
			t.Fatalf("accepted a document that pins nothing: %q", doc)
		}
		for _, img := range rv.Images {
			if len(img.Digest) != DigestSize {
				t.Fatalf("accepted a %d-byte digest", len(img.Digest))
			}
			for idx, v := range img.RTMRs {
				if idx == 0 {
					t.Fatalf("accepted a pin on RTMR[0]")
				}
				if len(v) != DigestSize {
					t.Fatalf("accepted a %d-byte RTMR pin", len(v))
				}
			}
		}
		rv.CommonRTMRs()
		rv.DigestSet()
		if _, err := Format(rv); err != nil {
			t.Fatalf("a parsed set does not format: %v", err)
		}
	})
}
