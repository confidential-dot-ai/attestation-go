package refvalues

import (
	"bytes"
	"slices"
	"testing"
)

// The flat flags enforced "digest in the list AND the one RTMR set". The
// converted images must say exactly that.
func TestFromFlagsMatchesFlatSemantics(t *testing.T) {
	b1, b2 := mustHex(t, d1), mustHex(t, d2)
	pins := mustHex(t, r1)

	rv := FromFlags([][]byte{b1, b2}, map[int][]byte{1: pins})
	if len(rv.Images) != 2 {
		t.Fatalf("got %d images, want 2", len(rv.Images))
	}
	for i, img := range rv.Images {
		if !bytes.Equal(img.RTMRs[1], pins) {
			t.Errorf("image %d does not carry the shared RTMR pin", i)
		}
	}
	common, uniform := rv.CommonRTMRs()
	if !uniform || !bytes.Equal(common[1], pins) {
		t.Errorf("CommonRTMRs = %v, %v; want the shared pin", common, uniform)
	}
}

// --rtmrs without --measurements has no image form; it stays on the flat path,
// so the converted set must report itself as pinning nothing rather than
// claiming a digest gate the operator never configured.
func TestFromFlagsRTMRsWithoutDigests(t *testing.T) {
	rv := FromFlags(nil, map[int][]byte{1: mustHex(t, r1)})
	if len(rv.Images) != 0 {
		t.Errorf("got %d images, want 0", len(rv.Images))
	}
	if !rv.Empty() {
		t.Error("Empty() = false for a set with no images")
	}
	if len(rv.Digests()) != 0 {
		t.Error("Digests() is non-empty for a set with no images")
	}
	if len(rv.Policy().Images) != 0 {
		t.Error("Policy() pins images for a set with none")
	}
}

// Images must not share one RTMR map: consumers assign to policy pins.
func TestFromFlagsImagesOwnTheirRTMRs(t *testing.T) {
	rv := FromFlags([][]byte{mustHex(t, d1), mustHex(t, d2)}, map[int][]byte{1: mustHex(t, r1)})

	rv.Images[0].RTMRs[2] = make([]byte, DigestSize)
	if _, leaked := rv.Images[1].RTMRs[2]; leaked {
		t.Error("mutating one image's RTMRs changed another's")
	}
}

func TestEmptySet(t *testing.T) {
	if !(ReferenceValues{}).Empty() {
		t.Error("zero ReferenceValues is not Empty()")
	}
	if !FromFlags(nil, nil).Empty() {
		t.Error("FromFlags(nil, nil) is not Empty()")
	}
}

// Every verifying path builds its policy here, so a field dropped in the
// conversion would silently unpin without failing to compile.
func TestPolicyCarriesEveryImage(t *testing.T) {
	rv, err := Parse([]byte(tdxFile(
		`{"name":"worker","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := rv.Policy()
	if len(policy.Images) != 1 || policy.Images[0].Name != "worker" {
		t.Fatalf("Images dropped in conversion: %+v", policy.Images)
	}
	if !bytes.Equal(policy.Images[0].Digest, mustHex(t, d1)) {
		t.Errorf("digest = %x, want %s", policy.Images[0].Digest, d1)
	}
	if !bytes.Equal(policy.Images[0].RTMRs[1], mustHex(t, r1)) {
		t.Errorf("RTMR[1] = %x, want %s", policy.Images[0].RTMRs[1], r1)
	}
}

// A verifier that cannot express per-image tuples must be able to tell that
// the images disagree, rather than silently taking the first.
func TestFlattenReportsDisagreement(t *testing.T) {
	rv, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]},` +
			`{"name":"b","mrtd":"` + d2 + `","rtmr":[null,"` + r2 + `"]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	digests, rtmrs, uniform := rv.Flatten()
	if uniform {
		t.Error("Flatten reported agreement across differing images")
	}
	if rtmrs != nil {
		t.Errorf("rtmrs = %v, want nil when the images disagree", rtmrs)
	}
	if len(digests) != 2 || digests[0] != d1 || digests[1] != d2 {
		t.Errorf("digests = %v, want [%s %s]", digests, d1, d2)
	}
}

func TestFlattenUniform(t *testing.T) {
	rv, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]},` +
			`{"name":"b","mrtd":"` + d2 + `","rtmr":[null,"` + r1 + `"]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	digests, rtmrs, uniform := rv.Flatten()
	if !uniform || len(digests) != 2 || !bytes.Equal(rtmrs[1], mustHex(t, r1)) {
		t.Errorf("Flatten = %v, %v, %v; want both digests and the shared pin", digests, rtmrs, uniform)
	}
}

func TestDigestAccessors(t *testing.T) {
	rv, err := Parse([]byte(snpFile(
		`{"name":"a","measurement":"` + d1 + `"},{"name":"b","measurement":"` + d2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := len(rv.Digests()); got != 2 {
		t.Errorf("Digests() len = %d, want 2", got)
	}
	if got := rv.hexDigests(); !slices.Equal(got, []string{d1, d2}) {
		t.Errorf("hexDigests() = %v, want both digests", got)
	}
}
