package refvalues

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// DigestSize is the SHA-384 width of every pinned register, launch digest and
// MRTD alike.
const DigestSize = runtimemeasure.Size

// ReferenceValues is what a verifier compares evidence against: the guest
// images one deployment accepts, on one TEE family. A verifier that cannot
// express a whole tuple flattens the set with [ReferenceValues.Flatten], which
// reports whether the flat form lost any pin.
type ReferenceValues struct {
	// Family is the hardware TEE the images were built for. One reference set
	// covers one family: a deployment mixing SNP and TDX images needs one set
	// each, because the registers mean different things.
	Family teetypes.Family

	// Images are the accepted guest images. Empty pins nothing, which accepts
	// any attested guest.
	Images []remote.ImagePin
}

// Empty reports whether the set pins nothing, so callers can warn rather than
// accept any attested peer without saying so.
func (rv ReferenceValues) Empty() bool { return len(rv.Images) == 0 }

// HasAnchors reports whether any image pins a launch anchor. Flattened digest
// and register policies cannot express these per-image bindings.
func (rv ReferenceValues) HasAnchors() bool {
	for _, img := range rv.Images {
		if img.Anchor != nil {
			return true
		}
	}
	return false
}

// Policy returns the verification policy these reference values express.
// Convert through it: a hand-written conversion that misses a field drops
// those pins and still compiles.
//
// Registers pinned without any digest have no image form (see [FromFlags]);
// a caller holding those sets Policy.RTMRs itself.
func (rv ReferenceValues) Policy() remote.Policy {
	return remote.Policy{Images: rv.Images}
}

// Digests returns every reference launch digest, for verifiers that match on
// the digest alone.
func (rv ReferenceValues) Digests() [][]byte {
	out := make([][]byte, 0, len(rv.Images))
	for _, img := range rv.Images {
		out = append(out, img.Digest)
	}
	return out
}

// hexDigests returns the pinned digests as lowercase hex, the shape [Flatten]
// renders.
func (rv ReferenceValues) hexDigests() []string {
	out := make([]string, 0, len(rv.Images))
	for _, img := range rv.Images {
		out = append(out, hex.EncodeToString(img.Digest))
	}
	return out
}

// CommonRTMRs returns the register pins shared by every image, and whether the
// images agree. A verifier that cannot express per-image tuples takes these
// pins; when uniform is false it must report that rather than drop them
// silently.
//
// uniform here answers only about registers. Anchors are a separate loss that
// [ReferenceValues.Flatten] folds in, so this reports uniform=true for an
// anchored set whose registers agree.
func (rv ReferenceValues) CommonRTMRs() (common map[int][]byte, uniform bool) {
	if len(rv.Images) == 0 {
		return nil, true
	}
	first := rv.Images[0].RTMRs
	for _, img := range rv.Images[1:] {
		if !maps.EqualFunc(first, img.RTMRs, bytes.Equal) {
			return nil, false
		}
	}
	return first, true
}

// Flatten renders the set for an interface that carries a digest list and one
// register map: every pinned digest as lowercase hex, plus the registers all
// images agree on.
//
// uniform is false when register pins differ or any image pins an anchor.
// In that case the flat form loses policy constraints, so a caller requiring
// the complete policy must refuse it rather than silently weaken admission.
func (rv ReferenceValues) Flatten() (digests []string, rtmrs map[int][]byte, uniform bool) {
	common, uniform := rv.CommonRTMRs()
	return rv.hexDigests(), common, uniform && !rv.HasAnchors()
}

// FromFlags converts the legacy flat pins into images: every digest carries
// the same registers, which is what the flat form enforced. Registers pinned
// without any digest have no image form and stay on the flat path, so
// FromFlags(nil, rtmrs) pins nothing. Repeated digests collapse to one image.
//
// The "image-N" names are placeholders that satisfy the document schema, which
// requires a name; they are diagnostic only and never matched on, so nothing
// should key off them.
func FromFlags(digests [][]byte, rtmrs map[int][]byte) ReferenceValues {
	images := make([]remote.ImagePin, 0, len(digests))
	seen := make(map[string]bool, len(digests))
	for _, d := range digests {
		if seen[string(d)] {
			continue
		}
		seen[string(d)] = true
		// Each image owns its map: callers mutate policy pins in place.
		own := maps.Clone(rtmrs)
		if len(own) == 0 {
			own = nil
		}
		images = append(images, remote.ImagePin{Name: fmt.Sprintf("image-%d", len(images)+1), Digest: d, RTMRs: own})
	}
	return ReferenceValues{Images: images}
}
