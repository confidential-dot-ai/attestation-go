package runtimemeasure

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ErrNoAnchor reports that a verified init-data claim carries no anchor
// digest: the field is absent, the wrong width, or padded with something other
// than zeros. A guest launched with no init-data document reports all zeros,
// which is a valid-width claim, so callers must still compare the anchor they
// get against the document they expect.
var ErrNoAnchor = errors.New("init-data claim is not an anchor digest")

// InitDataAnchor returns the 32-byte SHA-256 anchor a verified result commits
// in its init-data claim: the digest of the init-data document the guest was
// launched with.
//
// The two families carry the same 32 bytes in fields of different widths,
// which InitDataAnchor resolves:
//
//   - AMD SEV-SNP puts it in HOST_DATA, which is 32 bytes wide: verbatim.
//   - Intel TDX puts it in MRCONFIGID, which is 48 bytes wide: the anchor
//     zero-padded. The padding must be zero, or the prefix is a slice of some
//     other 48-byte value rather than an anchor.
//
// [HostData] is the producer side: it computes the same digest over the exact
// document bytes, for a launcher committing the field or a verifier deciding
// what the field should hold.
//
// Like [Binding] it takes a whole result, because an unverified init-data claim
// is host-chosen on both platforms. It refuses az-snp, where the paravisor owns
// HOST_DATA and the field says nothing about the guest's init data.
func InitDataAnchor(r *teetypes.VerificationResult) ([]byte, error) {
	if err := checkVerified(r); err != nil {
		return nil, err
	}
	if err := checkBindingPlatform(r.Platform); err != nil {
		return nil, err
	}
	claim := r.Claims.InitData
	if r.Platform.Family() == teetypes.FamilySNP {
		if len(claim) != HostDataSize {
			return nil, fmt.Errorf("%w: HOST_DATA is %d bytes, want %d", ErrNoAnchor, len(claim), HostDataSize)
		}
		return bytes.Clone(claim), nil
	}
	if len(claim) != Size {
		return nil, fmt.Errorf("%w: MRCONFIGID is %d bytes, want %d", ErrNoAnchor, len(claim), Size)
	}
	for _, b := range claim[HostDataSize:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: %d-byte MRCONFIGID is not a zero-padded %d-byte digest", ErrNoAnchor, Size, HostDataSize)
		}
	}
	return bytes.Clone(claim[:HostDataSize]), nil
}
