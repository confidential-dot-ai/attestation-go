package apiclient

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ImagePin is one guest image's measurement identity: its launch digest
// together with the registers measured from the same build.
//
// A launch digest and its registers only mean anything together — two images
// built against the same firmware share a TDX MRTD — so a pin is matched whole
// or not at all. Pinning the digest and the registers separately would accept a
// digest from one build paired with another build's registers.
type ImagePin struct {
	// Name identifies the image in diagnostics. It carries no matching
	// semantics.
	Name string

	// Digest is the SEV-SNP launch measurement or the TDX MRTD, 48 bytes.
	Digest []byte

	// RTMRs pins runtime measurement registers by index. An absent index is
	// unchecked; an all-zero value pins the register to zero. Empty on
	// platforms without registers.
	RTMRs map[int][]byte
}

// EnforceImages accepts evidence matching one pinned image whole: its launch
// digest and every register that image pins.
//
// An image that pins registers cannot match evidence from a platform without
// them: the pin asked for a check the evidence cannot answer, and passing on
// the digest alone would report it as enforced. A mixed reference set still
// works, since another image pinning only its digest can match instead. SEV-SNP
// folds the guest image into its launch digest and reports no registers, so an
// SNP pin is its digest alone.
func EnforceImages(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType) error {
	if len(images) == 0 {
		return nil
	}
	digest, err := launchDigest(resp)
	if err != nil {
		return err
	}

	// The last register mismatch is kept so a near-miss reports which image it
	// nearly was, rather than the generic "nothing matched".
	var lastErr error
	for _, img := range images {
		if !bytes.Equal(digest, img.Digest) {
			continue
		}
		if len(img.RTMRs) == 0 {
			return nil
		}
		if !platform.IsTDX() {
			lastErr = fmt.Errorf("%s: %w: %d register(s) pinned but platform %q has none",
				img.Name, ErrRTMRNotAllowed, len(img.RTMRs), platform)
			continue
		}
		if err := enforceRTMRsAgainst(resp.Result.Claims, img.RTMRs); err != nil {
			lastErr = fmt.Errorf("%s: %w", img.Name, err)
			continue
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: no pinned image has this launch measurement", ErrMeasurementNotAllowed)
}

// launchDigest decodes and width-checks the reported launch measurement.
func launchDigest(resp VerifyResponse) ([]byte, error) {
	raw := strings.ToLower(strings.TrimSpace(resp.Result.Claims.LaunchDigest))
	if raw == "" {
		return nil, fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
	}
	digest, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: launch digest is not hex: %w", ErrInvalidLaunchDigest, err)
	}
	if len(digest) != sha512.Size384 {
		return nil, fmt.Errorf("%w: launch digest is %d bytes, want %d", ErrInvalidLaunchDigest, len(digest), sha512.Size384)
	}
	return digest, nil
}
