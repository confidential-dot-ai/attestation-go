package remote

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// ImagePin is one guest image's measurement identity: its launch digest
// together with the registers measured from the same build and an optional
// anchor distinguishing the launch it was configured to trust.
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

	// Anchor pins the exact launch-bound bytes along with this image. Nil
	// leaves the binding unchecked; a non-nil empty anchor is invalid.
	// This checks the bare launch binding, with no workload extensions.
	Anchor []byte
}

// EnforceImages accepts evidence matching one pinned image whole: its launch
// digest, every register, and the launch anchor that image pins.
// Callers must first verify the hardware signature and freshness verdict.
//
// An image that pins registers cannot match evidence from a platform without
// them: the pin asked for a check the evidence cannot answer, and passing on
// the digest alone would report it as enforced. A mixed reference set still
// works, since another image pinning only its digest can match instead. SEV-SNP
// folds the guest image into its launch digest and reports no registers, so an
// SNP image measurement is its digest alone; an anchor still pins HOSTDATA.
func EnforceImages(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType) error {
	if len(images) == 0 {
		return nil
	}
	digest, err := launchDigest(resp)
	if err != nil {
		return err
	}

	// The last register or anchor mismatch is kept so a near-miss names the image it
	// nearly was, rather than the generic "nothing matched".
	var lastErr error
	for _, img := range images {
		if !bytes.Equal(digest, img.Digest) {
			continue
		}
		if len(img.RTMRs) > 0 {
			if !platform.HasRegisters() {
				lastErr = fmt.Errorf("%s: %w: %d register(s) pinned but platform %q has none",
					img.Name, ErrRTMRNotAllowed, len(img.RTMRs), platform)
				continue
			}
			if err := enforceRTMRsAgainst(resp.Result.Claims, img.RTMRs); err != nil {
				lastErr = fmt.Errorf("%s: %w", img.Name, err)
				continue
			}
		}
		if img.Anchor != nil {
			if teetypes.NormalizePlatform(string(platform)) != teetypes.NormalizePlatform(string(resp.Result.Platform)) {
				lastErr = fmt.Errorf("%s: %w: verified platform does not match evidence", img.Name, ErrAnchorNotAllowed)
				continue
			}
			if err := runtimemeasure.VerifyBinding(&resp.Result, img.Anchor, nil); err != nil {
				lastErr = fmt.Errorf("%s: %w: %w", img.Name, ErrAnchorNotAllowed, err)
				continue
			}
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: no pinned image has this launch measurement", ErrMeasurementNotAllowed)
}

// launchDigest reads the reported launch measurement, separating "the service
// reported none" — a policy miss — from a value it could not parse.
func launchDigest(resp VerifyResponse) ([]byte, error) {
	if strings.TrimSpace(resp.Result.Claims.LaunchDigest) == "" {
		return nil, fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
	}
	digest, err := resp.Result.Claims.LaunchMeasurement()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidLaunchDigest, err)
	}
	return digest, nil
}
