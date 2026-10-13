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

	// Registers pins runtime measurement registers by index. An absent index is
	// unchecked; an all-zero value pins the register to zero. Empty on
	// platforms without registers.
	Registers map[int][]byte

	// Anchor pins the exact launch-bound bytes along with this image. Nil
	// leaves the binding unchecked; a non-nil empty anchor is invalid. On TDX
	// the binding may carry runtime extensions on top of the anchor seed; see
	// [EnforceImagesWithRuntimeLog].
	Anchor []byte

	// AcceptExtension, when set, judges each runtime extension the quote
	// proves on top of Anchor; an error refuses the image. Nil accepts any
	// replayed list, which still proves the anchor. Unused without Anchor,
	// and never called on SEV-SNP, where no extension is provable: a peer's
	// list there is ignored, not refused.
	AcceptExtension func(digest string) error
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
//
// It requires the bare anchor seed, with no runtime extensions; a guest that
// extends RTMR[3] at runtime is checked with [EnforceImagesWithRuntimeLog].
func EnforceImages(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType) error {
	return EnforceImagesWithRuntimeLog(resp, images, platform, nil)
}

// EnforceImagesWithRuntimeLog is [EnforceImages] for a guest that extends
// RTMR[3] after launch. claimed is the guest's runtime extension list, as
// canonical digests in extend order (see [runtimemeasure.Journal]).
//
// For an image pinning Anchor, the binding must equal the anchor seed
// extended with some prefix claimed[:k] ([runtimemeasure.MatchBindingPrefix]),
// and AcceptExtension must accept each of claimed[:k]. The guest records
// before it extends, so the list may run ahead of the quote; entries past k
// were not measured into it, prove nothing, and are not judged. On SEV-SNP
// k is always 0. A nil claimed requires the bare seed.
//
// Each anchored image replays claimed at one SHA-384 per entry, so bound a
// list taken from a peer before passing it; armtls caps it at 512.
func EnforceImagesWithRuntimeLog(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType, claimed []string) error {
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
		if len(img.Registers) > 0 {
			if !platform.HasRegisters() {
				lastErr = fmt.Errorf("%s: %w: %d register(s) pinned but platform %q has none",
					img.Name, ErrRegistersNotAllowed, len(img.Registers), platform)
				continue
			}
			if err := enforceRTMRsAgainst(resp.Result.Claims, img.Registers); err != nil {
				lastErr = fmt.Errorf("%s: %w", img.Name, err)
				continue
			}
		}
		if img.Anchor != nil {
			if err := enforceAnchor(&resp.Result, img, claimed); err != nil {
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

// enforceAnchor requires the binding to prove img.Anchor plus a prefix of
// claimed, and img.AcceptExtension to accept that prefix. MatchBindingPrefix
// owns every platform question the anchor raises: which field carries the
// binding, and which platforms refuse it.
func enforceAnchor(r *teetypes.VerificationResult, img ImagePin, claimed []string) error {
	k, err := runtimemeasure.MatchBindingPrefix(r, img.Anchor, claimed)
	if err != nil {
		return err
	}
	if img.AcceptExtension == nil {
		return nil
	}
	for _, d := range claimed[:k] {
		if err := img.AcceptExtension(d); err != nil {
			return fmt.Errorf("runtime extension %s refused: %w", d, err)
		}
	}
	return nil
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
