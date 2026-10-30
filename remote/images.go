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
// launch binding — the anchor it was configured to trust, or the launch file
// it was launched with.
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

	// LaunchFile pins the exact bytes of the launch configuration file the
	// guest was launched with. The binding must carry that file alone, with no
	// runtime extension on top of it. Nil leaves the binding unchecked.
	//
	// An empty file, or one set alongside Anchor, which is the same hardware
	// field, or alongside AcceptExtension, which a launch-file binding never
	// calls, is refused with [ErrLaunchFileNotAllowed].
	LaunchFile []byte

	// AcceptExtension judges each runtime extension the quote proves on top
	// of Anchor. A refusal fails with [ErrAnchorNotAllowed] wrapping the
	// returned error, so errors.Is reaches the hook's own sentinel. Nil
	// refuses any proven extension, requiring the bare anchor seed as
	// [EnforceImages] does; func(string) error { return nil } accepts any
	// list that replays. Unused without Anchor, and never called on
	// SEV-SNP, where no extension is provable: a well-formed list there is
	// ignored, though a non-canonical entry still fails.
	AcceptExtension func(digest string) error
}

// EnforceImages accepts evidence matching one pinned image whole: its launch
// digest, every register, and the launch binding that image pins.
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
// and AcceptExtension must accept each of claimed[:k]; an image without
// AcceptExtension requires k = 0. The guest records
// before it extends, so the list may run ahead of the quote; entries past k
// were not measured into it, prove nothing, and are not judged. On SEV-SNP
// k is always 0. A nil claimed requires the bare seed.
//
// An image pinning LaunchFile requires the bare binding, so claimed says
// nothing about it: a guest launched with a pinned file extends nothing on top
// of it.
//
// Each anchored image replays claimed at one SHA-384 per entry, so bound a
// list taken from a peer before passing it; armtls caps it at 256.
func EnforceImagesWithRuntimeLog(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType, claimed []string) error {
	if len(images) == 0 {
		return nil
	}
	if err := checkVerifiedPlatform(resp, platform); err != nil {
		return err
	}
	if err := checkLaunchFilePins(images); err != nil {
		return err
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
		if img.LaunchFile != nil {
			if err := enforceLaunchFile(&resp.Result, img); err != nil {
				lastErr = fmt.Errorf("%s: %w: %w", img.Name, ErrLaunchFileNotAllowed, err)
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
	if k == 0 {
		return nil
	}
	if img.AcceptExtension == nil {
		return fmt.Errorf("RTMR[3] proves %d runtime extension(s), but the pin sets no AcceptExtension", k)
	}
	for _, d := range claimed[:k] {
		if err := img.AcceptExtension(d); err != nil {
			return fmt.Errorf("runtime extension %s refused: %w", d, err)
		}
	}
	return nil
}

// enforceLaunchFile requires the binding to prove img.LaunchFile and nothing
// else. VerifyBinding owns every platform question the file raises: which
// field carries the binding, and which platforms refuse it.
func enforceLaunchFile(r *teetypes.VerificationResult, img ImagePin) error {
	var noRuntimeExtensions []string
	return runtimemeasure.VerifyBinding(r, img.LaunchFile, noRuntimeExtensions)
}

// checkLaunchFilePins refuses a launch-file pin that cannot mean what it says:
// an empty file binds nothing, Anchor is the same hardware field, and
// AcceptExtension judges extensions a launch-file binding does not admit.
func checkLaunchFilePins(images []ImagePin) error {
	for _, img := range images {
		if img.LaunchFile == nil {
			continue
		}
		if len(img.LaunchFile) == 0 {
			return fmt.Errorf("%s: %w: the launch file pin is empty", img.Name, ErrLaunchFileNotAllowed)
		}
		if img.Anchor != nil {
			return fmt.Errorf("%s: %w: the pin sets both Anchor and LaunchFile", img.Name, ErrLaunchFileNotAllowed)
		}
		if img.AcceptExtension != nil {
			return fmt.Errorf("%s: %w: the pin sets AcceptExtension, which a launch-file binding never calls", img.Name, ErrLaunchFileNotAllowed)
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
