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
// it was launched with, whole or by digest.
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
	// An empty file, or one set alongside AcceptExtension, which a launch-file
	// binding never calls, is refused with [ErrLaunchFileNotAllowed].
	LaunchFile []byte

	// LaunchFileDigest pins the launch configuration file the guest was
	// launched with by its [runtimemeasure.LaunchFileDigest] alone: 32 bytes
	// on SEV-SNP, 48 on TDX. Like Anchor, the binding may carry runtime
	// extensions on top of it, judged by AcceptExtension. Nil leaves the
	// binding unchecked. A digest [runtimemeasure.CheckLaunchFileDigest]
	// refuses for the verified family is refused with
	// [ErrLaunchFileNotAllowed] before any evidence is matched.
	//
	// Anchor, LaunchFile and LaunchFileDigest pin the same hardware field, so
	// a pin setting more than one is refused with [ErrLaunchFileNotAllowed].
	LaunchFileDigest []byte

	// AcceptExtension judges each runtime extension the quote proves on top
	// of Anchor or LaunchFileDigest. A refusal fails with that binding's
	// sentinel wrapping the returned error, so errors.Is reaches the hook's
	// own. Nil refuses any proven extension, requiring the bare seed as
	// [EnforceImages] does; func(string) error { return nil } accepts any
	// list that replays. Unused without either, and never called on
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
// An image pinning LaunchFileDigest is matched as one pinning Anchor, with
// [runtimemeasure.MatchLaunchFileDigestPrefix]. An image pinning LaunchFile
// requires the bare binding, so claimed says nothing about it: a guest
// launched with a pinned file extends nothing on top of it.
//
// Each Anchor or LaunchFileDigest image replays claimed at one SHA-384 per
// entry, so bound a list taken from a peer before passing it; armtls caps it
// at 256.
func EnforceImagesWithRuntimeLog(resp VerifyResponse, images []ImagePin, platform teetypes.PlatformType, claimed []string) error {
	if len(images) == 0 {
		return nil
	}
	if err := checkVerifiedPlatform(resp, platform); err != nil {
		return err
	}
	if err := checkLaunchBindingPins(images, platform.Family()); err != nil {
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
				lastErr = fmt.Errorf("%s: %w", img.Name, errRegistersOffPlatform(len(img.Registers), platform))
				continue
			}
			if err := enforceRTMRsAgainst(resp.Result.Claims, img.Registers); err != nil {
				lastErr = fmt.Errorf("%s: %w", img.Name, err)
				continue
			}
		}
		if img.Anchor != nil {
			if err := enforceReplayedBinding(&resp.Result, img.Anchor, claimed, runtimemeasure.MatchBindingPrefix, img.AcceptExtension); err != nil {
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
		if img.LaunchFileDigest != nil {
			if err := enforceReplayedBinding(&resp.Result, img.LaunchFileDigest, claimed, runtimemeasure.MatchLaunchFileDigestPrefix, img.AcceptExtension); err != nil {
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

// bindingMatcher returns the k for which r's binding proves bound plus
// claimed[:k]: [runtimemeasure.MatchBindingPrefix] or
// [runtimemeasure.MatchLaunchFileDigestPrefix].
type bindingMatcher func(r *teetypes.VerificationResult, bound []byte, claimed []string) (int, error)

// enforceReplayedBinding requires match to prove bound plus a prefix of
// claimed, and accept to accept that prefix; a nil accept refuses any. The
// matcher owns every platform question the binding raises: which field
// carries it, and which platforms refuse it.
func enforceReplayedBinding(r *teetypes.VerificationResult, bound []byte, claimed []string, match bindingMatcher, accept func(string) error) error {
	k, err := match(r, bound, claimed)
	if err != nil {
		return err
	}
	proven := claimed[:k]
	if len(proven) > 0 && accept == nil {
		return fmt.Errorf("RTMR[3] proves %d runtime extension(s), but the pin sets no AcceptExtension", len(proven))
	}
	for _, d := range proven {
		if err := accept(d); err != nil {
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

// checkLaunchBindingPins refuses a pin that cannot mean what it says: its
// launch bindings all pin one hardware field, an empty file binds nothing, a
// digest must pass [runtimemeasure.CheckLaunchFileDigest] for the verified
// family, and AcceptExtension judges extensions a launch-file binding does not
// admit.
func checkLaunchBindingPins(images []ImagePin, family teetypes.Family) error {
	for _, img := range images {
		bindings := 0
		if img.Anchor != nil {
			bindings++
		}
		if img.LaunchFile != nil {
			bindings++
		}
		if img.LaunchFileDigest != nil {
			bindings++
		}
		if bindings > 1 {
			return fmt.Errorf("%s: %w: the pin sets more than one of Anchor, LaunchFile and LaunchFileDigest", img.Name, ErrLaunchFileNotAllowed)
		}
		if img.LaunchFile != nil && len(img.LaunchFile) == 0 {
			return fmt.Errorf("%s: %w: the launch file pin is empty", img.Name, ErrLaunchFileNotAllowed)
		}
		if img.LaunchFile != nil && img.AcceptExtension != nil {
			return fmt.Errorf("%s: %w: the pin sets AcceptExtension, which a launch-file binding never calls", img.Name, ErrLaunchFileNotAllowed)
		}
		if img.LaunchFileDigest != nil {
			if err := runtimemeasure.CheckLaunchFileDigest(family, img.LaunchFileDigest); err != nil {
				return fmt.Errorf("%s: %w: launch file digest %w", img.Name, ErrLaunchFileNotAllowed, err)
			}
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
