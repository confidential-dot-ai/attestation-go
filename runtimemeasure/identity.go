package runtimemeasure

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ErrWrongFamily reports an image pin checked against a result from another
// TEE family. Pinned values do not compare across families — a 48-byte SNP
// launch digest is not an MRTD — so this error means the wrong pin was loaded,
// not that the wrong image booted.
var ErrWrongFamily = errors.New("image pin is for another TEE family")

// LaunchVariant is one launch measurement a pinned image can produce.
type LaunchVariant struct {
	// Label tells variants of one image apart: "smp4" for an SNP build's
	// 4-vCPU digest, "" when the image has a single launch digest (TDX).
	Label  string
	Digest [Size]byte
}

// ImageIdentity is a pinned guest image, whichever family built it: the TDX
// MRTD + RTMR[1] + RTMR[2] tuple, or the SNP per-SMP launch-digest set.
// [LoadImageManifest] returns one without the caller naming a platform, and
// the concrete shapes stay unexported so a caller cannot pin one family by
// accident.
//
// It answers "is this the image I pinned", and nothing about what the guest
// did after launch. A full node check is both halves:
//
//	identity.Verify(r)                          // the pinned image booted
//	VerifyBinding(r, anchor, workloadDigests)   // it was launched for this
//	                                            // anchor and measured these
//
// Verify alone accepts any guest built from the pinned image, including one
// launched for someone else's anchor.
type ImageIdentity interface {
	// Verify checks r's signature-verified launch claims against the pinned
	// image, and fails closed on absent or malformed claims.
	Verify(r *teetypes.VerificationResult) error

	// Family is the TEE family the pin describes. A result from another
	// family is refused rather than compared.
	Family() teetypes.Family

	// LaunchDigests returns every launch measurement the pinned image can
	// report, in a deterministic order (ascending SMP on SNP).
	LaunchDigests() []LaunchVariant

	// RTMRs returns the registers pinned from the build: RTMR[1] and RTMR[2]
	// on TDX, empty on SNP.
	RTMRs() map[int][Size]byte
}

// Family reports Intel TDX: MRTD and the RTMRs exist nowhere else.
func (p tdxImagePins) Family() teetypes.Family { return teetypes.FamilyTDX }

// LaunchDigests reports the one launch measurement a TDX image has: its MRTD,
// unlabelled because the tuple does not vary with the VM shape.
func (p tdxImagePins) LaunchDigests() []LaunchVariant {
	return []LaunchVariant{{Digest: p.MRTD}}
}

// RTMRs reports the two registers the build pins: RTMR[1] (guest kernel) and
// RTMR[2] (guest rootfs). RTMR[0] varies with the VM shape and RTMR[3] is
// extended at runtime, so neither comes from a manifest.
func (p tdxImagePins) RTMRs() map[int][Size]byte {
	return map[int][Size]byte{1: p.RTMR1, 2: p.RTMR2}
}

// Verify checks the verified claims against the pinned image tuple: MRTD (the
// firmware's measured regions), RTMR[1] (guest kernel) and RTMR[2] (guest
// rootfs). All three come from one build and only mean anything together.
//
// RTMR[3] is not checked here: it carries the launch anchor and the workload
// chain, which [VerifyBinding] checks.
func (p tdxImagePins) Verify(r *teetypes.VerificationResult) error {
	if err := r.Check(); err != nil {
		return err
	}
	if err := checkFamily(r.Platform, teetypes.FamilyTDX, "a TDX image tuple (MRTD + RTMR[1] + RTMR[2])"); err != nil {
		return err
	}
	if strings.TrimSpace(r.Claims.LaunchDigest) == "" {
		return fmt.Errorf("verified claims carry no launch digest (MRTD)")
	}
	launch, err := r.Claims.LaunchMeasurement()
	if err != nil {
		return fmt.Errorf("MRTD: %w", err)
	}
	if !bytes.Equal(launch, p.MRTD[:]) {
		return fmt.Errorf("MRTD mismatch: node reports %x, image manifest pins %x (a different guest firmware/image booted)", launch, p.MRTD)
	}
	if err := r.Claims.CheckRTMRs(map[int][]byte{1: p.RTMR1[:], 2: p.RTMR2[:]}); err != nil {
		return fmt.Errorf("image pin mismatch: %w (RTMR[1] is the guest kernel, RTMR[2] the guest rootfs)", err)
	}
	return nil
}

// Family reports AMD SEV-SNP: the pin is a set of launch measurements.
func (p snpImagePins) Family() teetypes.Family { return teetypes.FamilySNP }

// LaunchDigests reports the pinned launch digests in ascending SMP order, one
// per vCPU count the build ships an IGVM for, labelled "smp<N>".
func (p snpImagePins) LaunchDigests() []LaunchVariant {
	out := make([]LaunchVariant, 0, len(p.BySMP))
	for _, smp := range slices.Sorted(maps.Keys(p.BySMP)) {
		out = append(out, LaunchVariant{
			Label:  fmt.Sprintf("smp%d", smp),
			Digest: p.BySMP[smp],
		})
	}
	return out
}

// RTMRs reports none: SNP folds firmware, kernel and initial vCPU state into
// the launch measurement and has no runtime registers to pin.
func (p snpImagePins) RTMRs() map[int][Size]byte { return nil }

// Verify checks the verified launch measurement against the pinned per-SMP
// set. SNP folds firmware, kernel and initial vCPU state into that one digest,
// so matching any pinned variant identifies the image as tightly as the TDX
// tuple does; which variant matched says only how many vCPUs the guest has.
//
// HOST_DATA is not checked here: it carries the launch anchor, which
// [VerifyBinding] checks.
func (p snpImagePins) Verify(r *teetypes.VerificationResult) error {
	if err := r.Check(); err != nil {
		return err
	}
	if err := checkFamily(r.Platform, teetypes.FamilySNP, "an SNP per-SMP launch-digest set"); err != nil {
		return err
	}
	if strings.TrimSpace(r.Claims.LaunchDigest) == "" {
		return fmt.Errorf("verified claims carry no launch digest (SNP MEASUREMENT)")
	}
	raw, err := r.Claims.LaunchMeasurement()
	if err != nil {
		return err
	}
	var got [Size]byte
	copy(got[:], raw)
	if !p.has(got) {
		return fmt.Errorf("launch digest mismatch: node reports %x, image manifest pins %s (a different guest image booted, or a vCPU count the manifest has no variant for)", raw, p)
	}
	return nil
}

// checkFamily refuses a result from the wrong family, naming what the pin
// holds so the error points at the pin rather than at the node.
func checkFamily(p teetypes.PlatformType, want teetypes.Family, pin string) error {
	if got := p.Family(); got != want {
		return fmt.Errorf("%w: verification result is from platform %q, but the pin is %s (family %q)", ErrWrongFamily, p, pin, want)
	}
	return nil
}
