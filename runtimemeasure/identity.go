package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ErrWrongFamily reports an image pin checked against a result from another
// TEE family. Pinned values do not compare across families — a 48-byte SNP
// launch digest is not an MRTD — so this error means the wrong pin was loaded,
// not that the wrong image booted.
var ErrWrongFamily = errors.New("image pin is for another TEE family")

// ImageIdentity is a pinned guest image, whichever family built it: the TDX
// tuple ([ImagePins]) or the SNP per-SMP launch-digest set ([SNPImagePins]).
// [LoadAnyImageManifest] returns one without the caller naming a platform.
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
}

// Family reports Intel TDX: MRTD and the RTMRs exist nowhere else.
func (p ImagePins) Family() teetypes.Family { return teetypes.FamilyTDX }

// Verify checks the verified claims against the pinned image tuple: MRTD (the
// firmware's measured regions), RTMR[1] (guest kernel) and RTMR[2] (guest
// rootfs). All three come from one build and only mean anything together.
//
// RTMR[3] is not checked here: it carries the launch anchor and the workload
// chain, which [VerifyBinding] checks.
func (p ImagePins) Verify(r *teetypes.VerificationResult) error {
	if err := checkVerified(r); err != nil {
		return err
	}
	if err := checkFamily(r.Platform, teetypes.FamilyTDX, "a TDX image tuple (MRTD + RTMR[1] + RTMR[2])"); err != nil {
		return err
	}
	launch := strings.ToLower(strings.TrimSpace(r.Claims.LaunchDigest))
	if launch == "" {
		return fmt.Errorf("verified claims carry no launch digest (MRTD)")
	}
	if want := hex.EncodeToString(p.MRTD[:]); launch != want {
		return fmt.Errorf("MRTD mismatch: node reports %s, image manifest pins %s (a different guest firmware/image booted)", launch, want)
	}
	for _, reg := range []struct {
		index   int
		meaning string
		want    [Size]byte
	}{
		{1, "guest kernel", p.RTMR1},
		{2, "guest rootfs", p.RTMR2},
	} {
		got, err := r.Claims.RTMR(reg.index)
		if err != nil {
			return fmt.Errorf("RTMR[%d] mismatch (%s): %w", reg.index, reg.meaning, err)
		}
		if !bytes.Equal(got, reg.want[:]) {
			return fmt.Errorf("RTMR[%d] mismatch (%s): node reports %x, image manifest pins %x", reg.index, reg.meaning, got, reg.want)
		}
	}
	return nil
}

// Family reports AMD SEV-SNP: the pin is a set of launch measurements.
func (p SNPImagePins) Family() teetypes.Family { return teetypes.FamilySNP }

// Verify checks the verified launch measurement against the pinned per-SMP
// set. SNP folds firmware, kernel and initial vCPU state into that one digest,
// so matching any pinned variant identifies the image as tightly as the TDX
// tuple does; which variant matched says only how many vCPUs the guest has.
//
// HOST_DATA is not checked here: it carries the launch anchor, which
// [VerifyBinding] checks.
func (p SNPImagePins) Verify(r *teetypes.VerificationResult) error {
	if err := checkVerified(r); err != nil {
		return err
	}
	if err := checkFamily(r.Platform, teetypes.FamilySNP, "an SNP per-SMP launch-digest set"); err != nil {
		return err
	}
	launch := strings.ToLower(strings.TrimSpace(r.Claims.LaunchDigest))
	if launch == "" {
		return fmt.Errorf("verified claims carry no launch digest (SNP MEASUREMENT)")
	}
	raw, err := hex.DecodeString(launch)
	if err != nil || len(raw) != Size {
		return fmt.Errorf("launch digest %q is not %d hex chars", launch, Size*2)
	}
	var got [Size]byte
	copy(got[:], raw)
	if !p.Has(got) {
		return fmt.Errorf("launch digest mismatch: node reports %s, image manifest pins %s (a different guest image booted, or a vCPU count the manifest has no variant for)", launch, p)
	}
	return nil
}

// checkVerified refuses a result whose claims no hardware signature covers.
// Every field these checks read is host-chosen until then.
func checkVerified(r *teetypes.VerificationResult) error {
	if r == nil {
		return fmt.Errorf("no verification result")
	}
	if !r.SignatureValid {
		return fmt.Errorf("verification result does not carry a valid signature, so its claims are unverified")
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
