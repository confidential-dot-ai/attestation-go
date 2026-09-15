package runtimemeasure

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// IdentityFromResult pins the image identified by a signature-verified result:
// one 48-byte launch digest and, on TDX, the required RTMR[1] and RTMR[2].
// The caller must have checked freshness and the trusted verifier before
// deriving reference values from a report. The result does not reveal an SNP
// vCPU count, so the observed launch variant has no label.
func IdentityFromResult(result *teetypes.VerificationResult) (ImageIdentity, error) {
	if err := result.Check(); err != nil {
		return nil, err
	}
	family := result.Platform.Family()
	if family != teetypes.FamilyTDX && family != teetypes.FamilySNP {
		return nil, fmt.Errorf("%w %q", ErrUnknownPlatform, result.Platform)
	}
	launch, err := result.Claims.LaunchMeasurement()
	if err != nil {
		return nil, err
	}
	digest := [Size]byte(launch)
	if family == teetypes.FamilySNP {
		// Zero is an internal slot, not an inferred vCPU count. The wrapper
		// removes the manifest-specific label while retaining its verifier.
		return observedImageIdentity{snpImagePins{BySMP: map[int][Size]byte{0: digest}}}, nil
	}
	rtmr1, err := result.Claims.RTMR(1)
	if err != nil {
		return nil, err
	}
	rtmr2, err := result.Claims.RTMR(2)
	if err != nil {
		return nil, err
	}
	return tdxImagePins{MRTD: digest, RTMR1: [Size]byte(rtmr1), RTMR2: [Size]byte(rtmr2)}, nil
}

// observedImageIdentity keeps the shared verifier while removing labels that
// a verified report cannot establish.
type observedImageIdentity struct{ ImageIdentity }

func (p observedImageIdentity) LaunchDigests() []LaunchVariant {
	variants := p.ImageIdentity.LaunchDigests()
	for i := range variants {
		variants[i].Label = ""
	}
	return variants
}
