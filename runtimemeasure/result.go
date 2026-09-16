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
		// The single slot holds the one digest the report carried; observed
		// pins are reported unlabelled, since nothing here names a vCPU count.
		return snpImagePins{BySMP: map[int][Size]byte{0: digest}, observed: true}, nil
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
