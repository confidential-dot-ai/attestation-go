package refvalues

import (
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/client"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// FromImageManifest derives the pins for one built guest image from its
// build-artifact manifest, naming them after name.
//
// An SNP launch measurement covers the initial vCPU state, so an SNP image
// yields one pin per vCPU variant, named "<name>-smp<N>". A TDX image yields
// one pin: MRTD with RTMR[1] and RTMR[2]. RTMR[0] varies with the VM shape and
// RTMR[3] is extended at runtime, so neither is ever pinned from a manifest.
//
// A family this package has no manifest shape for is an error, so a caller
// never ends up with an empty pin set that reads as "nothing to enforce".
func FromImageManifest(path, name string, fam teetypes.Family) ([]client.ImagePin, error) {
	identity, err := runtimemeasure.LoadImageManifestFor(path, fam)
	if err != nil {
		return nil, err
	}
	registers := identity.RTMRs()
	variants := identity.LaunchDigests()
	out := make([]client.ImagePin, 0, len(variants))
	for _, v := range variants {
		pin := client.ImagePin{Name: name, Digest: slices.Clone(v.Digest[:])}
		if v.Label != "" {
			pin.Name = name + "-" + v.Label
		}
		if len(registers) > 0 {
			pin.RTMRs = make(map[int][]byte, len(registers))
			for idx, reg := range registers {
				pin.RTMRs[idx] = slices.Clone(reg[:])
			}
		}
		out = append(out, pin)
	}
	return out, nil
}
