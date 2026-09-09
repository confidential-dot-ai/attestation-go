package refvalues

import (
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/apiclient"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
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
// cannot end up with an empty pin set that reads as "nothing to enforce".
func FromImageManifest(path, name string, fam teetypes.Family) ([]apiclient.ImagePin, error) {
	switch fam {
	case teetypes.FamilySNP:
		pins, err := runtimemeasure.LoadSNPImageManifest(path)
		if err != nil {
			return nil, err
		}
		out := make([]apiclient.ImagePin, 0, len(pins.BySMP))
		for _, smp := range slices.Sorted(maps.Keys(pins.BySMP)) {
			d := pins.BySMP[smp]
			out = append(out, apiclient.ImagePin{
				Name:   fmt.Sprintf("%s-smp%d", name, smp),
				Digest: slices.Clone(d[:]),
			})
		}
		return out, nil
	case teetypes.FamilyTDX:
		pins, err := runtimemeasure.LoadImageManifest(path)
		if err != nil {
			return nil, err
		}
		return []apiclient.ImagePin{{
			Name:   name,
			Digest: slices.Clone(pins.MRTD[:]),
			RTMRs: map[int][]byte{
				1: slices.Clone(pins.RTMR1[:]),
				2: slices.Clone(pins.RTMR2[:]),
			},
		}}, nil
	default:
		return nil, fmt.Errorf("image manifest %s: tee family %q has no manifest shape, want %q or %q",
			path, fam, teetypes.FamilySNP, teetypes.FamilyTDX)
	}
}
