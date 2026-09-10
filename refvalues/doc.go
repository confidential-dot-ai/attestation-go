// Package refvalues holds the reference values a verifier compares evidence
// against: the set of guest images a deployment accepts, each pinned as one
// atomic tuple of launch digest and runtime registers.
//
// A launch digest and its registers only mean anything together — two images
// built against the same TDVF firmware share an MRTD — so an image matches
// whole or not at all. A pinned image is an [apiclient.ImagePin], the type
// [apiclient.Policy] enforces, so a reference set is never restated on its way
// to the verifier.
//
// The package owns three shapes of the same thing:
//
//   - the measurements config file ([Parse], [Load], [Format]), which one
//     deployment writes for one TEE family;
//   - the flat digest and register lists that older flags and APIs carry
//     ([FromFlags], [ReferenceValues.Flatten], [ParseHexMeasurements],
//     [ParseRTMRPins]);
//   - a confidential-os build manifest ([FromImageManifest]).
//
// Family differences are hidden here. SEV-SNP folds the guest image into its
// launch digest and pins no registers, but ships one digest per vCPU count, so
// one SNP image becomes one pin per SMP variant. TDX pins MRTD plus RTMR[1]
// (kernel) and RTMR[2] (command line, carrying the dm-verity root hash), and
// never RTMR[0], which varies with the guest's vCPU and memory shape, or
// RTMR[3], which in-guest software extends at will.
package refvalues
