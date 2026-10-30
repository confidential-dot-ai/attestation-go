// Package refvalues holds the reference values a verifier compares evidence
// against: the set of guest images a deployment accepts, each pinned as one
// atomic tuple of launch digest, runtime registers, and optional launch
// binding.
//
// A launch digest and its registers only mean anything together — two images
// built against the same TDVF firmware share an MRTD — so an image matches
// whole or not at all. A pinned image is an [remote.ImagePin], the type
// [remote.Policy] enforces, so a reference set is never restated on its way
// to the verifier. An optional approver_key in the measurements document maps
// to ImagePin.Anchor: one ECDSA P-256 public key in PEM, pinned byte for byte.
// An image may appear with several anchors; a complete tuple must be unique.
// Generic programmatic anchors cannot be formatted as approver_key unless
// they satisfy that public-key contract.
//
// Each field names its one kind deliberately. [remote.ImagePin.Anchor] is
// opaque bytes because [runtimemeasure] hashes whatever it is given, but a
// document an operator reviews should say what the value it pins is, so that a
// reviewer can check it rather than compare hex. A second binding kind is a
// new field under a new schema_version, not a reinterpretation of the first.
//
// schema_version 2 adds that second kind: a launch_file holding the exact
// bytes of the launch configuration file a guest was launched with, mapped to
// [remote.ImagePin.LaunchFile]. An entry carries at most one of approver_key
// and launch_file, both naming the same hardware field. [Format] and [Render]
// write schema_version 2 only for a set that pins a launch file, so a schema 1
// reader sees a document it still loads, and refuse one they cannot preserve
// byte for byte. [Parse] refuses a launch_file under schema_version 1, where a
// reader has no such field; a schema 2 document may pin none.
//
// [ParseRendered] uses the same strict parsing rules as [Parse], while
// permitting the empty set a component may report through [Render]. [Diff]
// includes the launch binding in the tuple. [ReferenceValues.HasLaunchBindings]
// lets callers detect the bindings flat flags cannot express, of either kind;
// [ReferenceValues.Flatten] reports uniform=false for such a set rather than
// claiming those pins survived.
//
// The package owns three shapes of the same thing:
//
//   - the measurements config file ([Parse], [Load], [Format]), which one
//     deployment writes for one TEE family;
//   - the flat digest and register lists that older flags and APIs carry
//     ([FromFlags], [ReferenceValues.Flatten], [ParseHexMeasurements],
//     [ParseRegisterPins]);
//   - a confidential-os build manifest ([FromImageManifest]).
//
// Family differences are hidden here. SEV-SNP folds the guest image into its
// launch digest and pins no registers, but ships one digest per vCPU count, so
// one SNP image becomes one pin per SMP variant. TDX pins MRTD plus RTMR[1]
// (kernel) and RTMR[2] (command line, carrying the dm-verity root hash), and
// never derives RTMR[0], which varies with the guest's vCPU and memory shape,
// or RTMR[3], which is a launch/runtime binding rather than a build value.
// A measurements file may explicitly pin RTMR[3].
package refvalues
