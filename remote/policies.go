package remote

import (
	"bytes"
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// PoliciesFor translates a [Policy] into the server-side params for the
// platform an evidence envelope names, and nothing else: the service refuses
// evidence from any other platform, which is the fail-closed answer for an
// envelope whose tag the policy was not written for.
//
// Every pin the service can check is sent to it, so a mismatch is refused at
// the service as well as by [EnforcePins]: the report-data and init-data
// bindings, the debug rule, the SEV-SNP TCB floor, the set of launch
// measurements, flat register pins, vTPM PCR pins and SEV-SNP measurement
// registers. Images replace Measurements and Registers, as [EnforcePins]
// applies them: the service checks the image digests as the launch set,
// [EnforceImages] that the registers and anchor belong to the matched image.
//
// A policy element the platform cannot answer is a policy error here, before
// any request is made: MinTcb off SEV-SNP ([ErrMinTcbNotAllowed]), register
// pins on a platform without registers ([ErrRegistersNotAllowed]), PCR pins on
// a platform without a vTPM ([ErrPCRNotAllowed]), measurement registers off
// bare-metal snp or without the report-data and launch pins they need
// ([ErrRegistersNotAllowed]).
func PoliciesFor(platform teetypes.PlatformType, policy Policy) (Policies, error) {
	platform = teetypes.NormalizePlatform(string(platform))
	family := platform.Family()
	if family == teetypes.FamilyUnknown {
		return Policies{}, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, platform)
	}
	// Images replace the flat pins; see [Policy.Images].
	if len(policy.Images) > 0 {
		policy.Measurements, policy.Registers = nil, nil
	}
	// MinTcb is SEV-SNP's alone. Dropping it for another family would verify
	// under no floor while the caller believes one was applied.
	if policy.MinTcb != nil && family != teetypes.FamilySNP {
		return Policies{}, fmt.Errorf("%w: platform %q has no SEV-SNP TCB", ErrMinTcbNotAllowed, platform)
	}
	if len(policy.Registers) > 0 && !platform.HasRegisters() {
		return Policies{}, errRegistersOffPlatform(len(policy.Registers), platform)
	}
	if len(policy.PCRs) > 0 && !platform.HasVTPMQuote() {
		return Policies{}, errPCRsOffPlatform(len(policy.PCRs), platform)
	}
	if policy.MeasurementRegisters != nil {
		if !platform.HasMeasurementRegisters() {
			return Policies{}, errMeasurementRegistersOffPlatform(platform)
		}
		if err := checkMeasurementRegisterPins(policy.MeasurementRegisters); err != nil {
			return Policies{}, err
		}
	}
	launch, err := launchMeasurements(policy)
	if err != nil {
		return Policies{}, err
	}

	var out Policies
	switch family {
	case teetypes.FamilySNP:
		params := SNPParams{
			ReportData:   policy.ExpectedReportData,
			HostData:     policy.ExpectedInitDataHash,
			LaunchDigest: launch,
			AllowDebug:   policy.AllowDebug,
			MinTcb:       policy.MinTcb,
		}
		if policy.MeasurementRegisters != nil {
			if len(launch) == 0 {
				return Policies{}, fmt.Errorf("%w: measurement registers need a launch measurement pin (Images or Measurements)", ErrRegistersNotAllowed)
			}
			if n := len(policy.ExpectedReportData); n == 0 || n > reportDataSize {
				return Policies{}, fmt.Errorf("%w: measurement registers need ExpectedReportData of 1 to %d bytes, got %d",
					ErrRegistersNotAllowed, reportDataSize, n)
			}
			// The kernel committed to the full 64-byte field, which holds the
			// requester's bytes zero-extended, as /attest extends them.
			params.ReportData = make([]byte, reportDataSize)
			copy(params.ReportData, policy.ExpectedReportData)
			// Non-nil, so an all-zero pin travels as an empty list.
			registers := policy.MeasurementRegisters
			params.MeasurementRegisters = &registers
		}
		switch platform {
		case teetypes.PlatformAzSNP:
			out.AzSNP = &AzSNPParams{SNPParams: params, PCRs: policy.PCRs}
		case teetypes.PlatformGcpSNP:
			out.GcpSNP = &params
		default:
			out.SNP = &params
		}
	case teetypes.FamilyTDX:
		params := TDXParams{
			ReportData: policy.ExpectedReportData,
			InitData:   policy.ExpectedInitDataHash,
			MRTD:       launch,
			AllowDebug: policy.AllowDebug,
		}
		rtmrs := []*DigestSet{&params.RTMR0, &params.RTMR1, &params.RTMR2, &params.RTMR3}
		for _, idx := range slices.Sorted(maps.Keys(policy.Registers)) {
			if idx < 0 || idx >= len(rtmrs) {
				return Policies{}, fmt.Errorf("%w: RTMR index %d out of range 0..%d", ErrRegistersNotAllowed, idx, len(rtmrs)-1)
			}
			if n := len(policy.Registers[idx]); n != measurementSize {
				return Policies{}, fmt.Errorf("%w: RTMR[%d] pin is %d bytes, want %d", ErrRegistersNotAllowed, idx, n, measurementSize)
			}
			*rtmrs[idx] = DigestSet{policy.Registers[idx]}
		}
		switch platform {
		case teetypes.PlatformAzTDX:
			out.AzTDX = &AzTDXParams{TDXParams: params, PCRs: policy.PCRs}
		case teetypes.PlatformGcpTDX:
			out.GcpTDX = &params
		default:
			out.TDX = &params
		}
	}
	return out, nil
}

// launchMeasurements is the set of launch measurements the policy accepts:
// every image's digest, or the flat measurements when no image is pinned,
// each 48 bytes, without duplicates. Empty when the policy pins no launch measurement.
func launchMeasurements(policy Policy) ([][]byte, error) {
	var out [][]byte
	for _, img := range policy.Images {
		if n := len(img.Digest); n != measurementSize {
			return nil, fmt.Errorf("%w: image %q digest is %d bytes, want %d", ErrMeasurementNotAllowed, img.Name, n, measurementSize)
		}
		if !MeasurementAllowed(img.Digest, out) {
			out = append(out, img.Digest)
		}
	}
	for i, m := range policy.Measurements {
		if n := len(m); n != measurementSize {
			return nil, fmt.Errorf("%w: measurement %d is %d bytes, want %d", ErrMeasurementNotAllowed, i, n, measurementSize)
		}
		if !MeasurementAllowed(m, out) {
			out = append(out, m)
		}
	}
	return out, nil
}

// checkMeasurementRegisterPins rejects a [Policy.MeasurementRegisters] value
// with more entries than registers or an entry that is not SHA-384 wide.
func checkMeasurementRegisterPins(pins [][]byte) error {
	if len(pins) > teetypes.MeasurementRegisterCount {
		return fmt.Errorf("%w: %d measurement registers pinned, at most %d exist",
			ErrRegistersNotAllowed, len(pins), teetypes.MeasurementRegisterCount)
	}
	for i, r := range pins {
		if n := len(r); n != measurementSize {
			return fmt.Errorf("%w: measurement register %d pin is %d bytes, want %d",
				ErrRegistersNotAllowed, i, n, measurementSize)
		}
	}
	return nil
}

// The refusals shared by PoliciesFor and the exported Enforce entry points,
// which skip it, so both paths name a policy error the same way.
func errRegistersOffPlatform(n int, platform teetypes.PlatformType) error {
	return fmt.Errorf("%w: %d register(s) pinned but platform %q has none", ErrRegistersNotAllowed, n, platform)
}

func errPCRsOffPlatform(n int, platform teetypes.PlatformType) error {
	return fmt.Errorf("%w: %d register(s) pinned but platform %q carries no vTPM quote", ErrPCRNotAllowed, n, platform)
}

func errMeasurementRegistersOffPlatform(platform teetypes.PlatformType) error {
	return fmt.Errorf("%w: measurement registers pinned but platform %q has no kernel measurement registers", ErrRegistersNotAllowed, platform)
}

// Pins is the platform-neutral view of what one [Policies] entry asks the
// service to check: the entry's bindings and allowed sets, whichever platform
// tag named the entry. It is how a verdict is read back against the request
// ([EnforceVerdict]) and how a stub answers one.
type Pins struct {
	ReportData []byte
	// InitData is SEV-SNP HOST_DATA or TDX MRCONFIGID (vTPM PCR[8] on Azure).
	InitData []byte
	// Launch is the allowed launch measurement set: launch_digest or mrtd.
	Launch DigestSet
	// RTMRs are the allowed sets for RTMR[0..3]; empty when unpinned.
	RTMRs [4]DigestSet
	// MeasurementRegisters is the SEV-SNP register-mode pin, nil when off.
	MeasurementRegisters *[][]byte
	// PCRs are the vTPM PCR pins of an Azure entry.
	PCRs map[int][]byte
}

// Pins returns the checks the entry for platform asks for, and whether the
// policies carry one. A request without an entry for its platform asked for
// nothing; the service refuses it anyway.
func (p Policies) Pins(platform teetypes.PlatformType) (Pins, bool) {
	var snp *SNPParams
	var tdx *TDXParams
	var pcrs map[int][]byte
	switch teetypes.NormalizePlatform(string(platform)) {
	case teetypes.PlatformSNP:
		snp = p.SNP
	case teetypes.PlatformGcpSNP:
		snp = p.GcpSNP
	case teetypes.PlatformAzSNP:
		if p.AzSNP != nil {
			snp, pcrs = &p.AzSNP.SNPParams, p.AzSNP.PCRs
		}
	case teetypes.PlatformTDX:
		tdx = p.TDX
	case teetypes.PlatformGcpTDX:
		tdx = p.GcpTDX
	case teetypes.PlatformAzTDX:
		if p.AzTDX != nil {
			tdx, pcrs = &p.AzTDX.TDXParams, p.AzTDX.PCRs
		}
	}
	switch {
	case snp != nil:
		return Pins{
			ReportData:           snp.ReportData,
			InitData:             snp.HostData,
			Launch:               snp.LaunchDigest,
			MeasurementRegisters: snp.MeasurementRegisters,
			PCRs:                 pcrs,
		}, true
	case tdx != nil:
		return Pins{
			ReportData: tdx.ReportData,
			InitData:   tdx.InitData,
			Launch:     tdx.MRTD,
			RTMRs:      [4]DigestSet{tdx.RTMR0, tdx.RTMR1, tdx.RTMR2, tdx.RTMR3},
			PCRs:       pcrs,
		}, true
	}
	return Pins{}, false
}

// MeasurementRegistersMatch is whether got, a kernel's sixteen replayed
// measurement registers, equals the pinned list, with every register past the
// list zero. It is the register-mode rule the service applies; the client
// re-applies it to the registers the service reports.
func MeasurementRegistersMatch(got, pinned [][]byte) bool {
	if len(got) != teetypes.MeasurementRegisterCount {
		return false
	}
	var zero [measurementSize]byte
	for i, r := range got {
		want := zero[:]
		if i < len(pinned) {
			want = pinned[i]
		}
		if !bytes.Equal(r, want) {
			return false
		}
	}
	return true
}

// EnforceMeasurementRegisters requires, when pinned is non-nil, that the
// service verified the SEV-SNP kernel measurement registers and that the
// registers it reports equal the pinned values, with every register past the
// list zero. A result without them is a refusal: it is what evidence from an
// image without the register provider, or a verifier that was not asked, looks
// like, and neither says the guest measured what the policy expects.
//
// Only bare-metal snp has these registers; a pin against any other platform is
// a policy error, not a pass.
func EnforceMeasurementRegisters(resp VerifyResponse, platform teetypes.PlatformType, pinned [][]byte) error {
	if pinned == nil {
		return nil
	}
	if !platform.HasMeasurementRegisters() {
		return errMeasurementRegistersOffPlatform(platform)
	}
	if err := checkMeasurementRegisterPins(pinned); err != nil {
		return err
	}
	if !affirmed(resp.Result.MeasurementRegistersMatch) {
		return fmt.Errorf("%w: the service did not verify the measurement registers", ErrRegistersNotAllowed)
	}
	got := resp.Result.MeasurementRegisters
	if got == nil || !MeasurementRegistersMatch(got.Registers, pinned) {
		return fmt.Errorf("%w: the reported measurement registers do not match the pinned values", ErrRegistersNotAllowed)
	}
	return nil
}
