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
// measurements (from Images and Measurements together), flat register pins,
// vTPM PCR pins and SEV-SNP measurement registers. Image pins stay atomic on
// the client: the service checks the launch measurement set, [EnforceImages]
// that the registers and anchor belong to the matched image.
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
	// MinTcb is SEV-SNP's alone. Dropping it for another family would verify
	// under no floor while the caller believes one was applied.
	if policy.MinTcb != nil && family != teetypes.FamilySNP {
		return Policies{}, fmt.Errorf("%w: platform %q has no SEV-SNP TCB", ErrMinTcbNotAllowed, platform)
	}
	if len(policy.Registers) > 0 && !platform.HasRegisters() {
		return Policies{}, fmt.Errorf("%w: %d register(s) pinned but platform %q has none",
			ErrRegistersNotAllowed, len(policy.Registers), platform)
	}
	if len(policy.PCRs) > 0 && !platform.HasVTPMQuote() {
		return Policies{}, fmt.Errorf("%w: %d register(s) pinned but platform %q carries no vTPM quote",
			ErrPCRNotAllowed, len(policy.PCRs), platform)
	}
	// Only a bare-metal SEV-SNP kernel commits its measurement registers to
	// the report; everywhere else the pin would silently verify nothing.
	if policy.MeasurementRegisters != nil && platform != teetypes.PlatformSNP {
		return Policies{}, fmt.Errorf("%w: measurement registers pinned but platform %q has no kernel measurement registers",
			ErrRegistersNotAllowed, platform)
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
			registers, err := measurementRegisterPins(policy.MeasurementRegisters)
			if err != nil {
				return Policies{}, err
			}
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
			params.MeasurementRegisters = &registers
		}
		switch platform {
		case teetypes.PlatformAzSNP:
			out.AzSNP = &AzSNPParams{SNPParams: params, PCRs: pcrPins(policy.PCRs)}
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
			if err := checkMeasurementWidth(fmt.Sprintf("RTMR[%d] pin", idx), policy.Registers[idx]); err != nil {
				return Policies{}, fmt.Errorf("%w: %w", ErrRegistersNotAllowed, err)
			}
			*rtmrs[idx] = DigestSet{policy.Registers[idx]}
		}
		switch platform {
		case teetypes.PlatformAzTDX:
			out.AzTDX = &AzTDXParams{TDXParams: params, PCRs: pcrPins(policy.PCRs)}
		case teetypes.PlatformGcpTDX:
			out.GcpTDX = &params
		case teetypes.PlatformTDX:
			out.TDX = &params
		default:
			// dstack routes to the TDX family for the in-process verifiers but
			// has no entry at the service.
			return Policies{}, fmt.Errorf("%w: the service has no policy for %q", ErrUnsupportedPlatform, platform)
		}
	}
	return out, nil
}

// launchMeasurements is the set of launch measurements the policy accepts:
// every image's digest and every flat measurement, each 48 bytes, without
// duplicates. Empty when the policy pins no launch measurement.
func launchMeasurements(policy Policy) ([][]byte, error) {
	var out [][]byte
	add := func(what string, m []byte) error {
		if n := len(m); n != measurementSize {
			return fmt.Errorf("%w: %s is %d bytes, want %d", ErrMeasurementNotAllowed, what, n, measurementSize)
		}
		if !MeasurementAllowed(m, out) {
			out = append(out, m)
		}
		return nil
	}
	for _, img := range policy.Images {
		if err := add(fmt.Sprintf("image %q digest", img.Name), img.Digest); err != nil {
			return nil, err
		}
	}
	for i, m := range policy.Measurements {
		if err := add(fmt.Sprintf("measurement %d", i), m); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// measurementRegisterPins validates a [Policy.MeasurementRegisters] value and
// returns it as the list the service takes: never nil, so an all-zero pin is
// sent as an empty list rather than left out.
func measurementRegisterPins(pins [][]byte) ([][]byte, error) {
	if len(pins) > teetypes.MeasurementRegisterCount {
		return nil, fmt.Errorf("%w: %d measurement registers pinned, at most %d exist",
			ErrRegistersNotAllowed, len(pins), teetypes.MeasurementRegisterCount)
	}
	out := make([][]byte, 0, len(pins))
	for i, r := range pins {
		if n := len(r); n != measurementSize {
			return nil, fmt.Errorf("%w: measurement register %d pin is %d bytes, want %d",
				ErrRegistersNotAllowed, i, n, measurementSize)
		}
		out = append(out, r)
	}
	return out, nil
}

// checkMeasurementWidth rejects a non-empty measurement that is not SHA-384
// sized; empty means unpinned.
func checkMeasurementWidth(name string, b []byte) error {
	if n := len(b); n > 0 && n != measurementSize {
		return fmt.Errorf("%s is %d bytes, want %d", name, n, measurementSize)
	}
	return nil
}

// pcrPins copies the PCR pins for the wire; nil when there are none, so the
// field is left out.
func pcrPins(pins map[int][]byte) map[int][]byte {
	if len(pins) == 0 {
		return nil
	}
	return maps.Clone(pins)
}

// asked records which checks a request's policies asked the service for, so
// [EnforceVerdict] can require an affirmative answer to each.
type askedChecks struct {
	reportData, initData, launch bool
	rtmrs                        [4]bool
	measurementRegisters, pcrs   bool
}

// asked reads the checks requested for platform. A request that carries no
// entry for the platform asked for nothing; the service refuses it anyway.
func (p Policies) asked(platform teetypes.PlatformType) askedChecks {
	var a askedChecks
	snp := func(s *SNPParams) {
		a.reportData = len(s.ReportData) > 0
		a.initData = len(s.HostData) > 0
		a.launch = len(s.LaunchDigest) > 0
		a.measurementRegisters = s.MeasurementRegisters != nil
	}
	tdx := func(t *TDXParams) {
		a.reportData = len(t.ReportData) > 0
		a.initData = len(t.InitData) > 0
		a.launch = len(t.MRTD) > 0
		for i, r := range []DigestSet{t.RTMR0, t.RTMR1, t.RTMR2, t.RTMR3} {
			a.rtmrs[i] = len(r) > 0
		}
	}
	switch teetypes.NormalizePlatform(string(platform)) {
	case teetypes.PlatformSNP:
		if p.SNP != nil {
			snp(p.SNP)
		}
	case teetypes.PlatformGcpSNP:
		if p.GcpSNP != nil {
			snp(p.GcpSNP)
		}
	case teetypes.PlatformAzSNP:
		if p.AzSNP != nil {
			snp(&p.AzSNP.SNPParams)
			a.pcrs = len(p.AzSNP.PCRs) > 0
		}
	case teetypes.PlatformTDX:
		if p.TDX != nil {
			tdx(p.TDX)
		}
	case teetypes.PlatformGcpTDX:
		if p.GcpTDX != nil {
			tdx(p.GcpTDX)
		}
	case teetypes.PlatformAzTDX:
		if p.AzTDX != nil {
			tdx(&p.AzTDX.TDXParams)
			a.pcrs = len(p.AzTDX.PCRs) > 0
		}
	}
	return a
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
	if teetypes.NormalizePlatform(string(platform)) != teetypes.PlatformSNP {
		return fmt.Errorf("%w: measurement registers pinned but platform %q has no kernel measurement registers",
			ErrRegistersNotAllowed, platform)
	}
	expected, err := measurementRegisterPins(pinned)
	if err != nil {
		return err
	}
	if !affirmed(resp.Result.MeasurementRegistersMatch) {
		return fmt.Errorf("%w: the service did not verify the measurement registers", ErrRegistersNotAllowed)
	}
	got := resp.Result.MeasurementRegisters
	if got == nil || len(got.Registers) != teetypes.MeasurementRegisterCount {
		return fmt.Errorf("%w: the result carries no complete measurement registers", ErrRegistersNotAllowed)
	}
	for i, r := range got.Registers {
		want := make([]byte, measurementSize)
		if i < len(expected) {
			want = expected[i]
		}
		if !bytes.Equal(r, want) {
			return fmt.Errorf("%w: measurement register %d does not match", ErrRegistersNotAllowed, i)
		}
	}
	return nil
}
