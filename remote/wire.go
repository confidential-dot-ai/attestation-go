package remote

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// measurementSize is the byte length of every measurement the service compares:
// the SEV-SNP launch digest, the TDX MRTD and every RTMR are SHA-384.
const measurementSize = sha512.Size384

// PlatformAuto is request-only: it asks POST /attest to pick whichever platform
// the local machine is. No verified response ever carries it, so it is defined
// here rather than in teetypes alongside the tags a verifier can return.
const PlatformAuto teetypes.PlatformType = "auto"

// AttestRequest is the body of POST /attest.
//
// ReportData is the value to bind into the hardware report. Send the bare
// 48-byte SHA-384 digest: the service zero-extends it into the platform's
// report-data field. It travels as standard base64, which is what
// encoding/json does with a []byte.
//
// Platform left empty is omitted, and the service then detects the local
// platform as it does for [PlatformAuto]; an explicit empty string would be
// refused as an unknown platform.
type AttestRequest struct {
	ReportData []byte                `json:"report_data"`
	Platform   teetypes.PlatformType `json:"platform,omitempty"`
}

// AttestResponse is the body of a successful POST /attest.
//
// Evidence is the platform-specific evidence object (SnpEvidence, TdxEvidence,
// …) as the service emits it, not an envelope. Pair it with Platform to build a
// teetypes.AttestationEvidence for /verify or for a remote verifier.
type AttestResponse struct {
	Platform teetypes.PlatformType `json:"platform"`
	Evidence json.RawMessage       `json:"evidence"`
}

// Envelope returns the response as the self-describing evidence envelope every
// other entry point takes, so callers stop hand-assembling the pair.
func (r AttestResponse) Envelope() teetypes.AttestationEvidence {
	return teetypes.AttestationEvidence{Platform: r.Platform, Evidence: r.Evidence}
}

// VerifyRequest is the body of POST /verify. The service wants the platform at
// the top level and Evidence as the platform-specific object, so build it with
// [NewVerifyRequest] rather than by hand from an envelope.
type VerifyRequest struct {
	Platform   teetypes.PlatformType `json:"platform"`
	Evidence   json.RawMessage       `json:"evidence"`
	Params     *VerifyParams         `json:"params,omitempty"`
	IssueToken *bool                 `json:"issue_token,omitempty"`
}

// NewVerifyRequest splits an evidence envelope into the shape /verify expects.
func NewVerifyRequest(evidence teetypes.AttestationEvidence, params *VerifyParams, issueToken bool) VerifyRequest {
	return VerifyRequest{
		Platform:   evidence.Platform,
		Evidence:   evidence.Evidence,
		Params:     params,
		IssueToken: &issueToken,
	}
}

// VerifyParams are the optional checks /verify performs server-side. An empty
// field is not checked; the caller enforces anything it leaves out.
//
// The expected-measurement fields fail closed at the service: a mismatch and an
// expectation the evidence cannot answer — a register pin against SEV-SNP
// evidence, say — are both refusals, returned as an [APIError] rather than a
// report the caller must inspect. Fill them with [VerifyParams.SetExpectedMeasurements]
// rather than by hand; the service splits one concept across two platform
// fields, which that method hides.
//
// Each expected measurement is exactly 48 bytes. The service rejects any other
// length, so [VerifyParams.SetExpectedMeasurements] checks it before the round trip.
type VerifyParams struct {
	ExpectedReportData   []byte `json:"expected_report_data,omitempty"`
	ExpectedInitDataHash []byte `json:"expected_init_data_hash,omitempty"`
	AllowDebug           *bool  `json:"allow_debug,omitempty"`
	// MinTcb is an SEV-SNP floor. The service's TDX verifier has no
	// minimum-TCB parameter, so sending it with TDX evidence pins nothing.
	MinTcb *teetypes.SnpTcb `json:"min_tcb,omitempty"`

	// ExpectedLaunchDigest pins the SEV-SNP launch measurement. SNP only.
	ExpectedLaunchDigest []byte `json:"expected_launch_digest,omitempty"`
	// ExpectedMRTD pins the Intel TDX MRTD. TDX only. It is the same concept
	// as ExpectedLaunchDigest under the platform's own name.
	ExpectedMRTD []byte `json:"expected_mrtd,omitempty"`
	// ExpectedRTMR0 pins TDX RTMR[0]. It carries the TD HOB, so it varies with
	// the guest's vCPU and memory shape; pinning it denies guests by size
	// rather than by identity.
	ExpectedRTMR0 []byte `json:"expected_rtmr0,omitempty"`
	// ExpectedRTMR1 pins TDX RTMR[1], the guest kernel image.
	ExpectedRTMR1 []byte `json:"expected_rtmr1,omitempty"`
	// ExpectedRTMR2 pins TDX RTMR[2], the kernel command line and rootfs chain.
	ExpectedRTMR2 []byte `json:"expected_rtmr2,omitempty"`
	// ExpectedRTMR3 pins TDX RTMR[3], extended by in-guest software after
	// launch. See the runtimemeasure package for what a guest puts there.
	ExpectedRTMR3 []byte `json:"expected_rtmr3,omitempty"`
}

// SetExpectedMeasurements asks the service to enforce a launch measurement and
// registers, instead of the caller checking them against the returned report.
//
// launchMeasurement lands in expected_mrtd on Intel TDX and in
// expected_launch_digest on AMD SEV-SNP: the service splits one concept across
// two fields, and the caller should not have to know which. Pass nil to pin
// neither.
//
// rtmrs pins registers by index (0 to 3); nil pins none. Only TDX has
// registers, so a non-empty map on any other platform is a policy error
// reported here rather than at the service.
//
// Each call replaces all six expected-measurement fields: a register or the
// other family's digest left over from an earlier call would otherwise ride
// along as a pin the caller no longer asked for. On error p is unchanged.
//
// This pins ONE measurement. A policy accepting any of several images cannot be
// expressed server-side — use [Policy].Measurements or [Policy].Images, which
// [Client.VerifyEvidence] enforces against the returned report.
func (p *VerifyParams) SetExpectedMeasurements(platform teetypes.PlatformType, launchMeasurement []byte, rtmrs map[int][]byte) error {
	if err := checkMeasurementWidth("launch measurement", launchMeasurement); err != nil {
		return err
	}
	if len(rtmrs) > 0 && !platform.IsTDX() {
		return fmt.Errorf("platform %q has no runtime measurement registers, so %d register pin(s) cannot be enforced", platform, len(rtmrs))
	}

	var mrtd, launchDigest []byte
	switch platform.Family() {
	case teetypes.FamilyTDX:
		mrtd = launchMeasurement
	case teetypes.FamilySNP:
		launchDigest = launchMeasurement
	default:
		return fmt.Errorf("unknown platform %q: no measurement fields apply", platform)
	}

	var registers [4][]byte
	// Sorted so the error an operator sees is stable across runs.
	for _, idx := range slices.Sorted(maps.Keys(rtmrs)) {
		if idx < 0 || idx >= len(registers) {
			return fmt.Errorf("RTMR index %d out of range 0..%d", idx, len(registers)-1)
		}
		if err := checkMeasurementWidth(fmt.Sprintf("RTMR[%d] pin", idx), rtmrs[idx]); err != nil {
			return err
		}
		registers[idx] = rtmrs[idx]
	}

	p.ExpectedMRTD, p.ExpectedLaunchDigest = mrtd, launchDigest
	p.ExpectedRTMR0, p.ExpectedRTMR1, p.ExpectedRTMR2, p.ExpectedRTMR3 = registers[0], registers[1], registers[2], registers[3]
	return nil
}

// checkMeasurementWidth rejects a non-empty measurement that is not SHA-384
// sized; empty means unpinned.
func checkMeasurementWidth(name string, b []byte) error {
	if n := len(b); n > 0 && n != measurementSize {
		return fmt.Errorf("%s is %d bytes, want %d", name, n, measurementSize)
	}
	return nil
}

// VerifyResponse is the body of a successful POST /verify. Result carries the
// verdict; a caller must gate on it, which [Client.VerifyEnforced] does.
type VerifyResponse struct {
	Result teetypes.VerificationResult `json:"result"`
	Token  *string                     `json:"token"`
}

// HealthResponse is the body of GET /health.
type HealthResponse struct {
	Status      string                 `json:"status"`
	Platform    *teetypes.PlatformType `json:"platform,omitempty"`
	Cache       CacheStats             `json:"cache"`
	TokenIssuer bool                   `json:"token_issuer"`
}

// CacheStats reports the service's certificate and CRL cache occupancy.
type CacheStats struct {
	VcekEntries    uint64  `json:"vcek_entries"`
	ChainEntries   uint64  `json:"chain_entries"`
	LastCrlRefresh *string `json:"last_crl_refresh"`
}

// ErrorResponse is the body the service returns with a non-2xx status.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
