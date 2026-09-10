package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// Sentinel errors for the enforced verification paths, matchable with
// [errors.Is]. Transport and service failures keep their own typed errors
// ([RequestError], [APIError], [UnexpectedError]).
var (
	// ErrSignatureInvalid: the service reported the hardware signature chain
	// does not verify.
	ErrSignatureInvalid = errors.New("client: attestation signature invalid")

	// ErrReportDataMismatch: the evidence does not bind the expected
	// report data (absent or false verdict).
	ErrReportDataMismatch = errors.New("client: report data mismatch in attestation evidence")

	// ErrMeasurementNotAllowed: the verified launch measurement is absent or
	// matches none of the caller's reference values while some are pinned.
	ErrMeasurementNotAllowed = errors.New("client: launch measurement not allowed")

	// ErrInvalidLaunchDigest: the response carried a launch digest that is not
	// hex or not measurement-sized — malformed, distinct from a policy miss.
	ErrInvalidLaunchDigest = errors.New("client: launch digest malformed")

	// ErrRTMRNotAllowed: a pinned runtime measurement register is absent,
	// malformed, or does not match what the policy pins.
	ErrRTMRNotAllowed = errors.New("client: RTMR not allowed")

	// ErrMinTcbNotAllowed: the policy floors the SEV-SNP TCB but the evidence
	// is from another family, where the floor pins nothing.
	ErrMinTcbNotAllowed = errors.New("client: TCB floor not allowed")

	// ErrPCRNotAllowed: a pinned vTPM platform configuration register is
	// absent, malformed, not covered by the quote's signed selection, or does
	// not match what the policy pins.
	ErrPCRNotAllowed = errors.New("client: vTPM PCR not allowed")

	// ErrInitDataMismatch: the request pinned an init-data hash and the
	// verdict is absent or false.
	ErrInitDataMismatch = errors.New("client: init data mismatch in attestation evidence")

	// ErrUnsupportedPlatform: the envelope names a platform with no
	// verification rules here, so verification fails closed.
	ErrUnsupportedPlatform = errors.New("client: unsupported platform for evidence verification")
)

// Policy is what [Client.VerifyEvidence] enforces on top of the service's
// verdict. The zero value checks only the verdict: any attested guest passes,
// which is a development posture, not a deployment one.
type Policy struct {
	// ExpectedReportData is the value the evidence must bind: the same bytes
	// that were sent to /attest, typically a 48-byte SHA-384 digest. It is
	// sent verbatim. A native platform zero-pads it to the 64-byte hardware
	// field before comparing; a vTPM platform compares it byte for byte with
	// the quote nonce, which is what /attest received. Empty leaves the
	// binding unchecked.
	ExpectedReportData []byte

	// AllowDebug accepts guests whose debug bit is set. A debug guest's memory
	// is readable by the host, so leaving this false is what makes the rest of
	// the policy mean anything.
	AllowDebug bool

	// MinTcb, when set, floors the SEV-SNP TCB. It names SNP components, so
	// evidence from any other family is refused with [ErrMinTcbNotAllowed]
	// rather than verified under no floor; a mixed fleet needs one Policy per
	// family. The service ignores FMC.
	MinTcb *teetypes.SnpTcb

	// Images pins whole images — a launch digest together with the registers
	// measured from the same build. When set it replaces Measurements and
	// RTMRs, so a digest from one build cannot be paired with another's.
	Images []ImagePin

	// Measurements is the set of acceptable launch measurements; empty accepts
	// any. The service normalizes both the SEV-SNP launch digest and the TDX
	// MRTD into one claim, so one set covers both.
	Measurements [][]byte

	// RTMRs pins runtime measurement registers by index, and is what makes a
	// TDX guest's own bytes attested rather than just its firmware's: MRTD
	// covers TDVF alone, which measures the guest kernel into RTMR[1] and the
	// command line — carrying the dm-verity root hash — into RTMR[2]. Without
	// these a host can boot a different guest image under the pinned MRTD.
	//
	// A pin against a platform without registers is refused with
	// [ErrRTMRNotAllowed], never skipped. Absent indices are unpinned;
	// RTMR[0] should stay that way, as it carries the TD HOB and so
	// varies with the guest's vCPU and memory shape. RTMR[3] is extended by
	// in-guest software and cannot speak to guest identity on its own — a
	// substituted guest extends it with whatever it likes.
	RTMRs map[int][]byte

	// PCRs pins vTPM platform configuration registers by index, and is what
	// makes an Azure guest's OS attested rather than just Microsoft's
	// paravisor: on an Azure confidential VM the launch measurement covers the
	// paravisor image, while the guest kernel and initrd measure here.
	//
	// Values are SHA-256, 32 bytes. Pins apply only where the platform carries
	// a vTPM quote (teetypes.PlatformType.HasVTPMQuote); elsewhere there is
	// nothing for them to narrow, so a mixed fleet keeps working. Which
	// indices carry guest-OS identity depends on the image's measured-boot
	// layout.
	PCRs map[int][]byte

	// ExpectedInitDataHash, when set, is sent as expected_init_data_hash and
	// the verdict must come back affirmatively true. The platform decides what
	// backs it: SEV-SNP HOST_DATA, TDX MRCONFIGID zero-padded, or vTPM PCR[8]
	// on the Azure overlays.
	ExpectedInitDataHash []byte
}

// VerifyEnforced posts req to /verify and fails closed on the verdict
// ([EnforceVerdict]). Every caller that trusts a response must gate on the
// verdict fields; doing it here keeps the nil-tolerant fail-open out of call
// sites.
func (c Client) VerifyEnforced(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	resp, err := c.Verify(ctx, req)
	if err != nil {
		return VerifyResponse{}, err
	}
	if err := EnforceVerdict(req, resp); err != nil {
		return VerifyResponse{}, err
	}
	return resp, nil
}

// EnforceVerdict fails closed on a /verify response: the hardware signature
// must be valid, where req asked for a report-data or init-data match the
// verdict must be affirmatively true, and every expected measurement req
// carried must equal the claim the service returned. For callers holding a
// response from a fakeable interface; callers with a concrete [Client] use
// [Client.VerifyEnforced].
//
// Measurements are re-checked here rather than trusted to the service's
// verdict: a service predating those request fields ignores them and returns
// a clean report, so the only evidence that a pin was enforced is the claim
// itself.
func EnforceVerdict(req VerifyRequest, resp VerifyResponse) error {
	if !resp.Result.SignatureValid {
		return ErrSignatureInvalid
	}
	if req.Params == nil {
		return nil
	}
	if len(req.Params.ExpectedReportData) > 0 {
		if resp.Result.ReportDataMatch == nil || !*resp.Result.ReportDataMatch {
			return ErrReportDataMismatch
		}
	}
	if len(req.Params.ExpectedInitDataHash) > 0 {
		if resp.Result.InitDataMatch == nil || !*resp.Result.InitDataMatch {
			return ErrInitDataMismatch
		}
	}
	return enforceExpectedMeasurements(*req.Params, resp)
}

// enforceExpectedMeasurements compares the request's expected measurements
// with the returned claims. Both launch fields compare against the one
// normalized launch digest, since the service maps MRTD and the SNP launch
// measurement onto it.
func enforceExpectedMeasurements(params VerifyParams, resp VerifyResponse) error {
	var allowed [][]byte
	for _, m := range [][]byte{params.ExpectedLaunchDigest, params.ExpectedMRTD} {
		if len(m) > 0 {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		if err := EnforceLaunchMeasurement(resp, allowed); err != nil {
			return err
		}
	}
	pinned := map[int][]byte{}
	for idx, m := range [][]byte{params.ExpectedRTMR0, params.ExpectedRTMR1, params.ExpectedRTMR2, params.ExpectedRTMR3} {
		if len(m) > 0 {
			pinned[idx] = m
		}
	}
	return EnforceRTMRs(resp, pinned)
}

// VerifyEvidence verifies an evidence envelope against policy, enforcing the
// verdict and then the caller's reference values.
//
// The caller does not say which TEE produced the evidence: the envelope's tag
// selects the rules, and a tag with no rules here fails closed with
// [ErrUnsupportedPlatform] rather than being approved under another platform's.
func (c Client) VerifyEvidence(ctx context.Context, evidence teetypes.AttestationEvidence, policy Policy) (VerifyResponse, error) {
	family := evidence.Platform.Family()
	if family == teetypes.FamilyUnknown {
		return VerifyResponse{}, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, evidence.Platform)
	}

	// MinTcb is SEV-SNP's alone. Dropping it for another family would verify
	// under no floor while the caller believes one was applied.
	if policy.MinTcb != nil && family != teetypes.FamilySNP {
		return VerifyResponse{}, fmt.Errorf("%w: platform %q has no SEV-SNP TCB", ErrMinTcbNotAllowed, evidence.Platform)
	}

	resp, err := c.VerifyEnforced(ctx, NewVerifyRequest(evidence, &VerifyParams{
		ExpectedReportData:   policy.ExpectedReportData,
		ExpectedInitDataHash: policy.ExpectedInitDataHash,
		AllowDebug:           teetypes.Ptr(policy.AllowDebug),
		MinTcb:               policy.MinTcb,
	}, false))
	if err != nil {
		return VerifyResponse{}, err
	}
	if err := EnforcePins(resp, policy, evidence); err != nil {
		return VerifyResponse{}, err
	}
	return resp, nil
}

// EnforcePins applies whichever pin form policy configured, against a response
// the caller already verified. Exported for issuance gates that reach /verify
// through [Client.VerifyEnforced] rather than [Client.VerifyEvidence].
//
// Images are matched whole; the flat measurement/RTMR pair keeps its own path,
// so an operator who set only that sees exactly the decisions it always made.
func EnforcePins(resp VerifyResponse, policy Policy, evidence teetypes.AttestationEvidence) error {
	platform := evidence.Platform
	// PCR pins are orthogonal to the launch measurement: on an Azure guest the
	// launch measurement identifies the paravisor and the PCRs identify the
	// guest OS, so both forms apply to the same evidence.
	if err := EnforcePCRs(evidence, resp.Result.Claims, policy.PCRs); err != nil {
		return err
	}
	if len(policy.Images) > 0 {
		return EnforceImages(resp, policy.Images, platform)
	}
	if err := EnforceLaunchMeasurement(resp, policy.Measurements); err != nil {
		return err
	}
	// Registers exist only where the platform has them; pinning them elsewhere
	// is a policy error the caller should have caught, not a silent pass.
	if platform.IsTDX() {
		return EnforceRTMRs(resp, policy.RTMRs)
	}
	if len(policy.RTMRs) > 0 {
		return fmt.Errorf("%w: %d register(s) pinned but platform %q has none",
			ErrRTMRNotAllowed, len(policy.RTMRs), platform)
	}
	return nil
}

// EnforcePCRs requires each pinned vTPM register to byte-equal what the
// verifier reported, and to be covered by the quote's signed PCR selection.
//
// The attester supplies the whole PCR bank alongside the quote, but the AK
// signature covers only the registers the quote selected. A verifier that
// publishes the bank verbatim therefore reports attester-chosen values for the
// rest, and a guest could quote a selection that excludes the register a policy
// pins and supply the pinned value for it. The selection is re-read here from
// the evidence the service verified, so a pin outside it is a refusal
// regardless of what the report carries.
//
// A pinned register the evidence does not carry is a refusal, not a pass. So is
// a pin against a platform with no vTPM quote: the policy asked for a check
// that could never run, which is a policy error rather than something to skip
// quietly. Reference values are per-platform, so a pin reaching the wrong
// platform means the wrong policy was loaded.
func EnforcePCRs(evidence teetypes.AttestationEvidence, claims teetypes.Claims, pinned map[int][]byte) error {
	if len(pinned) == 0 {
		return nil
	}
	if !evidence.Platform.HasVTPMQuote() {
		return fmt.Errorf("%w: %d register(s) pinned but platform %q carries no vTPM quote",
			ErrPCRNotAllowed, len(pinned), evidence.Platform)
	}
	signed, err := signedPCRSelection(evidence.Evidence)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPCRNotAllowed, err)
	}
	// Sorted so the error an operator sees is stable across runs.
	for _, idx := range slices.Sorted(maps.Keys(pinned)) {
		if !slices.Contains(signed, idx) {
			return fmt.Errorf("%w: PCR[%d] is not in the quote's signed selection %v", ErrPCRNotAllowed, idx, signed)
		}
		got, err := claims.PCR(idx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPCRNotAllowed, err)
		}
		if !bytes.Equal(got, pinned[idx]) {
			return fmt.Errorf("%w: PCR[%d] does not match", ErrPCRNotAllowed, idx)
		}
	}
	return nil
}

// signedPCRSelection reads the quote's PCR selection from the tpm_quote the
// Azure evidence carries. The service verified the AK signature over these
// same bytes, which is what makes the selection authoritative.
func signedPCRSelection(evidence json.RawMessage) ([]int, error) {
	var ev struct {
		TPMQuote *tpmcommon.RawTPMQuote `json:"tpm_quote"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	if ev.TPMQuote == nil {
		return nil, fmt.Errorf("evidence carries no tpm_quote")
	}
	message, err := hex.DecodeString(ev.TPMQuote.Message)
	if err != nil {
		return nil, fmt.Errorf("tpm_quote.message hex: %w", err)
	}
	return tpmcommon.SignedPCRSelection(message)
}

// EnforceRTMRs requires each pinned register to byte-equal what the service
// reported. A pinned register the evidence does not carry is a refusal, not a
// pass: that is what evidence from a platform without registers looks like, and
// it does not say the guest is the expected one.
func EnforceRTMRs(resp VerifyResponse, pinned map[int][]byte) error {
	if len(pinned) == 0 {
		return nil
	}
	return enforceRTMRsAgainst(resp.Result.Claims, pinned)
}

// enforceRTMRsAgainst reads registers through teetypes.Claims.RTMR, which
// already validates index, presence, encoding and width, so the checks live in
// one place rather than being restated per caller.
func enforceRTMRsAgainst(claims teetypes.Claims, pinned map[int][]byte) error {
	// Sorted so the error an operator sees is stable across runs.
	for _, idx := range slices.Sorted(maps.Keys(pinned)) {
		got, err := claims.RTMR(idx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRTMRNotAllowed, err)
		}
		if !bytes.Equal(got, pinned[idx]) {
			return fmt.Errorf("%w: RTMR[%d] does not match", ErrRTMRNotAllowed, idx)
		}
	}
	return nil
}

// EnforceLaunchMeasurement validates the normalized launch digest and, when
// allowed is non-empty, requires it to match one reference value. The digest is
// the SEV-SNP launch measurement or the TDX MRTD; both are SHA-384.
func EnforceLaunchMeasurement(resp VerifyResponse, allowed [][]byte) error {
	if resp.Result.Claims.LaunchDigest == "" {
		if len(allowed) > 0 {
			return fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
		}
		return nil
	}
	measurement, err := launchDigest(resp)
	if err != nil {
		return err
	}
	if len(allowed) > 0 && !MeasurementAllowed(measurement, allowed) {
		return fmt.Errorf("%w: launch measurement does not match any reference value", ErrMeasurementNotAllowed)
	}
	return nil
}

// MeasurementAllowed reports whether measurement equals one of the reference
// launch digests. An empty set means "no pin" and is the caller's to handle.
func MeasurementAllowed(measurement []byte, allowed [][]byte) bool {
	return slices.ContainsFunc(allowed, func(m []byte) bool { return bytes.Equal(measurement, m) })
}
