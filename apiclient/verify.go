package apiclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Sentinel errors for the enforced verification paths, matchable with
// [errors.Is]. Transport and service failures keep their own typed errors
// ([RequestError], [APIError], [UnexpectedError]).
var (
	// ErrSignatureInvalid: the service reported the hardware signature chain
	// does not verify.
	ErrSignatureInvalid = errors.New("apiclient: attestation signature invalid")

	// ErrReportDataMismatch: the evidence does not bind the expected
	// report data (absent or false verdict).
	ErrReportDataMismatch = errors.New("apiclient: report data mismatch in attestation evidence")

	// ErrMeasurementNotAllowed: the verified launch measurement is absent or
	// matches none of the caller's reference values while some are pinned.
	ErrMeasurementNotAllowed = errors.New("apiclient: launch measurement not allowed")

	// ErrInvalidLaunchDigest: the response carried a launch digest that is not
	// hex or not measurement-sized — malformed, distinct from a policy miss.
	ErrInvalidLaunchDigest = errors.New("apiclient: launch digest malformed")

	// ErrRTMRNotAllowed: a pinned runtime measurement register is absent,
	// malformed, or does not match what the policy pins.
	ErrRTMRNotAllowed = errors.New("apiclient: RTMR not allowed")

	// ErrUnsupportedPlatform: the envelope names a platform with no
	// verification rules here, so verification fails closed.
	ErrUnsupportedPlatform = errors.New("apiclient: unsupported platform for evidence verification")
)

// Policy is what [Client.VerifyEvidence] enforces on top of the service's
// verdict. The zero value checks only the verdict: any attested guest passes,
// which is a development posture, not a deployment one.
type Policy struct {
	// ExpectedReportData is the full 64-byte report data the evidence must
	// bind (SHA-384 in bytes 0-47, zero-padded). The wire form follows the
	// platform: a vTPM platform compares the bare 48-byte digest, a native one
	// compares all 64. See teetypes.PlatformType.UsesTPMNonce.
	ExpectedReportData [64]byte

	// AllowDebug accepts guests whose debug bit is set. A debug guest's memory
	// is readable by the host, so leaving this false is what makes the rest of
	// the policy mean anything.
	AllowDebug bool

	// MinTcb, when set, floors the platform TCB. Sent on SEV-SNP only: the
	// service's TDX verifier has no minimum-TCB parameter, so it would pin
	// nothing there.
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
	// Ignored where the platform has no registers. Absent indices are
	// unpinned; RTMR[0] should stay that way, as it carries the TD HOB and so
	// varies with the guest's vCPU and memory shape. RTMR[3] is extended by
	// in-guest software and cannot speak to guest identity on its own — a
	// substituted guest extends it with whatever it likes.
	RTMRs map[int][]byte
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
// must be valid, and where req asked for a report-data match the verdict must
// be affirmatively true. For callers holding a response from a fakeable
// interface; callers with a concrete [Client] use [Client.VerifyEnforced].
func EnforceVerdict(req VerifyRequest, resp VerifyResponse) error {
	if !resp.Result.SignatureValid {
		return ErrSignatureInvalid
	}
	if req.Params != nil && req.Params.ExpectedReportData != nil {
		if resp.Result.ReportDataMatch == nil || !*resp.Result.ReportDataMatch {
			return ErrReportDataMismatch
		}
	}
	if req.Params != nil && req.Params.ExpectedInitDataHash != nil {
		if resp.Result.InitDataMatch == nil || !*resp.Result.InitDataMatch {
			return fmt.Errorf("apiclient: init data mismatch in attestation evidence")
		}
	}
	return nil
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

	// A vTPM platform binds the key through a quote whose nonce is the bare
	// 48-byte digest; a native platform carries the hardware field and compares
	// all 64. Sending the wrong width fails evidence that is in fact correct.
	reportData := policy.ExpectedReportData[:]
	if evidence.Platform.UsesTPMNonce() {
		reportData = policy.ExpectedReportData[:sha512.Size384]
	}

	// MinTcb is SEV-SNP's alone; sending it with TDX evidence pins nothing and
	// would read as a policy that is enforced when it is not.
	minTcb := policy.MinTcb
	if family != teetypes.FamilySNP {
		minTcb = nil
	}

	expected := NewBase64Bytes(reportData)
	allowDebug := policy.AllowDebug
	resp, err := c.VerifyEnforced(ctx, NewVerifyRequest(evidence, &VerifyParams{
		ExpectedReportData: &expected,
		AllowDebug:         &allowDebug,
		MinTcb:             minTcb,
	}, false))
	if err != nil {
		return VerifyResponse{}, err
	}
	if err := EnforcePins(resp, policy, evidence.Platform); err != nil {
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
func EnforcePins(resp VerifyResponse, policy Policy, platform teetypes.PlatformType) error {
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
