package remote

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// measurementSize is the width of every launch measurement and register the
// service pins: SHA-384.
const measurementSize = sha512.Size384

// reportDataSize is the width of the hardware report-data field on every
// native platform. The service zero-extends a shorter value into it.
const reportDataSize = 64

// PlatformAuto asks the service to detect the platform it runs on.
const PlatformAuto teetypes.PlatformType = "auto"

// DigestSet is a set of acceptable 48-byte measurements: the evidence's value
// must equal one of them. It travels as an array of standard base64 strings.
// The service also accepts a single string for a set of one, so a DigestSet
// decodes from either form; it always encodes as an array.
type DigestSet [][]byte

// UnmarshalJSON accepts an array of base64 strings or a single one.
func (s *DigestSet) UnmarshalJSON(data []byte) error {
	var many [][]byte
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	var one []byte
	if err := json.Unmarshal(data, &one); err != nil {
		return fmt.Errorf("remote: digest set is neither a base64 string nor an array of them: %w", err)
	}
	*s = DigestSet{one}
	return nil
}

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
// …) as the service emits it, not an envelope. Collateral is what the service
// attached for offline verification, when it could; it is opaque here and
// travels back to /verify as is. Pair them with Platform to build a
// teetypes.AttestationEvidence for /verify or for a remote verifier.
type AttestResponse struct {
	Platform   teetypes.PlatformType `json:"platform"`
	Evidence   json.RawMessage       `json:"evidence"`
	Collateral json.RawMessage       `json:"collateral,omitempty"`
}

// Envelope returns the response as the self-describing evidence envelope every
// other entry point takes, so callers stop hand-assembling the pair.
func (r AttestResponse) Envelope() teetypes.AttestationEvidence {
	return teetypes.AttestationEvidence{Platform: r.Platform, Evidence: r.Evidence, Collateral: r.Collateral}
}

// VerifyRequest is the body of POST /verify. The service wants the platform at
// the top level, Evidence as the platform-specific object, and the accepted
// platforms with their params under Policies, so build it with
// [NewVerifyRequest] rather than by hand from an envelope.
//
// Evidence for a platform without an entry in Policies is refused by the
// service (422 platform_not_allowed), so a request names exactly the platforms
// it accepts.
type VerifyRequest struct {
	Platform   teetypes.PlatformType `json:"platform"`
	Evidence   json.RawMessage       `json:"evidence"`
	Collateral json.RawMessage       `json:"collateral,omitempty"`
	Policies   Policies              `json:"policies"`
	IssueToken bool                  `json:"issue_token,omitempty"`
}

// NewVerifyRequest splits an evidence envelope into the shape /verify expects.
// policies usually comes from [PoliciesFor].
func NewVerifyRequest(evidence teetypes.AttestationEvidence, policies Policies, issueToken bool) VerifyRequest {
	return VerifyRequest{
		Platform:   evidence.Platform,
		Evidence:   evidence.Evidence,
		Collateral: evidence.Collateral,
		Policies:   policies,
		IssueToken: issueToken,
	}
}

// Policies names the platforms a /verify request accepts, each with the params
// the service enforces for it. A platform left nil is refused by the service.
// The service rejects unknown keys, so every field here is one it defines.
//
// [PoliciesFor] fills exactly the entry for the platform an envelope names;
// callers that accept several platforms in one request fill more.
type Policies struct {
	SNP    *SNPParams   `json:"snp,omitempty"`
	TDX    *TDXParams   `json:"tdx,omitempty"`
	AzSNP  *AzSNPParams `json:"az-snp,omitempty"`
	AzTDX  *AzTDXParams `json:"az-tdx,omitempty"`
	GcpSNP *SNPParams   `json:"gcp-snp,omitempty"`
	GcpTDX *TDXParams   `json:"gcp-tdx,omitempty"`
}

// SNPParams are the server-side checks for SEV-SNP evidence. Byte fields
// travel as standard base64; every digest is 48 bytes. An unset field is not
// checked, except AllowDebug (false refuses debug guests) and MaxVMPL (0).
type SNPParams struct {
	// ReportData is what the report's REPORT_DATA must equal, zero-extended to
	// 64 bytes. In register mode it is the requester's exact 64 bytes.
	ReportData []byte `json:"report_data,omitempty"`
	// HostData is what HOST_DATA must equal, zero-extended to 32 bytes. On
	// Azure it is the init-data hash checked against vTPM PCR[8].
	HostData []byte `json:"host_data,omitempty"`
	// LaunchDigest is the set of acceptable launch measurements; the report's
	// must equal one of them. Non-empty when set.
	LaunchDigest DigestSet `json:"launch_digest,omitempty"`
	AllowDebug   bool      `json:"allow_debug"`
	// MinTcb floors the reported, committed and launch TCB.
	MinTcb *teetypes.SnpTcb `json:"min_tcb,omitempty"`
	// MaxVMPL is the highest VMPL accepted. The service refuses more than 0
	// unless configured to allow it.
	MaxVMPL uint32 `json:"max_vmpl"`
	// MeasurementRegisters selects register mode when non-nil: the expected
	// final values of the guest kernel's measurement registers in index order,
	// at most sixteen; registers past the list must be zero, so an empty list
	// means all zero. The service then requires REPORT_DATA to commit to the
	// evidence's event log and to ReportData, which must be exactly 64 bytes;
	// LaunchDigest must be set and VMPL 0. Bare-metal snp only.
	MeasurementRegisters *[][]byte `json:"measurement_registers,omitempty"`
}

// TDXParams are the server-side checks for Intel TDX evidence. Byte fields
// travel as standard base64; every digest is 48 bytes. An unset field is not
// checked, except AllowDebug (false refuses debug TDs).
type TDXParams struct {
	// ReportData is what the quote's REPORTDATA must equal, zero-extended to
	// 64 bytes.
	ReportData []byte `json:"report_data,omitempty"`
	// InitData is what MRCONFIGID must equal, zero-extended to 48 bytes. On
	// Azure it is the init-data hash checked against vTPM PCR[8].
	InitData []byte `json:"init_data,omitempty"`
	// MRTD is the set of acceptable MRTD values.
	MRTD DigestSet `json:"mrtd,omitempty"`
	// RTMR0 through RTMR3 are the sets of acceptable register values.
	RTMR0      DigestSet `json:"rtmr0,omitempty"`
	RTMR1      DigestSet `json:"rtmr1,omitempty"`
	RTMR2      DigestSet `json:"rtmr2,omitempty"`
	RTMR3      DigestSet `json:"rtmr3,omitempty"`
	AllowDebug bool      `json:"allow_debug"`
	// AcceptedTCBStatuses lists the DCAP TCB statuses accepted; unset leaves
	// the service's default, every status except Revoked and NoMatchingLevel.
	AcceptedTCBStatuses []teetypes.TdxTcbStatus `json:"accepted_tcb_statuses,omitempty"`
}

// AzSNPParams are [SNPParams] plus vTPM PCR pins for Azure SEV-SNP guests.
// Keys are register indices, values SHA-256 digests.
type AzSNPParams struct {
	SNPParams
	PCRs map[int][]byte `json:"pcrs,omitempty"`
}

// AzTDXParams are [TDXParams] plus vTPM PCR pins for Azure TDX guests.
type AzTDXParams struct {
	TDXParams
	PCRs map[int][]byte `json:"pcrs,omitempty"`
}

// HealthResponse is the body of GET /health.
type HealthResponse struct {
	Status      string                 `json:"status"`
	Platform    *teetypes.PlatformType `json:"platform,omitempty"`
	Cache       CacheStats             `json:"cache"`
	TokenIssuer bool                   `json:"token_issuer"`
}

// CacheStats reports the service's collateral store occupancy.
type CacheStats struct {
	Collateral uint64 `json:"collateral"`
}

// ErrorResponse is the body the service returns with a non-2xx status. Error
// is a stable key (bad_request, platform_not_allowed, verification_failed,
// collateral_unavailable, …); Message is for people.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
