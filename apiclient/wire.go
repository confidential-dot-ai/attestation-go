package apiclient

import (
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

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
type AttestRequest struct {
	ReportData []byte                `json:"report_data"`
	Platform   teetypes.PlatformType `json:"platform"`
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
type VerifyParams struct {
	ExpectedReportData   []byte `json:"expected_report_data,omitempty"`
	ExpectedInitDataHash []byte `json:"expected_init_data_hash,omitempty"`
	AllowDebug           *bool  `json:"allow_debug,omitempty"`
	// MinTcb is an SEV-SNP floor. The service's TDX verifier has no
	// minimum-TCB parameter, so sending it with TDX evidence pins nothing.
	MinTcb *teetypes.SnpTcb `json:"min_tcb,omitempty"`
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
