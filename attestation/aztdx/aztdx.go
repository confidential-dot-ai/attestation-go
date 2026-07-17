// Package aztdx verifies Azure TDX ("az-tdx") attestation evidence: an HCL
// envelope wrapping a TD report plus a separate Intel DCAP TD quote and a vTPM
// quote. It mirrors attestation-rs's az_tdx verifier — the TDX DCAP layer is
// delegated to the tdx package, and the Azure vTPM freshness chain (where the
// per-request nonce lives, since the TD report_data binds the vTPM AK) is
// handled by tpmcommon:
//
//	TD quote (Intel-signed) -> report_data == SHA-256(var_data)
//	    -> AK pub (from var_data) -> TPM quote signature
//	        -> quote extraData == nonce
package aztdx

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// azTdxEvidence is the inner az-tdx evidence payload.
type azTdxEvidence struct {
	HCLReport string                 `json:"hcl_report"`
	TDQuote   string                 `json:"td_quote"`
	Version   int                    `json:"version"`
	TPMQuote  *tpmcommon.RawTPMQuote `json:"tpm_quote"`
}

// envelope is the self-describing {platform, evidence} wrapper.
type envelope struct {
	Platform string          `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
}

// --- Back-compat lightweight API (mirrors azsnp; used by TEErminator's Flow A
// policy layer so one tls-header remote can be backed by SNP or TDX) ---

// Result is the lightweight result of az-tdx hardware verification: the launch
// measurement (MRTD), the TD report's report_data, the HCL var_data (vTPM AK
// material), and the decoded vTPM quote. Use VerifyVTPMFreshness to bind a
// nonce. Mirrors azsnp.Result so callers can treat both Azure vTPM platforms
// uniformly.
type Result struct {
	Measurement string
	ReportData  []byte
	VarData     []byte
	TPMQuote    *tpmcommon.TPMQuote
}

// Verify verifies the TD quote inside an az-tdx envelope (Intel DCAP signature +
// chain via the tdx package) and returns the MRTD launch measurement, the TD
// report_data, the HCL var_data, and the decoded vTPM quote. It does not enforce
// freshness; use Result.VerifyVTPMFreshness. Mirrors azsnp.Verify.
func Verify(raw []byte) (*Result, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parsing az-tdx envelope: %w", err)
	}
	if env.Platform != string(teetypes.PlatformAzTDX) {
		return nil, fmt.Errorf("unexpected platform %q, want %q", env.Platform, teetypes.PlatformAzTDX)
	}
	var ev azTdxEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		return nil, fmt.Errorf("parsing az-tdx evidence: %w", err)
	}
	hcl, tdQuoteBytes, quote, err := decode(ev)
	if err != nil {
		return nil, err
	}
	hw, err := tdx.VerifyQuoteBytes(tdQuoteBytes, teetypes.VerifyParams{}, teetypes.PlatformAzTDX, tdx.Options{})
	if err != nil {
		return nil, err
	}
	return &Result{
		Measurement: hw.Claims.LaunchDigest,
		ReportData:  hw.Claims.ReportData,
		VarData:     hcl.VarData,
		TPMQuote:    quote,
	}, nil
}

// VerifyAttestation reports only whether the az-tdx TD quote is valid.
func VerifyAttestation(raw []byte) error {
	_, err := Verify(raw)
	return err
}

// VerifyVTPMFreshness verifies the az-tdx vTPM trust chain binds nonce:
// TD report_data == SHA-256(var_data) → AK pub → AK-signed quote → quote
// extraData == nonce. PCR digest integrity is checked too. Mirrors
// azsnp.Result.VerifyVTPMFreshness — the tpmcommon chain is platform-agnostic.
func (r *Result) VerifyVTPMFreshness(nonce []byte) error {
	if r.TPMQuote == nil {
		return fmt.Errorf("evidence carries no vTPM quote")
	}
	if len(r.VarData) == 0 {
		return fmt.Errorf("HCL report carries no var_data to bind the vTPM AK")
	}
	if err := tpmcommon.VerifyHCLVarDataBinding(r.ReportData, r.VarData); err != nil {
		return err
	}
	if err := tpmcommon.VerifyTPMSignature(r.TPMQuote.Signature, r.TPMQuote.Message, r.VarData); err != nil {
		return err
	}
	if err := tpmcommon.VerifyTPMPCRs(r.TPMQuote.Message, r.TPMQuote.PCRs); err != nil {
		return err
	}
	return tpmcommon.VerifyTPMNonce(r.TPMQuote.Message, nonce)
}

// decode pulls the HCL report, raw TD quote bytes, and decoded vTPM quote out of
// an az-tdx evidence payload, enforcing the required tpm_quote and TDX report
// type. Shared by Verify and VerifyEvidence.
func decode(ev azTdxEvidence) (*tpmcommon.HCLReport, []byte, *tpmcommon.TPMQuote, error) {
	if ev.TPMQuote == nil {
		return nil, nil, nil, fmt.Errorf("az-tdx evidence is missing the required tpm_quote")
	}
	hclBytes, err := tpmcommon.DecodeBase64URL(ev.HCLReport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding hcl_report: %w", err)
	}
	hcl, err := tpmcommon.ParseHCLReport(hclBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	if hcl.ReportType != tpmcommon.HCLReportTypeTDX {
		return nil, nil, nil, fmt.Errorf("HCL report_type is %d (expected %d for TDX)", hcl.ReportType, tpmcommon.HCLReportTypeTDX)
	}
	tdQuoteBytes, err := tpmcommon.DecodeBase64URL(ev.TDQuote)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding td_quote: %w", err)
	}
	quote, err := tpmcommon.DecodeTPMQuote(ev.TPMQuote)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding tpm_quote: %w", err)
	}
	return hcl, tdQuoteBytes, quote, nil
}

// --- Unified API (used by the dispatcher) ---

// VerifyEvidence verifies the inner az-tdx evidence payload end to end against
// params: the vTPM trust chain, the Intel TDX DCAP quote, the var_data binding,
// and (when requested) nonce freshness and init-data. opts tunes the DCAP layer
// (collateral, verification time). Mirrors attestation-rs
// az_tdx::verify::verify_evidence.
func VerifyEvidence(inner []byte, params teetypes.VerifyParams, opts tdx.Options) (*teetypes.VerificationResult, error) {
	var ev azTdxEvidence
	if err := json.Unmarshal(inner, &ev); err != nil {
		return nil, fmt.Errorf("parsing az-tdx evidence: %w", err)
	}
	if ev.Version != 1 {
		return nil, fmt.Errorf("unsupported az-tdx evidence version: %d", ev.Version)
	}

	hcl, tdQuoteBytes, quote, err := decode(ev)
	if err != nil {
		return nil, err
	}

	// TPM layer: the AK (from var_data) signs the quote; the quote's nonce and
	// PCR digest are checked. The AK binds to the TD report below.
	if err := tpmcommon.VerifyTPMSignature(quote.Signature, quote.Message, hcl.VarData); err != nil {
		return nil, fmt.Errorf("az-tdx vTPM: %w", err)
	}
	reportDataMatch, err := tpmcommon.CheckReportData(quote.Message, params.ExpectedReportData)
	if err != nil {
		return nil, fmt.Errorf("az-tdx vTPM: %w", err)
	}
	if err := tpmcommon.VerifyTPMPCRs(quote.Message, quote.PCRs); err != nil {
		return nil, fmt.Errorf("az-tdx vTPM: %w", err)
	}

	// TDX DCAP layer: verify the TD quote. Forward every param to the HW layer
	// EXCEPT the two that bind at the vTPM layer rather than the TD report: the
	// nonce (ExpectedReportData, checked against the TPM quote's extraData above)
	// and init-data (ExpectedInitDataHash, checked against PCR[8]). Deriving from
	// params and nulling only those two is fail-safe — a future HW-property field
	// (e.g. the launch measurement MR_TD and RTMRs, which live in the TD report)
	// flows through by default instead of being silently dropped.
	hwParams := params
	hwParams.ExpectedReportData = nil
	hwParams.ExpectedInitDataHash = nil
	hw, err := tdx.VerifyQuoteBytes(tdQuoteBytes, hwParams, teetypes.PlatformAzTDX, opts)
	if err != nil {
		return nil, err
	}

	// Bind the vTPM AK material into the TD report (report_data[:32] == SHA-256).
	if err := tpmcommon.VerifyHCLVarDataBinding(hw.Claims.ReportData, hcl.VarData); err != nil {
		return nil, err
	}
	initDataMatch, err := tpmcommon.CheckInitData(quote.Message, quote.PCRs, params.ExpectedInitDataHash)
	if err != nil {
		return nil, err
	}

	tpmcommon.ApplyTPMClaims(&hw.Claims, quote.PCRs, quote.Message)
	hw.ReportDataMatch = reportDataMatch
	hw.InitDataMatch = initDataMatch
	return hw, nil
}
