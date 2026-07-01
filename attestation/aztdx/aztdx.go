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
	if ev.TPMQuote == nil {
		return nil, fmt.Errorf("az-tdx evidence is missing the required tpm_quote")
	}

	hclBytes, err := tpmcommon.DecodeBase64URL(ev.HCLReport)
	if err != nil {
		return nil, fmt.Errorf("decoding hcl_report: %w", err)
	}
	hcl, err := tpmcommon.ParseHCLReport(hclBytes)
	if err != nil {
		return nil, err
	}
	if hcl.ReportType != tpmcommon.HCLReportTypeTDX {
		return nil, fmt.Errorf("HCL report_type is %d (expected %d for TDX)", hcl.ReportType, tpmcommon.HCLReportTypeTDX)
	}
	tdQuoteBytes, err := tpmcommon.DecodeBase64URL(ev.TDQuote)
	if err != nil {
		return nil, fmt.Errorf("decoding td_quote: %w", err)
	}
	quote, err := tpmcommon.DecodeTPMQuote(ev.TPMQuote)
	if err != nil {
		return nil, fmt.Errorf("decoding tpm_quote: %w", err)
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

	// TDX DCAP layer: verify the TD quote. The nonce binds via the TPM quote, so
	// ExpectedReportData is NOT forwarded to the TD report_data check. The launch
	// measurement (MR_TD) and RTMRs live in the TD report, so they ARE forwarded.
	hwParams := teetypes.VerifyParams{
		AllowDebug:           params.AllowDebug,
		ExpectedLaunchDigest: params.ExpectedLaunchDigest,
		ExpectedRTMRs:        params.ExpectedRTMRs,
	}
	hw, err := tdx.VerifyQuoteBytes(tdQuoteBytes, hwParams, teetypes.PlatformAzTDX, opts)
	if err != nil {
		return nil, err
	}

	// Bind the vTPM AK material into the TD report (report_data[:32] == SHA-256).
	if err := tpmcommon.VerifyHCLVarDataBinding(hw.Claims.ReportData, hcl.VarData); err != nil {
		return nil, err
	}
	initDataMatch, err := tpmcommon.CheckInitData(quote.PCRs, params.ExpectedInitDataHash)
	if err != nil {
		return nil, err
	}

	tpmcommon.ApplyTPMClaims(&hw.Claims, quote.PCRs, quote.Message)
	hw.ReportDataMatch = reportDataMatch
	hw.InitDataMatch = initDataMatch
	return hw, nil
}
