// Package azsnp verifies Azure SEV-SNP ("az-snp") attestation evidence: the HCL
// envelope an Azure Confidential VM hands back, wrapping an AMD SEV-SNP report
// plus a vTPM quote.
//
// Hardware verification (report signature + VCEK chain + policy) is delegated to
// the snp package (go-sev-guest); the Azure vTPM freshness chain — where the
// per-request nonce lives, because the hardware report_data binds the vTPM AK
// rather than the nonce — is handled by tpmcommon:
//
//	SNP report (VCEK-signed) -> report_data == SHA-256(var_data)
//	    -> AK pub (from var_data) -> TPM quote signature
//	        -> quote extraData == nonce
package azsnp

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// azSnpEvidence is the inner az-snp evidence payload (the value of the
// envelope's "evidence" field).
type azSnpEvidence struct {
	HCLReport string                 `json:"hcl_report"`
	Vcek      string                 `json:"vcek"`
	Version   int                    `json:"version"`
	TPMQuote  *tpmcommon.RawTPMQuote `json:"tpm_quote,omitempty"`
}

// decoded holds the pieces pulled out of an az-snp envelope.
type decoded struct {
	hcl   *tpmcommon.HCLReport
	vcek  []byte
	quote *tpmcommon.TPMQuote // nil if the evidence carried no tpm_quote
}

func decode(ev azSnpEvidence) (*decoded, error) {
	hclBytes, err := tpmcommon.DecodeBase64URL(ev.HCLReport)
	if err != nil {
		return nil, fmt.Errorf("decoding hcl_report: %w", err)
	}
	hcl, err := tpmcommon.ParseHCLReport(hclBytes)
	if err != nil {
		return nil, err
	}
	if hcl.ReportType != tpmcommon.HCLReportTypeSNP {
		return nil, fmt.Errorf("HCL report_type is %d (expected %d for SNP)", hcl.ReportType, tpmcommon.HCLReportTypeSNP)
	}
	vcek, err := tpmcommon.DecodeBase64URL(ev.Vcek)
	if err != nil {
		return nil, fmt.Errorf("decoding vcek: %w", err)
	}
	d := &decoded{hcl: hcl, vcek: vcek}
	if ev.TPMQuote != nil {
		q, err := tpmcommon.DecodeTPMQuote(ev.TPMQuote)
		if err != nil {
			return nil, fmt.Errorf("decoding tpm_quote: %w", err)
		}
		d.quote = q
	}
	return d, nil
}

// VerifyEvidence verifies the inner az-snp evidence payload end to end against
// params: the vTPM trust chain, the SNP hardware report, the var_data binding,
// and (when requested) nonce freshness and init-data. It mirrors attestation-rs
// az_snp::verify::verify_evidence. The nonce, if any, is params.ExpectedReportData
// (compared against the TPM quote's extraData, not the SNP report_data).
//
// opts tunes the SNP hardware layer (CRL revocation / collateral fetching). The
// zero value verifies offline; pass a Getter with CheckRevocations to enable
// VCEK revocation checks — previously this path could never reach them.
func VerifyEvidence(inner []byte, params teetypes.VerifyParams, opts snp.Options) (*teetypes.VerificationResult, error) {
	var ev azSnpEvidence
	if err := json.Unmarshal(inner, &ev); err != nil {
		return nil, fmt.Errorf("parsing az-snp evidence: %w", err)
	}
	if ev.Version != 1 {
		return nil, fmt.Errorf("unsupported az-snp evidence version: %d", ev.Version)
	}
	d, err := decode(ev)
	if err != nil {
		return nil, err
	}
	if d.quote == nil {
		return nil, fmt.Errorf("az-snp evidence is missing the required tpm_quote")
	}

	// TPM layer: the AK (from var_data) signs the quote; then the quote's nonce
	// and PCR digest are checked. The AK is bound to the hardware report below.
	if err := tpmcommon.VerifyTPMSignature(d.quote.Signature, d.quote.Message, d.hcl.VarData); err != nil {
		return nil, fmt.Errorf("az-snp vTPM: %w", err)
	}
	reportDataMatch, err := tpmcommon.CheckReportData(d.quote.Message, params.ExpectedReportData)
	if err != nil {
		return nil, fmt.Errorf("az-snp vTPM: %w", err)
	}
	if err := tpmcommon.VerifyTPMPCRs(d.quote.Message, d.quote.PCRs); err != nil {
		return nil, fmt.Errorf("az-snp vTPM: %w", err)
	}

	// Hardware layer: SNP report signature + chain + policy. Forward every param
	// to the HW layer EXCEPT the two that bind at the vTPM layer rather than the
	// SNP report: the nonce (ExpectedReportData, checked against the TPM quote's
	// extraData above) and init-data (ExpectedInitDataHash, checked against
	// PCR[8]). Deriving from params and nulling only those two is fail-safe — a
	// future HW-property field flows through by default instead of being silently
	// dropped from the Azure path.
	hwParams := params
	hwParams.ExpectedReportData = nil
	hwParams.ExpectedInitDataHash = nil
	hw, err := snp.VerifyReport(d.hcl.TEEReport, d.vcek, hwParams, teetypes.PlatformAzSNP, snp.MinReportVersionAzure, opts)
	if err != nil {
		return nil, err
	}

	// Bind the vTPM AK material into the hardware-signed report.
	if err := tpmcommon.VerifyHCLVarDataBinding(hw.Claims.ReportData, d.hcl.VarData); err != nil {
		return nil, err
	}
	initDataMatch, err := tpmcommon.CheckInitData(d.quote.Message, d.quote.PCRs, params.ExpectedInitDataHash)
	if err != nil {
		return nil, err
	}

	tpmcommon.ApplyTPMClaims(&hw.Claims, d.quote.PCRs, d.quote.Message)
	hw.ReportDataMatch = reportDataMatch
	hw.InitDataMatch = initDataMatch
	return hw, nil
}
