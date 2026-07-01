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

// envelope is the self-describing {platform, evidence} wrapper.
type envelope struct {
	Platform string          `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
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

// --- Back-compat lightweight API (used by TEErminator's policy layer) ---

// Result is the lightweight result of az-snp hardware verification: the launch
// measurement, report_data, HCL var_data (vTPM AK material), and decoded vTPM
// quote. Use VerifyVTPMFreshness to bind a nonce.
type Result struct {
	Measurement string
	ReportData  []byte
	VarData     []byte
	TPMQuote    *tpmcommon.TPMQuote
}

// Verify verifies the SNP hardware report inside an az-snp envelope (signature +
// VCEK chain + policy via the snp package) and returns the launch measurement,
// report_data, var_data, and decoded vTPM quote. It does not enforce freshness;
// use Result.VerifyVTPMFreshness.
func Verify(raw []byte) (*Result, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parsing az-snp envelope: %w", err)
	}
	if env.Platform != string(teetypes.PlatformAzSNP) {
		return nil, fmt.Errorf("unexpected platform %q, want %q", env.Platform, teetypes.PlatformAzSNP)
	}
	var ev azSnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		return nil, fmt.Errorf("parsing az-snp evidence: %w", err)
	}
	d, err := decode(ev)
	if err != nil {
		return nil, err
	}
	hw, err := snp.VerifyReport(d.hcl.TEEReport, d.vcek, teetypes.VerifyParams{}, teetypes.PlatformAzSNP, snp.MinReportVersionAzure, snp.Options{})
	if err != nil {
		return nil, err
	}
	return &Result{
		Measurement: hw.Claims.LaunchDigest,
		ReportData:  hw.Claims.ReportData,
		VarData:     d.hcl.VarData,
		TPMQuote:    d.quote,
	}, nil
}

// VerifyAttestation reports only whether the az-snp hardware report is valid.
func VerifyAttestation(raw []byte) error {
	_, err := Verify(raw)
	return err
}

// VerifyVTPMFreshness verifies the az-snp vTPM trust chain binds nonce:
// report_data == SHA-256(var_data) → AK pub → AK-signed quote → quote extraData
// == nonce. PCR digest integrity is checked too.
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

// --- Unified API (used by the dispatcher) ---

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

	// Hardware layer: SNP report signature + chain + policy. The nonce binds via
	// the TPM quote (above), so ExpectedReportData is NOT forwarded to the SNP
	// report_data check; init-data binds via PCR[8], not HOST_DATA. The launch
	// measurement is a property of the HW report, so it IS forwarded.
	hwParams := teetypes.VerifyParams{
		AllowDebug:           params.AllowDebug,
		MinTCB:               params.MinTCB,
		ExpectedLaunchDigest: params.ExpectedLaunchDigest,
	}
	hw, err := snp.VerifyReport(d.hcl.TEEReport, d.vcek, hwParams, teetypes.PlatformAzSNP, snp.MinReportVersionAzure, opts)
	if err != nil {
		return nil, err
	}

	// Bind the vTPM AK material into the hardware-signed report.
	if err := tpmcommon.VerifyHCLVarDataBinding(hw.Claims.ReportData, d.hcl.VarData); err != nil {
		return nil, err
	}
	initDataMatch, err := tpmcommon.CheckInitData(d.quote.PCRs, params.ExpectedInitDataHash)
	if err != nil {
		return nil, err
	}

	tpmcommon.ApplyTPMClaims(&hw.Claims, d.quote.PCRs, d.quote.Message)
	hw.ReportDataMatch = reportDataMatch
	hw.InitDataMatch = initDataMatch
	return hw, nil
}
