package ratls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// NormalizeSEVSNPReport returns the raw 1184-byte AMD report from raw, which is
// either the report itself or a Hyper-V HCL envelope around it — the shape an
// Azure confidential VM's vTPM hands back. Anything else fails with
// [ErrInvalidReport], including an HCL envelope whose report type is not SNP,
// so a TDX report cannot be read under SEV-SNP rules.
func NormalizeSEVSNPReport(raw []byte) ([]byte, error) {
	if len(raw) == SNPReportSize {
		return raw, nil
	}
	hcl, err := tpmcommon.ParseHCLReport(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: not a raw %d-byte SEV-SNP report: %v", ErrInvalidReport, SNPReportSize, err)
	}
	if hcl.ReportType != tpmcommon.HCLReportTypeSNP {
		return nil, fmt.Errorf("%w: HCL envelope carries report type %d, want SNP (%d)",
			ErrInvalidReport, hcl.ReportType, tpmcommon.HCLReportTypeSNP)
	}
	return hcl.TEEReport, nil
}

// snpEvidenceFields are the two places an evidence envelope can put the SEV-SNP
// report. The base64 alphabets differ by field and are part of each producer's
// wire format, so they are not interchangeable.
type snpEvidenceFields struct {
	// AttestationReport is the bare report, standard base64.
	AttestationReport string `json:"attestation_report"`
	// HCLReport is the Hyper-V HCL envelope, URL-safe base64 without padding.
	HCLReport string `json:"hcl_report"`
}

// ExtractSNPReport returns the raw 1184-byte report from an SEV-SNP evidence
// envelope, picking the field and base64 alphabet the producer used and
// unwrapping an HCL envelope when it finds one. Evidence carrying neither field
// fails with [ErrInvalidReport].
func ExtractSNPReport(env teetypes.AttestationEvidence) ([]byte, error) {
	var fields snpEvidenceFields
	if err := json.Unmarshal(env.Evidence, &fields); err != nil {
		return nil, fmt.Errorf("ratls: parse %q evidence: %w", env.Platform, err)
	}
	switch {
	case fields.AttestationReport != "":
		report, err := base64.StdEncoding.DecodeString(fields.AttestationReport)
		if err != nil {
			return nil, fmt.Errorf("ratls: decode attestation_report: %w", err)
		}
		return report, nil
	case fields.HCLReport != "":
		hcl, err := base64.RawURLEncoding.DecodeString(fields.HCLReport)
		if err != nil {
			return nil, fmt.Errorf("ratls: decode hcl_report: %w", err)
		}
		return NormalizeSEVSNPReport(hcl)
	default:
		return nil, fmt.Errorf("%w: %q evidence has neither attestation_report nor hcl_report",
			ErrInvalidReport, env.Platform)
	}
}
