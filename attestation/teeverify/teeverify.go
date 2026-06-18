// Package teeverify is the unified entry point for verifying TEE attestation
// evidence from a self-describing JSON envelope. It auto-detects the platform
// from the envelope's "platform" field and dispatches to the matching verifier,
// mirroring attestation-rs's top-level `verify(evidence_json, params)`.
//
// Supported platforms: snp, az-snp, tdx, az-tdx, gcp-snp, gcp-tdx. The GCP
// variants verify identically to their bare-metal counterparts and only carry a
// different (attester-claimed, not cryptographically proven) platform tag.
package teeverify

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/azsnp"
	"github.com/confidential-dot-ai/attestation-go/attestation/aztdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// MaxEvidenceSize bounds the evidence JSON to reject oversized input before
// parsing.
const MaxEvidenceSize = 1 << 20 // 1 MiB

// Options carries the per-family verifier options (collateral fetching,
// verification time). The zero value verifies offline.
type Options struct {
	SNP snp.Options
	TDX tdx.Options
}

// Verify verifies a self-describing evidence envelope offline (no collateral
// fetching). For collateral/CRL checks or a pinned verification time, use
// VerifyWithOptions.
func Verify(evidenceJSON []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	return VerifyWithOptions(evidenceJSON, params, Options{})
}

// VerifyWithOptions verifies a self-describing evidence envelope, dispatching on
// the platform tag.
func VerifyWithOptions(evidenceJSON []byte, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	if len(evidenceJSON) > MaxEvidenceSize {
		return nil, fmt.Errorf("evidence too large: %d bytes (max %d)", len(evidenceJSON), MaxEvidenceSize)
	}
	if len(params.ExpectedReportData) > 64 {
		return nil, fmt.Errorf("expected_report_data is %d bytes (max 64)", len(params.ExpectedReportData))
	}

	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(evidenceJSON, &env); err != nil {
		return nil, fmt.Errorf("parsing evidence envelope: %w", err)
	}

	switch env.Platform {
	case teetypes.PlatformSNP:
		return verifySNP(env.Evidence, params, opts.SNP, teetypes.PlatformSNP)
	case teetypes.PlatformGcpSNP:
		return verifySNP(env.Evidence, params, opts.SNP, teetypes.PlatformGcpSNP)
	case teetypes.PlatformAzSNP:
		return azsnp.VerifyEvidence(env.Evidence, params)
	case teetypes.PlatformTDX:
		return verifyTDX(env.Evidence, params, opts.TDX, teetypes.PlatformTDX)
	case teetypes.PlatformGcpTDX:
		return verifyTDX(env.Evidence, params, opts.TDX, teetypes.PlatformGcpTDX)
	case teetypes.PlatformAzTDX:
		return aztdx.VerifyEvidence(env.Evidence, params, opts.TDX)
	default:
		return nil, fmt.Errorf("unsupported platform %q", env.Platform)
	}
}

func verifySNP(inner json.RawMessage, params teetypes.VerifyParams, opts snp.Options, platform teetypes.PlatformType) (*teetypes.VerificationResult, error) {
	var ev snp.SnpEvidence
	if err := json.Unmarshal(inner, &ev); err != nil {
		return nil, fmt.Errorf("parsing snp evidence: %w", err)
	}
	res, err := snp.VerifyEvidence(ev, params, opts)
	if err != nil {
		return nil, err
	}
	res.Platform = platform // GcpSnp tag is an attester claim; see teetypes docs
	return res, nil
}

func verifyTDX(inner json.RawMessage, params teetypes.VerifyParams, opts tdx.Options, platform teetypes.PlatformType) (*teetypes.VerificationResult, error) {
	var ev tdx.TdxEvidence
	if err := json.Unmarshal(inner, &ev); err != nil {
		return nil, fmt.Errorf("parsing tdx evidence: %w", err)
	}
	res, err := tdx.VerifyEvidence(ev, params, opts)
	if err != nil {
		return nil, err
	}
	res.Platform = platform
	return res, nil
}
