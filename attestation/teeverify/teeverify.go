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
	"context"
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

// VerifyWithOptions verifies a self-describing evidence envelope with a
// background context; see VerifyWithOptionsContext.
func VerifyWithOptions(evidenceJSON []byte, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	return VerifyWithOptionsContext(context.Background(), evidenceJSON, params, opts)
}

// VerifyWithOptionsContext verifies a self-describing evidence envelope,
// dispatching on the platform tag.
//
// ctx bounds the AMD KDS fetch the snp and gcp-snp arms make when the evidence
// carries no inline VCEK and opts.SNP.Getter is set (see
// snp.VerifyEvidenceContext); a bare RA-TLS serving cert is the case that needs
// it. Nothing else here reaches the network: az-snp carries its VCEK inside the
// HCL envelope, and the TDX arms verify against collateral already supplied.
func VerifyWithOptionsContext(ctx context.Context, evidenceJSON []byte, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	if len(evidenceJSON) > MaxEvidenceSize {
		return nil, fmt.Errorf("evidence too large: %d bytes (max %d)", len(evidenceJSON), MaxEvidenceSize)
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(evidenceJSON, &env); err != nil {
		return nil, fmt.Errorf("parsing evidence envelope: %w", err)
	}
	return VerifyEnvelope(ctx, env, params, opts)
}

// VerifyEnvelope verifies an evidence envelope a caller already holds parsed,
// and is where the dispatch happens: the byte-slice entry points unmarshal and
// come here. A caller that built or received an envelope — RA-TLS extension
// evidence, an attestation service's /attest response — calls this rather than
// marshalling it only to have it parsed straight back.
//
// The size bound belongs to the byte-slice entry points, which is where
// untrusted bytes arrive; an envelope in hand has already been parsed by
// whoever produced it.
func VerifyEnvelope(ctx context.Context, env teetypes.AttestationEvidence, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	if len(params.ExpectedReportData) > 64 {
		return nil, fmt.Errorf("expected_report_data is %d bytes (max 64)", len(params.ExpectedReportData))
	}
	// Route on the canonicalized tag so the dispatcher accepts exactly what
	// teetypes.NormalizePlatform/Family say a tag means; the result carries the
	// canonical constant, never the attester's spelling.
	switch teetypes.NormalizePlatform(string(env.Platform)) {
	case teetypes.PlatformSNP:
		return verifySNP(ctx, env.Evidence, params, opts.SNP, teetypes.PlatformSNP)
	case teetypes.PlatformGcpSNP:
		return verifySNP(ctx, env.Evidence, params, opts.SNP, teetypes.PlatformGcpSNP)
	case teetypes.PlatformAzSNP:
		return azsnp.VerifyEvidence(env.Evidence, params, opts.SNP)
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

func verifySNP(ctx context.Context, inner json.RawMessage, params teetypes.VerifyParams, opts snp.Options, platform teetypes.PlatformType) (*teetypes.VerificationResult, error) {
	var ev snp.SnpEvidence
	if err := json.Unmarshal(inner, &ev); err != nil {
		return nil, fmt.Errorf("parsing snp evidence: %w", err)
	}
	res, err := snp.VerifyEvidenceContext(ctx, ev, params, opts)
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
