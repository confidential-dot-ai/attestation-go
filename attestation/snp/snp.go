// Package snp verifies bare-metal AMD SEV-SNP attestation evidence. The heavy
// cryptography (ARK→ASK→VCEK chain, report signature, VCEK TCB OID
// cross-validation, optional CRL revocation, and field/policy validation) is
// delegated to go-sev-guest — the Go counterpart of the `sev` crate plus the
// hand-rolled cert/CRL logic in attestation-rs's snp module. This package maps
// teetypes.VerifyParams onto go-sev-guest's verify/validate options and
// normalizes the report into teetypes.Claims.
package snp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Report version bounds. Bare-metal SNP requires v3+ (CPUID fields); Azure CVMs
// emit v2 reports, so az-snp passes MinReportVersionAzure.
const (
	MinReportVersion      = 3
	MinReportVersionAzure = 2
	MaxReportVersion      = 5
)

// SnpEvidence is the bare-metal SNP evidence payload. The ASK/ARK in cert_chain
// are accepted for compatibility but ignored — trust anchors come from
// go-sev-guest's bundled AMD roots so a rogue intermediate/root can't be
// substituted.
type SnpEvidence struct {
	AttestationReport string        `json:"attestation_report"` // base64 (std) of the 1184-byte report
	CertChain         *SnpCertChain `json:"cert_chain,omitempty"`
}

// SnpCertChain carries the VCEK/VLEK (the only field used) plus the ignored
// ASK/ARK.
type SnpCertChain struct {
	Vcek string `json:"vcek"` // base64 (std) DER
	Ask  string `json:"ask,omitempty"`
	Ark  string `json:"ark,omitempty"`
}

// Options tunes hardware verification.
type Options struct {
	// CheckRevocations fetches AMD CRLs and checks the VCEK/ASK for revocation.
	// Requires network (Getter). Off by default → offline verification.
	CheckRevocations bool
	// Getter fetches collateral (CRLs, missing certs). Defaults to none
	// (offline); set for revocation/cert fetching.
	Getter trust.HTTPSGetter
}

// VerifyEvidence verifies a bare-metal SNP evidence envelope and returns
// normalized claims. The VCEK must be supplied in cert_chain (offline);
// fetching from AMD KDS is intentionally not done here.
func VerifyEvidence(ev SnpEvidence, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	if ev.CertChain == nil || ev.CertChain.Vcek == "" {
		return nil, fmt.Errorf("snp: evidence is missing cert_chain.vcek (offline verification requires the VCEK)")
	}
	reportBytes, err := base64.StdEncoding.DecodeString(ev.AttestationReport)
	if err != nil {
		return nil, fmt.Errorf("snp: decoding attestation_report: %w", err)
	}
	vcekDER, err := base64.StdEncoding.DecodeString(ev.CertChain.Vcek)
	if err != nil {
		return nil, fmt.Errorf("snp: decoding vcek: %w", err)
	}
	return VerifyReport(reportBytes, vcekDER, params, teetypes.PlatformSNP, MinReportVersion, opts)
}

// VerifyReport verifies a raw 1184-byte SNP report against the given VCEK DER:
// signature + chain (go-sev-guest verify) and field/policy validation
// (go-sev-guest validate), then extracts claims. minVersion lets az-snp accept
// v2 reports while bare-metal requires v3. Shared by the snp and azsnp packages.
func VerifyReport(reportBytes, vcekDER []byte, params teetypes.VerifyParams, platform teetypes.PlatformType, minVersion uint32, opts Options) (*teetypes.VerificationResult, error) {
	report, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("snp: parsing report: %w", err)
	}
	if v := report.GetVersion(); v < minVersion || v > MaxReportVersion {
		return nil, fmt.Errorf("snp: unsupported report version %d (want %d..%d)", v, minVersion, MaxReportVersion)
	}

	attestation := &spb.Attestation{
		Report:           report,
		CertificateChain: &spb.CertificateChain{VcekCert: vcekDER},
	}

	// Hardware verification: report signature + ARK→ASK→VCEK chain + VCEK TCB
	// OID cross-validation, against go-sev-guest's bundled AMD roots. The product
	// (Milan/Genoa/Turin) selects which embedded roots to use; we resolve it from
	// the report so verification stays offline (DisableCertFetching) unless a
	// Getter is supplied for CRL/cert fetching.
	verifyOpts := sv.DefaultOptions()
	verifyOpts.CheckRevocations = opts.CheckRevocations
	verifyOpts.Product = productFromReport(report)
	verifyOpts.DisableCertFetching = opts.Getter == nil
	if opts.Getter != nil {
		verifyOpts.Getter = opts.Getter
	}
	if err := sv.SnpAttestation(attestation, verifyOpts); err != nil {
		return nil, fmt.Errorf("snp: hardware verification failed: %w", err)
	}

	// Field/policy validation: VMPL==0, debug policy, report_data, host_data,
	// minimum TCB. Maps teetypes.VerifyParams onto validate.Options.
	vOpts, err := validateOptions(params)
	if err != nil {
		return nil, err
	}
	if err := validate.SnpAttestation(attestation, vOpts); err != nil {
		return nil, fmt.Errorf("snp: policy validation failed: %w", err)
	}

	res := &teetypes.VerificationResult{
		SignatureValid:     true,
		Platform:           platform,
		Claims:             extractClaims(report),
		CollateralVerified: opts.CheckRevocations,
	}
	if params.ExpectedReportData != nil {
		res.ReportDataMatch = teetypes.Ptr(true) // validate enforced it (mismatch errors above)
	}
	if params.ExpectedInitDataHash != nil {
		res.InitDataMatch = teetypes.Ptr(true)
	}
	return res, nil
}

// validateOptions maps VerifyParams onto go-sev-guest validate.Options. The
// guest policy is the most-permissive maximum except Debug, which is gated by
// AllowDebug; VMPL is pinned to 0 (matching attestation-rs).
func validateOptions(params teetypes.VerifyParams) (*validate.Options, error) {
	vmpl0 := 0
	opts := &validate.Options{
		GuestPolicy: abi.SnpPolicy{
			SMT:          true,
			MigrateMA:    true,
			Debug:        params.AllowDebug,
			SingleSocket: false,
		},
		VMPL: &vmpl0,
	}
	if d := params.ExpectedReportData; d != nil {
		if len(d) > 64 {
			return nil, fmt.Errorf("snp: expected_report_data is %d bytes (max 64)", len(d))
		}
		opts.ReportData = pad(d, 64)
	}
	if d := params.ExpectedInitDataHash; d != nil {
		if len(d) > 32 {
			return nil, fmt.Errorf("snp: expected_init_data_hash is %d bytes (max 32)", len(d))
		}
		opts.HostData = pad(d, 32)
	}
	if t := params.MinTCB; t != nil {
		opts.MinimumTCB = kds.TCBParts{
			BlSpl:    t.Bootloader,
			TeeSpl:   t.Tee,
			SnpSpl:   t.Snp,
			UcodeSpl: t.Microcode,
		}
	}
	return opts, nil
}

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// productFromReport resolves the AMD product (which selects the embedded ARK/ASK
// roots) from the report's CPUID. go-sev-guest recognizes the canonical model
// IDs; for the Genoa-family 0xA0 range (Bergamo/Siena and some Genoa SKUs) its
// detection returns Unknown, so we fall back to the same family/model mapping
// attestation-rs uses, keeping verification offline.
func productFromReport(report *spb.Report) *spb.SevProduct {
	fms := report.GetCpuid1EaxFms()
	if p := abi.SevProductFromCpuid1Eax(fms); p.GetName() != spb.SevProduct_SEV_PRODUCT_UNKNOWN {
		return p
	}
	family, model, stepping := abi.FmsFromCpuid1Eax(fms)
	name := spb.SevProduct_SEV_PRODUCT_UNKNOWN
	switch {
	case family == 0x19 && model <= 0x0F:
		name = spb.SevProduct_SEV_PRODUCT_MILAN
	case family == 0x19 && ((model >= 0x10 && model <= 0x1F) || (model >= 0xA0 && model <= 0xAF)):
		name = spb.SevProduct_SEV_PRODUCT_GENOA
	case family == 0x1A && model <= 0x11:
		name = spb.SevProduct_SEV_PRODUCT_TURIN
	default:
		return abi.SevProductFromCpuid1Eax(fms) // leave Unknown; verify reports it
	}
	return &spb.SevProduct{Name: name, MachineStepping: wrapperspb.UInt32(uint32(stepping))}
}

// extractClaims normalizes an SNP report into teetypes.Claims (mirrors
// attestation-rs snp::claims::extract_claims).
func extractClaims(report *spb.Report) teetypes.Claims {
	policy, _ := abi.ParseSnpPolicy(report.GetPolicy())
	plat, _ := abi.ParseSnpPlatformInfo(report.GetPlatformInfo())
	tcb := kds.DecomposeTCBVersion(kds.TCBVersion(report.GetReportedTcb()))

	platformData := map[string]any{
		"policy": map[string]any{
			"abi_major":     policy.ABIMajor,
			"abi_minor":     policy.ABIMinor,
			"smt_allowed":   policy.SMT,
			"migrate_ma":    policy.MigrateMA,
			"debug_allowed": policy.Debug,
			"single_socket": policy.SingleSocket,
		},
		"platform_info": map[string]any{
			"tsme_enabled": plat.TSMEEnabled,
			"smt_enabled":  plat.SMTEnabled,
		},
		"vmpl":            report.GetVmpl(),
		"chip_id":         hex.EncodeToString(report.GetChipId()),
		"current_build":   report.GetCurrentBuild(),
		"current_minor":   report.GetCurrentMinor(),
		"current_major":   report.GetCurrentMajor(),
		"committed_build": report.GetCommittedBuild(),
		"committed_minor": report.GetCommittedMinor(),
		"committed_major": report.GetCommittedMajor(),
		"guest_svn":       report.GetGuestSvn(),
		"signature_algo":  report.GetSignatureAlgo(),
	}

	bl, tee, snp, uc := tcb.BlSpl, tcb.TeeSpl, tcb.SnpSpl, tcb.UcodeSpl
	return teetypes.Claims{
		LaunchDigest: hex.EncodeToString(report.GetMeasurement()),
		ReportData:   report.GetReportData(),
		SignedData:   stripTrailingNulls(report.GetReportData()),
		InitData:     report.GetHostData(),
		TCB: teetypes.TcbInfo{
			Type:       "Snp",
			Bootloader: &bl,
			Tee:        &tee,
			Snp:        &snp,
			Microcode:  &uc,
		},
		PlatformData: platformData,
	}
}

func stripTrailingNulls(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}
