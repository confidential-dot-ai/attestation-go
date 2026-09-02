// Package teetypes holds the platform-agnostic types shared by the TEE
// attestation verifiers (snp, tdx, az-snp, az-tdx, …). It mirrors the
// attestation-rs `types` module so the Go and Rust verifiers expose the same
// VerifyParams / VerificationResult / Claims shapes.
package teetypes

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PlatformType identifies which TEE platform produced a piece of evidence.
//
// For the cloud-overlay platforms (GcpSnp, GcpTdx, AzSnp, AzTdx) this is an
// attester-reported claim derived from the evidence envelope, NOT a
// cryptographic proof of cloud-provider origin. Do not grant elevated trust on
// the platform tag alone — verify report fields (measurement, chip_id, TCB).
type PlatformType string

const (
	PlatformSNP    PlatformType = "snp"
	PlatformTDX    PlatformType = "tdx"
	PlatformAzSNP  PlatformType = "az-snp"
	PlatformAzTDX  PlatformType = "az-tdx"
	PlatformGcpSNP PlatformType = "gcp-snp"
	PlatformGcpTDX PlatformType = "gcp-tdx"
	PlatformDstack PlatformType = "dstack"
)

// Family is the hardware evidence family a platform tag verifies as.
type Family string

const (
	FamilySNP Family = "sev-snp"
	FamilyTDX Family = "tdx"
)

// Family maps a platform tag to its hardware evidence family: SEV-SNP for
// snp/az-snp/gcp-snp, TDX for tdx/az-tdx/gcp-tdx/dstack (dstack evidence
// carries a TDX quote). An unknown tag returns ("", false) — treat it as
// unverifiable, never as a default family.
func (p PlatformType) Family() (Family, bool) {
	switch p {
	case PlatformSNP, PlatformAzSNP, PlatformGcpSNP:
		return FamilySNP, true
	case PlatformTDX, PlatformAzTDX, PlatformGcpTDX, PlatformDstack:
		return FamilyTDX, true
	default:
		return "", false
	}
}

// IsSNP reports whether p verifies as SEV-SNP evidence.
func (p PlatformType) IsSNP() bool {
	f, ok := p.Family()
	return ok && f == FamilySNP
}

// IsTDX reports whether p verifies as TDX evidence.
func (p PlatformType) IsTDX() bool {
	f, ok := p.Family()
	return ok && f == FamilyTDX
}

// AttestationEvidence is the self-describing evidence envelope: a platform tag
// plus the platform-specific payload, so a verifier can auto-detect the
// platform.
type AttestationEvidence struct {
	Platform PlatformType    `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
}

// MaxEvidenceFieldSize caps a single decoded evidence field (quote, report,
// cert, event log, vTPM quote). The dispatcher already bounds the whole envelope
// (teeverify.MaxEvidenceSize), but the per-platform VerifyEvidence entry points
// are exported and may be called directly, so they bound their own fields.
// Mirrors attestation-rs's utils::MAX_EVIDENCE_FIELD_SIZE.
const MaxEvidenceFieldSize = 1 << 20 // 1 MiB

// CheckFieldSize returns an error if an evidence field exceeds
// MaxEvidenceFieldSize.
func CheckFieldSize(name string, n int) error {
	if n > MaxEvidenceFieldSize {
		return fmt.Errorf("evidence field %q too large: %d bytes (max %d)", name, n, MaxEvidenceFieldSize)
	}
	return nil
}

// VerifyParams is what the caller wants checked during verification. The zero
// value verifies the hardware signature/chain and rejects debug guests, with no
// freshness/init-data/TCB-floor checks.
type VerifyParams struct {
	// ExpectedReportData, if set, must match the report_data bound in the
	// evidence (the SNP/TDX report_data directly, or the vTPM quote nonce on
	// Azure platforms). At most 64 bytes.
	ExpectedReportData []byte
	// ExpectedInitDataHash, if set, must match the init-data binding (SNP
	// HOST_DATA / TDX MR_CONFIG_ID, or PCR[8] on Azure vTPM). At most 32 bytes.
	ExpectedInitDataHash []byte
	// AllowDebug permits guests launched with a debug policy. Default false.
	AllowDebug bool
	// MinTCB, if set, enforces a component-wise minimum SNP TCB.
	MinTCB *SnpTcb
	// ExpectedLaunchDigest, if set, must match the launch measurement (SNP
	// MEASUREMENT / TDX MR_TD). Must be 48 bytes. A mismatch is returned as an
	// error, not a false result.
	ExpectedLaunchDigest []byte
	// ExpectedRTMRs, if set, pins TDX RTMR values. Entry i (0..3) that is
	// non-nil must equal RTMR[i]; nil entries are not checked. Each non-nil
	// entry must be 48 bytes. TDX-only; ignored for SNP.
	ExpectedRTMRs [][]byte
}

// VerificationResult is the outcome of verification. The caller decides
// pass/fail from these fields.
type VerificationResult struct {
	// SignatureValid reports whether the hardware signature on the evidence was
	// valid. Always true on a non-error return (errors are returned instead).
	SignatureValid bool `json:"signature_valid"`
	// Platform that produced the evidence (attester claim for cloud overlays).
	Platform PlatformType `json:"platform"`
	// Claims are the parsed, normalized report fields.
	Claims Claims `json:"claims"`
	// ReportDataMatch is nil when no ExpectedReportData was supplied, else true
	// (a mismatch is returned as an error, not false).
	ReportDataMatch *bool `json:"report_data_match,omitempty"`
	// InitDataMatch is nil when no ExpectedInitDataHash was supplied.
	InitDataMatch *bool `json:"init_data_match,omitempty"`
	// LaunchDigestMatch is nil when no ExpectedLaunchDigest was supplied, else
	// true (a mismatch is returned as an error, not false).
	LaunchDigestMatch *bool `json:"launch_digest_match,omitempty"`
	// CollateralVerified is true when collateral (CRL/TCB/QE identity) was
	// available and all collateral checks passed; false when skipped.
	CollateralVerified bool `json:"collateral_verified"`
	// EventlogVerified is nil when the evidence carried no event log. When
	// non-nil it is true: the CCEL replayed to the quote's RTMR[0-2], binding
	// the event log to the signed quote. A replay mismatch is returned as an
	// error, not false.
	EventlogVerified *bool `json:"eventlog_verified,omitempty"`
	// RTMR3ReplayMatch is nil when the evidence carried no event log, else
	// reports whether the replayed RTMR[3] matched the quote. False is normal
	// and not a failure: RTMR[3] is runtime-extendable and such extends are not
	// recorded in the CCEL. Pin RTMR[3] via VerifyParams.ExpectedRTMRs — that is
	// checked against the signed quote — rather than relying on this field.
	RTMR3ReplayMatch *bool `json:"rtmr3_replay_match,omitempty"`
	// TCBStatus carries platform-specific collateral/TCB details (TDX DCAP).
	TCBStatus *DcapVerificationStatus `json:"tcb_status,omitempty"`
}

// Claims are normalized claims extracted from evidence.
type Claims struct {
	// LaunchDigest is the hex launch measurement (MR_TD for TDX, MEASUREMENT
	// for SNP).
	LaunchDigest string `json:"launch_digest"`
	// ReportData is the raw report_data field from the HW quote.
	ReportData HexBytes `json:"report_data"`
	// SignedData is the data the attester requested be signed. Equals
	// ReportData for bare-metal platforms; the TPM nonce for vTPM platforms.
	SignedData HexBytes `json:"signed_data"`
	// InitData is the init/host data from the quote (SNP HOST_DATA / TDX
	// MR_CONFIG_ID).
	InitData HexBytes `json:"init_data"`
	// TCB is the platform-specific TCB version info.
	TCB TcbInfo `json:"tcb"`
	// PlatformData carries all platform-specific claim fields.
	PlatformData map[string]any `json:"platform_data"`
}

// RTMR returns the 48-byte SHA-384 value of RTMR[i] (0..3) from the TDX
// platform-data claims. It fails for claims without RTMRs (SNP) and for a
// missing or malformed register claim, so a caller pinning a register fails
// closed. Prefer VerifyParams.ExpectedRTMRs, which the verifier checks against
// the signed quote; use this accessor to read verified claims afterwards.
func (c Claims) RTMR(i int) ([]byte, error) {
	if i < 0 || i > 3 {
		return nil, fmt.Errorf("RTMR index %d out of range 0..3", i)
	}
	key := fmt.Sprintf("rtmr_%d", i)
	v, ok := c.PlatformData[key].(string)
	if !ok || v == "" {
		return nil, fmt.Errorf("claims carry no %s", key)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if len(b) != sha512.Size384 {
		return nil, fmt.Errorf("%s is %d bytes, want %d", key, len(b), sha512.Size384)
	}
	return b, nil
}

// DebugEnabled reports whether the evidence marks the guest debuggable: the
// SNP guest policy debug bit, or the TDX TD_ATTRIBUTES debug bit. It fails
// when the claims carry neither, so a caller gating on it fails closed. The
// verifier already rejects debug guests unless VerifyParams.AllowDebug is set;
// use this accessor for reporting or an extra gate.
func (c Claims) DebugEnabled() (bool, error) {
	if policy, ok := c.PlatformData["policy"].(map[string]any); ok {
		if v, ok := policy["debug_allowed"].(bool); ok {
			return v, nil
		}
	}
	if attrs, ok := c.PlatformData["td_attributes_parsed"].(map[string]any); ok {
		if v, ok := attrs["debug"].(bool); ok {
			return v, nil
		}
	}
	return false, fmt.Errorf("claims carry no debug flag (policy.debug_allowed or td_attributes_parsed.debug)")
}

// SMTEnabled reports whether simultaneous multithreading is enabled on the SNP
// host. It fails for claims without SNP platform info (TDX).
func (c Claims) SMTEnabled() (bool, error) {
	if info, ok := c.PlatformData["platform_info"].(map[string]any); ok {
		if v, ok := info["smt_enabled"].(bool); ok {
			return v, nil
		}
	}
	return false, fmt.Errorf("claims carry no platform_info.smt_enabled")
}

// TcbInfo is the platform-specific TCB version, tagged by Type ("Snp"/"Tdx") to
// match the attestation-rs serde representation.
type TcbInfo struct {
	Type string `json:"type"`
	// SNP components (Type == "Snp").
	Bootloader *uint8 `json:"bootloader,omitempty"`
	Tee        *uint8 `json:"tee,omitempty"`
	Snp        *uint8 `json:"snp,omitempty"`
	Microcode  *uint8 `json:"microcode,omitempty"`
	// FMC is present only on Turin SNP processors.
	FMC *uint8 `json:"fmc,omitempty"`
	// TCBSvn is the raw 16-byte TDX TCB SVN (Type == "Tdx").
	TCBSvn HexBytes `json:"tcb_svn,omitempty"`
}

// SnpTcb is an SNP TCB version (used for the MinTCB floor and KDS lookups).
type SnpTcb struct {
	Bootloader uint8  `json:"bootloader"`
	Tee        uint8  `json:"tee"`
	Snp        uint8  `json:"snp"`
	Microcode  uint8  `json:"microcode"`
	FMC        *uint8 `json:"fmc,omitempty"`
}

// TdxTcbStatus is the TDX TCB status from Intel DCAP collateral evaluation.
type TdxTcbStatus string

const (
	TdxUpToDate                          TdxTcbStatus = "UpToDate"
	TdxSWHardeningNeeded                 TdxTcbStatus = "SWHardeningNeeded"
	TdxConfigurationNeeded               TdxTcbStatus = "ConfigurationNeeded"
	TdxConfigurationAndSWHardeningNeeded TdxTcbStatus = "ConfigurationAndSWHardeningNeeded"
	TdxOutOfDate                         TdxTcbStatus = "OutOfDate"
	TdxOutOfDateConfigurationNeeded      TdxTcbStatus = "OutOfDateConfigurationNeeded"
	TdxRevoked                           TdxTcbStatus = "Revoked"
)

// DcapVerificationStatus carries the Intel DCAP collateral evaluation result.
type DcapVerificationStatus struct {
	TCBStatus         TdxTcbStatus `json:"tcb_status"`
	FMSPC             string       `json:"fmspc"`
	AdvisoryIDs       []string     `json:"advisory_ids"`
	CollateralExpired bool         `json:"collateral_expired"`
}

// HexBytes is a byte slice that marshals to/from a hex string in JSON, matching
// the attestation-rs `hex_bytes` serde helper.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("hex decode: %w", err)
	}
	*h = b
	return nil
}

// Ptr returns a pointer to v. Helper for the optional *bool / *uint8 fields.
func Ptr[T any](v T) *T { return &v }
