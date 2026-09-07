package teetypes

import "strings"

// Family is the hardware TEE behind a platform tag: the cloud-overlay tags
// (az-*, gcp-*) name the same silicon as their bare-metal counterpart and are
// verified by the same code path, so policy that is inherently
// hardware-specific — pinning TDX RTMRs, flooring the four-component SEV-SNP
// TCB — must key off the family, never off the tag string.
type Family string

const (
	// FamilyUnknown is returned for any tag this module does not route to a
	// verifier. Callers must fail closed on it: it means "no verification rules
	// apply", not "no policy applies".
	FamilyUnknown Family = ""
	// FamilySNP is AMD SEV-SNP: snp, az-snp, gcp-snp.
	FamilySNP Family = "sev-snp"
	// FamilyTDX is Intel TDX: tdx, az-tdx, gcp-tdx.
	FamilyTDX Family = "tdx"
)

// Family reports the hardware TEE family this module routes the tag to, and is
// the single place that mapping is defined — teeverify's dispatcher is kept in
// lockstep with it by test.
//
// A tag is an attester claim carried outside any report or transcript (see
// PlatformType), so comparing it raw lets an attester pick "gcp-tdx" to slip
// past a rule written for "tdx". Normalize through Family (or IsTDX/IsSNP)
// before any platform decision.
//
// PlatformDstack maps to FamilyUnknown: teeverify has no dstack verifier, so no
// verified result can carry that tag, and answering FamilyTDX would let a
// TDX-only policy report itself as enforced against evidence this module never
// checked.
func (p PlatformType) Family() Family {
	switch NormalizePlatform(string(p)) {
	case PlatformSNP, PlatformAzSNP, PlatformGcpSNP:
		return FamilySNP
	case PlatformTDX, PlatformAzTDX, PlatformGcpTDX:
		return FamilyTDX
	default:
		return FamilyUnknown
	}
}

// IsTDX reports whether the tag names an Intel TDX platform this module
// verifies. False for an unknown tag, so a TDX-only policy fails closed.
func (p PlatformType) IsTDX() bool { return p.Family() == FamilyTDX }

// IsSNP reports whether the tag names an AMD SEV-SNP platform this module
// verifies. False for an unknown tag, so an SNP-only policy fails closed.
func (p PlatformType) IsSNP() bool { return p.Family() == FamilySNP }

// NormalizePlatform canonicalizes a platform tag read from configuration or
// from the wire: surrounding space is trimmed and ASCII case folded, since a
// tag differing only in those is the same platform. Nothing else is rewritten —
// an unrecognized tag comes back as the caller wrote it (modulo trim/fold) so
// an error message can quote what was actually supplied. Use Family on the
// result to decide what a tag means.
func NormalizePlatform(platform string) PlatformType {
	return PlatformType(strings.ToLower(strings.TrimSpace(platform)))
}
