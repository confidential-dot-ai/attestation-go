package teetypes

import (
	"fmt"
	"strings"
)

// Family is the hardware TEE behind a platform tag. The cloud-overlay tags
// (az-*, gcp-*) name the same silicon as their bare-metal counterpart and take
// the same verification path, so hardware-specific policy — pinning TDX RTMRs,
// flooring the four-component SEV-SNP TCB — keys off the family, never off the
// tag string.
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

// String returns the family's canonical name, and "unknown" for FamilyUnknown
// so a message formatted from a family never shows an empty string. Use it for
// display; use the constants for comparison.
func (f Family) String() string {
	if f == FamilyUnknown {
		return "unknown"
	}
	return string(f)
}

// DefaultPlatform returns the bare-metal platform tag for the family. A config
// that names only a family needs it wherever an API demands a tag: opening a
// runtimemeasure.Register, or filling a remote.AttestRequest.
//
// A cloud overlay is never the default, since it names the same silicon and
// verifies identically; a guest that must announce az-snp or gcp-tdx says so
// explicitly. FamilyUnknown maps to the empty tag, which routes to no verifier
// and so fails closed.
func (f Family) DefaultPlatform() PlatformType {
	switch f {
	case FamilySNP:
		return PlatformSNP
	case FamilyTDX:
		return PlatformTDX
	default:
		return ""
	}
}

// familySpellings is every input ParseFamily accepts, in the order its error
// lists them, so the message cannot drift from what the function takes.
var familySpellings = []string{
	string(FamilySNP), string(PlatformSNP), string(PlatformAzSNP), string(PlatformGcpSNP),
	string(FamilyTDX), string(PlatformAzTDX), string(PlatformGcpTDX),
}

// ParseFamily resolves a hardware TEE family from either spelling in use: a
// family name ("sev-snp", its common alias "snp", or "tdx"), or any platform
// tag this module verifies ("az-snp", "gcp-tdx", …). Surrounding space is
// trimmed and ASCII case folded.
//
// Configuration names the family while evidence carries a tag, so a caller
// holding a config string cannot call Family() on it: PlatformType("sev-snp")
// has no verifier and answers FamilyUnknown by design. ParseFamily is the one
// place the two vocabularies meet.
//
// It never returns FamilyUnknown with a nil error — an unrecognized input is
// an error quoting what was supplied, so a typo fails closed at config load
// rather than at first handshake.
func ParseFamily(s string) (Family, error) {
	p := NormalizePlatform(s)
	if p == PlatformType(FamilySNP) {
		return FamilySNP, nil
	}
	if f := p.Family(); f != FamilyUnknown {
		return f, nil
	}
	return FamilyUnknown, fmt.Errorf("unknown TEE platform or family %q, want one of: %s",
		s, strings.Join(familySpellings, ", "))
}

// Family reports the hardware TEE family this module routes the tag to, and is
// the single definition of that mapping; a test keeps teeverify's dispatcher in
// step with it.
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

// HasVTPMQuote reports whether verified evidence from the platform carries a
// vTPM quote, and so the PCR bank Claims.PCR reads.
//
// It is a per-tag property, not a family one: the Azure overlays quote a vTPM,
// while GCP guests expose a vTPM but attest through the native hardware
// report, so their evidence carries no PCR bank.
func (p PlatformType) HasVTPMQuote() bool {
	switch NormalizePlatform(string(p)) {
	case PlatformAzSNP, PlatformAzTDX:
		return true
	default:
		return false
	}
}
