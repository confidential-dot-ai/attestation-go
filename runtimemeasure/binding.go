package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Binding returns the post-launch binding a verified result carries: RTMR[3]
// on Intel TDX (Size bytes), HOSTDATA on AMD SEV-SNP (HostDataSize bytes).
//
// It takes a whole VerificationResult, not bare Claims, because the value is
// only meaningful once the hardware signature over it has been checked: the
// same field read off an unverified self-report is host-chosen on both sides.
//
// The two widths are never interchangeable. A caller comparing them by hand
// risks matching a 48-byte TDX value against a 32-byte SNP one; use
// [VerifyBinding] rather than comparing what this returns.
func Binding(r *teetypes.VerificationResult) ([]byte, error) {
	if err := checkVerified(r); err != nil {
		return nil, err
	}
	if err := checkBindingPlatform(r.Platform); err != nil {
		return nil, err
	}
	switch r.Platform.Family() {
	case teetypes.FamilyTDX:
		return r.Claims.RTMR(3)
	default: // FamilySNP; checkBindingPlatform refused the rest.
		// InitData is HOST_DATA on SNP. On TDX the same field is MR_CONFIG_ID
		// at 48 bytes, which is why this arm is family-gated rather than
		// reading InitData unconditionally.
		if n := len(r.Claims.InitData); n != HostDataSize {
			return nil, fmt.Errorf("HOSTDATA claim is %d bytes, want %d", n, HostDataSize)
		}
		return r.Claims.InitData, nil
	}
}

// checkBindingPlatform refuses platforms whose evidence carries no
// launcher-chosen binding. On az-snp the Azure paravisor owns HOSTDATA, so the
// field says nothing about the anchor; the az verifiers bind init data through
// vTPM PCR[8] instead, which this package does not read.
func checkBindingPlatform(p teetypes.PlatformType) error {
	switch p.Family() {
	case teetypes.FamilyTDX, teetypes.FamilySNP:
	default:
		return fmt.Errorf("%w %q", ErrUnknownPlatform, p)
	}
	if teetypes.NormalizePlatform(string(p)) == teetypes.PlatformAzSNP {
		return fmt.Errorf("platform %q: HOSTDATA is set by the Azure paravisor, not the launcher, so it carries no anchor binding: %w", p, ErrNoRegister)
	}
	return nil
}

// ExpectedBinding returns the value [Binding] must equal for a guest launched
// with anchor, having measured workloadDigests in that order.
//
// anchor is whatever the guest was launched to trust; see [Seed]. It is hashed
// byte for byte, so pass the exact bytes the guest committed. An empty anchor
// is refused: its digest is a public constant, so a guest launched with an
// empty anchor file would verify as bound to nothing in particular.
//
// workloadDigests are canonical "sha256:<64-hex>" strings (see
// [CanonicalDigest]), deduplicated and in extend order. SEV-SNP has no runtime
// extends, so a non-empty list there is a policy error rather than a value this
// function could compute.
func ExpectedBinding(p teetypes.PlatformType, anchor []byte, workloadDigests []string) ([]byte, error) {
	if len(anchor) == 0 {
		return nil, fmt.Errorf("anchor is empty; a binding to no anchor proves nothing")
	}
	if err := checkBindingPlatform(p); err != nil {
		return nil, err
	}
	if p.Family() == teetypes.FamilyTDX {
		reg := FromDigestsSeeded(Seed(anchor), workloadDigests)
		return reg[:], nil
	}
	if len(workloadDigests) > 0 {
		return nil, fmt.Errorf("platform %q has no runtime extends, so %d workload digest(s) cannot be measured into its binding: %w",
			p, len(workloadDigests), ErrNoRegister)
	}
	hd := HostData(anchor)
	return hd[:], nil
}

// VerifyBinding reports whether the guest that produced r was launched with
// anchor, having measured workloadDigests. It resolves the whole TDX-versus-SNP
// difference — which field carries the binding, how wide it is, and how the
// anchor digest folds into it — so callers never branch on platform.
//
// Pass a nil workloadDigests for a guest that runs no workload measurer, which
// is the case an in-guest service checking its own staged anchor wants: the
// register must then equal the bare seed exactly, and any extension beyond it
// means an unexpected measurer ran or the value was tampered with. A verifier
// checking a guest that does measure workloads passes the digests it expects.
//
// A mismatch is an error naming both values. They are digests, not the anchor
// itself, so the comparison is a plain one and the error may be logged.
func VerifyBinding(r *teetypes.VerificationResult, anchor []byte, workloadDigests []string) error {
	got, err := Binding(r)
	if err != nil {
		return err
	}
	want, err := ExpectedBinding(r.Platform, anchor, workloadDigests)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf(
			"guest is not bound to the expected anchor: %s carries %s, anchor implies %s",
			bindingName(r.Platform), hex.EncodeToString(got), hex.EncodeToString(want))
	}
	return nil
}

// bindingName names the field the binding lives in, so a mismatch error tells
// an operator where to look rather than quoting two bare hex strings.
func bindingName(p teetypes.PlatformType) string {
	if p.Family() == teetypes.FamilySNP {
		return "HOSTDATA"
	}
	return "RTMR[3]"
}
