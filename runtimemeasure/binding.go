package runtimemeasure

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// launchBinding is one TEE family's launch binding: the init-data field that
// commits a launch file's digest, and, on TDX, the runtime log in RTMR[3]
// beside it. [familyBinding] and [platformBinding] are the only places that
// choose one.
type launchBinding struct {
	family teetypes.Family
	field  string // the init-data claim's hardware name
	hash   func() hash.Hash
	width  int // hash's output size, and so the field's
}

var (
	tdxLaunchBinding = launchBinding{family: teetypes.FamilyTDX, field: "MRCONFIGID", hash: sha512.New384, width: sha512.Size384}
	snpLaunchBinding = launchBinding{family: teetypes.FamilySNP, field: "HOSTDATA", hash: sha256.New, width: sha256.Size}
)

func familyBinding(f teetypes.Family) (launchBinding, error) {
	switch f {
	case teetypes.FamilyTDX:
		return tdxLaunchBinding, nil
	case teetypes.FamilySNP:
		return snpLaunchBinding, nil
	default:
		return launchBinding{}, fmt.Errorf("%w: family %s has no launch binding", ErrUnknownPlatform, f)
	}
}

// platformBinding returns the launch binding evidence from p carries. On the
// Azure overlays (az-snp, az-tdx) Azure sets HOSTDATA and MRCONFIGID, not the
// launcher, so neither says which file the guest was launched with; the az
// verifiers bind init data through vTPM PCR[8] instead, which this package
// does not read. gcp-snp and gcp-tdx carry the bare-metal report and bind as
// snp and tdx do.
func platformBinding(p teetypes.PlatformType) (launchBinding, error) {
	tag := teetypes.NormalizePlatform(string(p))
	b, err := familyBinding(tag.Family())
	if err != nil {
		return launchBinding{}, fmt.Errorf("platform %q: %w", p, err)
	}
	if tag == teetypes.PlatformAzSNP || tag == teetypes.PlatformAzTDX {
		return launchBinding{}, fmt.Errorf("platform %q: Azure, not the launcher, sets %s, so it carries no launch binding: %w", p, b.field, ErrNoRegister)
	}
	return b, nil
}

// resultBinding returns the launch binding a signature-verified r carries.
func resultBinding(r *teetypes.VerificationResult) (launchBinding, error) {
	if err := r.Check(); err != nil {
		return launchBinding{}, err
	}
	return platformBinding(r.Platform)
}

func (b launchBinding) hasRuntimeLog() bool { return b.family == teetypes.FamilyTDX }

func (b launchBinding) emptyFileDigest() []byte { return b.hash().Sum(nil) }

// fileDigest returns the digest b's field commits for file. An empty file is
// refused: its digest is a public constant.
func (b launchBinding) fileDigest(file []byte) ([]byte, error) {
	if len(file) == 0 {
		return nil, fmt.Errorf("launch file is empty; a binding to no file proves nothing")
	}
	h := b.hash()
	h.Write(file)
	return h.Sum(nil), nil
}

// pinnedDigest returns digest if b's field can hold it, refusing what
// [launchBinding.checkDigest] refuses.
func (b launchBinding) pinnedDigest(digest []byte) ([]byte, error) {
	if err := b.checkDigest(digest); err != nil {
		return nil, fmt.Errorf("launch file digest %w", err)
	}
	return digest, nil
}

// checkDigest refuses a digest b's field cannot hold, or one a guest launched
// with no init data, or an empty file, carries. The error reads after a field
// name.
func (b launchBinding) checkDigest(digest []byte) error {
	if len(digest) != b.width {
		return fmt.Errorf("is %d bytes, want %d on %s", len(digest), b.width, b.family)
	}
	if bytes.Equal(digest, make([]byte, b.width)) {
		return fmt.Errorf("is all zero, which equals a launch with no init data")
	}
	if bytes.Equal(digest, b.emptyFileDigest()) {
		return fmt.Errorf("is the digest of the empty file, which binds nothing")
	}
	return nil
}

// claim returns r's init-data claim, refused unless it is exactly b's width.
func (b launchBinding) claim(r *teetypes.VerificationResult) ([]byte, error) {
	if n := len(r.Claims.InitData); n != b.width {
		return nil, fmt.Errorf("%s claim is %d bytes, want %d", b.field, n, b.width)
	}
	return bytes.Clone(r.Claims.InitData), nil
}

// checkLaunch requires r's init-data claim to equal digest.
func (b launchBinding) checkLaunch(r *teetypes.VerificationResult, digest []byte) error {
	got, err := b.claim(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, digest) {
		return fmt.Errorf("guest does not carry the expected launch binding: %s carries %s, want %s",
			b.field, hex.EncodeToString(got), hex.EncodeToString(digest))
	}
	return nil
}

// replayLog returns the k for which r's RTMR[3] equals [Zero] extended with
// claimed[:k]. A family with no runtime log proves no extension, so k is 0
// there.
func (b launchBinding) replayLog(r *teetypes.VerificationResult, claimed []string) (int, error) {
	if !b.hasRuntimeLog() {
		return 0, nil
	}
	got, err := r.Claims.RTMR(3)
	if err != nil {
		return 0, fmt.Errorf("runtime log: %w", err)
	}
	// SHA-384 chaining makes every prefix fold to a distinct value, so at most
	// one prefix matches and the first hit is the only one.
	reg := Zero
	if bytes.Equal(got, reg[:]) {
		return 0, nil
	}
	for i, d := range claimed {
		reg = Extend(reg, Event(d))
		if bytes.Equal(got, reg[:]) {
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("guest's runtime log differs: RTMR[3] carries %s, which is neither zero nor zero extended with a prefix of the %d claimed digest(s)",
		hex.EncodeToString(got), len(claimed))
}

// Binding returns the launch binding a verified result carries: MRCONFIGID on
// Intel TDX (Size bytes), HOSTDATA on AMD SEV-SNP (HostDataSize bytes).
//
// It takes a whole VerificationResult, not bare Claims, because the value is
// only meaningful once the hardware signature over it has been checked: the
// same field read off an unverified self-report is host-chosen on both sides.
// It refuses az-snp and az-tdx, where Azure sets the field.
//
// The two widths are never interchangeable. A caller comparing them by hand
// risks matching a 48-byte TDX value against a 32-byte SNP one; use
// [VerifyBinding] rather than comparing what this returns.
func Binding(r *teetypes.VerificationResult) ([]byte, error) {
	b, err := resultBinding(r)
	if err != nil {
		return nil, err
	}
	return b.claim(r)
}

// VerifyBinding reports whether the guest that produced r was launched with
// anchor, having measured workloadDigests. It resolves the whole TDX-versus-SNP
// difference — which field carries the binding, how wide it is, and whether a
// runtime log sits beside it — so callers never branch on platform.
//
// anchor is the exact bytes the guest was launched with, hashed byte for byte
// ([LaunchFileDigest]); an empty anchor is refused. The launch binding must
// equal its digest: MRCONFIGID == SHA-384(anchor) on TDX, HOSTDATA ==
// SHA-256(anchor) on SEV-SNP.
//
// On TDX, RTMR[3] must equal [Zero] extended with workloadDigests in order
// ([FromDigests]). Pass nil for a guest that runs no workload measurer, which
// is the case an in-guest service checking its own staged anchor wants:
// RTMR[3] must then be Zero, and any extension means an unexpected measurer
// ran. SEV-SNP has no runtime log, so non-empty digests never verify there. A
// missing RTMR[3] claim is an error.
//
// A mismatch is an error naming both values. They are digests, not the anchor
// itself, so the error may be logged.
func VerifyBinding(r *teetypes.VerificationResult, anchor []byte, workloadDigests []string) error {
	b, err := resultBinding(r)
	if err != nil {
		return err
	}
	digest, err := b.fileDigest(anchor)
	if err != nil {
		return err
	}
	if err := b.checkLaunch(r, digest); err != nil {
		return err
	}
	k, err := b.replayLog(r, workloadDigests)
	if err != nil {
		return err
	}
	if k != len(workloadDigests) {
		return fmt.Errorf("guest's runtime log on %q proves %d of the %d expected workload digest(s)", r.Platform, k, len(workloadDigests))
	}
	return nil
}

// MatchBindingPrefix checks that r's launch binding commits anchor, as
// [VerifyBinding] does, and returns the k for which RTMR[3] equals [Zero]
// extended with claimed[:k], or an error when no prefix matches.
//
// claimed is the guest's own account of what it extended, in order. A
// [Journal] records before it extends and may be read after the quote, so the
// list can run ahead of the register; only claimed[:k] is proven, and entries
// past k prove nothing. Every entry must be canonical ([CanonicalDigest]): the
// guest never extends anything else, so one that is not fails the whole list.
//
// SEV-SNP has no runtime log, so a well-formed list yields k = 0 there; a
// non-canonical entry still fails. az-snp and az-tdx are refused as by
// [VerifyBinding].
//
// The cost is one SHA-384 per entry, and the list usually comes from the peer,
// so bound it before calling; armtls caps it at 256.
func MatchBindingPrefix(r *teetypes.VerificationResult, anchor []byte, claimed []string) (int, error) {
	return matchBindingPrefix(r, anchor, claimed, launchBinding.fileDigest)
}

// MatchLaunchFileDigestPrefix is [MatchBindingPrefix] for a guest pinned by
// its launch file's [LaunchFileDigest] rather than the file. digest must be of
// the width r's family commits, so one family's digest never matches the
// other's evidence. An all-zero digest, or the empty file's, is refused.
func MatchLaunchFileDigestPrefix(r *teetypes.VerificationResult, digest []byte, claimed []string) (int, error) {
	return matchBindingPrefix(r, digest, claimed, launchBinding.pinnedDigest)
}

// matchBindingPrefix requires the launch binding of r's own family, b, to
// commit expected(b, pinned), then returns the prefix of claimed its runtime
// log proves.
func matchBindingPrefix(r *teetypes.VerificationResult, pinned []byte, claimed []string, expected func(launchBinding, []byte) ([]byte, error)) (int, error) {
	for i, d := range claimed {
		if c, err := CanonicalDigest(d); err != nil || c != d {
			return 0, fmt.Errorf("claimed extension %d (%q) is not a canonical sha256 digest", i, d)
		}
	}
	b, err := resultBinding(r)
	if err != nil {
		return 0, err
	}
	digest, err := expected(b, pinned)
	if err != nil {
		return 0, err
	}
	if err := b.checkLaunch(r, digest); err != nil {
		return 0, err
	}
	return b.replayLog(r, claimed)
}
