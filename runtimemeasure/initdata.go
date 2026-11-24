package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// VerifyInitDataFile reports whether the launcher of the guest that produced
// r committed launchFile in the init-data field it sets at launch: MRCONFIGID
// on Intel TDX, HOSTDATA on AMD SEV-SNP. The field must equal the file's
// [LaunchFileDigest] at its full width.
//
// This is the binding of a guest whose launcher owns the field and whose
// image seeds no register, as a Kata Containers runtime does with its
// initdata document. On SEV-SNP it is the check [VerifyBinding] makes: HOSTDATA
// is whatever the launcher chose, so a match proves only what the launcher
// committed, and [remote.ImagePin.LaunchFileInInitData] refuses SEV-SNP
// evidence because a plain launch-file pin already reads that field: that is
// a choice of policy in remote, not a difference in how the field compares,
// and this function stays the bare comparison. Wired into an SEV-SNP verifier
// it is therefore the plain launch-file check and adds nothing to it. On TDX
// it reads a different field: [VerifyBinding] reads RTMR[3], which such a
// guest's own software extends and this check does not constrain.
//
// [InitDataAnchor] reads the same TDX field under another convention, a
// 32-byte SHA-256 zero-padded to the field's width. A launcher follows one
// or the other: a full-width SHA-384 is not an anchor, and a padded SHA-256
// does not match here.
//
// Only results tagged tdx or snp are compared, against MRCONFIGID and
// HOSTDATA; a cloud provider's variant (az-snp, az-tdx, gcp-snp, gcp-tdx) is
// refused. On az-snp the paravisor owns HOSTDATA. For the others this package
// has not established who sets the field under the provider's stack, and
// refuses rather than assume it is the tenant's launcher: a Kata guest there
// cannot be bound this way. The refusal is conservative, and a documented
// owner of the field under a provider's stack would lift it. That refusal
// carries [ErrNoRegister], reused here to mean the result holds nothing the
// tenant's launcher bound, and never [ErrUnknownPlatform]. In remote it
// arrives inside one image's [remote.ErrLaunchFileNotAllowed], as that
// image's mismatch, and does not refuse the set. The tag is the
// one the evidence was verified under. The comparison proves what the signed
// field holds, not where the guest runs: a caller that must exclude a
// provider's hosts needs evidence of that from elsewhere.
func VerifyInitDataFile(r *teetypes.VerificationResult, launchFile []byte) error {
	if err := r.Check(); err != nil {
		return err
	}
	digest, err := LaunchFileDigest(r.Platform.Family(), launchFile)
	if err != nil {
		return err
	}
	return VerifyInitDataDigest(r, digest)
}

// VerifyInitDataDigest is [VerifyInitDataFile] for a guest pinned by its
// launch file's [LaunchFileDigest] rather than the file. A digest
// [CheckLaunchFileDigest] refuses for r's family is refused. The limits
// [VerifyInitDataFile] states for SEV-SNP and for a provider's tags apply.
func VerifyInitDataDigest(r *teetypes.VerificationResult, digest []byte) error {
	if err := r.Check(); err != nil {
		return err
	}
	// One reading of the tag decides both whether the field is read and at
	// which family's width.
	platform := teetypes.NormalizePlatform(string(r.Platform))
	if err := checkInitDataPlatform(platform); err != nil {
		return err
	}
	family := platform.Family()
	if err := CheckLaunchFileDigest(family, digest); err != nil {
		return fmt.Errorf("launch file digest %w", err)
	}
	got := r.Claims.InitData
	if len(got) != len(digest) {
		return fmt.Errorf("%s claim is %d bytes, want %d", initDataName(family), len(got), len(digest))
	}
	if !bytes.Equal(got, digest) {
		return fmt.Errorf(
			"guest is not bound to the expected launch file: %s carries %s, expected %s",
			initDataName(family), hex.EncodeToString(got), hex.EncodeToString(digest))
	}
	return nil
}

// checkInitDataPlatform refuses the platform tags under which a tenant's
// launcher does not set the init-data field.
func checkInitDataPlatform(p teetypes.PlatformType) error {
	switch teetypes.NormalizePlatform(string(p)) {
	case teetypes.PlatformTDX, teetypes.PlatformSNP:
		return nil
	}
	if p.Family() == teetypes.FamilyUnknown {
		return fmt.Errorf("%w %q", ErrUnknownPlatform, p)
	}
	return fmt.Errorf("platform %q: the init-data field is not known to be the tenant launcher's under a provider's stack, so it is not read as a launch file binding: %w", p, ErrNoRegister)
}

// initDataName names the field a launcher commits init data in.
func initDataName(f teetypes.Family) string {
	if f == teetypes.FamilyTDX {
		return "MRCONFIGID"
	}
	return "HOSTDATA"
}
