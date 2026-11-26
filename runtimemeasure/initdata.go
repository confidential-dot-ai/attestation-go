package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// VerifyInitDataFile compares [LaunchFileDigest] with TDX MRCONFIGID or SNP HOSTDATA.
// TDX requires full SHA-384, not [InitDataAnchor]'s padded SHA-256; RTMR[3] is unchecked.
// On SEV-SNP this is the same launch-file check as [VerifyBinding].
//
// Only tdx/snp tags are supported; provider tags return [ErrNoRegister] and
// unknown platforms [ErrUnknownPlatform]. A match proves the launcher's
// commitment, not file use or location. Pin software that checks the binding.
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

// VerifyInitDataDigest is [VerifyInitDataFile] for a precomputed digest.
// The digest must pass [CheckLaunchFileDigest] for the verified family.
func VerifyInitDataDigest(r *teetypes.VerificationResult, digest []byte) error {
	if err := r.Check(); err != nil {
		return err
	}
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

func initDataName(f teetypes.Family) string {
	if f == teetypes.FamilyTDX {
		return "MRCONFIGID"
	}
	return "HOSTDATA"
}
