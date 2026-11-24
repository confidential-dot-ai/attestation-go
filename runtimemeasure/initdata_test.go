package runtimemeasure

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The launcher commits the file's digest at the field's own width on each
// family, and a file it did not launch with is refused.
func TestVerifyInitDataFileBothFamilies(t *testing.T) {
	file, other := []byte("launch document\n"), []byte("another document\n")
	for _, p := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(p), func(t *testing.T) {
			launched := initDataResult(p, mustLaunchFileDigest(t, p.Family(), file))
			if err := VerifyInitDataFile(launched, file); err != nil {
				t.Fatalf("the launch file was refused: %v", err)
			}
			if err := VerifyInitDataDigest(launched, mustLaunchFileDigest(t, p.Family(), file)); err != nil {
				t.Fatalf("the launch file's digest was refused: %v", err)
			}
			err := VerifyInitDataFile(launched, other)
			if err == nil || !strings.Contains(err.Error(), initDataName(p.Family())) {
				t.Fatalf("another file = %v, want a mismatch naming %s", err, initDataName(p.Family()))
			}
		})
	}
}

// On TDX the init-data field and RTMR[3] are separate: a guest whose image
// seeded the register proves nothing about the field, and the reverse.
func TestVerifyInitDataFileReadsMRCONFIGIDNotTheRegister(t *testing.T) {
	file := []byte("launch document\n")
	seed := Seed(file)

	seeded := tdxResult(teetypes.PlatformTDX, seed[:])
	seeded.Claims.InitData = make([]byte, Size)
	if err := VerifyInitDataFile(seeded, file); err == nil {
		t.Fatal("a guest that only seeded RTMR[3] passed the init-data check")
	}

	launched := initDataResult(teetypes.PlatformTDX, mustLaunchFileDigest(t, teetypes.FamilyTDX, file))
	if err := VerifyBinding(launched, file, nil); err == nil {
		t.Fatal("a guest bound only in MRCONFIGID passed the register check")
	}
}

func TestVerifyInitDataRefusesWhatBindsNothing(t *testing.T) {
	file := []byte("launch document\n")
	sha256Padded := make([]byte, Size)
	digest := sha256.Sum256(file)
	copy(sha256Padded, digest[:])

	tests := []struct {
		name   string
		result *teetypes.VerificationResult
		file   []byte
	}{
		{"zero-padded SHA-256 in MRCONFIGID", initDataResult(teetypes.PlatformTDX, sha256Padded), file},
		{"no init data", initDataResult(teetypes.PlatformTDX, make([]byte, Size)), file},
		{"truncated claim", initDataResult(teetypes.PlatformTDX, mustLaunchFileDigest(t, teetypes.FamilyTDX, file)[:HostDataSize]), file},
		{"empty file", initDataResult(teetypes.PlatformSNP, digest[:]), nil},
		{"az-snp", initDataResult(teetypes.PlatformAzSNP, digest[:]), file},
		{"gcp-snp", initDataResult(teetypes.PlatformGcpSNP, digest[:]), file},
		{"az-tdx", initDataResult(teetypes.PlatformAzTDX, mustLaunchFileDigest(t, teetypes.FamilyTDX, file)), file},
		{"gcp-tdx", initDataResult(teetypes.PlatformGcpTDX, mustLaunchFileDigest(t, teetypes.FamilyTDX, file)), file},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyInitDataFile(tc.result, tc.file); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// The padded SHA-256 reaches the comparison and is refused there.
	if err := VerifyInitDataFile(initDataResult(teetypes.PlatformTDX, sha256Padded), file); err == nil || !strings.Contains(err.Error(), "MRCONFIGID carries") {
		t.Fatalf("zero-padded SHA-256 = %v, want the MRCONFIGID mismatch", err)
	}

	unsigned := initDataResult(teetypes.PlatformSNP, digest[:])
	unsigned.SignatureValid = false
	if err := VerifyInitDataFile(unsigned, file); err == nil {
		t.Fatal("an unverified result was accepted")
	}
	if err := VerifyInitDataDigest(initDataResult(teetypes.PlatformSNP, digest[:]), mustLaunchFileDigest(t, teetypes.FamilyTDX, file)); err == nil {
		t.Fatal("a TDX-width digest matched SEV-SNP evidence")
	}
	if err := VerifyInitDataFile(initDataResult("unknown", digest[:]), file); !errors.Is(err, ErrUnknownPlatform) {
		t.Fatalf("unknown platform = %v, want ErrUnknownPlatform", err)
	}
}

// The provider-tag refusal belongs to this layer and carries its own
// sentinel: a provider's stack sets the field, so even a matching value binds
// no launch file there.
func TestVerifyInitDataRefusesProviderTagsWithErrNoRegister(t *testing.T) {
	file := []byte("clusterID: alpha\n")
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformAzTDX, teetypes.PlatformGcpTDX, teetypes.PlatformAzSNP, teetypes.PlatformGcpSNP,
	} {
		t.Run(string(platform), func(t *testing.T) {
			digest := mustLaunchFileDigest(t, platform.Family(), file)
			matching := initDataResult(platform, digest)
			if err := VerifyInitDataFile(matching, file); !errors.Is(err, ErrNoRegister) {
				t.Fatalf("VerifyInitDataFile = %v, want ErrNoRegister", err)
			}
			if err := VerifyInitDataDigest(matching, digest); !errors.Is(err, ErrNoRegister) {
				t.Fatalf("VerifyInitDataDigest = %v, want ErrNoRegister", err)
			}
			if err := VerifyInitDataFile(matching, file); errors.Is(err, ErrUnknownPlatform) {
				t.Fatalf("a known provider tag was reported as an unknown platform: %v", err)
			}
		})
	}
}
