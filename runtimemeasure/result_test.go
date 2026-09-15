package runtimemeasure

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestIdentityFromResultPinsVerifiedImage(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformAzTDX, teetypes.PlatformSNP, teetypes.PlatformGcpSNP} {
		t.Run(string(platform), func(t *testing.T) {
			r := tdxImageResult(platform, mrtdHex, rtmr1Hex, rtmr2Hex)
			identity, err := IdentityFromResult(r)
			if err != nil {
				t.Fatal(err)
			}
			if identity.Family() != platform.Family() {
				t.Errorf("family = %s, want %s", identity.Family(), platform.Family())
			}
			variants := identity.LaunchDigests()
			if len(variants) != 1 || variants[0].Label != "" || hex.EncodeToString(variants[0].Digest[:]) != mrtdHex {
				t.Fatalf("observed launch variants = %+v", variants)
			}
			if platform.Family() == teetypes.FamilyTDX {
				pins := identity.RTMRs()
				if len(pins) != 2 {
					t.Fatalf("register pins = %v, want RTMR[1] and RTMR[2]", pins)
				}
				for i, want := range map[int]string{1: rtmr1Hex, 2: rtmr2Hex} {
					got := pins[i]
					if hex.EncodeToString(got[:]) != want {
						t.Errorf("RTMR[%d] = %x, want %s", i, got, want)
					}
				}
			} else if identity.RTMRs() != nil {
				t.Error("SNP identity carries TDX registers")
			}
			if err := identity.Verify(r); err != nil {
				t.Fatalf("derived identity does not verify original report: %v", err)
			}
			r.Claims.LaunchDigest = strings.Repeat("aa", Size)
			if err := identity.Verify(r); err == nil {
				t.Error("changing the report also changed its pinned identity")
			}
			r.Platform = teetypes.PlatformSNP
			if platform.Family() == teetypes.FamilySNP {
				r.Platform = teetypes.PlatformTDX
			}
			if err := identity.Verify(r); !errors.Is(err, ErrWrongFamily) {
				t.Errorf("cross-family report = %v", err)
			}
		})
	}
}

func TestIdentityFromResultFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*teetypes.VerificationResult){
		"invalid signature": func(r *teetypes.VerificationResult) { r.SignatureValid = false },
		"unknown platform":  func(r *teetypes.VerificationResult) { r.Platform = "unknown" },
		"missing digest":    func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = "" },
		"short digest":      func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = "aa" },
		"long digest":       func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("aa", Size+1) },
		"nonhex digest":     func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("zz", Size) },
		"missing rtmr1":     func(r *teetypes.VerificationResult) { delete(r.Claims.PlatformData, "rtmr_1") },
		"missing rtmr2":     func(r *teetypes.VerificationResult) { delete(r.Claims.PlatformData, "rtmr_2") },
		"short rtmr1":       func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_1"] = "aa" },
		"short rtmr2":       func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_2"] = "aa" },
		"long rtmr2":        func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_2"] = strings.Repeat("aa", Size+1) },
	} {
		t.Run(name, func(t *testing.T) {
			r := tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, rtmr2Hex)
			mutate(r)
			if _, err := IdentityFromResult(r); err == nil {
				t.Fatal("accepted invalid report")
			}
		})
	}
	if _, err := IdentityFromResult(nil); err == nil {
		t.Fatal("accepted nil report")
	}
}
