package runtimemeasure

import (
	"bytes"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// initDataResult builds a signature-verified result whose init-data claim is
// claim, the field InitDataAnchor reads on both families.
func initDataResult(p teetypes.PlatformType, claim []byte) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims:         teetypes.Claims{InitData: claim},
	}
}

// The same 32 bytes, in the field each family puts them in. HostData is the
// producer side of the value read back here.
func TestInitDataAnchorBothFamilies(t *testing.T) {
	document := []byte("{\"algorithm\":\"sha256\"}\n")
	want := HostData(document)

	snp := initDataResult(teetypes.PlatformSNP, want[:])
	got, err := InitDataAnchor(snp)
	if err != nil {
		t.Fatalf("InitDataAnchor(snp) = _, %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Errorf("InitDataAnchor(snp) = %x, want %x", got, want)
	}

	mrConfigID := make([]byte, Size)
	copy(mrConfigID, want[:])
	tdx := initDataResult(teetypes.PlatformTDX, mrConfigID)
	got, err = InitDataAnchor(tdx)
	if err != nil {
		t.Fatalf("InitDataAnchor(tdx) = _, %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Errorf("InitDataAnchor(tdx) = %x, want %x", got, want)
	}
	// The anchor must not alias the claim: a caller keeping it should not be
	// able to rewrite the verified claims through it.
	got[0] ^= 0xff
	if !bytes.Equal(mrConfigID[:HostDataSize], want[:]) {
		t.Error("InitDataAnchor returned a slice aliasing the claim")
	}
}

func TestInitDataAnchorRefusals(t *testing.T) {
	anchor32 := make([]byte, HostDataSize)
	padded := make([]byte, Size)
	notPadded := make([]byte, Size)
	notPadded[Size-1] = 1

	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
		want   error // errors.Is target; nil means "some error"
	}{
		{"nil result", nil, nil},
		{"unverified signature", &teetypes.VerificationResult{Platform: teetypes.PlatformSNP}, nil},
		{"snp claim is MRCONFIGID-wide", initDataResult(teetypes.PlatformSNP, padded), ErrNoAnchor},
		{"snp claim is empty", initDataResult(teetypes.PlatformSNP, nil), ErrNoAnchor},
		{"tdx claim is HOST_DATA-wide", initDataResult(teetypes.PlatformTDX, anchor32), ErrNoAnchor},
		{"tdx padding is not zero", initDataResult(teetypes.PlatformTDX, notPadded), ErrNoAnchor},
		// The Azure paravisor owns HOST_DATA, so the field is not the guest's
		// init data there — the same reason Binding refuses az-snp.
		{"az-snp", initDataResult(teetypes.PlatformAzSNP, anchor32), ErrNoRegister},
		{"unknown platform", initDataResult("nonsense", anchor32), ErrUnknownPlatform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InitDataAnchor(tc.result)
			if err == nil {
				t.Fatalf("InitDataAnchor = %x, nil; want an error", got)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("InitDataAnchor = _, %v, want %v", err, tc.want)
			}
		})
	}
}

// A guest launched with no init-data document reports all zeros, which is a
// valid-width anchor: the refusal has to come from comparing it against the
// document the caller expects, not from this accessor.
func TestInitDataAnchorAcceptsAllZeroClaim(t *testing.T) {
	got, err := InitDataAnchor(initDataResult(teetypes.PlatformSNP, make([]byte, HostDataSize)))
	if err != nil {
		t.Fatalf("InitDataAnchor = _, %v", err)
	}
	if want := HostData([]byte("some document")); bytes.Equal(got, want[:]) {
		t.Error("an all-zero claim must not equal a real document digest")
	}
}
