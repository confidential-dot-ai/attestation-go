package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Arbitrary launch-anchor bytes; the package does not interpret them.
var anchor = []byte("anchor-bytes-v1\n")

// tdxResult builds a verified-result stand-in whose RTMR[3] claim is reg.
func tdxResult(p teetypes.PlatformType, reg []byte) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims: teetypes.Claims{
			PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg)},
		},
	}
}

func snpResult(p teetypes.PlatformType, hostData []byte) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims:         teetypes.Claims{InitData: hostData},
	}
}

func TestBindingReadsTheRightField(t *testing.T) {
	seed := Seed(anchor)
	hostData := HostData(anchor)

	got, err := Binding(tdxResult(teetypes.PlatformTDX, seed[:]))
	if err != nil {
		t.Fatalf("Binding(tdx) = _, %v", err)
	}
	if !bytes.Equal(got, seed[:]) {
		t.Errorf("Binding(tdx) = %x, want RTMR[3] %x", got, seed)
	}

	got, err = Binding(snpResult(teetypes.PlatformSNP, hostData[:]))
	if err != nil {
		t.Fatalf("Binding(snp) = _, %v", err)
	}
	if !bytes.Equal(got, hostData[:]) {
		t.Errorf("Binding(snp) = %x, want HOSTDATA %x", got, hostData)
	}
}

// A TDX report reaching the SNP arm carries a 48-byte MR_CONFIG_ID where
// HOSTDATA is expected. It must be refused by width, never silently truncated.
func TestBindingRejectsWrongWidthHostData(t *testing.T) {
	mrConfigID := make([]byte, Size)
	_, err := Binding(snpResult(teetypes.PlatformSNP, mrConfigID))
	if err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Errorf("Binding(snp with 48-byte InitData) = _, %v, want a width error", err)
	}
}

func TestBindingUnknownPlatform(t *testing.T) {
	if _, err := Binding(snpResult("nonsense", nil)); !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("Binding(unknown) = _, %v, want ErrUnknownPlatform", err)
	}
	if _, err := Binding(nil); err == nil {
		t.Error("Binding(nil) = _, nil, want an error")
	}
}

// The binding is read off claims that are only meaningful once the hardware
// signature over them has been checked; a result saying it was not is refused.
func TestBindingRefusesUnsignedResult(t *testing.T) {
	seed := Seed(anchor)
	r := tdxResult(teetypes.PlatformTDX, seed[:])
	r.SignatureValid = false
	if _, err := Binding(r); err == nil {
		t.Error("Binding(SignatureValid=false) = _, nil, want an error")
	}
	if err := VerifyBinding(r, anchor, nil); err == nil {
		t.Error("VerifyBinding(SignatureValid=false) = nil, want an error")
	}
}

// On az-snp the paravisor owns HOSTDATA, so there is no launcher binding to
// compare and the refusal must say so rather than blame the anchor.
func TestBindingRefusesAzureSNP(t *testing.T) {
	hostData := HostData(anchor)
	err := VerifyBinding(snpResult(teetypes.PlatformAzSNP, hostData[:]), anchor, nil)
	if !errors.Is(err, ErrNoRegister) || !strings.Contains(err.Error(), "paravisor") {
		t.Errorf("VerifyBinding(az-snp) = %v, want ErrNoRegister naming the paravisor", err)
	}
}

// An empty anchor hashes to a public constant, so a guest launched with an
// empty anchor file must not verify as bound.
func TestExpectedBindingRejectsEmptyAnchor(t *testing.T) {
	for _, p := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		if _, err := ExpectedBinding(p, nil, nil); err == nil {
			t.Errorf("ExpectedBinding(%q, empty anchor) = _, nil, want an error", p)
		}
	}
	seed := Seed(nil)
	if err := VerifyBinding(tdxResult(teetypes.PlatformTDX, seed[:]), []byte{}, nil); err == nil {
		t.Error("VerifyBinding with an empty anchor = nil, want an error")
	}
}

func TestVerifyBinding(t *testing.T) {
	digests := []string{"sha256:" + strings.Repeat("ab", 32)}
	seeded := FromDigestsSeeded(Seed(anchor), digests)
	bare := Seed(anchor)
	hostData := HostData(anchor)

	for _, tc := range []struct {
		name    string
		result  *teetypes.VerificationResult
		digests []string
		wantErr bool
	}{
		{"tdx bare seed", tdxResult(teetypes.PlatformTDX, bare[:]), nil, false},
		{"tdx seeded chain", tdxResult(teetypes.PlatformTDX, seeded[:]), digests, false},
		{"tdx cloud overlay", tdxResult(teetypes.PlatformAzTDX, bare[:]), nil, false},
		{"tdx chain where none expected", tdxResult(teetypes.PlatformTDX, seeded[:]), nil, true},
		{"tdx wrong key", tdxResult(teetypes.PlatformTDX, Zero[:]), nil, true},
		{"snp hostdata", snpResult(teetypes.PlatformSNP, hostData[:]), nil, false},
		{"snp cloud overlay", snpResult(teetypes.PlatformGcpSNP, hostData[:]), nil, false},
		{"snp wrong key", snpResult(teetypes.PlatformSNP, make([]byte, HostDataSize)), nil, true},
		{"snp with workload digests", snpResult(teetypes.PlatformSNP, hostData[:]), digests, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyBinding(tc.result, anchor, tc.digests)
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyBinding() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// The two families' bindings differ in width, so no accidental cross-platform
// match is possible even for one anchor. Guards against a future refactor that
// compares them as raw byte slices.
func TestBindingsAreNotInterchangeable(t *testing.T) {
	tdx := Seed(anchor)
	snp := HostData(anchor)
	if bytes.Equal(tdx[:], snp[:]) {
		t.Fatal("TDX seed equals SNP HOSTDATA for the same anchor")
	}
	if err := VerifyBinding(snpResult(teetypes.PlatformSNP, tdx[:len(snp)]), anchor, nil); err == nil {
		t.Error("a truncated TDX seed verified as SNP HOSTDATA")
	}
}

func TestExpectedBindingUnknownPlatform(t *testing.T) {
	if _, err := ExpectedBinding("nonsense", anchor, nil); !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("ExpectedBinding(unknown) = _, %v, want ErrUnknownPlatform", err)
	}
	if _, err := ExpectedBinding("nonsense", anchor, nil); errors.Is(err, ErrNoRegister) {
		t.Error("ExpectedBinding(unknown) matches ErrNoRegister, so a caller skipping SNP would skip an unknown tag too")
	}
}
