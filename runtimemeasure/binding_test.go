package runtimemeasure

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Arbitrary launch-anchor bytes; the package does not interpret them.
var anchor = []byte("anchor-bytes-v1\n")

// tdxResult builds a verified-result stand-in whose MRCONFIGID claim is
// mrConfigID and whose RTMR[3] claim is rtmr3; a nil rtmr3 omits the claim.
func tdxResult(p teetypes.PlatformType, mrConfigID, rtmr3 []byte) *teetypes.VerificationResult {
	pd := map[string]any{}
	if rtmr3 != nil {
		pd["rtmr_3"] = hex.EncodeToString(rtmr3)
	}
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims:         teetypes.Claims{InitData: mrConfigID, PlatformData: pd},
	}
}

func snpResult(p teetypes.PlatformType, hostData []byte) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims:         teetypes.Claims{InitData: hostData},
	}
}

// mrConfigID is the MRCONFIGID a launcher sets for file.
func mrConfigID(file []byte) []byte {
	d := sha512.Sum384(file)
	return d[:]
}

// runtimeLog is RTMR[3] after extending digests from Zero.
func runtimeLog(digests ...string) []byte {
	reg := FromDigests(digests)
	return reg[:]
}

// extendedWithFileDigest is RTMR[3] extended from Zero with SHA-384(file),
// then with digests.
func extendedWithFileDigest(file []byte, digests ...string) []byte {
	reg := Extend(Zero, sha512.Sum384(file))
	for _, d := range digests {
		reg = Extend(reg, Event(d))
	}
	return reg[:]
}

// paddedHostData is the zero-padded SHA-256 MRCONFIGID convention.
func paddedHostData(file []byte) []byte {
	hostData := HostData(file)
	return append(hostData[:], make([]byte, Size-HostDataSize)...)
}

func TestLaunchBindingWidthIsHashSize(t *testing.T) {
	for _, b := range []launchBinding{tdxLaunchBinding, snpLaunchBinding} {
		if got := b.hash().Size(); got != b.width {
			t.Errorf("%s: width %d, hash size %d", b.family, b.width, got)
		}
	}
}

func TestBindingReadsTheRightField(t *testing.T) {
	hostData := HostData(anchor)

	got, err := Binding(tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), runtimeLog(digestA)))
	if err != nil {
		t.Fatalf("Binding(tdx) = _, %v", err)
	}
	if !bytes.Equal(got, mrConfigID(anchor)) {
		t.Errorf("Binding(tdx) = %x, want MRCONFIGID %x", got, mrConfigID(anchor))
	}

	got, err = Binding(snpResult(teetypes.PlatformSNP, hostData[:]))
	if err != nil {
		t.Fatalf("Binding(snp) = _, %v", err)
	}
	if !bytes.Equal(got, hostData[:]) {
		t.Errorf("Binding(snp) = %x, want HOSTDATA %x", got, hostData)
	}
}

// An init-data claim of the other family's width, or any other width, is
// refused by width on every path.
func TestBindingRefusesWrongWidthInitData(t *testing.T) {
	tdx := mrConfigID(anchor)
	hostData := HostData(anchor)
	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
	}{
		{"tdx 0 bytes", tdxResult(teetypes.PlatformTDX, nil, Zero[:])},
		{"tdx 32 bytes, the SHA-256", tdxResult(teetypes.PlatformTDX, hostData[:], Zero[:])},
		{"tdx 47 bytes", tdxResult(teetypes.PlatformTDX, tdx[:Size-1], Zero[:])},
		{"tdx 49 bytes", tdxResult(teetypes.PlatformTDX, append(bytes.Clone(tdx), 0), Zero[:])},
		{"snp 48 bytes, padded", snpResult(teetypes.PlatformSNP, paddedHostData(anchor))},
		{"snp 48 bytes, the SHA-384", snpResult(teetypes.PlatformSNP, tdx)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := Binding(tc.result); err == nil || !strings.Contains(err.Error(), "want") {
				t.Errorf("Binding() = %x, %v, want a width error", got, err)
			}
			if err := VerifyBinding(tc.result, anchor, nil); err == nil {
				t.Error("VerifyBinding() = nil, want an error")
			}
			if k, err := MatchBindingPrefix(tc.result, anchor, nil); err == nil {
				t.Errorf("MatchBindingPrefix() = %d, nil, want an error", k)
			}
		})
	}
}

func TestBindingUnknownPlatform(t *testing.T) {
	r := snpResult("nonsense", nil)
	if _, err := Binding(r); !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("Binding(unknown) = _, %v, want ErrUnknownPlatform", err)
	}
	err := VerifyBinding(r, anchor, nil)
	if !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("VerifyBinding(unknown) = %v, want ErrUnknownPlatform", err)
	}
	if errors.Is(err, ErrNoRegister) {
		t.Error("VerifyBinding(unknown) matches ErrNoRegister, so a caller skipping SNP would skip an unknown tag too")
	}
	if _, err := Binding(nil); err == nil {
		t.Error("Binding(nil) = _, nil, want an error")
	}
}

// The binding is read off claims that are only meaningful once the hardware
// signature over them has been checked; a result saying it was not is refused.
func TestBindingRefusesUnsignedResult(t *testing.T) {
	r := tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), Zero[:])
	r.SignatureValid = false
	if _, err := Binding(r); err == nil {
		t.Error("Binding(SignatureValid=false) = _, nil, want an error")
	}
	if err := VerifyBinding(r, anchor, nil); err == nil {
		t.Error("VerifyBinding(SignatureValid=false) = nil, want an error")
	}
	if _, err := MatchBindingPrefix(r, anchor, nil); err == nil {
		t.Error("MatchBindingPrefix(SignatureValid=false) = _, nil, want an error")
	}
}

// Azure sets HOSTDATA and MRCONFIGID itself, so its overlays carry no launch
// binding even when the field equals the anchor's digest. GCP's carry the
// bare-metal report and bind as bare metal does.
func TestBindingCloudOverlays(t *testing.T) {
	hostData := HostData(anchor)
	for _, tc := range []struct {
		result *teetypes.VerificationResult
		want   error
	}{
		{tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), Zero[:]), nil},
		{tdxResult(teetypes.PlatformGcpTDX, mrConfigID(anchor), Zero[:]), nil},
		{tdxResult(teetypes.PlatformAzTDX, mrConfigID(anchor), Zero[:]), ErrNoRegister},
		{tdxResult(" AZ-TDX ", mrConfigID(anchor), Zero[:]), ErrNoRegister},
		{snpResult(teetypes.PlatformSNP, hostData[:]), nil},
		{snpResult(teetypes.PlatformGcpSNP, hostData[:]), nil},
		{snpResult(teetypes.PlatformAzSNP, hostData[:]), ErrNoRegister},
	} {
		t.Run(string(tc.result.Platform), func(t *testing.T) {
			digest := mustLaunchFileDigest(t, tc.result.Platform.Family(), anchor)
			_, binding := Binding(tc.result)
			_, prefix := MatchBindingPrefix(tc.result, anchor, nil)
			_, digestPrefix := MatchLaunchFileDigestPrefix(tc.result, digest, nil)
			for name, err := range map[string]error{
				"Binding":                     binding,
				"VerifyBinding":               VerifyBinding(tc.result, anchor, nil),
				"MatchBindingPrefix":          prefix,
				"MatchLaunchFileDigestPrefix": digestPrefix,
			} {
				if !errors.Is(err, tc.want) {
					t.Errorf("%s = %v, want %v", name, err, tc.want)
				}
			}
		})
	}
}

// An empty anchor hashes to a public constant, so a guest launched with an
// empty anchor file must not verify as bound.
func TestBindingRejectsEmptyAnchor(t *testing.T) {
	emptySNP := HostData(nil)
	for _, r := range []*teetypes.VerificationResult{
		tdxResult(teetypes.PlatformTDX, mrConfigID(nil), Zero[:]),
		snpResult(teetypes.PlatformSNP, emptySNP[:]),
	} {
		for _, empty := range [][]byte{nil, {}} {
			if err := VerifyBinding(r, empty, nil); err == nil {
				t.Errorf("VerifyBinding(%s, empty anchor) = nil, want an error", r.Platform)
			}
			if k, err := MatchBindingPrefix(r, empty, nil); err == nil {
				t.Errorf("MatchBindingPrefix(%s, empty anchor) = %d, nil, want an error", r.Platform, k)
			}
		}
	}
}

func TestVerifyBinding(t *testing.T) {
	digests := []string{digestA, digestB}
	tdx := mrConfigID(anchor)
	hostData := HostData(anchor)

	for _, tc := range []struct {
		name    string
		result  *teetypes.VerificationResult
		digests []string
		wantErr bool
		errIs   error
	}{
		{name: "tdx bare", result: tdxResult(teetypes.PlatformTDX, tdx, Zero[:])},
		{name: "tdx runtime log", result: tdxResult(teetypes.PlatformTDX, tdx, runtimeLog(digests...)), digests: digests},
		{name: "tdx runtime log where none expected", result: tdxResult(teetypes.PlatformTDX, tdx, runtimeLog(digests...)), wantErr: true},
		{name: "tdx runtime log shorter than expected", result: tdxResult(teetypes.PlatformTDX, tdx, runtimeLog(digestA)), digests: digests, wantErr: true},
		{name: "tdx runtime log reordered", result: tdxResult(teetypes.PlatformTDX, tdx, runtimeLog(digestB, digestA)), digests: digests, wantErr: true},
		{name: "tdx zero where a log is expected", result: tdxResult(teetypes.PlatformTDX, tdx, Zero[:]), digests: digests, wantErr: true},
		{name: "tdx RTMR[3] extended with the file digest", result: tdxResult(teetypes.PlatformTDX, tdx, extendedWithFileDigest(anchor)), wantErr: true},
		{name: "tdx runtime log after the file digest", result: tdxResult(teetypes.PlatformTDX, tdx, extendedWithFileDigest(anchor, digests...)), digests: digests, wantErr: true},
		{name: "old image: zero MRCONFIGID, RTMR[3] extended with the file digest", result: tdxResult(teetypes.PlatformTDX, make([]byte, Size), extendedWithFileDigest(anchor)), wantErr: true},
		{name: "tdx missing RTMR[3]", result: tdxResult(teetypes.PlatformTDX, tdx, nil), wantErr: true},
		{name: "tdx RTMR[3] of SHA-256 width", result: tdxResult(teetypes.PlatformTDX, tdx, make([]byte, HostDataSize)), wantErr: true},
		{name: "tdx missing RTMR[3] with digests", result: tdxResult(teetypes.PlatformTDX, tdx, nil), digests: digests, wantErr: true},
		{name: "tdx another file", result: tdxResult(teetypes.PlatformTDX, mrConfigID([]byte("another file\n")), Zero[:]), wantErr: true},
		{name: "tdx zero MRCONFIGID", result: tdxResult(teetypes.PlatformTDX, make([]byte, Size), Zero[:]), wantErr: true},
		{name: "tdx zero-padded SHA-256", result: tdxResult(teetypes.PlatformTDX, paddedHostData(anchor), Zero[:]), wantErr: true},
		{name: "snp hostdata", result: snpResult(teetypes.PlatformSNP, hostData[:])},
		{name: "snp wrong key", result: snpResult(teetypes.PlatformSNP, make([]byte, HostDataSize)), wantErr: true},
		{name: "snp with workload digests", result: snpResult(teetypes.PlatformSNP, hostData[:]), digests: digests, wantErr: true},
		{name: "az-tdx refused", result: tdxResult(teetypes.PlatformAzTDX, tdx, Zero[:]), wantErr: true, errIs: ErrNoRegister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyBinding(tc.result, anchor, tc.digests)
			if (err != nil) != tc.wantErr || (tc.errIs != nil && !errors.Is(err, tc.errIs)) {
				t.Fatalf("VerifyBinding() = %v, wantErr %v matching %v", err, tc.wantErr, tc.errIs)
			}
		})
	}
}

func TestMatchBindingPrefix(t *testing.T) {
	d := func(b string) string { return "sha256:" + strings.Repeat(b, 32) }
	claimed := []string{d("01"), d("02"), d("03")}
	tdx := mrConfigID(anchor)
	atK := func(k int) []byte { return runtimeLog(claimed[:k]...) }
	hostData := HostData(anchor)

	for _, tc := range []struct {
		name    string
		result  *teetypes.VerificationResult
		claimed []string
		want    int
		wantErr bool
		errIs   error
	}{
		{name: "zero, no list", result: tdxResult(teetypes.PlatformTDX, tdx, atK(0)), want: 0},
		{name: "zero, list ahead", result: tdxResult(teetypes.PlatformTDX, tdx, atK(0)), claimed: claimed, want: 0},
		{name: "first entry", result: tdxResult(teetypes.PlatformTDX, tdx, atK(1)), claimed: claimed, want: 1},
		{name: "middle prefix", result: tdxResult(teetypes.PlatformTDX, tdx, atK(2)), claimed: claimed, want: 2},
		{name: "whole list", result: tdxResult(teetypes.PlatformGcpTDX, tdx, atK(3)), claimed: claimed, want: 3},
		{name: "extended, empty list", result: tdxResult(teetypes.PlatformTDX, tdx, atK(1)), claimed: []string{}, wantErr: true},
		{name: "extended, nil list", result: tdxResult(teetypes.PlatformTDX, tdx, atK(1)), wantErr: true},
		{name: "duplicate extended twice", result: tdxResult(teetypes.PlatformTDX, tdx, runtimeLog(claimed[0], claimed[0])), claimed: []string{claimed[0], claimed[0]}, want: 2},
		{name: "duplicate extended once", result: tdxResult(teetypes.PlatformTDX, tdx, atK(1)), claimed: []string{claimed[0], claimed[0]}, want: 1},
		{name: "extended past the list", result: tdxResult(teetypes.PlatformTDX, tdx, atK(3)), claimed: claimed[:2], wantErr: true},
		{name: "reordered list", result: tdxResult(teetypes.PlatformTDX, tdx, atK(2)), claimed: []string{claimed[1], claimed[0]}, wantErr: true},
		{name: "RTMR[3] extended with the file digest", result: tdxResult(teetypes.PlatformTDX, tdx, extendedWithFileDigest(anchor)), claimed: claimed, wantErr: true},
		{name: "prefix after the file digest", result: tdxResult(teetypes.PlatformTDX, tdx, extendedWithFileDigest(anchor, claimed[:2]...)), claimed: claimed, wantErr: true},
		{name: "old image: zero MRCONFIGID, RTMR[3] extended with the file digest", result: tdxResult(teetypes.PlatformTDX, make([]byte, Size), extendedWithFileDigest(anchor)), claimed: claimed, wantErr: true},
		{name: "missing RTMR[3]", result: tdxResult(teetypes.PlatformTDX, tdx, nil), claimed: claimed, wantErr: true},
		{name: "RTMR[3] of SHA-256 width", result: tdxResult(teetypes.PlatformTDX, tdx, make([]byte, HostDataSize)), claimed: claimed, wantErr: true},
		{name: "another file", result: tdxResult(teetypes.PlatformTDX, mrConfigID([]byte("another file\n")), atK(1)), claimed: claimed, wantErr: true},
		{name: "zero-padded SHA-256", result: tdxResult(teetypes.PlatformTDX, paddedHostData(anchor), atK(1)), claimed: claimed, wantErr: true},
		{name: "non-canonical entry", result: tdxResult(teetypes.PlatformTDX, tdx, atK(1)), claimed: []string{claimed[0], "img@" + claimed[1]}, wantErr: true},
		{name: "uppercase entry", result: tdxResult(teetypes.PlatformTDX, tdx, atK(0)), claimed: []string{strings.ToUpper(claimed[0])}, wantErr: true},
		{name: "snp ignores list", result: snpResult(teetypes.PlatformSNP, hostData[:]), claimed: claimed, want: 0},
		{name: "snp wrong anchor", result: snpResult(teetypes.PlatformSNP, make([]byte, HostDataSize)), wantErr: true},
		{name: "snp HOSTDATA on tdx", result: tdxResult(teetypes.PlatformTDX, hostData[:], atK(0)), wantErr: true},
		{name: "az-snp refused", result: snpResult(teetypes.PlatformAzSNP, hostData[:]), errIs: ErrNoRegister, wantErr: true},
		{name: "az-tdx refused", result: tdxResult(teetypes.PlatformAzTDX, tdx, atK(1)), claimed: claimed, errIs: ErrNoRegister, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := MatchBindingPrefix(tc.result, anchor, tc.claimed)
			if tc.wantErr {
				if err == nil || (tc.errIs != nil && !errors.Is(err, tc.errIs)) {
					t.Fatalf("MatchBindingPrefix() = %d, %v, want an error matching %v", k, err, tc.errIs)
				}
				return
			}
			if err != nil || k != tc.want {
				t.Fatalf("MatchBindingPrefix() = %d, %v, want %d, nil", k, err, tc.want)
			}
		})
	}
}

// A launch binding mismatch reads the same whichever path finds it.
func TestMatchBindingPrefixNoListMismatch(t *testing.T) {
	r := tdxResult(teetypes.PlatformTDX, make([]byte, Size), Zero[:])
	_, got := MatchBindingPrefix(r, anchor, nil)
	want := VerifyBinding(r, anchor, nil)
	if got == nil || want == nil || got.Error() != want.Error() || !strings.Contains(got.Error(), "MRCONFIGID") {
		t.Fatalf("MatchBindingPrefix(nil) = %v, want %v naming MRCONFIGID", got, want)
	}
}
