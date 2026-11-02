package runtimemeasure

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

var launchFile = []byte("schemaVersion: c8s-worker/v1\n")

func mustLaunchFileDigest(t *testing.T, f teetypes.Family, file []byte) []byte {
	t.Helper()
	d, err := LaunchFileDigest(f, file)
	if err != nil {
		t.Fatalf("LaunchFileDigest(%s): %v", f, err)
	}
	return d
}

// The digest is the init data a launcher commits, so a launcher committing it
// and a verifier holding the file agree.
func TestLaunchFileDigest(t *testing.T) {
	hostData := HostData(launchFile)
	if got := mustLaunchFileDigest(t, teetypes.FamilySNP, launchFile); !bytes.Equal(got, hostData[:]) {
		t.Errorf("snp digest = %x, want HOSTDATA %x", got, hostData)
	}
	tdx := mustLaunchFileDigest(t, teetypes.FamilyTDX, launchFile)
	if want := sha512.Sum384(launchFile); !bytes.Equal(tdx, want[:]) {
		t.Errorf("tdx digest = %x, want SHA-384 %x", tdx, want)
	}
	for _, f := range []teetypes.Family{teetypes.FamilySNP, teetypes.FamilyTDX} {
		for _, empty := range [][]byte{nil, {}} {
			if _, err := LaunchFileDigest(f, empty); err == nil {
				t.Errorf("LaunchFileDigest(%s, %q) = _, nil, want an error", f, empty)
			}
		}
	}
	if _, err := LaunchFileDigest(teetypes.FamilyUnknown, launchFile); !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("LaunchFileDigest(unknown) = _, %v, want ErrUnknownPlatform", err)
	}
}

func TestParseLaunchFileDigest(t *testing.T) {
	snp := mustLaunchFileDigest(t, teetypes.FamilySNP, launchFile)
	tdx := mustLaunchFileDigest(t, teetypes.FamilyTDX, launchFile)
	snpHex, tdxHex := hex.EncodeToString(snp), hex.EncodeToString(tdx)
	emptySNP, emptyTDX := sha256.Sum256(nil), sha512.Sum384(nil)

	for _, tc := range []struct {
		name   string
		family teetypes.Family
		s      string
		want   []byte
	}{
		{"snp", teetypes.FamilySNP, snpHex, snp},
		{"tdx", teetypes.FamilyTDX, tdxHex, tdx},
		{"tdx width on snp", teetypes.FamilySNP, tdxHex, nil},
		{"snp width on tdx", teetypes.FamilyTDX, snpHex, nil},
		{"uppercase", teetypes.FamilySNP, strings.ToUpper(snpHex), nil},
		{"0x prefix", teetypes.FamilySNP, "0x" + snpHex[2:], nil},
		{"algorithm prefix", teetypes.FamilySNP, "sha256:" + snpHex, nil},
		{"odd length", teetypes.FamilySNP, snpHex[:63], nil},
		{"surrounding space", teetypes.FamilySNP, " " + snpHex[1:], nil},
		{"empty", teetypes.FamilySNP, "", nil},
		{"all zero snp", teetypes.FamilySNP, strings.Repeat("0", 64), nil},
		{"all zero tdx", teetypes.FamilyTDX, strings.Repeat("0", 96), nil},
		{"empty file snp", teetypes.FamilySNP, hex.EncodeToString(emptySNP[:]), nil},
		{"empty file tdx", teetypes.FamilyTDX, hex.EncodeToString(emptyTDX[:]), nil},
		{"unknown family", teetypes.FamilyUnknown, snpHex, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLaunchFileDigest(tc.family, tc.s)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ParseLaunchFileDigest(%s, %q) = %x, want an error", tc.family, tc.s, got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("ParseLaunchFileDigest(%s, %q) = %x, %v, want %x", tc.family, tc.s, got, err, tc.want)
			}
		})
	}
}

func TestMatchLaunchFileDigestPrefix(t *testing.T) {
	snp := mustLaunchFileDigest(t, teetypes.FamilySNP, launchFile)
	tdx := mustLaunchFileDigest(t, teetypes.FamilyTDX, launchFile)
	claimed := []string{"sha256:" + strings.Repeat("01", 32), "sha256:" + strings.Repeat("02", 32)}
	extended := runtimeLog(claimed[:1]...)
	other := []byte("another file\n")
	otherHostData := HostData(other)
	emptySNP, emptyTDX := sha256.Sum256(nil), sha512.Sum384(nil)
	zeroHostData := make([]byte, HostDataSize)

	for _, tc := range []struct {
		name    string
		result  *teetypes.VerificationResult
		digest  []byte
		claimed []string
		want    int
		wantErr bool
		errIs   error
	}{
		{name: "tdx bare", result: tdxResult(teetypes.PlatformTDX, tdx, Zero[:]), digest: tdx, want: 0},
		{name: "tdx extended", result: tdxResult(teetypes.PlatformTDX, tdx, extended), digest: tdx, claimed: claimed, want: 1},
		{name: "tdx extended, no list", result: tdxResult(teetypes.PlatformTDX, tdx, extended), digest: tdx, wantErr: true},
		{name: "tdx RTMR[3] extended with the file digest", result: tdxResult(teetypes.PlatformTDX, tdx, extendedWithFileDigest(launchFile)), digest: tdx, claimed: claimed, wantErr: true},
		{name: "tdx missing RTMR[3]", result: tdxResult(teetypes.PlatformTDX, tdx, nil), digest: tdx, wantErr: true},
		{name: "tdx other file", result: tdxResult(teetypes.PlatformTDX, mrConfigID(other), Zero[:]), digest: tdx, wantErr: true},
		{name: "tdx zero-padded SHA-256", result: tdxResult(teetypes.PlatformTDX, paddedHostData(launchFile), Zero[:]), digest: tdx, wantErr: true},
		{name: "snp", result: snpResult(teetypes.PlatformSNP, snp), digest: snp, claimed: claimed, want: 0},
		{name: "snp other file", result: snpResult(teetypes.PlatformSNP, otherHostData[:]), digest: snp, wantErr: true},
		{name: "zero digest on keyless snp", result: snpResult(teetypes.PlatformSNP, zeroHostData), digest: zeroHostData, wantErr: true},
		{name: "zero digest on keyless tdx", result: tdxResult(teetypes.PlatformTDX, Zero[:], Zero[:]), digest: Zero[:], wantErr: true},
		{name: "empty file on snp", result: snpResult(teetypes.PlatformSNP, emptySNP[:]), digest: emptySNP[:], wantErr: true},
		{name: "empty file on tdx", result: tdxResult(teetypes.PlatformTDX, emptyTDX[:], Zero[:]), digest: emptyTDX[:], wantErr: true},
		{name: "non-canonical claim", result: tdxResult(teetypes.PlatformTDX, tdx, extended), digest: tdx, claimed: []string{strings.ToUpper(claimed[0])}, wantErr: true},
		{name: "az-snp refused", result: snpResult(teetypes.PlatformAzSNP, snp), digest: snp, wantErr: true, errIs: ErrNoRegister},
		{name: "az-tdx refused", result: tdxResult(teetypes.PlatformAzTDX, tdx, Zero[:]), digest: tdx, wantErr: true, errIs: ErrNoRegister},
		{name: "unknown platform", result: snpResult("nonsense", snp), digest: snp, wantErr: true, errIs: ErrUnknownPlatform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := MatchLaunchFileDigestPrefix(tc.result, tc.digest, tc.claimed)
			if tc.wantErr {
				if err == nil || (tc.errIs != nil && !errors.Is(err, tc.errIs)) {
					t.Fatalf("MatchLaunchFileDigestPrefix() = %d, %v, want an error matching %v", k, err, tc.errIs)
				}
				return
			}
			if err != nil || k != tc.want {
				t.Fatalf("MatchLaunchFileDigestPrefix() = %d, %v, want %d, nil", k, err, tc.want)
			}
		})
	}
}

// A digest one family's binding cannot hold is refused, even where it shares a
// prefix with the digest the evidence proves.
func TestMatchLaunchFileDigestPrefixRefusesWrongWidth(t *testing.T) {
	tdx := mustLaunchFileDigest(t, teetypes.FamilyTDX, launchFile)
	snp := mustLaunchFileDigest(t, teetypes.FamilySNP, launchFile)
	tdxEvidence := tdxResult(teetypes.PlatformTDX, tdx, Zero[:])
	snpEvidence := snpResult(teetypes.PlatformSNP, snp)
	for name, tc := range map[string]struct {
		result *teetypes.VerificationResult
		digest []byte
	}{
		"tdx, nil":                     {tdxEvidence, nil},
		"tdx, cut to sev-snp width":    {tdxEvidence, tdx[:HostDataSize]},
		"tdx, one byte over":           {tdxEvidence, append(bytes.Clone(tdx), 0)},
		"sev-snp, nil":                 {snpEvidence, nil},
		"sev-snp, padded to tdx width": {snpEvidence, append(bytes.Clone(snp), make([]byte, Size-HostDataSize)...)},
		"sev-snp, one byte over":       {snpEvidence, append(bytes.Clone(snp), 0)},
	} {
		t.Run(name, func(t *testing.T) {
			if k, err := MatchLaunchFileDigestPrefix(tc.result, tc.digest, nil); err == nil {
				t.Fatalf("MatchLaunchFileDigestPrefix(%d-byte digest) = %d, nil, want an error", len(tc.digest), k)
			}
		})
	}
}

// A digest pin answers exactly as an anchor pin of the same file does.
func TestMatchLaunchFileDigestPrefixAgreesWithAnchor(t *testing.T) {
	claimed := []string{"sha256:" + strings.Repeat("01", 32), "sha256:" + strings.Repeat("02", 32)}
	hostData := HostData(anchor)
	results := []*teetypes.VerificationResult{snpResult(teetypes.PlatformSNP, hostData[:]), snpResult(teetypes.PlatformSNP, make([]byte, HostDataSize))}
	for k := range len(claimed) + 1 {
		results = append(results, tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), runtimeLog(claimed[:k]...)))
	}
	results = append(results,
		tdxResult(teetypes.PlatformTDX, make([]byte, Size), Zero[:]),
		tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), extendedWithFileDigest(anchor)),
		tdxResult(teetypes.PlatformTDX, mrConfigID(anchor), nil))
	for i, r := range results {
		digest := mustLaunchFileDigest(t, r.Platform.Family(), anchor)
		for _, list := range [][]string{nil, claimed} {
			wantK, wantErr := MatchBindingPrefix(r, anchor, list)
			gotK, gotErr := MatchLaunchFileDigestPrefix(r, digest, list)
			if gotK != wantK || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("result %d, list %q: digest pin = %d, %v; anchor pin = %d, %v", i, list, gotK, gotErr, wantK, wantErr)
			}
		}
	}
}
