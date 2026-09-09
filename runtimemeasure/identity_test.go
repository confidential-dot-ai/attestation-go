package runtimemeasure

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func testImagePins() ImagePins {
	var p ImagePins
	for _, f := range []struct {
		hex string
		dst *[Size]byte
	}{{mrtdHex, &p.MRTD}, {rtmr1Hex, &p.RTMR1}, {rtmr2Hex, &p.RTMR2}} {
		if err := decodeRegister(f.hex, f.dst); err != nil {
			panic(err)
		}
	}
	return p
}

// tdxImageResult builds a signature-verified result carrying the launch
// measurement and register claims ImagePins.Verify reads.
func tdxImageResult(p teetypes.PlatformType, mrtd, rtmr1, rtmr2 string) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims: teetypes.Claims{
			LaunchDigest: mrtd,
			PlatformData: map[string]any{"rtmr_1": rtmr1, "rtmr_2": rtmr2},
		},
	}
}

func snpImageResult(p teetypes.PlatformType, launch string) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       p,
		Claims:         teetypes.Claims{LaunchDigest: launch},
	}
}

func TestImagePinsVerify(t *testing.T) {
	pins := testImagePins()
	if err := pins.Verify(tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, rtmr2Hex)); err != nil {
		t.Fatalf("Verify(matching) = %v", err)
	}
	// The launch digest is hex, so case and stray whitespace are not identity.
	spaced := " " + strings.ToUpper(mrtdHex) + "\n"
	if err := pins.Verify(tdxImageResult(teetypes.PlatformGcpTDX, spaced, rtmr1Hex, rtmr2Hex)); err != nil {
		t.Fatalf("Verify(uppercase MRTD on gcp-tdx) = %v", err)
	}

	other := strings.Repeat("9f", Size)
	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
		want   error
	}{
		{"nil result", nil, nil},
		{"unverified", &teetypes.VerificationResult{Platform: teetypes.PlatformTDX}, nil},
		{"snp result", snpImageResult(teetypes.PlatformSNP, mrtdHex), ErrWrongFamily},
		{"unknown platform", tdxImageResult("nonsense", mrtdHex, rtmr1Hex, rtmr2Hex), ErrWrongFamily},
		{"no launch digest", tdxImageResult(teetypes.PlatformTDX, "", rtmr1Hex, rtmr2Hex), nil},
		{"mrtd mismatch", tdxImageResult(teetypes.PlatformTDX, other, rtmr1Hex, rtmr2Hex), nil},
		{"rtmr1 mismatch", tdxImageResult(teetypes.PlatformTDX, mrtdHex, other, rtmr2Hex), nil},
		{"rtmr2 mismatch", tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, other), nil},
		{"rtmr2 absent", tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, ""), nil},
		{"rtmr1 malformed", tdxImageResult(teetypes.PlatformTDX, mrtdHex, "zz", rtmr2Hex), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := pins.Verify(tc.result)
			if err == nil {
				t.Fatal("Verify = nil, want an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// RTMR[3] carries the anchor and the workload chain, which move between
// launches of one image: Verify must ignore it, leaving it to VerifyBinding.
func TestImagePinsVerifyIgnoresRTMR3(t *testing.T) {
	pins := testImagePins()
	res := tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, rtmr2Hex)
	res.Claims.PlatformData["rtmr_3"] = strings.Repeat("7d", Size)
	if err := pins.Verify(res); err != nil {
		t.Fatalf("Verify = %v, want the image check to ignore RTMR[3]", err)
	}
}

func testSNPPins() SNPImagePins {
	pins := SNPImagePins{BySMP: map[int][Size]byte{}}
	for smp, h := range map[int]string{2: mrtdHex, 4: rtmr1Hex} {
		var d [Size]byte
		if err := decodeRegister(h, &d); err != nil {
			panic(err)
		}
		pins.BySMP[smp] = d
	}
	return pins
}

func TestSNPImagePinsVerify(t *testing.T) {
	pins := testSNPPins()
	for _, launch := range []string{mrtdHex, rtmr1Hex} {
		if err := pins.Verify(snpImageResult(teetypes.PlatformSNP, launch)); err != nil {
			t.Fatalf("Verify(pinned variant %s...) = %v", launch[:8], err)
		}
	}
	// Every SNP tag is checked the same way: unlike the anchor binding, a
	// launch measurement means the same thing under the Azure paravisor.
	if err := pins.Verify(snpImageResult(teetypes.PlatformAzSNP, strings.ToUpper(mrtdHex))); err != nil {
		t.Fatalf("Verify(az-snp) = %v", err)
	}

	for _, tc := range []struct {
		name   string
		result *teetypes.VerificationResult
		want   error
	}{
		{"nil result", nil, nil},
		{"unverified", &teetypes.VerificationResult{Platform: teetypes.PlatformSNP}, nil},
		{"tdx result", tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, rtmr2Hex), ErrWrongFamily},
		{"no launch digest", snpImageResult(teetypes.PlatformSNP, ""), nil},
		{"unpinned variant", snpImageResult(teetypes.PlatformSNP, strings.Repeat("9f", Size)), nil},
		{"not hex", snpImageResult(teetypes.PlatformSNP, strings.Repeat("zz", Size)), nil},
		{"wrong width", snpImageResult(teetypes.PlatformSNP, strings.Repeat("9f", HostDataSize)), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := pins.Verify(tc.result)
			if err == nil {
				t.Fatal("Verify = nil, want an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// HOST_DATA carries the anchor, which moves between launches of one image:
// Verify must ignore it, leaving it to VerifyBinding.
func TestSNPImagePinsVerifyIgnoresHostData(t *testing.T) {
	pins := testSNPPins()
	res := snpImageResult(teetypes.PlatformSNP, mrtdHex)
	res.Claims.InitData = make([]byte, HostDataSize)
	if err := pins.Verify(res); err != nil {
		t.Fatalf("Verify = %v, want the image check to ignore HOST_DATA", err)
	}
}

func TestImageIdentityFamilies(t *testing.T) {
	for _, tc := range []struct {
		identity ImageIdentity
		want     teetypes.Family
	}{
		{testImagePins(), teetypes.FamilyTDX},
		{testSNPPins(), teetypes.FamilySNP},
	} {
		if got := tc.identity.Family(); got != tc.want {
			t.Errorf("%T.Family() = %q, want %q", tc.identity, got, tc.want)
		}
	}
}

// A pin and a matching binding are the two halves of a node check: neither
// alone says both which image booted and what it was launched for.
func TestVerifyThenVerifyBinding(t *testing.T) {
	pins := testImagePins()
	anchorBytes := []byte("anchor-bytes-v1\n")
	seed := Seed(anchorBytes)
	res := tdxImageResult(teetypes.PlatformTDX, mrtdHex, rtmr1Hex, rtmr2Hex)
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])

	if err := pins.Verify(res); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if err := VerifyBinding(res, anchorBytes, nil); err != nil {
		t.Fatalf("VerifyBinding = %v", err)
	}
	if err := VerifyBinding(res, []byte("another anchor"), nil); err == nil {
		t.Fatal("VerifyBinding(wrong anchor) = nil, want a mismatch")
	}
}
