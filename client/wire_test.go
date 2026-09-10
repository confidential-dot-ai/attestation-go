package client

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func measurement(b byte) []byte { return bytes.Repeat([]byte{b}, sha512.Size384) }

// One concept, two field names: the caller says "launch measurement" and the
// platform decides which the service is asked about.
func TestSetExpectedMeasurementsPicksThePlatformField(t *testing.T) {
	m := measurement(0xab)
	for _, tc := range []struct {
		platform  teetypes.PlatformType
		wantMRTD  bool
		wantSNPLD bool
	}{
		{teetypes.PlatformTDX, true, false},
		{teetypes.PlatformAzTDX, true, false},
		{teetypes.PlatformGcpTDX, true, false},
		{teetypes.PlatformSNP, false, true},
		{teetypes.PlatformAzSNP, false, true},
		{teetypes.PlatformGcpSNP, false, true},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			var p VerifyParams
			if err := p.SetExpectedMeasurements(tc.platform, m, nil); err != nil {
				t.Fatalf("SetExpectedMeasurements: %v", err)
			}
			if got := p.ExpectedMRTD != nil; got != tc.wantMRTD {
				t.Errorf("expected_mrtd set = %v, want %v", got, tc.wantMRTD)
			}
			if got := p.ExpectedLaunchDigest != nil; got != tc.wantSNPLD {
				t.Errorf("expected_launch_digest set = %v, want %v", got, tc.wantSNPLD)
			}
		})
	}
}

func TestSetExpectedMeasurementsRegisters(t *testing.T) {
	m := measurement(0x01)
	var p VerifyParams
	pins := map[int][]byte{0: measurement(0), 1: measurement(1), 2: measurement(2), 3: measurement(3)}
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, m, pins); err != nil {
		t.Fatalf("SetExpectedMeasurements: %v", err)
	}
	for i, got := range [][]byte{p.ExpectedRTMR0, p.ExpectedRTMR1, p.ExpectedRTMR2, p.ExpectedRTMR3} {
		if !bytes.Equal(got, pins[i]) {
			t.Errorf("RTMR[%d] = %x, want %x", i, got, pins[i])
		}
	}
}

// Each call replaces every expected-measurement field, so nothing from an
// earlier call survives as a pin the caller no longer asked for.
func TestSetExpectedMeasurementsReplacesEarlierPins(t *testing.T) {
	var p VerifyParams
	if err := p.SetExpectedMeasurements(teetypes.PlatformSNP, measurement(0x01), nil); err != nil {
		t.Fatal(err)
	}
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, measurement(0x02), map[int][]byte{3: measurement(0x03)}); err != nil {
		t.Fatal(err)
	}
	if p.ExpectedLaunchDigest != nil {
		t.Errorf("expected_launch_digest survived a switch to TDX: %x", p.ExpectedLaunchDigest)
	}
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, nil, nil); err != nil {
		t.Fatal(err)
	}
	if p.ExpectedMRTD != nil || p.ExpectedRTMR3 != nil {
		t.Errorf("pins survived a clearing call: mrtd=%x rtmr3=%x", p.ExpectedMRTD, p.ExpectedRTMR3)
	}

	// A failed call leaves the previous pins in place rather than half of the
	// new ones.
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, measurement(0x04), map[int][]byte{1: measurement(0x01)}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, measurement(0x05), map[int][]byte{0: measurement(0x00), 2: measurement(0x02)[:5]}); err == nil {
		t.Fatal("short register pin accepted")
	}
	if !bytes.Equal(p.ExpectedMRTD, measurement(0x04)) || !bytes.Equal(p.ExpectedRTMR1, measurement(0x01)) || p.ExpectedRTMR0 != nil {
		t.Errorf("failed call changed pins: mrtd=%x rtmr0=%x rtmr1=%x", p.ExpectedMRTD, p.ExpectedRTMR0, p.ExpectedRTMR1)
	}
}

func TestSetExpectedMeasurementsRejectsBadInput(t *testing.T) {
	good := measurement(0xaa)
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		launch   []byte
		rtmrs    map[int][]byte
		want     string
	}{
		{"short launch measurement", teetypes.PlatformTDX, good[:47], nil, "47 bytes"},
		{"registers on SNP", teetypes.PlatformSNP, good, map[int][]byte{1: good}, "no runtime measurement registers"},
		{"register index out of range", teetypes.PlatformTDX, good, map[int][]byte{4: good}, "out of range"},
		{"short register pin", teetypes.PlatformTDX, good, map[int][]byte{1: good[:10]}, "10 bytes"},
		{"unknown platform", "nonsense", good, nil, "unknown platform"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p VerifyParams
			err := p.SetExpectedMeasurements(tc.platform, tc.launch, tc.rtmrs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SetExpectedMeasurements() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// Nothing is pinned unless it was asked for, so omitempty keeps an unpinned
// request identical to what it was before these fields existed.
func TestVerifyParamsOmitsUnsetMeasurements(t *testing.T) {
	var p VerifyParams
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, nil, nil); err != nil {
		t.Fatalf("SetExpectedMeasurements: %v", err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"expected_mrtd", "expected_launch_digest", "expected_rtmr0", "expected_rtmr1", "expected_rtmr2", "expected_rtmr3"} {
		if strings.Contains(string(body), field) {
			t.Errorf("unset %s appears on the wire: %s", field, body)
		}
	}
}

// The service decodes these as base64 and requires 48 bytes; encoding/json
// gives that for free on a []byte.
func TestExpectedMeasurementsMarshalAsBase64(t *testing.T) {
	var p VerifyParams
	if err := p.SetExpectedMeasurements(teetypes.PlatformTDX, measurement(0x00), nil); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// 48 zero bytes in standard base64.
	if !strings.Contains(string(body), `"expected_mrtd":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`) {
		t.Errorf("expected_mrtd is not standard base64: %s", body)
	}
}
