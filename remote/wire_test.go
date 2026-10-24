package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// measurement is a 48-byte SHA-384-shaped value filled with b.
func measurement(b byte) []byte { return bytes.Repeat([]byte{b}, measurementSize) }

// policyKeys are the top-level keys a marshalled Policies may carry: the
// service refuses any other.
var policyKeys = []string{"snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"}

// sentKeys returns the platform entries a marshalled Policies carries.
func sentKeys(t *testing.T, p Policies) []string {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(m))
	for _, k := range keys {
		if !slices.Contains(policyKeys, k) {
			t.Fatalf("Policies marshalled an unknown key %q: %s", k, body)
		}
	}
	return keys
}

// Exactly the envelope's platform gets an entry, under the service's tag.
func TestPoliciesForNamesOnlyTheEvidencePlatform(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		key      string
	}{
		{teetypes.PlatformSNP, "snp"},
		{teetypes.PlatformTDX, "tdx"},
		{teetypes.PlatformAzSNP, "az-snp"},
		{teetypes.PlatformAzTDX, "az-tdx"},
		{teetypes.PlatformGcpSNP, "gcp-snp"},
		{teetypes.PlatformGcpTDX, "gcp-tdx"},
		{" TDX ", "tdx"},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			p, err := PoliciesFor(tc.platform, Policy{ExpectedReportData: measurement(0x5a)})
			if err != nil {
				t.Fatalf("PoliciesFor: %v", err)
			}
			if got := sentKeys(t, p); !slices.Equal(got, []string{tc.key}) {
				t.Fatalf("policies name %v, want [%s]", got, tc.key)
			}
		})
	}
	for _, platform := range []teetypes.PlatformType{"nonsense", "", teetypes.PlatformDstack} {
		if _, err := PoliciesFor(platform, Policy{}); !errors.Is(err, ErrUnsupportedPlatform) {
			t.Errorf("PoliciesFor(%q) = %v, want ErrUnsupportedPlatform", platform, err)
		}
	}
}

// The report-data and init-data pins land in the platform's own fields, and an
// unset pin is left out, so the service does not check a zero value.
func TestPoliciesForBindings(t *testing.T) {
	rd, init := measurement(0x01), pcr(0x02)
	floor := &teetypes.SnpTcb{Bootloader: 10, Snp: 27, Microcode: 28}

	snp, err := PoliciesFor(teetypes.PlatformSNP, Policy{ExpectedReportData: rd, ExpectedInitDataHash: init, AllowDebug: true, MinTcb: floor})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snp.SNP.ReportData, rd) || !bytes.Equal(snp.SNP.HostData, init) || !snp.SNP.AllowDebug || snp.SNP.MinTcb != floor {
		t.Fatalf("snp params = %+v", snp.SNP)
	}
	tdx, err := PoliciesFor(teetypes.PlatformAzTDX, Policy{ExpectedReportData: rd, ExpectedInitDataHash: init, PCRs: map[int][]byte{4: init}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tdx.AzTDX.ReportData, rd) || !bytes.Equal(tdx.AzTDX.InitData, init) || !bytes.Equal(tdx.AzTDX.PCRs[4], init) {
		t.Fatalf("az-tdx params = %+v", tdx.AzTDX)
	}

	body, err := json.Marshal(tdx)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "accepted_tcb_statuses", "launch_digest", "measurement_registers", "min_tcb"} {
		if strings.Contains(string(body), `"`+absent+`"`) {
			t.Errorf("unset %s was sent: %s", absent, body)
		}
	}
	for _, present := range []string{`"report_data"`, `"init_data"`, `"pcrs":{"4":`, `"allow_debug":false`} {
		if !strings.Contains(string(body), present) {
			t.Errorf("%s missing from %s", present, body)
		}
	}
	empty, err := PoliciesFor(teetypes.PlatformTDX, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := json.Marshal(empty); string(body) != `{"tdx":{"allow_debug":false}}` {
		t.Fatalf("zero policy marshals as %s", body)
	}
}

// Launch measurements reach the service as one set under the platform's name;
// flat register pins become single-value sets. Images replace the flat pins,
// as EnforcePins applies them.
func TestPoliciesForMeasurementSets(t *testing.T) {
	a, b, c := measurement(0x0a), measurement(0x0b), measurement(0x0c)
	flat := Policy{Measurements: [][]byte{b, c, b}, Registers: map[int][]byte{2: c}}
	tdx, err := PoliciesFor(teetypes.PlatformTDX, flat)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(tdx.TDX.MRTD, [][]byte{b, c}, bytes.Equal) {
		t.Fatalf("mrtd = %x, want [%x %x]", tdx.TDX.MRTD, b, c)
	}
	if tdx.TDX.RTMR1 != nil || !slices.EqualFunc(tdx.TDX.RTMR2, [][]byte{c}, bytes.Equal) {
		t.Fatalf("rtmr1 = %x, rtmr2 = %x, want only rtmr2 = [%x]", tdx.TDX.RTMR1, tdx.TDX.RTMR2, c)
	}

	images := flat
	images.Images = []ImagePin{{Name: "x", Digest: a}, {Name: "y", Digest: b, Registers: map[int][]byte{1: c}}, {Name: "z", Digest: a}}
	snp, err := PoliciesFor(teetypes.PlatformGcpSNP, images)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]byte{a, b}; !slices.EqualFunc(snp.GcpSNP.LaunchDigest, want, bytes.Equal) {
		t.Fatalf("launch_digest = %x, want the image digests %x", snp.GcpSNP.LaunchDigest, want)
	}
	tdx, err = PoliciesFor(teetypes.PlatformTDX, images)
	if err != nil {
		t.Fatal(err)
	}
	// Image registers stay a client-side, per-image check, and the flat
	// register pin is superseded with the flat measurements.
	if !slices.EqualFunc(tdx.TDX.MRTD, [][]byte{a, b}, bytes.Equal) || tdx.TDX.RTMR1 != nil || tdx.TDX.RTMR2 != nil {
		t.Fatalf("mrtd = %x, rtmr1 = %x, rtmr2 = %x, want the image digests and no register pin", tdx.TDX.MRTD, tdx.TDX.RTMR1, tdx.TDX.RTMR2)
	}

	body, err := json.Marshal(snp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"launch_digest":["`+base64.StdEncoding.EncodeToString(a)+`","`) {
		t.Fatalf("launch digests are not a base64 array: %s", body)
	}
	if _, err := PoliciesFor(teetypes.PlatformTDX, Policy{Measurements: [][]byte{[]byte("short")}}); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Fatalf("short measurement = %v, want ErrMeasurementNotAllowed", err)
	}
}

// A policy element the platform cannot answer is refused before any request.
func TestPoliciesForRefusesUnanswerablePins(t *testing.T) {
	m := measurement(0x01)
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		policy   Policy
		want     error
	}{
		{"min TCB off SNP", teetypes.PlatformTDX, Policy{MinTcb: &teetypes.SnpTcb{}}, ErrMinTcbNotAllowed},
		{"RTMR on SNP", teetypes.PlatformSNP, Policy{Registers: map[int][]byte{1: m}}, ErrRegistersNotAllowed},
		{"RTMR index", teetypes.PlatformTDX, Policy{Registers: map[int][]byte{4: m}}, ErrRegistersNotAllowed},
		{"RTMR width", teetypes.PlatformTDX, Policy{Registers: map[int][]byte{1: []byte("x")}}, ErrRegistersNotAllowed},
		{"PCR off vTPM", teetypes.PlatformSNP, Policy{PCRs: map[int][]byte{4: pcr(0x01)}}, ErrPCRNotAllowed},
		{"PCR off vTPM gcp", teetypes.PlatformGcpTDX, Policy{PCRs: map[int][]byte{4: pcr(0x01)}}, ErrPCRNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PoliciesFor(tc.platform, tc.policy); !errors.Is(err, tc.want) {
				t.Fatalf("PoliciesFor = %v, want %v", err, tc.want)
			}
		})
	}
}

// Register mode: the pin is sent as the list the service takes (an empty list
// for all zero, never left out), the report data is zero-extended to the field
// the kernel committed to, and the launch pin it needs must be there.
func TestPoliciesForMeasurementRegisters(t *testing.T) {
	digest, r0 := measurement(0x5a), measurement(0x01)
	image := Policy{Images: []ImagePin{{Name: "node", Digest: digest}}}

	zero := image
	zero.ExpectedReportData, zero.MeasurementRegisters = measurement(0x77), AllZeroMeasurementRegisters()
	p, err := PoliciesFor(teetypes.PlatformSNP, zero)
	if err != nil {
		t.Fatalf("PoliciesFor(all zero): %v", err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"measurement_registers":[]`) {
		t.Fatalf("all-zero pin is not an empty list: %s", body)
	}
	want := make([]byte, reportDataSize)
	copy(want, measurement(0x77))
	if !bytes.Equal(p.SNP.ReportData, want) {
		t.Fatalf("report_data = %x, want the pin zero-extended to 64 bytes", p.SNP.ReportData)
	}
	if !strings.Contains(string(body), `"report_data":"`+base64.StdEncoding.EncodeToString(want)+`"`) {
		t.Fatalf("report_data not sent zero-extended: %s", body)
	}

	one := zero
	one.MeasurementRegisters = [][]byte{r0}
	p, err = PoliciesFor(teetypes.PlatformSNP, one)
	if err != nil {
		t.Fatal(err)
	}
	if got := *p.SNP.MeasurementRegisters; len(got) != 1 || !bytes.Equal(got[0], r0) {
		t.Fatalf("measurement_registers = %x, want [%x]", got, r0)
	}

	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		mutate   func(*Policy)
	}{
		{"off bare-metal snp", teetypes.PlatformAzSNP, func(*Policy) {}},
		{"gcp", teetypes.PlatformGcpSNP, func(*Policy) {}},
		{"tdx", teetypes.PlatformTDX, func(*Policy) {}},
		{"no launch pin", teetypes.PlatformSNP, func(p *Policy) { p.Images = nil }},
		{"no report data", teetypes.PlatformSNP, func(p *Policy) { p.ExpectedReportData = nil }},
		{"report data too long", teetypes.PlatformSNP, func(p *Policy) { p.ExpectedReportData = make([]byte, 65) }},
		{"too many registers", teetypes.PlatformSNP, func(p *Policy) { p.MeasurementRegisters = make([][]byte, 17) }},
		{"short register", teetypes.PlatformSNP, func(p *Policy) { p.MeasurementRegisters = [][]byte{[]byte("x")} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := zero
			tc.mutate(&policy)
			if _, err := PoliciesFor(tc.platform, policy); !errors.Is(err, ErrRegistersNotAllowed) {
				t.Fatalf("PoliciesFor = %v, want ErrRegistersNotAllowed", err)
			}
		})
	}

	// Measurements pin the launch digest as well as Images do.
	flat := Policy{Measurements: [][]byte{digest}, ExpectedReportData: measurement(0x77), MeasurementRegisters: AllZeroMeasurementRegisters()}
	if _, err := PoliciesFor(teetypes.PlatformSNP, flat); err != nil {
		t.Fatalf("PoliciesFor(flat launch pin): %v", err)
	}
}

// The verify request is the service's shape: the platform and its evidence at
// the top level, collateral forwarded as is, and the policies beside them.
func TestNewVerifyRequestShape(t *testing.T) {
	ev := teetypes.AttestationEvidence{
		Platform:   teetypes.PlatformSNP,
		Evidence:   json.RawMessage(`{"attestation_report":"AA=="}`),
		Collateral: json.RawMessage(`[{"url":"https://kds","body":"x"}]`),
	}
	policies, err := PoliciesFor(ev.Platform, Policy{ExpectedReportData: measurement(0x01)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(NewVerifyRequest(ev, policies, false))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(got))
	if want := []string{"collateral", "evidence", "platform", "policies"}; !slices.Equal(keys, want) {
		t.Fatalf("request keys = %v, want %v", keys, want)
	}
	if string(got["evidence"]) != string(ev.Evidence) || string(got["collateral"]) != string(ev.Collateral) {
		t.Fatalf("evidence or collateral rewritten: %s", body)
	}
	if strings.Contains(string(body), "issue_token") {
		t.Fatalf("issue_token false was sent: %s", body)
	}
	body, _ = json.Marshal(NewVerifyRequest(teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)}, policies, true))
	if !strings.Contains(string(body), `"issue_token":true`) || strings.Contains(string(body), "collateral") {
		t.Fatalf("request = %s", body)
	}
}

// Pins reads back exactly what PoliciesFor placed, for every platform tag, so
// the verdict is enforced against the pins the request really carried.
func TestPinsRoundTrip(t *testing.T) {
	policy := Policy{
		ExpectedReportData:   measurement(0x11),
		ExpectedInitDataHash: bytes.Repeat([]byte{0x22}, 32),
		Measurements:         [][]byte{measurement(0x33)},
	}
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformSNP, teetypes.PlatformGcpSNP, teetypes.PlatformAzSNP,
		teetypes.PlatformTDX, teetypes.PlatformGcpTDX, teetypes.PlatformAzTDX,
	} {
		t.Run(string(platform), func(t *testing.T) {
			p := policy
			if platform.HasRegisters() {
				p.Registers = map[int][]byte{2: measurement(0x44)}
			}
			if platform.HasVTPMQuote() {
				p.PCRs = map[int][]byte{4: pcr(0x55)}
			}
			if platform.HasMeasurementRegisters() {
				p.MeasurementRegisters = [][]byte{measurement(0x66)}
			}
			policies, err := PoliciesFor(platform, p)
			if err != nil {
				t.Fatal(err)
			}
			pins, ok := policies.Pins(platform)
			if !ok {
				t.Fatal("no entry for the platform the policies were built for")
			}
			if !bytes.Equal(pins.InitData, p.ExpectedInitDataHash) || len(pins.Launch) != 1 || !bytes.Equal(pins.Launch[0], measurement(0x33)) {
				t.Fatalf("pins = %+v", pins)
			}
			if platform.HasMeasurementRegisters() {
				if pins.MeasurementRegisters == nil || !bytes.Equal(pins.ReportData, append(measurement(0x11), make([]byte, 16)...)) {
					t.Fatalf("register mode pins = %+v", pins)
				}
			} else if !bytes.Equal(pins.ReportData, p.ExpectedReportData) || pins.MeasurementRegisters != nil {
				t.Fatalf("pins = %+v", pins)
			}
			if got := len(pins.RTMRs[2]); got != len(p.Registers) {
				t.Fatalf("RTMR[2] set has %d values, want %d", got, len(p.Registers))
			}
			if !maps.EqualFunc(pins.PCRs, p.PCRs, bytes.Equal) {
				t.Fatalf("PCRs = %v, want %v", pins.PCRs, p.PCRs)
			}
			for _, other := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
				if other != platform {
					if _, ok := policies.Pins(other); ok {
						t.Fatalf("an entry for %s as well", other)
					}
				}
			}
		})
	}
}
