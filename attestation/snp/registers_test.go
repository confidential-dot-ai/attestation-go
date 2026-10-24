package snp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/abi"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Hardware fixtures from attestation-rs: Genoa guest kernels with the
// measurement-register provider, 2026-10-20, and the chip's VCEK.
var (
	//go:embed testdata/kmr/kmr-vcek.der
	kmrVCEK []byte
	// The provider kernel after a full log: 4096 events, then extend fails.
	//go:embed testdata/kmr/kmr-full-report.bin
	kmrReport []byte
	//go:embed testdata/kmr/kmr-full-event-log.bin
	kmrEventLog []byte
	//go:embed testdata/kmr/kmr-full-caller-data.bin
	kmrCallerData []byte
	// SNP_GET_REPORT with vmpl 1 from the provider kernel, six events.
	//go:embed testdata/kmr/kmr-vmpl/vmpl1.report.bin
	kmrVMPL1Report []byte
	//go:embed testdata/kmr/kmr-vmpl/event-log.bin
	kmrVMPL1EventLog []byte
	//go:embed testdata/kmr/kmr-vmpl/caller-data.bin
	kmrVMPL1CallerData []byte
	// Guest root on an image without the provider, passing a forged H ‖ C as
	// its report data over event-log.bin and caller-data.bin.
	//go:embed testdata/kmr/kmr-forge/report.bin
	kmrForgeReport []byte
	//go:embed testdata/kmr/kmr-forge/event-log.bin
	kmrForgeEventLog []byte
	//go:embed testdata/kmr/kmr-forge/caller-data.bin
	kmrForgeCallerData []byte
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func logEntry(index, b byte) []byte {
	return append([]byte{index}, bytes.Repeat([]byte{b}, registerSize)...)
}

// prefixLog is four events in registers 0, 1, 0 and 15, and a fifth entry
// past the count. The commitment and registers are from Python hashlib.
func prefixLog() []byte {
	return slices.Concat(logEntry(0, 1), logEntry(1, 2), logEntry(0, 3), logEntry(15, 4), logEntry(4, 5))
}

const prefixReportData = "0400000000000000000000000000000099bc02ea57ae232704f512bcc942c10c023dd6bc7efedde64bb6fc4f0b8ed443b6e6183e3db85da964f4768e0129b6f1"

func TestVerifyCommitmentKnownAnswers(t *testing.T) {
	callerData := make([]byte, reportDataSize)
	for i := range callerData {
		callerData[i] = byte(i)
	}
	genesis := mustHex(t, "00000000000000000000000000000000d48e8448c5430f57994fb15caa1855aa3fa0f03b6e4c91511aa3f83b363ad4474bb701d740aac53b0cfabba7c2ffa6a7")
	got, err := VerifyCommitment(genesis, nil, callerData)
	if err != nil || got == nil {
		t.Fatalf("genesis: %v, %v", got, err)
	}
	if got.EventCount != 0 || len(got.Registers) != teetypes.MeasurementRegisterCount {
		t.Fatalf("genesis = %+v", got)
	}
	for i, r := range got.Registers {
		if !bytes.Equal(r, make([]byte, registerSize)) {
			t.Fatalf("genesis register %d = %x, want zero", i, r)
		}
	}

	callerData = bytes.Repeat([]byte{7}, reportDataSize)
	got, err = VerifyCommitment(mustHex(t, prefixReportData), prefixLog(), callerData)
	if err != nil || got == nil {
		t.Fatalf("prefix: %v, %v", got, err)
	}
	want := map[int]string{
		0:  "6198ab2caaa45d0bcc5d1f27e7c4a763f5518d272c0d74c2166aec2c5d280418d9d341caf10434d4f87a4921778d2d6a",
		1:  "66f60db53f35b91eb7f71aad347e076712169849778651cebd1b6f3c3b5eb756820617468d20330a8ea9913f60c1cc55",
		15: "273130d1fd0a53dad497ed8fc5c79d3c9f3c16963ff6cfac62b5890eeea1fc9bef91b9fefb568e5cdf375bcdbdcc817b",
	}
	if got.EventCount != 4 {
		t.Fatalf("event count = %d, want 4", got.EventCount)
	}
	for i, r := range got.Registers {
		expected := make([]byte, registerSize)
		if h, ok := want[i]; ok {
			expected = mustHex(t, h)
		}
		if !bytes.Equal(r, expected) {
			t.Fatalf("register %d = %x, want %x", i, r, expected)
		}
	}
}

func TestVerifyCommitmentRejects(t *testing.T) {
	log := prefixLog()
	four := log[:4*eventLogEntrySize]
	reported := mustHex(t, prefixReportData)
	callerData := bytes.Repeat([]byte{7}, reportDataSize)
	with := func(log []byte, at int, value byte) []byte {
		out := slices.Clone(log)
		out[at] = value
		return out
	}
	registers, ok, err := ReplayEventLog(log, 4)
	if err != nil || !ok {
		t.Fatal(err)
	}
	registers[1][0] ^= 1
	overOtherRegisters, err := CommitmentReportData(4, registers, callerData)
	if err != nil {
		t.Fatal(err)
	}
	reordered := slices.Concat(four[2*eventLogEntrySize:3*eventLogEntrySize], four[eventLogEntrySize:2*eventLogEntrySize],
		four[:eventLogEntrySize], four[3*eventLogEntrySize:])

	for name, bad := range map[string][]byte{
		"index above 15":                with(four, 3*eventLogEntrySize, 16),
		"index above 15 past the count": with(log, 4*eventLogEntrySize, 16),
		"trailing partial entry":        append(slices.Clone(four), 0),
	} {
		if _, err := VerifyCommitment(reported, bad, callerData); err == nil {
			t.Errorf("%s: want a malformed-log error", name)
		}
	}

	for _, tc := range []struct {
		name                  string
		log, reported, caller []byte
	}{
		{"log shorter than the count", four[:3*eventLogEntrySize], reported, callerData},
		{"nonzero header padding", four, with(reported, 15, 1), callerData},
		{"reordered within a register", reordered, reported, callerData},
		{"other caller data", four, reported, with(callerData, 63, 6)},
		{"an entry moved to another register", with(four, 0, 2), reported, callerData},
		{"a lower event count", four, with(reported, 0, 3), callerData},
		{"a commitment over other registers", four, overOtherRegisters, callerData},
	} {
		got, err := VerifyCommitment(tc.reported, tc.log, tc.caller)
		if err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if got != nil {
			t.Errorf("%s: verified %+v, want a mismatch", tc.name, got)
		}
	}
}

// A seeded xorshift64* generator, so property cases are reproducible.
type xorshift uint64

func (r *xorshift) next() uint64 {
	x := uint64(*r)
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	*r = xorshift(x)
	return x * 0x2545F4914F6CDD1D
}

func (r *xorshift) below(n int) int { return int(r.next() % uint64(n)) }

func (r *xorshift) bytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(r.next())
	}
	return out
}

func TestCommitmentRoundTripsAndAnyFlipIsRejected(t *testing.T) {
	rng := xorshift(0x5eed6b6d7231)
	for range 1000 {
		entries := rng.below(41)
		var log []byte
		for range entries {
			log = append(log, byte(rng.below(teetypes.MeasurementRegisterCount)))
			log = append(log, rng.bytes(registerSize)...)
		}
		eventCount := uint32(rng.below(entries + 1))
		callerData := rng.bytes(reportDataSize)
		registers, ok, err := ReplayEventLog(log, eventCount)
		if err != nil || !ok {
			t.Fatal(err)
		}
		reported, err := CommitmentReportData(eventCount, registers, callerData)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyCommitment(reported, log, callerData)
		if err != nil || got == nil || got.EventCount != eventCount {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
		flip := func(b []byte) []byte {
			out := slices.Clone(b)
			bit := rng.below(len(out) * 8)
			out[bit/8] ^= 1 << (bit % 8)
			return out
		}
		committed := int(eventCount) * eventLogEntrySize
		var flippedLog, flippedReported, flippedCaller = log, reported, callerData
		switch pick := rng.below(3); {
		case pick == 0 && committed > 0:
			flippedLog = slices.Concat(flip(log[:committed]), log[committed:])
		case pick == 1:
			flippedReported = flip(reported)
		default:
			flippedCaller = flip(callerData)
		}
		got, err = VerifyCommitment(flippedReported, flippedLog, flippedCaller)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatal("a flipped commitment verified")
		}
		if committed < len(log) {
			// A digest flip past the count is not attested and changes
			// nothing (an index flip there could only make the log malformed).
			untouched := slices.Clone(log)
			at := committed + rng.below(len(log)-committed)
			if at%eventLogEntrySize == 0 {
				at++
			}
			untouched[at] ^= 1 << rng.below(8)
			if got, err := VerifyCommitment(reported, untouched, callerData); err != nil || got == nil {
				t.Fatalf("flip past the count: %+v, %v", got, err)
			}
		}
	}
}

// kmrEvidence is the provider kernel's evidence with its VCEK inline.
func kmrEvidence(report, eventLog []byte) SnpEvidence {
	return SnpEvidence{
		AttestationReport: base64.StdEncoding.EncodeToString(report),
		CertChain:         &SnpCertChain{Vcek: base64.StdEncoding.EncodeToString(kmrVCEK)},
		EventLog:          base64.StdEncoding.EncodeToString(eventLog),
	}
}

func reportMeasurement(t *testing.T, report []byte) []byte {
	t.Helper()
	proto, err := abi.ReportToProto(report)
	if err != nil {
		t.Fatal(err)
	}
	return proto.GetMeasurement()
}

// replayed is the register state after the whole log, for an expectation.
func replayed(t *testing.T, log []byte, count int) [][]byte {
	t.Helper()
	registers, ok, err := ReplayEventLog(log, uint32(count))
	if err != nil || !ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	return registers
}

func kmrParams(t *testing.T) teetypes.VerifyParams {
	return teetypes.VerifyParams{
		ExpectedReportData:   kmrCallerData,
		ExpectedLaunchDigest: reportMeasurement(t, kmrReport),
		MeasurementRegisters: replayed(t, kmrEventLog, len(kmrEventLog)/eventLogEntrySize),
	}
}

func TestVerifyEvidenceKernelRegisters(t *testing.T) {
	params := kmrParams(t)
	res, err := VerifyEvidence(kmrEvidence(kmrReport, kmrEventLog), params, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch || res.LaunchDigestMatch == nil || !*res.LaunchDigestMatch {
		t.Fatalf("bindings not reported: %+v", res)
	}
	if res.MeasurementRegisters == nil || res.MeasurementRegisters.EventCount != 4096 {
		t.Fatalf("registers = %+v", res.MeasurementRegisters)
	}
	if res.MeasurementRegistersMatch == nil || !*res.MeasurementRegistersMatch {
		t.Fatal("measurement registers not reported matched")
	}
	for i, r := range res.MeasurementRegisters.Registers {
		if !bytes.Equal(r, params.MeasurementRegisters[i]) || bytes.Equal(r, make([]byte, registerSize)) {
			t.Fatalf("register %d = %x", i, r)
		}
	}

	// A whole entry past the count is not attested and changes nothing.
	longer := slices.Concat(kmrEventLog, logEntry(3, 9))
	if _, err := VerifyEvidence(kmrEvidence(kmrReport, longer), params, Options{}); err != nil {
		t.Fatalf("longer log: %v", err)
	}

	otherCaller := params
	otherCaller.ExpectedReportData = slices.Clone(kmrCallerData)
	otherCaller.ExpectedReportData[0] ^= 1
	otherValue := params
	otherValue.MeasurementRegisters = slices.Clone(params.MeasurementRegisters)
	otherValue.MeasurementRegisters[15] = slices.Clone(params.MeasurementRegisters[15])
	otherValue.MeasurementRegisters[15][47] ^= 1
	shorterList := params
	shorterList.MeasurementRegisters = params.MeasurementRegisters[:15]
	otherLog := slices.Clone(kmrEventLog)
	otherLog[60] ^= 1
	for _, tc := range []struct {
		name   string
		log    []byte
		params teetypes.VerifyParams
		want   string
	}{
		{"other caller data", kmrEventLog, otherCaller, "does not commit"},
		{"other log", otherLog, params, "does not commit"},
		{"log shorter than the count", kmrEventLog[:4095*eventLogEntrySize], params, "does not commit"},
		{"empty log", nil, params, "does not commit"},
		{"other register value", kmrEventLog, otherValue, "register 15 does not match"},
		{"shorter expected list", kmrEventLog, shorterList, "register 15 does not match"},
		{"trailing junk", append(slices.Clone(kmrEventLog), 0), params, "not whole entries"},
	} {
		_, err := VerifyEvidence(kmrEvidence(kmrReport, tc.log), tc.params, Options{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Evidence without an event log is a kernel that extended nothing: a report
// committing to events fails, a bare report path included.
func TestVerifyEvidenceMissingLogIsEmpty(t *testing.T) {
	ev := kmrEvidence(kmrReport, nil)
	ev.EventLog = ""
	if _, err := VerifyEvidence(ev, kmrParams(t), Options{}); err == nil || !strings.Contains(err.Error(), "does not commit") {
		t.Fatalf("err = %v", err)
	}
	if _, err := VerifyReport(kmrReport, kmrVCEK, kmrParams(t), teetypes.PlatformSNP, MinReportVersion, Options{}); err == nil || !strings.Contains(err.Error(), "does not commit") {
		t.Fatalf("bare report: err = %v", err)
	}
}

// Register mode checks the commitment instead of the raw field, so the raw
// comparison must not run: the kernel never writes the caller's bytes there.
func TestVerifyEvidenceRegistersSkipRawReportData(t *testing.T) {
	params := kmrParams(t)
	params.MeasurementRegisters = nil
	if _, err := VerifyEvidence(kmrEvidence(kmrReport, kmrEventLog), params, Options{}); err == nil {
		t.Fatal("raw REPORT_DATA comparison passed against a commitment")
	}
}

func TestVerifyEvidenceVMPL1ReportFails(t *testing.T) {
	params := teetypes.VerifyParams{
		ExpectedReportData:   kmrVMPL1CallerData,
		ExpectedLaunchDigest: reportMeasurement(t, kmrVMPL1Report),
		MeasurementRegisters: replayed(t, kmrVMPL1EventLog, 6),
	}
	_, err := VerifyEvidence(kmrEvidence(kmrVMPL1Report, kmrVMPL1EventLog), params, Options{})
	if err == nil || !strings.Contains(err.Error(), "policy validation failed") {
		t.Fatalf("err = %v, want the VMPL rejection", err)
	}
}

// Guest root on an image without the provider passes a forged H ‖ C as its
// report data. Only the launch digest pin tells it apart.
func TestVerifyEvidenceForgedCommitmentNeedsItsImagePinned(t *testing.T) {
	forged := make([][]byte, 5)
	for i := range forged {
		forged[i] = make([]byte, registerSize)
	}
	forged[1] = mustHex(t, "faef475db093da0bf48d02e58db273cf2efd9cc33fea6f75c86b094c9f2352b73c7021e4629e7f784f97893febebfc0d")
	forged[4] = mustHex(t, "9447d432169ab5914449fe9c0cc297b1ed8fca7b9a934151a81d174ab72df392fdd6e0305ff7c1587254f511381d9efa")
	params := func(launch []byte) teetypes.VerifyParams {
		return teetypes.VerifyParams{ExpectedReportData: kmrForgeCallerData, ExpectedLaunchDigest: launch, MeasurementRegisters: forged}
	}
	ev := kmrEvidence(kmrForgeReport, kmrForgeEventLog)

	_, err := VerifyEvidence(ev, params(reportMeasurement(t, kmrReport)), Options{})
	if err == nil || !strings.Contains(err.Error(), "policy validation failed") {
		t.Fatalf("provider pin: err = %v, want the launch digest rejection", err)
	}
	// Pinning the image without the provider accepts the forged registers:
	// the pin set is the whole defence.
	res, err := VerifyEvidence(ev, params(reportMeasurement(t, kmrForgeReport)), Options{})
	if err != nil {
		t.Fatalf("image pin: %v", err)
	}
	for i := range forged {
		if !bytes.Equal(res.MeasurementRegisters.Registers[i], forged[i]) {
			t.Fatalf("register %d = %x", i, res.MeasurementRegisters.Registers[i])
		}
	}
}

func TestVerifyEvidenceRegisterParamsRefused(t *testing.T) {
	base := kmrParams(t)
	ev := kmrEvidence(kmrReport, kmrEventLog)
	for _, tc := range []struct {
		name   string
		mutate func(*teetypes.VerifyParams)
		want   string
	}{
		{"no launch pin", func(p *teetypes.VerifyParams) { p.ExpectedLaunchDigest = nil }, "expected_launch_digest"},
		{"no report data", func(p *teetypes.VerifyParams) { p.ExpectedReportData = nil }, "expected_report_data"},
		{"report data too long", func(p *teetypes.VerifyParams) { p.ExpectedReportData = make([]byte, 65) }, "expected_report_data"},
		{"too many registers", func(p *teetypes.VerifyParams) { p.MeasurementRegisters = make([][]byte, 17) }, "at most 16"},
		{"short register", func(p *teetypes.VerifyParams) { p.MeasurementRegisters = [][]byte{{1}} }, "want 48"},
	} {
		params := base
		tc.mutate(&params)
		_, err := VerifyEvidence(ev, params, Options{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	_, err := VerifyReportContext(context.Background(), kmrReport, kmrVCEK, base, teetypes.PlatformGcpSNP, MinReportVersion, Options{})
	if err == nil || !strings.Contains(err.Error(), "bare-metal snp only") {
		t.Fatalf("gcp-snp: err = %v", err)
	}
	ev.EventLog = strings.Repeat("A", teetypes.MaxEvidenceFieldSize+4)
	if _, err := VerifyEvidence(ev, base, Options{}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized log: err = %v", err)
	}
}

// A requester's bytes shorter than the field are zero-extended before the
// commitment is checked, as /attest extended them for the kernel.
func TestCheckMeasurementRegistersZeroExtendsCallerData(t *testing.T) {
	short := bytes.Repeat([]byte{0x5a}, 48)
	registers, _, err := ReplayEventLog(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	reported, err := CommitmentReportData(0, registers, pad(short, reportDataSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkMeasurementRegisters(reported, nil, pad(short, reportDataSize), nil); err != nil {
		t.Fatalf("zero-extended caller data: %v", err)
	}
	other := bytes.Repeat([]byte{0x5b}, 48)
	if _, err := checkMeasurementRegisters(reported, nil, pad(other, reportDataSize), nil); err == nil || !strings.Contains(err.Error(), "does not commit") {
		t.Fatalf("other caller data: err = %v", err)
	}
}
