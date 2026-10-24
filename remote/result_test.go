package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The files under testdata are attestation-api's own answers, captured from
// its test suite at the commit this client targets, so the decoding here is
// checked against the service rather than against this package's idea of it.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeFixture(t *testing.T, name string) VerifyResponse {
	t.Helper()
	var resp VerifyResponse
	if err := json.Unmarshal(fixture(t, name), &resp); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return resp
}

func TestDecodeSNPRegistersPassed(t *testing.T) {
	resp := decodeFixture(t, "snp-registers-passed.json")
	if !resp.Passed {
		t.Fatal("passed = false")
	}
	if resp.Token == nil {
		t.Fatal("the token the fixture carries was dropped")
	}
	r := resp.Result
	if !r.SignatureValid || r.Platform != teetypes.PlatformSNP {
		t.Fatalf("result = %+v", r)
	}
	if !affirmed(r.ReportDataMatch) || !affirmed(r.LaunchDigestMatch) || r.InitDataMatch != nil {
		t.Fatalf("verdicts: report data %v, launch %v, init %v", r.ReportDataMatch, r.LaunchDigestMatch, r.InitDataMatch)
	}
	if !affirmed(r.MeasurementRegistersMatch) || r.MeasurementRegisters == nil {
		t.Fatalf("measurement registers: match %v, registers %v", r.MeasurementRegistersMatch, r.MeasurementRegisters)
	}
	if r.MeasurementRegisters.EventCount != 4096 || len(r.MeasurementRegisters.Registers) != teetypes.MeasurementRegisterCount {
		t.Fatalf("measurement registers = %d events, %d registers", r.MeasurementRegisters.EventCount, len(r.MeasurementRegisters.Registers))
	}
	for i, reg := range r.MeasurementRegisters.Registers {
		if len(reg) != measurementSize {
			t.Fatalf("register %d is %d bytes", i, len(reg))
		}
	}
	// The claims c8s reads.
	if r.Claims.LaunchDigest != "5d931eeda3fcdf2fc4cd58a1f3f7a5bf776b7e5e1dcaf918437a05ad64dbc3fef71ec40b5bc7610def19dbdd9fd16d70" {
		t.Fatalf("launch digest = %q", r.Claims.LaunchDigest)
	}
	if _, err := r.Claims.LaunchMeasurement(); err != nil {
		t.Fatal(err)
	}
	if debug, err := r.Claims.DebugEnabled(); err != nil || debug {
		t.Fatalf("DebugEnabled() = %v, %v", debug, err)
	}
	if smt, err := r.Claims.SMTEnabled(); err != nil || !smt {
		t.Fatalf("SMTEnabled() = %v, %v", smt, err)
	}
	if r.Claims.TCB.Type != "Snp" || r.Claims.TCB.Snp == nil || *r.Claims.TCB.Snp != 27 {
		t.Fatalf("tcb = %+v", r.Claims.TCB)
	}
	if len(r.Claims.ReportData) != reportDataSize {
		t.Fatalf("report_data is %d bytes", len(r.Claims.ReportData))
	}
	if resp.Checks.VMPL != 0 || resp.Checks.MigrateMA || resp.Checks.Debug || !affirmed(resp.Checks.CRLOK) {
		t.Fatalf("checks = %+v", resp.Checks)
	}
	if len(resp.Checks.Collateral) != 1 || resp.Checks.Collateral[0].Name != "amd-crl genoa" || !resp.Checks.Collateral[0].Current {
		t.Fatalf("collateral = %+v", resp.Checks.Collateral)
	}
	if !r.CollateralVerified {
		t.Fatal("CollateralVerified = false on a passed result")
	}

	// The registers the service verified are the ones the request pinned.
	var policies Policies
	if err := json.Unmarshal(fixture(t, "snp-registers-policies.json"), &policies); err != nil {
		t.Fatal(err)
	}
	pinned := *policies.SNP.MeasurementRegisters
	if err := EnforceMeasurementRegisters(resp, teetypes.PlatformSNP, pinned); err != nil {
		t.Fatalf("EnforceMeasurementRegisters(pinned): %v", err)
	}
	other := append([][]byte{}, pinned...)
	other[3] = measurement(0x99)
	if err := EnforceMeasurementRegisters(resp, teetypes.PlatformSNP, other); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Fatalf("EnforceMeasurementRegisters(other) = %v, want ErrRegistersNotAllowed", err)
	}
	if err := EnforceMeasurementRegisters(resp, teetypes.PlatformSNP, AllZeroMeasurementRegisters()); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Fatalf("EnforceMeasurementRegisters(all zero) = %v, want ErrRegistersNotAllowed", err)
	}
	req := VerifyRequest{Platform: teetypes.PlatformSNP, Policies: policies}
	if err := EnforceVerdict(req, resp); err != nil {
		t.Fatalf("EnforceVerdict: %v", err)
	}
	// The request the service answered is what PoliciesFor builds.
	launch, _ := base64.StdEncoding.DecodeString("XZMe7aP83y/EzVih8/elv3drfl4dyvkYQ3oFrWTbw/73HsQLW8dhDe8Z292f0W1w")
	built, err := PoliciesFor(teetypes.PlatformSNP, Policy{
		ExpectedReportData:   policies.SNP.ReportData,
		Measurements:         [][]byte{launch},
		MeasurementRegisters: pinned,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture leaves the defaults (allow_debug, max_vmpl) out; the client
	// sends them, so compare what the service was asked to check.
	if built.SNP == nil ||
		!bytes.Equal(built.SNP.ReportData, policies.SNP.ReportData) ||
		!slices.EqualFunc(built.SNP.LaunchDigest, policies.SNP.LaunchDigest, bytes.Equal) ||
		built.SNP.MeasurementRegisters == nil ||
		!slices.EqualFunc(*built.SNP.MeasurementRegisters, pinned, bytes.Equal) {
		got, _ := json.Marshal(built)
		want, _ := json.Marshal(policies)
		t.Fatalf("PoliciesFor = %s\nwant the request the service answered\n%s", got, want)
	}
	if built.SNP.AllowDebug || built.SNP.MaxVMPL != 0 || built.SNP.HostData != nil || built.SNP.MinTcb != nil {
		t.Fatalf("PoliciesFor added checks the fixture did not ask for: %+v", built.SNP)
	}
}

// Another caller's bytes: genuine evidence, commitment mismatch. The service
// withholds the registers and reports the two verdicts false.
func TestDecodeSNPRegistersRejected(t *testing.T) {
	resp := decodeFixture(t, "snp-registers-rejected.json")
	if resp.Passed || resp.Token != nil {
		t.Fatalf("passed = %v, token = %v", resp.Passed, resp.Token)
	}
	r := resp.Result
	if !r.SignatureValid || affirmed(r.ReportDataMatch) || affirmed(r.MeasurementRegistersMatch) || r.MeasurementRegisters != nil {
		t.Fatalf("result = %+v", r)
	}
	if !affirmed(r.LaunchDigestMatch) {
		t.Fatal("the launch digest pin held in the fixture")
	}
	var policies Policies
	if err := json.Unmarshal(fixture(t, "snp-registers-policies.json"), &policies); err != nil {
		t.Fatal(err)
	}
	req := VerifyRequest{Platform: teetypes.PlatformSNP, Policies: policies}
	if err := EnforceVerdict(req, resp); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("EnforceVerdict = %v, want ErrReportDataMismatch", err)
	}
	if err := EnforceMeasurementRegisters(resp, teetypes.PlatformSNP, *policies.SNP.MeasurementRegisters); !errors.Is(err, ErrRegistersNotAllowed) {
		t.Fatalf("EnforceMeasurementRegisters = %v, want ErrRegistersNotAllowed", err)
	}
}

func TestDecodeSNPPassedWithoutPins(t *testing.T) {
	resp := decodeFixture(t, "snp-passed.json")
	if !resp.Passed {
		t.Fatal("passed = false")
	}
	r := resp.Result
	if r.ReportDataMatch != nil || r.LaunchDigestMatch != nil || r.InitDataMatch != nil || r.MeasurementRegistersMatch != nil {
		t.Fatalf("unasked checks answered: %+v", r)
	}
	// Nothing asked, nothing to affirm; the verdict stands on passed alone.
	if err := EnforceVerdict(VerifyRequest{Platform: teetypes.PlatformSNP, Policies: Policies{SNP: &SNPParams{}}}, resp); err != nil {
		t.Fatalf("EnforceVerdict: %v", err)
	}
	// A pin the request made but the service did not answer is a refusal.
	req := VerifyRequest{Platform: teetypes.PlatformSNP, Policies: Policies{SNP: &SNPParams{ReportData: []byte("x")}}}
	if err := EnforceVerdict(req, resp); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("EnforceVerdict(unanswered report data) = %v, want ErrReportDataMismatch", err)
	}
}

func TestDecodeTDXPassed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
	}{
		{"tdx-passed.json", teetypes.PlatformTDX},
		{"gcp-tdx-passed.json", teetypes.PlatformGcpTDX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := decodeFixture(t, tc.name)
			if !resp.Passed {
				t.Fatal("passed = false")
			}
			r := resp.Result
			if r.Platform != tc.platform || !r.SignatureValid {
				t.Fatalf("result = %+v", r)
			}
			if r.LaunchDigestMatch != nil || r.MRTDMatch != nil || r.RTMR0Match != nil || r.RTMR3Match != nil || r.InitDataMatch != nil {
				t.Fatalf("unasked TDX checks answered: %+v", r)
			}
			if r.TCBStatus == nil || r.TCBStatus.FMSPC == "" {
				t.Fatalf("tcb_status = %+v", r.TCBStatus)
			}
			if r.Claims.TCB.Type != "Tdx" || len(r.Claims.TCB.TCBSvn) != 16 {
				t.Fatalf("tcb = %+v", r.Claims.TCB)
			}
			for i := range 4 {
				if _, err := r.Claims.RTMR(i); err != nil {
					t.Fatalf("RTMR(%d): %v", i, err)
				}
			}
			if !affirmed(resp.Checks.TCBStatusAccepted) || len(resp.Checks.Collateral) < 4 {
				t.Fatalf("checks = %+v", resp.Checks)
			}
		})
	}
	resp := decodeFixture(t, "tdx-passed.json")
	if affirmed(resp.Checks.EndorsementMatch) || !resp.Checks.Debug || !resp.Checks.AllowDebug {
		t.Fatalf("checks = %+v", resp.Checks)
	}
	if !affirmed(resp.Result.ReportDataMatch) {
		t.Fatal("report_data_match was pinned true in the fixture")
	}
	gcp := decodeFixture(t, "gcp-tdx-passed.json")
	if !affirmed(gcp.Checks.EndorsementMatch) {
		t.Fatal("endorsement_match not decoded")
	}
}

// A bad signature is a 422 with the error envelope, never a 200.
func TestBadSignatureIsAnAPIError(t *testing.T) {
	var body ErrorResponse
	if err := json.Unmarshal(fixture(t, "snp-bad-signature-422.json"), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "verification_failed" || body.Message == "" {
		t.Fatalf("error body = %+v", body)
	}
}

// What a stub writes, a client reads back unchanged, on both families.
func TestVerifyResponseRoundTrip(t *testing.T) {
	yes, no := true, false
	for _, resp := range []VerifyResponse{
		{
			Passed: true,
			Result: teetypes.VerificationResult{
				SignatureValid: true, Platform: teetypes.PlatformSNP,
				ReportDataMatch: &yes, InitDataMatch: &yes, LaunchDigestMatch: &no,
				Claims:                    teetypes.Claims{LaunchDigest: digestHex, PlatformData: map[string]any{"vmpl": float64(0)}},
				MeasurementRegisters:      &teetypes.MeasurementRegisters{EventCount: 2, Registers: [][]byte{measurement(1), measurement(2)}},
				MeasurementRegistersMatch: &yes,
			},
			Checks: ServiceChecks{MinTcbMet: &yes, CRLOK: &yes, Collateral: []CollateralUsed{{Name: "amd-crl genoa", From: "held", Current: true}}},
		},
		{
			Passed: false,
			Result: teetypes.VerificationResult{
				SignatureValid: true, Platform: teetypes.PlatformAzTDX,
				ReportDataMatch: &no, InitDataMatch: &no, LaunchDigestMatch: &yes, RTMR1Match: &yes, RTMR3Match: &no,
				Claims: teetypes.Claims{LaunchDigest: digestHex},
			},
			Checks: ServiceChecks{Debug: true, PCRsMatch: &no, TCBStatusAccepted: &yes, CRLOK: &yes},
		},
	} {
		t.Run(string(resp.Result.Platform), func(t *testing.T) {
			body, err := json.Marshal(resp)
			if err != nil {
				t.Fatal(err)
			}
			var back VerifyResponse
			if err := json.Unmarshal(body, &back); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			// The wire has no signature_valid: a 200 is genuine.
			if bytes.Contains(body, []byte("signature_valid")) {
				t.Fatalf("signature_valid on the wire: %s", body)
			}
			if resp.Checks.Collateral == nil {
				resp.Checks.Collateral = []CollateralUsed{}
			}
			got, _ := json.Marshal(back)
			want, _ := json.Marshal(resp)
			if !bytes.Equal(got, want) {
				t.Fatalf("round trip changed the response:\n got %s\nwant %s", got, want)
			}
			if back.Result.MeasurementRegisters != nil && !bytes.Equal(back.Result.MeasurementRegisters.Registers[1], measurement(2)) {
				t.Fatal("registers did not survive the round trip")
			}
		})
	}
}

// A 200 whose body is not a /verify result (a proxy page, a stub answering the
// wrong shape) must not decode into a result with a valid signature.
func TestDecodeRequiresAPlatform(t *testing.T) {
	for _, body := range []string{`{}`, `{"result":{},"passed":true}`, `{"result":{"platform":""},"passed":true}`} {
		var resp VerifyResponse
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			t.Fatalf("%s decoded to %+v, want an error", body, resp)
		}
	}
}

// CollateralVerified keeps its in-process meaning: the collateral checks ran
// and passed. A revoked chain is checked, not verified.
func TestDecodeCollateralVerifiedFollowsCRLOK(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"result":{"platform":"snp","crl_ok":true,"collateral":[]},"passed":true}`, true},
		{`{"result":{"platform":"snp","crl_ok":false,"collateral":[]},"passed":false}`, false},
		{`{"result":{"platform":"snp","crl_ok":null,"collateral":[]},"passed":true}`, false},
	} {
		var resp VerifyResponse
		if err := json.Unmarshal([]byte(tc.body), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Result.CollateralVerified != tc.want {
			t.Fatalf("%s: CollateralVerified = %v, want %v", tc.body, resp.Result.CollateralVerified, tc.want)
		}
	}
}
