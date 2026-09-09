package apiclienttest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/apiclient"
	"github.com/confidential-dot-ai/attestation-go/apiclient/apiclienttest"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// snpReport pulls the raw report back out of the stub's evidence, the way a
// caller extracting evidence does.
func snpReport(t *testing.T, evidence json.RawMessage) []byte {
	t.Helper()
	var ev struct {
		AttestationReport string `json:"attestation_report"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		t.Fatalf("evidence is not the attestation_report envelope: %v", err)
	}
	report, err := base64.StdEncoding.DecodeString(ev.AttestationReport)
	if err != nil {
		t.Fatalf("attestation_report is not standard base64: %v", err)
	}
	if len(report) != apiclienttest.SNPReportSize {
		t.Fatalf("report = %d bytes, want %d", len(report), apiclienttest.SNPReportSize)
	}
	return report
}

// Both transports must serve the same stub: apiclient picks a Unix-socket
// transport for a unix:// address, and a test adopting the stub should not have
// to know which it got.
func TestStubServesBothTransports(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func(testing.TB) *apiclienttest.Stub
	}{
		{"http", apiclienttest.New},
		{"unix", apiclienttest.NewUnix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := tc.new(t)
			client := apiclient.NewClient(stub.URL())

			health, err := client.Health(context.Background())
			if err != nil || health.Status != "ok" {
				t.Fatalf("Health = %+v, %v; want status ok", health, err)
			}
			resp, err := client.Attest(context.Background(), apiclient.AttestRequest{
				ReportData: []byte("nonce"),
				Platform:   apiclient.PlatformAuto,
			})
			if err != nil {
				t.Fatalf("Attest: %v", err)
			}
			if resp.Platform != teetypes.PlatformSNP {
				t.Fatalf("platform = %q, want snp", resp.Platform)
			}
		})
	}
}

// The stub's /attest evidence must survive the round trip that production
// evidence extraction makes: the envelope shape, the report width, and the
// report data landing in REPORTDATA.
func TestStubAttestRecordsAndReturnsSNPEvidence(t *testing.T) {
	stub := apiclienttest.New(t)
	reportData := []byte("0123456789abcdef0123456789abcdef0123456789abcdef")

	resp, err := apiclient.NewClient(stub.URL()).Attest(context.Background(), apiclient.AttestRequest{
		ReportData: reportData,
		Platform:   apiclient.PlatformAuto,
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	report := snpReport(t, resp.Evidence)
	var want [64]byte
	copy(want[:], reportData)
	if got := report[0x50:0x90]; !bytes.Equal(got, want[:]) {
		t.Fatalf("REPORTDATA = %x, want %x", got, want)
	}

	reqs := stub.AttestRequests()
	if len(reqs) != 1 {
		t.Fatalf("/attest calls = %d, want 1", len(reqs))
	}
	if !bytes.Equal(reqs[0].ReportData, reportData) {
		t.Fatalf("recorded report_data = %x, want %x", reqs[0].ReportData, reportData)
	}
}

// Report data wider than the hardware field is clamped, not an error: the
// stub answers what the hardware would.
func TestFakeSNPEvidenceClampsReportDataToTheField(t *testing.T) {
	oversize := bytes.Repeat([]byte{0xAB}, 100)
	report := snpReport(t, apiclienttest.FakeSNPEvidence(oversize))
	if got := report[0x50:0x90]; !bytes.Equal(got, oversize[:64]) {
		t.Fatalf("REPORTDATA = %x, want the leading 64 bytes %x", got, oversize[:64])
	}
	if report[0] != 0x02 {
		t.Fatalf("report version = %d, want 2", report[0])
	}
}

func TestStubAttestPlatformResolution(t *testing.T) {
	attest := func(t *testing.T, s *apiclienttest.Stub, platform teetypes.PlatformType) teetypes.PlatformType {
		t.Helper()
		resp, err := apiclient.NewClient(s.URL()).Attest(context.Background(), apiclient.AttestRequest{
			ReportData: []byte("x"),
			Platform:   platform,
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		return resp.Platform
	}

	t.Run("auto resolves to the detected platform", func(t *testing.T) {
		stub := apiclienttest.New(t)
		if got := attest(t, stub, apiclient.PlatformAuto); got != teetypes.PlatformSNP {
			t.Fatalf("platform = %q, want snp", got)
		}
		stub.SetPlatform(teetypes.PlatformTDX)
		if got := attest(t, stub, apiclient.PlatformAuto); got != teetypes.PlatformTDX {
			t.Fatalf("platform = %q after SetPlatform(tdx), want tdx", got)
		}
	})
	t.Run("explicit platform is honored", func(t *testing.T) {
		stub := apiclienttest.New(t)
		if got := attest(t, stub, teetypes.PlatformGcpSNP); got != teetypes.PlatformGcpSNP {
			t.Fatalf("platform = %q, want gcp-snp", got)
		}
	})
}

func TestStubVerifyRecordsAndAnswersVerdict(t *testing.T) {
	stub := apiclienttest.New(t)
	stub.SetVerdict(apiclienttest.PassingVerdict("deadbeef"))

	expected := []byte("expected-report-data")
	req := apiclient.NewVerifyRequest(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformGcpSNP,
		Evidence: json.RawMessage(`{"quote":"x"}`),
	}, &apiclient.VerifyParams{ExpectedReportData: expected}, false)

	resp, err := apiclient.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyEnforced against a passing verdict: %v", err)
	}
	if resp.Result.Platform != req.Platform {
		t.Fatalf("response platform = %q, want the request's %q", resp.Result.Platform, req.Platform)
	}
	if resp.Result.Claims.LaunchDigest != "deadbeef" {
		t.Fatalf("launch digest = %q, want deadbeef", resp.Result.Claims.LaunchDigest)
	}

	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	if reqs[0].Params == nil || !bytes.Equal(reqs[0].Params.ExpectedReportData, expected) {
		t.Fatalf("recorded expected_report_data = %+v, want %x", reqs[0].Params, expected)
	}
	if reqs[0].Platform != teetypes.PlatformGcpSNP {
		t.Fatalf("recorded platform = %q, want gcp-snp", reqs[0].Platform)
	}
}

// Defense in depth: a mismatch verdict on a 200 is a shape the service never
// sends, and enforcement must still fail closed on it.
func TestStubVerifyMismatchFailsEnforcement(t *testing.T) {
	stub := apiclienttest.New(t)
	verdict := apiclienttest.PassingVerdict("")
	verdict.ReportDataMatch = teetypes.Ptr(false)
	stub.SetVerdict(verdict)

	req := apiclient.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&apiclient.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := apiclient.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)
	if !errors.Is(err, apiclient.ErrReportDataMismatch) {
		t.Fatalf("err = %v, want ErrReportDataMismatch", err)
	}
}

// The shape a refused report actually arrives in: HTTP 422 carrying the
// verification_failed envelope, which reaches callers as *apiclient.APIError —
// a different branch from every verdict sentinel.
func TestStubVerifyErrorAnswersTheRefusalShape(t *testing.T) {
	stub := apiclienttest.New(t)
	stub.SetVerifyError(apiclienttest.VerificationFailed("report signature does not verify"))
	client := apiclient.NewClient(stub.URL())

	req := apiclient.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&apiclient.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := client.VerifyEnforced(context.Background(), req)

	var apiErr *apiclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %#v, want *apiclient.APIError", err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	if apiErr.Response.Error != apiclienttest.ErrorCodeVerificationFailed {
		t.Fatalf("error code = %q, want %q", apiErr.Response.Error, apiclienttest.ErrorCodeVerificationFailed)
	}
	if errors.Is(err, apiclient.ErrSignatureInvalid) || errors.Is(err, apiclient.ErrReportDataMismatch) {
		t.Fatalf("a 422 refusal matched a verdict sentinel: %v", err)
	}

	// The refusal is decided after the body is parsed, so the request stays recorded.
	if got := len(stub.VerifyRequests()); got != 1 {
		t.Fatalf("/verify calls = %d, want 1", got)
	}

	// A zero reply restores the verdict.
	stub.SetVerifyError(apiclienttest.ErrorReply{})
	if _, err := client.VerifyEnforced(context.Background(), req); err != nil {
		t.Fatalf("VerifyEnforced after a zero-Status reset: %v", err)
	}
}

// A codeless ErrorReply is the framework rejection: a status with a text/plain
// body the client cannot decode into the error envelope.
func TestStubVerifyErrorPlainTextBody(t *testing.T) {
	stub := apiclienttest.New(t)
	stub.SetVerifyError(apiclienttest.ErrorReply{
		Status:  http.StatusUnprocessableEntity,
		Message: "Failed to deserialize the JSON body into the target type",
	})

	req := apiclient.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&apiclient.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := apiclient.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)

	var unexpected *apiclient.UnexpectedError
	if !errors.As(err, &unexpected) {
		t.Fatalf("err = %#v, want *apiclient.UnexpectedError", err)
	}
	if unexpected.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", unexpected.Status)
	}
	if !strings.Contains(unexpected.Text, "Failed to deserialize") {
		t.Fatalf("body = %q, want the plain-text rejection", unexpected.Text)
	}
}

func TestStubRejectsUnknownPaths(t *testing.T) {
	stub := apiclienttest.New(t)
	resp, err := http.Post(stub.URL()+"/nope", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// The service splits its rejection: 400 for a body that is not valid JSON, 422
// for one that does not fit the request type.
func TestStubRejectsUndecodableBody(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
		wantPrefix string
	}{
		{"not valid JSON", `not json`, http.StatusBadRequest, "Failed to parse the request body as JSON"},
		{"wrong field type", `{"platform": 123}`, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := apiclienttest.New(t)
			resp, err := http.Post(stub.URL()+"/verify", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.wantStatus, body)
			}
			if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
				t.Fatalf("content-type = %q, want the text/plain rejection", got)
			}
			if !strings.HasPrefix(string(body), tc.wantPrefix) {
				t.Fatalf("body = %q, want the rejection prefix %q", body, tc.wantPrefix)
			}
			if got := len(stub.VerifyRequests()); got != 0 {
				t.Fatalf("an undecodable body was recorded as %d request(s)", got)
			}
		})
	}
}

// A closed stub is an unreachable service, which the client reports as a
// transport failure rather than a verdict.
func TestStubCloseMakesTheServiceUnreachable(t *testing.T) {
	stub := apiclienttest.New(t)
	stub.Close()
	_, err := apiclient.NewClient(stub.URL()).Health(context.Background())
	var reqErr *apiclient.RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("err = %#v, want *apiclient.RequestError", err)
	}
}
