package mockapi_test

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

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
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
	if len(report) != mockapi.SNPReportSize {
		t.Fatalf("report = %d bytes, want %d", len(report), mockapi.SNPReportSize)
	}
	return report
}

// Both transports must serve the same stub: client picks a Unix-socket
// transport for a unix:// address, and a test adopting the stub should not have
// to know which it got.
func TestStubServesBothTransports(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func(testing.TB) *mockapi.Stub
	}{
		{"http", mockapi.New},
		{"unix", mockapi.NewUnix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := tc.new(t)
			c := remote.NewClient(stub.URL())

			health, err := c.Health(context.Background())
			if err != nil || health.Status != "ok" {
				t.Fatalf("Health = %+v, %v; want status ok", health, err)
			}
			resp, err := c.Attest(context.Background(), remote.AttestRequest{
				ReportData: []byte("nonce"),
				Platform:   remote.PlatformAuto,
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
	stub := mockapi.New(t)
	reportData := []byte("0123456789abcdef0123456789abcdef0123456789abcdef")

	resp, err := remote.NewClient(stub.URL()).Attest(context.Background(), remote.AttestRequest{
		ReportData: reportData,
		Platform:   remote.PlatformAuto,
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

// Report data wider than the hardware field is truncated, not an error: the
// stub answers what the hardware would. The evidence wraps exactly the report
// [mockapi.FakeSNPReport] builds, so a test that needs the bytes alone gets the
// same fixture the server serves.
func TestFakeSNPEvidenceClampsReportDataToTheField(t *testing.T) {
	oversize := bytes.Repeat([]byte{0xAB}, 100)
	report := snpReport(t, mockapi.FakeSNPEvidence(oversize))
	if got := report[0x50:0x90]; !bytes.Equal(got, oversize[:64]) {
		t.Fatalf("REPORTDATA = %x, want the leading 64 bytes %x", got, oversize[:64])
	}
	if report[0] != 0x02 {
		t.Fatalf("report version = %d, want 2", report[0])
	}
	if !bytes.Equal(report, mockapi.FakeSNPReport(oversize)) {
		t.Error("the evidence does not wrap FakeSNPReport's bytes")
	}
}

func TestStubAttestPlatformResolution(t *testing.T) {
	attest := func(t *testing.T, s *mockapi.Stub, platform teetypes.PlatformType) teetypes.PlatformType {
		t.Helper()
		resp, err := remote.NewClient(s.URL()).Attest(context.Background(), remote.AttestRequest{
			ReportData: []byte("x"),
			Platform:   platform,
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		return resp.Platform
	}

	t.Run("auto resolves to the detected platform", func(t *testing.T) {
		stub := mockapi.New(t)
		if got := attest(t, stub, remote.PlatformAuto); got != teetypes.PlatformSNP {
			t.Fatalf("platform = %q, want snp", got)
		}
		stub.SetPlatform(teetypes.PlatformTDX)
		if got := attest(t, stub, remote.PlatformAuto); got != teetypes.PlatformTDX {
			t.Fatalf("platform = %q after SetPlatform(tdx), want tdx", got)
		}
	})
	t.Run("explicit platform is honored", func(t *testing.T) {
		stub := mockapi.New(t)
		if got := attest(t, stub, teetypes.PlatformGcpSNP); got != teetypes.PlatformGcpSNP {
			t.Fatalf("platform = %q, want gcp-snp", got)
		}
	})
}

func TestStubVerifyRecordsAndAnswersVerdict(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict("deadbeef"))

	expected := []byte("expected-report-data")
	req := remote.NewVerifyRequest(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformGcpSNP,
		Evidence: json.RawMessage(`{"quote":"x"}`),
	}, &remote.VerifyParams{ExpectedReportData: expected}, false)

	resp, err := remote.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)
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
	stub := mockapi.New(t)
	verdict := mockapi.PassingVerdict("")
	verdict.ReportDataMatch = teetypes.Ptr(false)
	stub.SetVerdict(verdict)

	req := remote.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&remote.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := remote.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)
	if !errors.Is(err, remote.ErrReportDataMismatch) {
		t.Fatalf("err = %v, want ErrReportDataMismatch", err)
	}
}

// The shape a refused report actually arrives in: HTTP 422 carrying the
// verification_failed envelope, which reaches callers as *remote.APIError —
// a different branch from every verdict sentinel.
func TestStubVerifyErrorAnswersTheRefusalShape(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerifyError(mockapi.VerificationFailed("report signature does not verify"))
	c := remote.NewClient(stub.URL())

	req := remote.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&remote.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := c.VerifyEnforced(context.Background(), req)

	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %#v, want *remote.APIError", err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	if apiErr.Response.Error != mockapi.ErrorCodeVerificationFailed {
		t.Fatalf("error code = %q, want %q", apiErr.Response.Error, mockapi.ErrorCodeVerificationFailed)
	}
	if errors.Is(err, remote.ErrSignatureInvalid) || errors.Is(err, remote.ErrReportDataMismatch) {
		t.Fatalf("a 422 refusal matched a verdict sentinel: %v", err)
	}

	// The refusal is decided after the body is parsed, so the request stays recorded.
	if got := len(stub.VerifyRequests()); got != 1 {
		t.Fatalf("/verify calls = %d, want 1", got)
	}

	// A zero reply restores the verdict.
	stub.SetVerifyError(mockapi.ErrorReply{})
	if _, err := c.VerifyEnforced(context.Background(), req); err != nil {
		t.Fatalf("VerifyEnforced after a zero-Status reset: %v", err)
	}
}

// A codeless ErrorReply is the framework rejection: a status with a text/plain
// body the client cannot decode into the error envelope.
func TestStubVerifyErrorPlainTextBody(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerifyError(mockapi.ErrorReply{
		Status:  http.StatusUnprocessableEntity,
		Message: "Failed to deserialize the JSON body into the target type",
	})

	req := remote.NewVerifyRequest(
		teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: json.RawMessage(`{}`)},
		&remote.VerifyParams{ExpectedReportData: []byte("expected-report-data")}, false)
	_, err := remote.NewClient(stub.URL()).VerifyEnforced(context.Background(), req)

	var unexpected *remote.UnexpectedError
	if !errors.As(err, &unexpected) {
		t.Fatalf("err = %#v, want *remote.UnexpectedError", err)
	}
	if unexpected.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", unexpected.Status)
	}
	if !strings.Contains(unexpected.Text, "Failed to deserialize") {
		t.Fatalf("body = %q, want the plain-text rejection", unexpected.Text)
	}
}

func TestStubRejectsUnknownPaths(t *testing.T) {
	stub := mockapi.New(t)
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
			stub := mockapi.New(t)
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
	stub := mockapi.New(t)
	stub.Close()
	_, err := remote.NewClient(stub.URL()).Health(context.Background())
	var reqErr *remote.RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("err = %#v, want *remote.RequestError", err)
	}
}
