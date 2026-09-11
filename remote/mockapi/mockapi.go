package mockapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// ErrorCodeVerificationFailed is the service's error code for evidence that did
// not verify, carried in [remote.ErrorResponse].Error.
const ErrorCodeVerificationFailed = "verification_failed"

// SNPReportSize is the byte length of an AMD SEV-SNP attestation report, the
// size of the report [FakeSNPReport] builds.
const SNPReportSize = snp.ReportSize

// Verdict is what /verify answers for every request. The fields map onto
// [teetypes.VerificationResult]; the match fields are pointers so the
// no-check wire shape — the service's explicit null — stays expressible.
type Verdict struct {
	SignatureValid  bool
	ReportDataMatch *bool
	InitDataMatch   *bool
	Claims          teetypes.Claims
}

// PassingVerdict is the verdict for evidence that verified: signature valid,
// both bindings matched, and launchDigest reported as the claims' launch
// digest. The match fields are read only when the request pinned the
// corresponding value, so an unpinned true is inert.
func PassingVerdict(launchDigest string) Verdict {
	return Verdict{
		SignatureValid:  true,
		ReportDataMatch: teetypes.Ptr(true),
		InitDataMatch:   teetypes.Ptr(true),
		Claims:          teetypes.Claims{LaunchDigest: launchDigest},
	}
}

// ErrorReply is an error response from the service. A non-empty Code sends the
// [remote.ErrorResponse] envelope, which callers see as an
// [remote.APIError]; an empty Code sends Message as text/plain — the
// framework's own rejection shape — which callers see as an
// [remote.UnexpectedError].
type ErrorReply struct {
	Status  int
	Code    string
	Message string
}

// VerificationFailed is what the service answers /verify with for evidence that
// does not verify: HTTP 422 carrying [ErrorCodeVerificationFailed].
func VerificationFailed(message string) ErrorReply {
	return ErrorReply{
		Status:  http.StatusUnprocessableEntity,
		Code:    ErrorCodeVerificationFailed,
		Message: message,
	}
}

// Stub is a running stub attestation-api. The default verdict is
// PassingVerdict("") and the detected platform is snp; change them with
// [Stub.SetVerdict] and [Stub.SetPlatform]. Every method is safe to call while
// requests are in flight.
type Stub struct {
	server *httptest.Server
	url    string

	mu        sync.Mutex
	verdict   Verdict
	verifyErr ErrorReply
	platform  teetypes.PlatformType
	attest    []remote.AttestRequest
	verify    []remote.VerifyRequest
}

// New starts a stub serving plain HTTP, closed at test cleanup.
func New(t testing.TB) *Stub {
	t.Helper()
	s := newStub()
	s.server = httptest.NewServer(s.handler())
	s.url = s.server.URL
	t.Cleanup(s.Close)
	return s
}

// NewUnix starts a stub serving on a Unix socket in t.TempDir(), closed at test
// cleanup. Use it to exercise the transport [remote.NewClient] selects for a
// "unix://" address, which re-validates the socket's owner and mode on every
// request; [New] is otherwise equivalent and cheaper.
func NewUnix(t testing.TB) *Stub {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "attest.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	s := newStub()
	s.server = httptest.NewUnstartedServer(s.handler())
	// Swap in the socket listener before Start, and close the TCP listener
	// httptest opened, so nothing is left listening on a port.
	_ = s.server.Listener.Close()
	s.server.Listener = ln
	s.server.Start()
	s.url = "unix://" + socket
	t.Cleanup(s.Close)
	return s
}

func newStub() *Stub {
	return &Stub{verdict: PassingVerdict(""), platform: teetypes.PlatformSNP}
}

func (s *Stub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /attest", s.handleAttest)
	mux.HandleFunc("POST /verify", s.handleVerify)
	return mux
}

// URL is the stub's address, in the form [remote.NewClient] takes: an
// http:// address from [New], a unix:// one from [NewUnix].
func (s *Stub) URL() string { return s.url }

// Close stops the stub. Tests need not call it — cleanup does — except to make
// the service unreachable mid-test. Closing twice is harmless.
func (s *Stub) Close() { s.server.Close() }

// SetVerdict replaces the verdict /verify answers.
func (s *Stub) SetVerdict(v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdict = v
}

// SetVerifyError makes /verify answer reply instead of a verdict, still
// recording the request. A zero Status restores the verdict.
func (s *Stub) SetVerifyError(reply ErrorReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyErr = reply
}

// SetPlatform sets the platform the stub reports detecting: what /attest
// resolves an [remote.PlatformAuto] or empty request platform to, and what
// /health reports. The evidence bytes stay an SNP report whatever the tag.
func (s *Stub) SetPlatform(p teetypes.PlatformType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.platform = p
}

// AttestRequests returns the /attest requests received so far, in order.
func (s *Stub) AttestRequests() []remote.AttestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]remote.AttestRequest(nil), s.attest...)
}

// VerifyRequests returns the /verify requests received so far, in order. An
// undecodable body is refused before it is recorded, so every entry is a
// request the service accepted.
func (s *Stub) VerifyRequests() []remote.VerifyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]remote.VerifyRequest(nil), s.verify...)
}

func (s *Stub) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	platform := s.platform
	s.mu.Unlock()
	writeJSON(w, remote.HealthResponse{Status: "ok", Platform: &platform})
}

func (s *Stub) handleAttest(w http.ResponseWriter, r *http.Request) {
	var req remote.AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, undecodableBody(err))
		return
	}
	s.mu.Lock()
	s.attest = append(s.attest, req)
	platform := s.platform
	s.mu.Unlock()

	if req.Platform != "" && req.Platform != remote.PlatformAuto {
		platform = req.Platform
	}
	writeJSON(w, remote.AttestResponse{
		Platform: platform,
		Evidence: FakeSNPEvidence(req.ReportData),
	})
}

// FakeSNPReport builds the report every fake in this module is made of: a
// minimal SEV-SNP report — version 2, SMT-allowed policy, reportData copied
// into the 64-byte REPORTDATA field and truncated if longer.
//
// It is unsigned and carries no VCEK, so it exercises parsing, extraction and
// report-data binding; verification must fail on it. One builder rather than a
// copy per test package keeps every fixture the same shape.
func FakeSNPReport(reportData []byte) []byte {
	report := make([]byte, SNPReportSize)
	report[0] = 0x02    // report version
	report[0x0A] = 0x03 // guest policy: SMT allowed
	copy(report[snp.ReportDataOffset:snp.ReportDataOffset+64], reportData)
	return report
}

// FakeSNPEvidence wraps [FakeSNPReport] as {"attestation_report": <base64>},
// the shape evidence extraction reads, and is what /attest answers.
func FakeSNPEvidence(reportData []byte) json.RawMessage {
	evidence, err := json.Marshal(snp.SnpEvidence{
		AttestationReport: base64.StdEncoding.EncodeToString(FakeSNPReport(reportData)),
	})
	if err != nil { // a struct of strings always marshals
		panic(err)
	}
	return evidence
}

func (s *Stub) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req remote.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, undecodableBody(err))
		return
	}
	s.mu.Lock()
	s.verify = append(s.verify, req)
	verdict, verifyErr := s.verdict, s.verifyErr
	s.mu.Unlock()

	if verifyErr.Status != 0 {
		writeError(w, verifyErr)
		return
	}
	writeJSON(w, remote.VerifyResponse{
		Result: teetypes.VerificationResult{
			Platform:        req.Platform,
			SignatureValid:  verdict.SignatureValid,
			ReportDataMatch: verdict.ReportDataMatch,
			InitDataMatch:   verdict.InitDataMatch,
			Claims:          verdict.Claims,
		},
	})
}

// undecodableBody mirrors the service's JSON rejection: 400 for a body that is
// not valid JSON, 422 for one that does not fit the handler's type; both
// text/plain, so a caller sees an [remote.UnexpectedError] rather than the
// error envelope.
func undecodableBody(err error) ErrorReply {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return ErrorReply{
			Status:  http.StatusUnprocessableEntity,
			Message: "Failed to deserialize the JSON body into the target type: " + err.Error(),
		}
	}
	return ErrorReply{
		Status:  http.StatusBadRequest,
		Message: "Failed to parse the request body as JSON: " + err.Error(),
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, reply ErrorReply) {
	if reply.Code == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(reply.Status)
		_, _ = io.WriteString(w, reply.Message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.Status)
	_ = json.NewEncoder(w).Encode(remote.ErrorResponse{Error: reply.Code, Message: reply.Message})
}
