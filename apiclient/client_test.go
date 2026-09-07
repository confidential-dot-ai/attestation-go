package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestAttestRoundTrip(t *testing.T) {
	var got AttestRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Errorf("path = %q, want /attest", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(AttestResponse{
			Platform: teetypes.PlatformTDX,
			Evidence: json.RawMessage(`{"quote":"AAAA"}`),
		})
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL).Attest(context.Background(), AttestRequest{
		ReportData: []byte("nonce"),
		Platform:   PlatformAuto,
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if string(got.ReportData) != "nonce" {
		t.Errorf("report_data = %q, want %q", got.ReportData, "nonce")
	}
	if got.Platform != PlatformAuto {
		t.Errorf("platform = %q, want %q", got.Platform, PlatformAuto)
	}
	// Envelope is what every verification entry point takes.
	env := resp.Envelope()
	if env.Platform != teetypes.PlatformTDX || string(env.Evidence) != `{"quote":"AAAA"}` {
		t.Errorf("Envelope() = %+v, want the response's platform and evidence", env)
	}
}

func TestErrorResponses(t *testing.T) {
	structured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "bad_request", Message: "no platform"})
	}))
	defer structured.Close()

	_, err := NewClient(structured.URL).Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("Health() = %v, want *APIError with status 400", err)
	}

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not json", http.StatusBadGateway)
	}))
	defer plain.Close()

	_, err = NewClient(plain.URL).Health(context.Background())
	var unexpected *UnexpectedError
	if !errors.As(err, &unexpected) || unexpected.Status != http.StatusBadGateway {
		t.Fatalf("Health() = %v, want *UnexpectedError with status 502", err)
	}

	_, err = NewClient("http://127.0.0.1:1").Health(context.Background())
	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("Health() against a dead address = %v, want *RequestError", err)
	}
}

func TestUnixSocketTransport(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "attest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	resp, err := NewClient("unix://" + sock).Health(context.Background())
	if err != nil {
		t.Fatalf("Health over unix socket: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
}

// The socket is re-checked on every dial, so a socket made world-writable
// after the client was built still fails closed.
func TestSocketValidation(t *testing.T) {
	dir := t.TempDir()

	if err := validateSocket("relative.sock"); err == nil {
		t.Error("relative path accepted, want an error")
	}
	if err := validateSocket(filepath.Join(dir, "absent")); err == nil {
		t.Error("missing socket accepted, want an error")
	}

	notSocket := filepath.Join(dir, "regular")
	if err := os.WriteFile(notSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSocket(notSocket); err == nil {
		t.Error("regular file accepted, want an error")
	}

	sock := filepath.Join(dir, "attest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if err := validateSocket(sock); err != nil {
		t.Fatalf("validateSocket on a good socket = %v, want nil", err)
	}
	if err := os.Chmod(sock, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateSocket(sock); err == nil {
		t.Error("world-writable socket accepted, want an error")
	}
}
