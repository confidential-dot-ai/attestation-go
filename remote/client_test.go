package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestValidateSocket(t *testing.T) {
	dir := t.TempDir()
	notSocket := filepath.Join(dir, "regular")
	if err := os.WriteFile(notSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "attest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open.sock")
	openLn, err := net.Listen("unix", open)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = openLn.Close() }()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"good socket", sock, false},
		{"relative path", "relative.sock", true},
		{"absent", filepath.Join(dir, "absent"), true},
		{"regular file", notSocket, true},
		{"symlink to a socket", link, true},
		{"world-writable", open, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSocket(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSocket(%q) = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
		})
	}
}

// The socket is re-checked on every request, not only on the first dial: a
// socket made world-writable after the client has already used it fails
// closed on the next call.
func TestSocketRecheckedOnEveryRequest(t *testing.T) {
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

	c := NewClient("unix://" + sock)
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("first Health: %v", err)
	}
	if err := os.Chmod(sock, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("Health over a socket made world-writable after first use = nil, want an error")
	}
}

// A caller-supplied client keeps its own timeout on a unix:// address and
// gets the socket transport it cannot build itself.
func TestNewClientWithHTTPKeepsCallerTimeoutOnUnix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "attest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	// Accept and never answer.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		}
	}()

	c := NewClientWithHTTP("unix://"+sock, &http.Client{Timeout: 50 * time.Millisecond})
	if c.httpClient.Timeout != 50*time.Millisecond {
		t.Fatalf("Timeout = %v, want the caller's 50ms", c.httpClient.Timeout)
	}
	start := time.Now()
	_, err = c.Health(context.Background())
	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("Health against a silent peer = %v, want *RequestError", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Health took %v; the caller's timeout was not applied", elapsed)
	}
}

func TestAttestRequestOmitsEmptyPlatform(t *testing.T) {
	body, err := json.Marshal(AttestRequest{ReportData: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "platform") {
		t.Errorf("empty platform is sent, which the service refuses: %s", body)
	}
}
