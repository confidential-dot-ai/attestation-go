// Package apiclient is the Go client for attestation-api, the HTTP service that
// produces and verifies TEE evidence on a confidential host (the attestation-rs
// binary).
//
// The service exposes three endpoints, wrapped here as [Client.Attest],
// [Client.Verify] and [Client.Health]. Most callers want neither raw endpoint
// but [Client.VerifyEvidence], which posts to /verify and then fails closed on
// the verdict and on the caller's reference values — the endpoint returns a
// report, not a decision, and a caller that reads the report without gating on
// it accepts any evidence the service could parse.
//
// # Choosing an address
//
// The /verify verdict is not signed, so the client trusts whatever answers.
// Prefer a Unix-domain socket inside the trust boundary:
//
//	c := apiclient.NewClient("unix:///run/attestation/attest.sock")
//
// A routable HTTP address lets anything that can influence name resolution or
// routing answer in the service's place. The socket's owner and mode are
// re-checked on every dial, so a socket swapped or made world-writable after
// startup fails closed rather than being trusted for the process's lifetime.
//
// # Platform neutrality
//
// Nothing here asks the caller which TEE it is on. Platform tags travel as
// teetypes.PlatformType and are compared by family, so the cloud overlays
// (az-*, gcp-*) route like their bare-metal counterparts, and an unknown tag
// fails closed instead of falling through to another platform's rules.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxErrorBodyBytes caps how much of a non-2xx body is read into an error. The
// body can come from an unhealthy or untrusted endpoint and flows into error
// strings and logs.
const maxErrorBodyBytes = 8 << 10

// requestTimeout bounds one call; the peer decides whether it ever answers.
const requestTimeout = 60 * time.Second

// socketDialTimeout bounds the connect to a local socket, which is either
// immediate or not happening.
const socketDialTimeout = 5 * time.Second

// Client calls one attestation-api instance. The zero value is not usable;
// build one with [NewClient] or [NewClientWithHTTP].
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient returns a client for baseURL.
//
// A "unix:///path/to/attest.sock" address routes every request over that local
// socket instead of a routable HTTP address; see the package documentation for
// why that is the safer default.
func NewClient(baseURL string) Client {
	if socket, ok := strings.CutPrefix(baseURL, "unix://"); ok {
		return Client{
			baseURL:    "http://unix",
			httpClient: &http.Client{Transport: socketTransport(socket), Timeout: requestTimeout},
		}
	}
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: requestTimeout},
	}
}

// NewClientWithHTTP is [NewClient] with a caller-supplied HTTP client, for
// custom timeouts, instrumentation or a test transport.
//
// A "unix://" address keeps the supplied client — its Timeout still bounds each
// request — and swaps only the transport: a TCP transport cannot reach a Unix
// socket, so the caller's would silently fail.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	if socket, ok := strings.CutPrefix(baseURL, "unix://"); ok {
		c := *httpClient
		c.Transport = socketTransport(socket)
		return Client{baseURL: "http://unix", httpClient: &c}
	}
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// socketTransport dials socketPath for every request, validating it first so
// the caller never talks to a socket an untrusted actor replaced.
func socketTransport(socketPath string) *http.Transport {
	dialer := net.Dialer{Timeout: socketDialTimeout}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := validateSocket(socketPath); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
}

// validateSocket asserts socketPath is a real socket (not a symlink to one),
// not world-writable, and owned by root or by this process.
func validateSocket(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("attestation-api socket %q must be an absolute path", socketPath)
	}
	fi, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("stat attestation-api socket %q: %w", socketPath, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("attestation-api socket %q is not a socket (mode %s)", socketPath, fi.Mode())
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("attestation-api socket %q is world-writable (mode %#o)", socketPath, fi.Mode().Perm())
	}
	return checkSocketOwner(fi, socketPath)
}

// Health calls GET /health.
func (c Client) Health(ctx context.Context) (HealthResponse, error) {
	var out HealthResponse
	if err := c.getJSON(ctx, "/health", &out); err != nil {
		return HealthResponse{}, err
	}
	return out, nil
}

// Attest calls POST /attest, returning evidence that binds req.ReportData.
func (c Client) Attest(ctx context.Context, req AttestRequest) (AttestResponse, error) {
	var out AttestResponse
	if err := c.postJSON(ctx, "/attest", req, &out); err != nil {
		return AttestResponse{}, err
	}
	return out, nil
}

// Verify calls POST /verify and returns the service's report verbatim.
//
// The report is not a decision: it says what the evidence contained, including
// when the signature did not check out. Use [Client.VerifyEnforced] or
// [Client.VerifyEvidence] unless you are enforcing the verdict yourself.
func (c Client) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	var out VerifyResponse
	if err := c.postJSON(ctx, "/verify", req, &out); err != nil {
		return VerifyResponse{}, err
	}
	return out, nil
}

func (c Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.doAndDecode(req, out)
}

func (c Client) postJSON(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doAndDecode(req, out)
}

func (c Client) doAndDecode(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &RequestError{Err: err}
	}
	// The body is drained by the decoder below or capped on the error path;
	// the close error tells the caller nothing they can act on.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return &APIError{Status: resp.StatusCode, Response: errResp}
		}
		return &UnexpectedError{Status: resp.StatusCode, Text: string(body)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// RequestError is a transport-level failure: the request never got an answer.
type RequestError struct {
	Err error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("attestation-api request failed: %s", e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

// APIError is a structured non-2xx response from the service.
type APIError struct {
	Status   int
	Response ErrorResponse
}

func (e *APIError) Error() string {
	return fmt.Sprintf("attestation-api error (%d): %s", e.Status, e.Response.Message)
}

// UnexpectedError is a non-2xx response whose body was not the service's
// error shape, so it likely came from something other than the service.
type UnexpectedError struct {
	Status int
	Text   string
}

func (e *UnexpectedError) Error() string {
	return fmt.Sprintf("attestation-api unexpected response (%d): %s", e.Status, e.Text)
}
