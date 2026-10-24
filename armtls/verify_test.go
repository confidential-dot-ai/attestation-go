package armtls

import (
	"bytes"
	"context"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// A real Azure SEV-SNP evidence envelope, the shape the extension embeds for a
// vTPM platform. Its report data is the binding the original attester asked
// for, which no test key can reproduce — see TestVerifyOfflineEnforcesBinding.
//
//go:embed testdata/az-snp.json
var azSnpEnvelope []byte

// azSnpAttestation is that fixture carried in an ARmTLS extension.
func azSnpAttestation(t *testing.T) *Attestation {
	t.Helper()
	att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
		TEEType: wireSNP,
		Report:  azSnpEnvelope,
	}))
	if err != nil {
		t.Fatalf("UnmarshalExtension: %v", err)
	}
	return att
}

// The fixture verifies on its own, so the only thing VerifyOffline adds is the
// key binding — and that is what must make it fail for a key the guest never saw.
func TestVerifyOfflineEnforcesBinding(t *testing.T) {
	if _, err := teeverify.Verify(azSnpEnvelope, teetypes.VerifyParams{}); err != nil {
		t.Fatalf("fixture does not verify without a binding: %v", err)
	}

	key := testKey(t)
	_, err := VerifyOffline(azSnpAttestation(t), &key.PublicKey, nil, teetypes.VerifyParams{}, teeverify.Options{})
	if err == nil {
		t.Fatal("VerifyOffline accepted evidence bound to another key")
	}
	// The rejection names whichever form of the binding the platform carries:
	// report_data in the hardware report, or the vTPM quote nonce on Azure.
	if !strings.Contains(err.Error(), "report_data") && !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err = %v, want a rejection of the key binding", err)
	}
}

// The anchor is derived from the key, so a caller cannot point the check at
// report data of its own choosing. Refusing beats overwriting: the caller asked
// for a different check than this function performs.
func TestVerifyOfflineRefusesConflictingReportData(t *testing.T) {
	key := testKey(t)
	att := azSnpAttestation(t)

	_, err := VerifyOffline(att, &key.PublicKey, nil,
		teetypes.VerifyParams{ExpectedReportData: bytes.Repeat([]byte{0xAA}, sha512.Size384)}, teeverify.Options{})
	if err == nil || !strings.Contains(err.Error(), "does not bind the key") {
		t.Fatalf("err = %v, want a refusal of the caller-set report data", err)
	}

	// The anchor itself is accepted: it names the same check.
	anchor, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	_, err = VerifyOffline(att, &key.PublicKey, nil,
		teetypes.VerifyParams{ExpectedReportData: anchor[:sha512.Size384]}, teeverify.Options{})
	if err != nil && strings.Contains(err.Error(), "does not bind the key") {
		t.Fatalf("the anchor itself was refused: %v", err)
	}
}

// A raw report reaches the SEV-SNP verifier through Envelope, and an unsigned
// one is rejected there rather than passed through.
func TestVerifyOfflineRejectsUnsignedRawReport(t *testing.T) {
	key := testKey(t)
	anchor, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport(anchor[:])}

	if _, err := VerifyOffline(att, &key.PublicKey, nil, teetypes.VerifyParams{}, teeverify.Options{}); err == nil {
		t.Fatal("VerifyOffline accepted an unsigned report")
	}
}

func TestVerifyCertOfflineWithoutExtension(t *testing.T) {
	cert, _ := certWithExtension(t, nil)
	_, err := VerifyCertOffline(cert, testOID, nil, teetypes.VerifyParams{}, teeverify.Options{})
	if !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("err = %v, want ErrNoAttestation", err)
	}
}

// verifySpy is a stub attestation service answering one verdict, with the
// request it received.
type verifySpy struct{ stub *mockapi.Stub }

func newSpy(t *testing.T, verdict mockapi.Verdict) *verifySpy {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetVerdict(verdict)
	return &verifySpy{stub: stub}
}

func (s *verifySpy) service() remote.Client { return remote.NewClient(s.stub.URL()) }

// request is the last /verify request the stub saw; zero when none reached it.
func (s *verifySpy) request() remote.VerifyRequest {
	reqs := s.stub.VerifyRequests()
	if len(reqs) == 0 {
		return remote.VerifyRequest{}
	}
	return reqs[len(reqs)-1]
}

// sentReportData is the report-data pin the recorded request carried.
func (s *verifySpy) sentReportData() []byte {
	req := s.request()
	pins, _ := req.Policies.Pins(req.Platform)
	return pins.ReportData
}

// passingVerdict is what a service returns for evidence it accepted, bound to
// the anchor and reporting measurement as the launch digest.
func passingVerdict(measurement []byte) mockapi.Verdict {
	return mockapi.Verdict{
		SignatureValid:  true,
		ReportDataMatch: teetypes.Ptr(true),
		Claims:          teetypes.Claims{LaunchDigest: hex.EncodeToString(measurement)},
	}
}

// The service must be asked to check the key anchor, unpadded: a native
// platform pads it back to 64 bytes, while a vTPM platform compares it with the
// quote nonce it was given.
func TestVerifyWithServiceSendsKeyAnchor(t *testing.T) {
	key := testKey(t)
	measurement := bytes.Repeat([]byte{0x42}, sha512.Size384)
	spy := newSpy(t, passingVerdict(measurement))
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}

	resp, err := VerifyWithService(context.Background(), spy.service(), att, &key.PublicKey, nil,
		remote.Policy{Measurements: [][]byte{measurement}})
	if err != nil {
		t.Fatalf("VerifyWithService: %v", err)
	}
	if !resp.Result.SignatureValid {
		t.Fatal("response verdict was not returned")
	}

	anchor, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if !bytes.Equal(spy.sentReportData(), anchor[:sha512.Size384]) {
		t.Fatalf("report_data = %x, want the key anchor %x", spy.sentReportData(), anchor[:sha512.Size384])
	}
	if spy.request().Platform != teetypes.PlatformSNP {
		t.Fatalf("platform = %q, want snp", spy.request().Platform)
	}
}

// A nonce changes the anchor, so a report bound to the nonce-free anchor no
// longer satisfies the request.
func TestVerifyWithServiceNonceChangesAnchor(t *testing.T) {
	key := testKey(t)
	spy := newSpy(t, passingVerdict(nil))
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}

	if _, err := VerifyWithService(context.Background(), spy.service(), att, &key.PublicKey, []byte("nonce"), remote.Policy{}); err != nil {
		t.Fatalf("VerifyWithService: %v", err)
	}
	bare, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if bytes.Equal(spy.sentReportData(), bare[:sha512.Size384]) {
		t.Fatal("the nonce did not reach the anchor the service was asked to check")
	}
}

// The verdict and the policy pins both fail closed, and the client sentinels
// reach the caller.
func TestVerifyWithServiceFailsClosed(t *testing.T) {
	key := testKey(t)
	measurement := bytes.Repeat([]byte{0x42}, sha512.Size384)
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}

	cases := []struct {
		name    string
		verdict mockapi.Verdict
		policy  remote.Policy
		wantErr error
	}{
		{
			// The service refuses an unverifiable signature with 422, which
			// reaches the caller as the API error, not a verdict sentinel.
			name:    "invalid signature",
			verdict: mockapi.Verdict{SignatureValid: false},
			wantErr: &remote.APIError{},
		},
		{
			name:    "no report-data verdict",
			verdict: mockapi.Verdict{SignatureValid: true},
			wantErr: remote.ErrReportDataMismatch,
		},
		{
			name:    "measurement outside the pin",
			verdict: passingVerdict(bytes.Repeat([]byte{0x43}, sha512.Size384)),
			policy:  remote.Policy{Measurements: [][]byte{measurement}},
			wantErr: remote.ErrMeasurementNotAllowed,
		},
		{
			name:    "register pinned on a platform without registers",
			verdict: passingVerdict(measurement),
			policy:  remote.Policy{Registers: map[int][]byte{1: measurement}},
			wantErr: remote.ErrRegistersNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := newSpy(t, tc.verdict)
			_, err := VerifyWithService(context.Background(), spy.service(), att, &key.PublicKey, nil, tc.policy)
			if apiErr, ok := tc.wantErr.(*remote.APIError); ok {
				if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
					t.Fatalf("err = %v, want a 422 *remote.APIError", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyWithServiceRefusesConflictingReportData(t *testing.T) {
	key := testKey(t)
	spy := newSpy(t, passingVerdict(nil))
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}

	_, err := VerifyWithService(context.Background(), spy.service(), att, &key.PublicKey, nil,
		remote.Policy{ExpectedReportData: bytes.Repeat([]byte{0xAA}, sha512.Size384)})
	if err == nil || !strings.Contains(err.Error(), "does not bind the key") {
		t.Fatalf("err = %v, want a refusal of the caller-set report data", err)
	}
	if spy.request().Platform != "" {
		t.Fatal("the request reached the service despite the refusal")
	}
}

// The certificate path binds the certificate's own key, which is what makes the
// certificate self-attesting.
func TestVerifyCertWithServiceBindsCertKey(t *testing.T) {
	att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}
	cert, key := certWithExtension(t, att)
	spy := newSpy(t, passingVerdict(nil))

	if _, err := VerifyCertWithService(context.Background(), spy.service(), cert, testOID, nil, remote.Policy{}); err != nil {
		t.Fatalf("VerifyCertWithService: %v", err)
	}
	anchor, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if !bytes.Equal(spy.sentReportData(), anchor[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x, want the certificate key's anchor %x",
			spy.sentReportData(), anchor[:sha512.Size384])
	}
}

func TestVerifyCertWithServiceWithoutExtension(t *testing.T) {
	cert, _ := certWithExtension(t, nil)
	spy := newSpy(t, passingVerdict(nil))
	_, err := VerifyCertWithService(context.Background(), spy.service(), cert, testOID, nil, remote.Policy{})
	if !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("err = %v, want ErrNoAttestation", err)
	}
}
