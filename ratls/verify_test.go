package ratls

import (
	"bytes"
	"context"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/client"
)

// A real Azure SEV-SNP evidence envelope, the shape the extension embeds for a
// vTPM platform. Its report data is the binding the original attester asked
// for, which no test key can reproduce — see TestVerifyOfflineEnforcesBinding.
//
//go:embed testdata/az-snp.json
var azSnpEnvelope []byte

// azSnpAttestation is that fixture carried in an RA-TLS extension.
func azSnpAttestation(t *testing.T) *Attestation {
	t.Helper()
	att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
		TEEType: int(TEETypeSEVSNP),
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
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport(anchor)}

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

// verifySpy is an attestation service that records the request and answers with
// a caller-supplied verdict.
type verifySpy struct {
	request client.VerifyRequest
	result  teetypes.VerificationResult
}

func (s *verifySpy) service(t *testing.T) client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&s.request); err != nil {
			t.Errorf("decode verify request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(client.VerifyResponse{Result: s.result}); err != nil {
			t.Errorf("encode verify response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return client.NewClient(srv.URL)
}

// passingVerdict is what a service returns for evidence it accepted, bound to
// the anchor and reporting measurement as the launch digest.
func passingVerdict(measurement []byte) teetypes.VerificationResult {
	return teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformSNP,
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
	spy := &verifySpy{result: passingVerdict(measurement)}
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	resp, err := VerifyWithService(context.Background(), spy.service(t), att, &key.PublicKey, nil,
		client.Policy{Measurements: [][]byte{measurement}})
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
	if spy.request.Params == nil || !bytes.Equal(spy.request.Params.ExpectedReportData, anchor[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x, want the key anchor %x", spy.request.Params.ExpectedReportData, anchor[:sha512.Size384])
	}
	if spy.request.Platform != teetypes.PlatformSNP {
		t.Fatalf("platform = %q, want snp", spy.request.Platform)
	}
}

// A nonce changes the anchor, so a report bound to the nonce-free anchor no
// longer satisfies the request.
func TestVerifyWithServiceNonceChangesAnchor(t *testing.T) {
	key := testKey(t)
	spy := &verifySpy{result: passingVerdict(nil)}
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	if _, err := VerifyWithService(context.Background(), spy.service(t), att, &key.PublicKey, []byte("nonce"), client.Policy{}); err != nil {
		t.Fatalf("VerifyWithService: %v", err)
	}
	bare, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if bytes.Equal(spy.request.Params.ExpectedReportData, bare[:sha512.Size384]) {
		t.Fatal("the nonce did not reach the anchor the service was asked to check")
	}
}

// The verdict and the policy pins both fail closed, and the client sentinels
// reach the caller.
func TestVerifyWithServiceFailsClosed(t *testing.T) {
	key := testKey(t)
	measurement := bytes.Repeat([]byte{0x42}, sha512.Size384)
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	cases := []struct {
		name    string
		result  teetypes.VerificationResult
		policy  client.Policy
		wantErr error
	}{
		{
			name:    "invalid signature",
			result:  teetypes.VerificationResult{SignatureValid: false},
			wantErr: client.ErrSignatureInvalid,
		},
		{
			name:    "no report-data verdict",
			result:  teetypes.VerificationResult{SignatureValid: true},
			wantErr: client.ErrReportDataMismatch,
		},
		{
			name:    "measurement outside the pin",
			result:  passingVerdict(bytes.Repeat([]byte{0x43}, sha512.Size384)),
			policy:  client.Policy{Measurements: [][]byte{measurement}},
			wantErr: client.ErrMeasurementNotAllowed,
		},
		{
			name:    "register pinned on a platform without registers",
			result:  passingVerdict(measurement),
			policy:  client.Policy{RTMRs: map[int][]byte{1: measurement}},
			wantErr: client.ErrRTMRNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &verifySpy{result: tc.result}
			_, err := VerifyWithService(context.Background(), spy.service(t), att, &key.PublicKey, nil, tc.policy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyWithServiceRefusesConflictingReportData(t *testing.T) {
	key := testKey(t)
	spy := &verifySpy{result: passingVerdict(nil)}
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	_, err := VerifyWithService(context.Background(), spy.service(t), att, &key.PublicKey, nil,
		client.Policy{ExpectedReportData: bytes.Repeat([]byte{0xAA}, sha512.Size384)})
	if err == nil || !strings.Contains(err.Error(), "does not bind the key") {
		t.Fatalf("err = %v, want a refusal of the caller-set report data", err)
	}
	if spy.request.Params != nil {
		t.Fatal("the request reached the service despite the refusal")
	}
}

// The certificate path binds the certificate's own key, which is what makes the
// certificate self-attesting.
func TestVerifyCertWithServiceBindsCertKey(t *testing.T) {
	att := &Attestation{TEEType: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}
	cert, key := certWithExtension(t, att)
	spy := &verifySpy{result: passingVerdict(nil)}

	if _, err := VerifyCertWithService(context.Background(), spy.service(t), cert, testOID, nil, client.Policy{}); err != nil {
		t.Fatalf("VerifyCertWithService: %v", err)
	}
	anchor, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if !bytes.Equal(spy.request.Params.ExpectedReportData, anchor[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x, want the certificate key's anchor %x",
			spy.request.Params.ExpectedReportData, anchor[:sha512.Size384])
	}
}

func TestVerifyCertWithServiceWithoutExtension(t *testing.T) {
	cert, _ := certWithExtension(t, nil)
	spy := &verifySpy{result: passingVerdict(nil)}
	_, err := VerifyCertWithService(context.Background(), spy.service(t), cert, testOID, nil, client.Policy{})
	if !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("err = %v, want ErrNoAttestation", err)
	}
}
