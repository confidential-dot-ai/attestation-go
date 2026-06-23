package attestation

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	test "github.com/google/go-sev-guest/testing"
)

// fakeReport mints a fake-but-cryptographically-consistent SEV-SNP report
// signed by a test-only AMD key chain, returning the bare report, the VCEK DER,
// and verify options that trust the fake roots. Fully offline and deterministic.
//
// The canned test report (test.TestCases / zeroReport) has an all-zero
// measurement and report_data and the DEBUG policy bit set, so happy-path
// verification must allow debug.
func fakeReport(t *testing.T) (report, vcekDER []byte, vopts *sv.Options) {
	t.Helper()
	device, err := test.TcDevice(test.TestCases(), &test.DeviceOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("TcDevice: %v", err)
	}
	if device.SevProduct == nil {
		device.SevProduct = abi.DefaultSevProduct()
	}
	qp := &test.QuoteProvider{Device: device}
	raw, err := qp.GetRawQuote([64]byte{}) // keyed by all-zero report_data
	if err != nil {
		t.Fatalf("GetRawQuote: %v", err)
	}
	if len(raw) < abi.ReportSize {
		t.Fatalf("raw quote too short: %d", len(raw))
	}
	report = append([]byte(nil), raw[:abi.ReportSize]...)
	vcekDER = device.Signer.Vcek.Raw

	roots := map[string][]*trust.AMDRootCerts{}
	for _, line := range []string{"Milan", "Genoa", "Turin"} {
		roots[line] = []*trust.AMDRootCerts{{
			ProductLine: line,
			ProductCerts: &trust.ProductCerts{
				Ask:  device.Signer.Ask,
				Ark:  device.Signer.Ark,
				Asvk: device.Signer.Asvk,
			},
		}}
	}
	vopts = &sv.Options{
		TrustedRoots:        roots,
		Product:             device.Product(),
		DisableCertFetching: true,
	}
	return report, vcekDER, vopts
}

func TestVerifySNPReport_Valid(t *testing.T) {
	report, vcek, vopts := fakeReport(t)

	claims, err := VerifySNPReport(report, vcek, &validate.Options{GuestPolicy: abi.SnpPolicy{Debug: true}}, vopts)
	if err != nil {
		t.Fatalf("VerifySNPReport: %v", err)
	}
	if len(claims.Measurement) != abi.MeasurementSize {
		t.Errorf("measurement = %d bytes, want %d", len(claims.Measurement), abi.MeasurementSize)
	}
	if len(claims.ReportData) != abi.ReportDataSize {
		t.Errorf("report_data = %d bytes, want %d", len(claims.ReportData), abi.ReportDataSize)
	}
}

func TestVerifySNPReport_TamperedReportFailsSignature(t *testing.T) {
	report, vcek, vopts := fakeReport(t)
	// Flip a byte inside the signed body (measurement region) — signature must fail.
	report[0x90] ^= 0xff

	if _, err := VerifySNPReport(report, vcek, &validate.Options{GuestPolicy: abi.SnpPolicy{Debug: true}}, vopts); err == nil {
		t.Fatal("expected signature verification to fail on tampered report, got nil")
	}
}

func TestVerifySNPReport_ReportDataBindingEnforced(t *testing.T) {
	report, vcek, vopts := fakeReport(t)

	// The canned report has all-zero report_data; demanding a non-zero value
	// must be rejected by validate.SnpAttestation.
	wrong := bytes.Repeat([]byte{0x01}, abi.ReportDataSize)
	if _, err := VerifySNPReport(report, vcek, &validate.Options{GuestPolicy: abi.SnpPolicy{Debug: true}, ReportData: wrong}, vopts); err == nil {
		t.Fatal("expected report_data mismatch to fail, got nil")
	}

	// The matching (all-zero) value passes.
	if _, err := VerifySNPReport(report, vcek, &validate.Options{GuestPolicy: abi.SnpPolicy{Debug: true}, ReportData: make([]byte, abi.ReportDataSize)}, vopts); err != nil {
		t.Fatalf("matching report_data should verify: %v", err)
	}
}

func TestVerifySNPReport_DebugRejectedByDefault(t *testing.T) {
	report, vcek, vopts := fakeReport(t)

	// Default guest policy disallows debug; the canned report has debug set.
	if _, err := VerifySNPReport(report, vcek, &validate.Options{}, vopts); err == nil {
		t.Fatal("expected debug-policy report to be rejected when debug not allowed, got nil")
	}
}

func TestVerifySNPReport_GarbageReport(t *testing.T) {
	_, _, vopts := fakeReport(t)
	if _, err := VerifySNPReport([]byte("not a report"), nil, nil, vopts); err == nil {
		t.Fatal("expected parse error on garbage report, got nil")
	}
}
