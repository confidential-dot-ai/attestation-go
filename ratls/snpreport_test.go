package ratls

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestNormalizeSEVSNPReport(t *testing.T) {
	report := fakeSNPReport([64]byte{1, 2, 3})

	t.Run("a bare report passes through", func(t *testing.T) {
		got, err := NormalizeSEVSNPReport(report)
		if err != nil {
			t.Fatalf("NormalizeSEVSNPReport: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("report mismatch")
		}
	})

	t.Run("HCL envelope with padding is unwrapped", func(t *testing.T) {
		got, err := NormalizeSEVSNPReport(fakeHCLEnvelope(report, 128))
		if err != nil {
			t.Fatalf("NormalizeSEVSNPReport: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("report mismatch")
		}
	})

	t.Run("HCL envelope with no padding is unwrapped", func(t *testing.T) {
		got, err := NormalizeSEVSNPReport(fakeHCLEnvelope(report, 0))
		if err != nil {
			t.Fatalf("NormalizeSEVSNPReport: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("report mismatch")
		}
	})

	// A header-only buffer is recognized as HCL and reported as truncated,
	// rather than as a bare report of the wrong size.
	t.Run("truncated HCL envelope", func(t *testing.T) {
		raw := make([]byte, 32)
		copy(raw[:4], "HCLA")
		_, err := NormalizeSEVSNPReport(raw)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
		if !strings.Contains(err.Error(), "HCL report") {
			t.Fatalf("err = %v, want it to name the HCL truncation", err)
		}
	})

	// The HCL envelope also carries TDX reports; reading one as SEV-SNP would
	// verify one platform's evidence under another's rules.
	t.Run("HCL envelope carrying a TDX report", func(t *testing.T) {
		env := fakeHCLEnvelope(report, 0)
		binary.LittleEndian.PutUint32(env[32+SNPReportSize+8:], 4) // report_type: TDX
		_, err := NormalizeSEVSNPReport(env)
		if !errors.Is(err, ErrInvalidReport) || !strings.Contains(err.Error(), "report type 4") {
			t.Fatalf("err = %v, want a report-type rejection", err)
		}
	})

	t.Run("neither shape", func(t *testing.T) {
		if _, err := NormalizeSEVSNPReport(make([]byte, SNPReportSize+1)); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
	})
}

func TestExtractSNPReport(t *testing.T) {
	report := fakeSNPReport([64]byte{0x99})

	mkEvidence := func(t *testing.T, platform teetypes.PlatformType, fields map[string]any) teetypes.AttestationEvidence {
		t.Helper()
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("marshal evidence: %v", err)
		}
		return teetypes.AttestationEvidence{Platform: platform, Evidence: raw}
	}

	// Bare-metal writes standard base64 under attestation_report; the Azure
	// vTPM writes URL-safe base64 without padding under hcl_report. Swapping
	// the alphabets corrupts the report silently, so each field keeps its own.
	t.Run("attestation_report, standard base64", func(t *testing.T) {
		env := mkEvidence(t, teetypes.PlatformSNP, map[string]any{
			"attestation_report": base64.StdEncoding.EncodeToString(report),
		})
		got, err := ExtractSNPReport(env)
		if err != nil {
			t.Fatalf("ExtractSNPReport: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("report mismatch")
		}
	})

	t.Run("hcl_report, URL-safe base64, unwrapped", func(t *testing.T) {
		env := mkEvidence(t, teetypes.PlatformAzSNP, map[string]any{
			"hcl_report": base64.RawURLEncoding.EncodeToString(fakeHCLEnvelope(report, 128)),
		})
		got, err := ExtractSNPReport(env)
		if err != nil {
			t.Fatalf("ExtractSNPReport: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("report mismatch after the HCL unwrap")
		}
	})

	t.Run("hcl_report shorter than header plus report", func(t *testing.T) {
		short := make([]byte, 32+SNPReportSize-1)
		copy(short[:4], "HCLA")
		env := mkEvidence(t, teetypes.PlatformAzSNP, map[string]any{
			"hcl_report": base64.RawURLEncoding.EncodeToString(short),
		})
		if _, err := ExtractSNPReport(env); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
	})

	t.Run("hcl_report without the HCLA signature", func(t *testing.T) {
		buf := make([]byte, 32+SNPReportSize+20+16)
		copy(buf[:4], "XXXX")
		env := mkEvidence(t, teetypes.PlatformAzSNP, map[string]any{
			"hcl_report": base64.RawURLEncoding.EncodeToString(buf),
		})
		if _, err := ExtractSNPReport(env); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
	})

	t.Run("neither field", func(t *testing.T) {
		env := mkEvidence(t, teetypes.PlatformSNP, map[string]any{"something_else": "value"})
		if _, err := ExtractSNPReport(env); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
	})

	t.Run("unparseable evidence", func(t *testing.T) {
		env := teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: []byte("not-json")}
		if _, err := ExtractSNPReport(env); err == nil {
			t.Fatal("ExtractSNPReport accepted unparseable evidence")
		}
	})
}
