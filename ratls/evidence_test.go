package ratls

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// snpEvidence is what an attestation service returns for a guest that attests
// through the hardware report alone.
func snpEvidence(t *testing.T, platform teetypes.PlatformType, report []byte) teetypes.AttestationEvidence {
	t.Helper()
	inner, err := json.Marshal(map[string]string{"attestation_report": base64.StdEncoding.EncodeToString(report)})
	if err != nil {
		t.Fatalf("marshal snp evidence: %v", err)
	}
	return teetypes.AttestationEvidence{Platform: platform, Evidence: inner}
}

// The native SEV-SNP platforms embed the raw report. gcp-snp is the case a
// raw tag comparison against "snp" gets wrong: its evidence is byte-identical
// to bare-metal's, so it must take the same path.
func TestEvidenceForExtensionNativeSNPEmbedsRawReport(t *testing.T) {
	report := mockapi.FakeSNPReport([]byte{0x11})
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformGcpSNP} {
		t.Run(string(platform), func(t *testing.T) {
			got, err := EvidenceForExtension(snpEvidence(t, platform, report))
			if err != nil {
				t.Fatalf("EvidenceForExtension: %v", err)
			}
			if !bytes.Equal(got, report) {
				t.Fatalf("payload is %d bytes, want the %d-byte raw report", len(got), len(report))
			}
		})
	}
}

// Azure SEV-SNP proves its binding through a vTPM quote the hardware report
// does not carry, so the envelope must survive intact.
func TestEvidenceForExtensionAzureSNPKeepsEnvelope(t *testing.T) {
	inner := json.RawMessage(`{"hcl_report":"AAAA","tpm_quote":{"message":"cafe","signature":"beef"}}`)
	got, err := EvidenceForExtension(teetypes.AttestationEvidence{Platform: teetypes.PlatformAzSNP, Evidence: inner})
	if err != nil {
		t.Fatalf("EvidenceForExtension: %v", err)
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(got, &env); err != nil {
		t.Fatalf("payload is not an envelope: %v", err)
	}
	if env.Platform != teetypes.PlatformAzSNP {
		t.Errorf("platform = %q, want az-snp", env.Platform)
	}
	if !bytes.Equal(env.Evidence, inner) {
		t.Errorf("evidence = %s, want it preserved", env.Evidence)
	}
}

// A native TDX event log is ~85 KB and would push the certificate past a TLS
// handshake record. gcp-tdx carries the same shape, so it is stripped too.
func TestEvidenceForExtensionNativeTDXStripsEventlog(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformGcpTDX} {
		t.Run(string(platform), func(t *testing.T) {
			got, err := EvidenceForExtension(teetypes.AttestationEvidence{
				Platform: platform,
				Evidence: json.RawMessage(`{"quote":"abc","cc_eventlog":"AAAA"}`),
			})
			if err != nil {
				t.Fatalf("EvidenceForExtension: %v", err)
			}
			var env struct {
				Platform teetypes.PlatformType      `json:"platform"`
				Evidence map[string]json.RawMessage `json:"evidence"`
			}
			if err := json.Unmarshal(got, &env); err != nil {
				t.Fatalf("payload is not an envelope: %v", err)
			}
			if env.Platform != platform {
				t.Errorf("platform = %q, want %q", env.Platform, platform)
			}
			if string(env.Evidence["quote"]) != `"abc"` {
				t.Errorf("quote = %s, want \"abc\"", env.Evidence["quote"])
			}
			if len(env.Evidence) != 1 {
				t.Errorf("evidence keys = %v, want only quote", env.Evidence)
			}
		})
	}
}

// az-tdx evidence is a different object: rewriting it to {quote} would drop the
// vTPM quote its binding rests on.
func TestEvidenceForExtensionAzureTDXKeepsEnvelope(t *testing.T) {
	inner := json.RawMessage(`{"td_quote":"AAAA","tpm_quote":{"message":"cafe","signature":"beef"}}`)
	got, err := EvidenceForExtension(teetypes.AttestationEvidence{Platform: teetypes.PlatformAzTDX, Evidence: inner})
	if err != nil {
		t.Fatalf("EvidenceForExtension: %v", err)
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(got, &env); err != nil {
		t.Fatalf("payload is not an envelope: %v", err)
	}
	if !bytes.Equal(env.Evidence, inner) {
		t.Fatalf("evidence = %s, want it preserved", env.Evidence)
	}
}

func TestEvidenceForExtensionRejects(t *testing.T) {
	t.Run("unknown platform", func(t *testing.T) {
		_, err := EvidenceForExtension(teetypes.AttestationEvidence{Platform: teetypes.PlatformDstack, Evidence: json.RawMessage(`{}`)})
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Fatalf("err = %v, want ErrUnsupportedTEE", err)
		}
	})

	t.Run("unparseable tdx evidence", func(t *testing.T) {
		_, err := EvidenceForExtension(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`not-json`)})
		if err == nil {
			t.Fatal("EvidenceForExtension accepted unparseable tdx evidence")
		}
	})
}

// NewAttestation must produce an attestation that reads back the way
// UnmarshalExtension would read it off the wire.
func TestNewAttestation(t *testing.T) {
	t.Run("native SNP", func(t *testing.T) {
		report := mockapi.FakeSNPReport([]byte{0x22})
		att, err := NewAttestation(snpEvidence(t, teetypes.PlatformSNP, report))
		if err != nil {
			t.Fatalf("NewAttestation: %v", err)
		}
		if att.Family != teetypes.FamilySNP {
			t.Fatalf("Family = %q, want %q", att.Family, teetypes.FamilySNP)
		}
		if _, ok := att.EmbeddedEvidence(); ok {
			t.Fatal("native SNP evidence should embed the raw report, not an envelope")
		}
		if !bytes.Equal(att.Report, report) {
			t.Fatal("report mismatch")
		}
	})

	t.Run("envelope platform is parsed back", func(t *testing.T) {
		att, err := NewAttestation(teetypes.AttestationEvidence{
			Platform: teetypes.PlatformTDX,
			Evidence: json.RawMessage(`{"quote":"abc","cc_eventlog":"AAAA"}`),
		})
		if err != nil {
			t.Fatalf("NewAttestation: %v", err)
		}
		if att.Family != teetypes.FamilyTDX {
			t.Fatalf("Family = %q, want %q", att.Family, teetypes.FamilyTDX)
		}
		env, ok := att.EmbeddedEvidence()
		if !ok || env.Platform != teetypes.PlatformTDX {
			t.Fatalf("EmbeddedEvidence() = (%q, %t), want (tdx, true)", env.Platform, ok)
		}
	})

	t.Run("round trips through the extension", func(t *testing.T) {
		att, err := NewAttestation(snpEvidence(t, teetypes.PlatformGcpSNP, mockapi.FakeSNPReport([]byte{0x33})))
		if err != nil {
			t.Fatalf("NewAttestation: %v", err)
		}
		ext, err := att.MarshalExtension(testOID)
		if err != nil {
			t.Fatalf("MarshalExtension: %v", err)
		}
		got, err := UnmarshalExtension(ext.Value)
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		if !bytes.Equal(got.Report, att.Report) {
			t.Fatal("report did not survive the round trip")
		}
	})

	t.Run("unknown platform", func(t *testing.T) {
		_, err := NewAttestation(teetypes.AttestationEvidence{Platform: "auto", Evidence: json.RawMessage(`{}`)})
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Fatalf("err = %v, want ErrUnsupportedTEE", err)
		}
	})
}
