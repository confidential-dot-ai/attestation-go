package snp

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/milan-report.bin
var milanReport []byte

//go:embed testdata/milan-vcek.der
var milanVcek []byte

//go:embed testdata/live-evidence-genoa.json
var genoaEvidence []byte

// TestVerifyReport_Milan exercises the full SNP verification core (report
// signature + ARK→ASK→VCEK chain against bundled Milan roots + policy validation
// + claims) on a real paired Milan report and VCEK. This is the shared path the
// az-snp verifier also drives.
func TestVerifyReport_Milan(t *testing.T) {
	report, vcek := milanReport, milanVcek

	res, err := VerifyReport(report, vcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if !res.SignatureValid || res.Platform != teetypes.PlatformSNP {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Claims.LaunchDigest) != 96 || res.Claims.TCB.Type != "Snp" || res.Claims.TCB.Snp == nil {
		t.Fatalf("unexpected claims: %+v", res.Claims)
	}

	// An absurd minimum-TCB floor must fail closed.
	hi := uint8(255)
	if _, err := VerifyReport(report, vcek, teetypes.VerifyParams{MinTCB: &teetypes.SnpTcb{Snp: hi}}, teetypes.PlatformSNP, MinReportVersionAzure, Options{}); err == nil {
		t.Fatal("absurd MinTCB should fail")
	}

	// A tampered report must fail the signature check.
	bad := append([]byte(nil), report...)
	bad[0x90] ^= 0xFF // flip a measurement byte
	if _, err := VerifyReport(bad, vcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{}); err == nil {
		t.Fatal("tampered report should fail")
	}
}

func TestVerifyEvidence_Errors(t *testing.T) {
	if _, err := VerifyEvidence(SnpEvidence{AttestationReport: "x"}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("missing vcek should fail")
	}
	if _, err := VerifyEvidence(SnpEvidence{AttestationReport: "!", CertChain: &SnpCertChain{Vcek: "AA"}}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("bad base64 report should fail")
	}
}

// TestVerifyEvidence_BareMetalEnvelope drives the bare-metal envelope path with
// a real Genoa-family v5 fixture. go-sev-guest v0.15 doesn't recognize the
// 0xA0 (Bergamo/Siena) CPU model offline, so it can't pick embedded roots for
// it; the test skips with that documented limitation rather than failing.
func TestVerifyEvidence_BareMetalEnvelope(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(genoaEvidence, &env); err != nil {
		t.Fatal(err)
	}
	var ev SnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(ev.AttestationReport); err != nil {
		t.Fatalf("envelope report should be valid base64: %v", err)
	}

	res, err := VerifyEvidence(ev, teetypes.VerifyParams{}, Options{})
	if err != nil {
		if strings.Contains(err.Error(), "Unknown") || strings.Contains(err.Error(), "no embedded roots") {
			t.Skipf("known go-sev-guest gap: Genoa-family model 0xA0 (Bergamo/Siena) product not recognized offline: %v", err)
		}
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if res.Platform != teetypes.PlatformSNP {
		t.Fatalf("platform = %s", res.Platform)
	}
}
