package snp

import (
	_ "embed"
	"encoding/json"
	"testing"

	spb "github.com/google/go-sev-guest/proto/sevsnp"

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

// TestVerifyEvidence_BareMetalEnvelope drives the bare-metal envelope path with a
// real Genoa-family fixture whose CPUID model (0xA0, Bergamo/Siena) go-sev-guest
// cannot classify offline. vcekProductRoots back-fills the Genoa roots from the
// VCEK certificate so verification succeeds end to end.
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

	res, err := VerifyEvidence(ev, teetypes.VerifyParams{}, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if !res.SignatureValid || res.Platform != teetypes.PlatformSNP {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Claims.LaunchDigest) != 96 || res.Claims.TCB.Type != "Snp" {
		t.Fatalf("unexpected claims: %+v", res.Claims)
	}
}

// TestVCEKProductRoots_Guards covers the cases where the VCEK product fallback
// must stay out of go-sev-guest's way and return no override.
func TestVCEKProductRoots_Guards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *spb.Report
		vcek   []byte
	}{
		{"v2 report (no CPUID)", &spb.Report{}, []byte{0x30}},
		{"v3 report without a VCEK", &spb.Report{Cpuid1EaxFms: sienaFms}, nil},
		{"classifiable v3 (Genoa)", &spb.Report{Cpuid1EaxFms: genoaFms}, []byte("ignored")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, err := vcekProductRoots(tc.report, tc.vcek)
			if err != nil || roots != nil {
				t.Fatalf("want (nil, nil); got (%v, %v)", roots, err)
			}
		})
	}
}

// Genoa-family CPUID_1_EAX values: genoaFms (family 0x19, model 0x11) is
// classifiable by go-sev-guest; sienaFms (model 0xA0, Zen4c) is not.
const (
	genoaFms = uint32(0x00a10f11)
	sienaFms = uint32(0x00aa0f02)
)
