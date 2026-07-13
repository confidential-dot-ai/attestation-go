package azsnp

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/evidence-v1.json
var evidenceV1Fixture []byte

// TestVerifyEvidence_V1BoundNonce verifies the recorded az-snp evidence whose
// vTPM quote binds the ASCII nonce "challenge" (mirrors attestation-rs
// az_snp verify.rs tests). The nonce is compared raw against the quote's
// extraData — callers pass the anchor unpadded.
func TestVerifyEvidence_V1BoundNonce(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(evidenceV1Fixture, &env); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedReportData: []byte("challenge")}, snp.Options{})
	if err != nil {
		t.Fatalf("evidence-v1 should verify with its bound nonce: %v", err)
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		t.Fatal("report_data_match must be affirmatively true")
	}
	if _, err := VerifyEvidence(env.Evidence, teetypes.VerifyParams{ExpectedReportData: []byte("other-nonce")}, snp.Options{}); err == nil {
		t.Fatal("a different nonce must fail closed")
	}
}
