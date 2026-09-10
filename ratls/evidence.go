package ratls

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// EvidenceForExtension returns the payload to embed in the extension's Report
// field for evidence fresh from an attestation service.
//
// Native SEV-SNP evidence (snp, gcp-snp) becomes the raw report: it is
// self-contained, so a verifier needs no evidence schema and no service. Every
// other platform keeps its envelope, because the binding it proves lives
// outside the hardware report — in the vTPM quote on Azure, in Intel
// collateral for TDX. The two shapes are told apart on parse, so one OID
// carries both.
//
// Native TDX evidence loses its cc_eventlog (see [stripTDXEventlog]). The
// Azure overlays keep theirs: their evidence is a different object, and
// rewriting it would drop the vTPM quote the binding rests on.
func EvidenceForExtension(env teetypes.AttestationEvidence) ([]byte, error) {
	platform := teetypes.NormalizePlatform(string(env.Platform))
	family := platform.Family()
	if family == teetypes.FamilyUnknown {
		return nil, fmt.Errorf("%w: no RA-TLS evidence shape for platform %q", ErrUnsupportedTEE, env.Platform)
	}
	// Both branches turn on the native/vTPM split, not on the tag: a guest that
	// attests through its hardware report alone is handled the same way whether
	// it runs bare-metal or on GCP.
	if !platform.HasVTPMQuote() {
		if family == teetypes.FamilySNP {
			return ExtractSNPReport(env)
		}
		stripped, err := stripTDXEventlog(env.Evidence)
		if err != nil {
			return nil, err
		}
		env.Evidence = stripped
	}
	env.Platform = platform
	evidence, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("ratls: marshal %q evidence envelope: %w", platform, err)
	}
	return evidence, nil
}

// NewAttestation builds the attestation to embed from a service's evidence
// envelope: the TEE type from the platform tag, the payload from
// [EvidenceForExtension].
func NewAttestation(env teetypes.AttestationEvidence) (*Attestation, error) {
	teeType, err := TEETypeFor(teetypes.NormalizePlatform(string(env.Platform)))
	if err != nil {
		return nil, err
	}
	report, err := EvidenceForExtension(env)
	if err != nil {
		return nil, err
	}
	return newAttestation(teeType, report, nil)
}

// stripTDXEventlog drops cc_eventlog from native TDX evidence, keeping the
// quote.
//
// A bare-metal TDX event log runs to ~85 KB, which pushes the certificate past
// the 16 KB ceiling on a TLS 1.3 handshake record; crypto/tls then answers with
// an internal_error alert rather than a diagnosable failure. The quote carries
// the RTMR values a policy pins, so a verifier that wants the log fetches it
// out of band and replays it there.
//
// Re-marshaling from a declared struct, rather than deleting a JSON key, keeps
// a field added to the evidence schema from reaching a certificate unnoticed.
func stripTDXEventlog(raw json.RawMessage) (json.RawMessage, error) {
	var body struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("ratls: parse tdx evidence for event-log strip: %w", err)
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ratls: re-marshal stripped tdx evidence: %w", err)
	}
	return out, nil
}
