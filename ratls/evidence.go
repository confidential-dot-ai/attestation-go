package ratls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
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
	payload, _, err := evidenceForExtension(env)
	return payload, err
}

// evidenceForExtension also returns the envelope the payload encodes, or nil
// when the payload is a raw SEV-SNP report, so [NewAttestation] need not parse
// back what it just marshalled.
func evidenceForExtension(env teetypes.AttestationEvidence) ([]byte, *teetypes.AttestationEvidence, error) {
	platform := teetypes.NormalizePlatform(string(env.Platform))
	family := platform.Family()
	if family == teetypes.FamilyUnknown {
		return nil, nil, fmt.Errorf("%w: no RA-TLS evidence shape for platform %q", ErrUnsupportedTEE, env.Platform)
	}
	// Both branches turn on the native/vTPM split, not on the tag: a guest that
	// attests through its hardware report alone is handled the same way whether
	// it runs bare-metal or on GCP.
	if !platform.HasVTPMQuote() {
		if family == teetypes.FamilySNP {
			report, err := ExtractSNPReport(env)
			return report, nil, err
		}
		stripped, err := stripTDXEventlog(env.Evidence)
		if err != nil {
			return nil, nil, err
		}
		env.Evidence = stripped
	}
	env.Platform = platform
	evidence, err := json.Marshal(env)
	if err != nil {
		return nil, nil, fmt.Errorf("ratls: marshal %q evidence envelope: %w", platform, err)
	}
	return evidence, &env, nil
}

// NewAttestation builds the attestation to embed from a service's evidence
// envelope: the family from the platform tag, the payload from
// [EvidenceForExtension]. A tag with no family is refused there, so a cloud
// overlay embeds exactly as its bare-metal counterpart does and nothing else
// gets a default. Native SNP collateral is preserved in CertChain so the
// resulting extension can still be verified offline.
func NewAttestation(env teetypes.AttestationEvidence) (*Attestation, error) {
	report, embedded, err := evidenceForExtension(env)
	if err != nil {
		return nil, err
	}
	var certChain []byte
	if embedded == nil && env.Platform.IsSNP() {
		var evidence snp.SnpEvidence
		if err := json.Unmarshal(env.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("ratls: parse snp collateral: %w", err)
		}
		if evidence.CertChain != nil && evidence.CertChain.Vcek != "" {
			certChain, err = base64.StdEncoding.DecodeString(evidence.CertChain.Vcek)
			if err != nil {
				return nil, fmt.Errorf("ratls: decode snp cert_chain.vcek: %w", err)
			}
		}
	}
	return newAttestation(env.Platform.Family(), report, certChain, embedded)
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
