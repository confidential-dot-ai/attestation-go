package attestation

import (
	"crypto/x509"
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
)

// SNPClaims holds the verified fields extracted from a SEV-SNP attestation
// report. They are meaningful ONLY after VerifySNPReport returns a nil error:
// the report is untrusted until the AMD signature chain has been checked.
type SNPClaims struct {
	// Measurement is the 48-byte SHA-384 launch digest.
	Measurement []byte
	// ReportData is the 64-byte REPORTDATA field.
	ReportData []byte
	// GuestPolicy is the packed SNP guest policy.
	GuestPolicy uint64
	// CurrentTCB is the platform's current TCB version (packed).
	CurrentTCB uint64
}

// VerifySNPReport verifies a bare AMD SEV-SNP attestation — a raw 1184-byte
// ATTESTATION_REPORT plus an optional DER certificate chain (VCEK [|| ASK ||
// ARK]) — and returns the verified claims.
//
// Unlike VerifyAttestation, which expects a go-tpm-tools attestation bundle
// (TPM quote + event log) as produced on GCE, this entry point takes the bare
// hardware report directly. It is the verification primitive for callers that
// carry SEV-SNP evidence outside the GCE vTPM envelope (e.g. RA-TLS certificate
// extensions or a /.well-known attestation endpoint).
//
// Order is load-bearing and matches go-sev-guest's contract: the AMD signature
// chain (verify.SnpAttestation) is checked BEFORE any report field is validated
// (validate.SnpAttestation), so no untrusted field is read before the signature
// is confirmed. verify.SnpAttestation also fills in any certificates the chain
// omits, which validation then relies on.
//
// validateOpts carries the field policy (expected ReportData, GuestPolicy,
// MinimumTCB, etc.); a nil-or-empty validateOpts.ReportData skips the binding
// check. verifyOpts controls trusted roots / KDS access; nil uses go-sev-guest
// defaults (bundled AMD product roots, with KDS fallback for missing certs).
func VerifySNPReport(report, certChainDER []byte, validateOpts *validate.Options, verifyOpts *sv.Options) (*SNPClaims, error) {
	if validateOpts == nil {
		validateOpts = &validate.Options{}
	}
	if verifyOpts == nil {
		verifyOpts = &sv.Options{}
	}

	proto, err := sabi.ReportToProto(report)
	if err != nil {
		return nil, fmt.Errorf("attestation: parse SEV-SNP report: %w", err)
	}

	att := &spb.Attestation{Report: proto}
	if len(certChainDER) > 0 {
		chain, err := certChainFromDER(certChainDER)
		if err != nil {
			return nil, err
		}
		att.CertificateChain = chain
	}

	// INVARIANT: signature before fields. verifySevSnpAttestation runs
	// verify.SnpAttestation then validate.SnpAttestation in that order.
	if err := verifySevSnpAttestation(att, &verifySnpOpts{Validation: validateOpts, Verification: verifyOpts}); err != nil {
		return nil, err
	}

	return &SNPClaims{
		Measurement: proto.GetMeasurement(),
		ReportData:  proto.GetReportData(),
		GuestPolicy: proto.GetPolicy(),
		CurrentTCB:  proto.GetCurrentTcb(),
	}, nil
}

// certChainFromDER parses concatenated DER certificates into the go-sev-guest
// CertificateChain shape. Order is VCEK, ASK, ARK (the AMD chain order); any
// certificate the chain omits is left empty for verify.SnpAttestation to fetch.
func certChainFromDER(der []byte) (*spb.CertificateChain, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("attestation: parse VCEK cert chain: %w", err)
	}
	chain := &spb.CertificateChain{}
	for i, cert := range certs {
		switch i {
		case 0:
			chain.VcekCert = cert.Raw
		case 1:
			chain.AskCert = cert.Raw
		case 2:
			chain.ArkCert = cert.Raw
		}
	}
	return chain, nil
}
