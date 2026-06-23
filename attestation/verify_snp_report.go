package attestation

import (
	"crypto/x509"
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
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

	// Back-fill the product classification go-sev-guest lacks (e.g. Zen4c
	// Bergamo/Siena): when it can't anchor the report's CPUID to bundled roots,
	// derive the product line from the VCEK certificate and supply the matching
	// roots. Skipped when the caller already pinned TrustedRoots.
	if verifyOpts.TrustedRoots == nil {
		roots, err := vcekProductRootsFallback(proto, att.GetCertificateChain().GetVcekCert())
		if err != nil {
			return nil, err
		}
		if roots != nil {
			opts := *verifyOpts
			opts.TrustedRoots = roots
			verifyOpts = &opts
		}
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

// vcekProductRootsFallback returns trusted roots for go-sev-guest when it cannot
// classify a v3 report's CPUID (so it would fail anchoring as product
// "Unknown"), by reading the authoritative product line from the VCEK
// certificate — the same source go-sev-guest uses for v2 reports, and what the
// attestation-api (attestation-rs) relies on. This back-fills support for parts
// go-sev-guest's CPUID table omits, notably Zen4c (Bergamo/Siena), whose VCEKs
// chain to the Genoa roots.
//
// It returns nil (no override) when: the report is v2 (go-sev-guest already
// reads the VCEK product name), go-sev-guest can classify the CPUID itself, no
// VCEK is available, or the VCEK's product line is also unknown to go-sev-guest
// (no bundled roots to anchor to — that part genuinely needs upstream support).
func vcekProductRootsFallback(report *spb.Report, vcekDER []byte) (map[string][]*trust.AMDRootCerts, error) {
	if len(vcekDER) == 0 {
		return nil, nil
	}
	fms := report.GetCpuid1EaxFms()
	if fms == 0 {
		return nil, nil // v2 report: go-sev-guest already derives product from the VCEK.
	}
	// reportLine is the product line go-sev-guest derives from the v3 CPUID and
	// keys root lookup by; only intervene when it has no bundled roots for it.
	reportLine := kds.ProductLineFromFms(fms)
	if trust.DefaultRootCerts[reportLine] != nil {
		return nil, nil // go-sev-guest can anchor this part itself.
	}

	cert, err := x509.ParseCertificate(vcekDER)
	if err != nil {
		return nil, fmt.Errorf("attestation: parse VCEK for product fallback: %w", err)
	}
	exts, err := kds.VcekCertificateExtensions(cert)
	if err != nil {
		return nil, fmt.Errorf("attestation: read VCEK product extension: %w", err)
	}
	vcekLine := kds.ProductLineOfProductName(exts.ProductName)
	base := trust.DefaultRootCerts[vcekLine]
	if base == nil {
		return nil, nil // VCEK's product line is also unknown to go-sev-guest.
	}

	root := trust.AMDRootCertsProduct(vcekLine)
	root.AskSev = base.AskSev
	root.ArkSev = base.ArkSev
	// Key under the (e.g. "Unknown") line go-sev-guest computes for this report.
	return map[string][]*trust.AMDRootCerts{reportLine: {root}}, nil
}
