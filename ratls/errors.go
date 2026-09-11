package ratls

import "errors"

// Sentinel errors for the failures a caller acts on differently, matchable with
// [errors.Is].
//
// Verification failures are not among them: [VerifyOffline] surfaces the
// verifier's own error, and [VerifyWithService] wraps the client sentinels
// (remote.ErrSignatureInvalid, remote.ErrReportDataMismatch,
// remote.ErrMeasurementNotAllowed, …) so errors.Is reaches them unchanged.
var (
	// ErrUnsupportedTEE reports a TEE this package has no rules for: an
	// unknown wire value in the extension, or a platform tag that maps to
	// teetypes.FamilyUnknown. Fail closed on it — it means no verification
	// rules apply, not that none are needed.
	ErrUnsupportedTEE = errors.New("ratls: unsupported TEE platform")

	// ErrInvalidReport reports structurally unusable evidence: an SEV-SNP
	// report that is neither 1184 bytes nor a valid HCL envelope, an evidence
	// envelope missing its platform or payload, or a shape the extension does
	// not allow for the TEE type it declares.
	ErrInvalidReport = errors.New("ratls: invalid attestation report")

	// ErrNoAttestation reports a certificate with no RA-TLS extension, so
	// nothing binds its key to a TEE.
	ErrNoAttestation = errors.New("ratls: certificate carries no RA-TLS attestation extension")
)
