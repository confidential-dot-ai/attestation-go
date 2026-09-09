package ratls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/apiclient"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

// VerifyOffline verifies the attestation in-process and requires it to bind
// pub: the expected REPORTDATA comes from [ReportDataForKey], never from the
// caller, so a key binding cannot be verified against the wrong key by
// misconfiguration. A params.ExpectedReportData that disagrees with the anchor
// is refused rather than overwritten, since it means the caller is asking for a
// different check than the one this function performs.
//
// Everything else in params is the caller's policy — debug, TCB floor, launch
// digest, RTMRs — and the verifier enforces it. opts carries collateral
// fetching: the zero value is fully offline, which needs the SEV-SNP VCEK
// inline (see [Attestation.CertChain]); set opts.SNP.Getter to let the verifier
// fetch it from AMD KDS instead.
//
// The result is returned only when the hardware signature verified and the
// binding matched affirmatively. A verdict that merely fails to say no is
// treated as a failure.
func VerifyOffline(att *Attestation, pub crypto.PublicKey, nonce []byte, params teetypes.VerifyParams, opts teeverify.Options) (*teetypes.VerificationResult, error) {
	env, err := att.Envelope()
	if err != nil {
		return nil, err
	}
	anchor, err := bindingAnchor(pub, nonce, params.ExpectedReportData)
	if err != nil {
		return nil, err
	}
	params.ExpectedReportData = anchor

	evidenceJSON, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("ratls: marshal evidence envelope: %w", err)
	}
	result, err := teeverify.VerifyWithOptions(evidenceJSON, params, opts)
	if err != nil {
		return nil, fmt.Errorf("ratls: verify %s evidence: %w", env.Platform, err)
	}
	// The verifier reports a mismatch as an error, so these hold on this path.
	// Re-checking them means a verifier that ever returns a bare result cannot
	// be read here as a pass.
	if !result.SignatureValid {
		return nil, fmt.Errorf("ratls: %s verifier returned signature_valid=false", env.Platform)
	}
	if result.ReportDataMatch == nil || !*result.ReportDataMatch {
		return nil, fmt.Errorf("ratls: %s evidence does not bind the certificate key", env.Platform)
	}
	return result, nil
}

// VerifyCertOffline verifies the RA-TLS extension of cert against cert's own
// public key, which is what makes the certificate self-attesting.
//
// It checks the evidence and nothing else: validity window, issuer chain and
// self-signature are the caller's to verify. The evidence binds only the key,
// so every other field of a self-issued certificate is attacker-writable under
// a genuine extension.
func VerifyCertOffline(cert *x509.Certificate, nonce []byte, params teetypes.VerifyParams, opts teeverify.Options) (*teetypes.VerificationResult, error) {
	att, pub, err := attestationAndKey(cert)
	if err != nil {
		return nil, err
	}
	return VerifyOffline(att, pub, nonce, params, opts)
}

// VerifyWithService verifies the attestation through an attestation service and
// requires it to bind pub, on the same terms as [VerifyOffline]: the expected
// report data comes from [ReportDataForKey], and a policy.ExpectedReportData
// that disagrees is refused.
//
// It goes through [apiclient.Client.VerifyEvidence], which fails closed on the
// verdict and then on the policy's pins, and refuses a platform tag it has no
// rules for. Its sentinels (apiclient.ErrSignatureInvalid,
// apiclient.ErrReportDataMismatch, apiclient.ErrMeasurementNotAllowed, …) reach
// the caller unchanged, so errors.Is reaches them.
//
// The response is only as trustworthy as the service: it is not signed, so the
// service must sit inside the same trust boundary as the caller — a node-local
// socket or an in-guest loopback endpoint, not a remote URL.
func VerifyWithService(ctx context.Context, client apiclient.Client, att *Attestation, pub crypto.PublicKey, nonce []byte, policy apiclient.Policy) (apiclient.VerifyResponse, error) {
	env, err := att.Envelope()
	if err != nil {
		return apiclient.VerifyResponse{}, err
	}
	anchor, err := bindingAnchor(pub, nonce, policy.ExpectedReportData)
	if err != nil {
		return apiclient.VerifyResponse{}, err
	}
	policy.ExpectedReportData = anchor
	return client.VerifyEvidence(ctx, env, policy)
}

// VerifyCertWithService verifies the RA-TLS extension of cert against cert's
// own public key through an attestation service. Like [VerifyCertOffline] it
// checks the evidence alone; the certificate's validity and chain remain the
// caller's to verify.
func VerifyCertWithService(ctx context.Context, client apiclient.Client, cert *x509.Certificate, nonce []byte, policy apiclient.Policy) (apiclient.VerifyResponse, error) {
	att, pub, err := attestationAndKey(cert)
	if err != nil {
		return apiclient.VerifyResponse{}, err
	}
	return VerifyWithService(ctx, client, att, pub, nonce, policy)
}

// bindingAnchor returns the report data that pub and nonce must be bound to,
// and refuses a caller-supplied value that differs from it.
//
// The anchor is the unpadded SHA-384 prefix: a native platform zero-pads it
// back to the 64-byte hardware field, while a vTPM platform compares it byte
// for byte with the quote nonce, which is the value the attester asked to have
// bound.
func bindingAnchor(pub crypto.PublicKey, nonce, supplied []byte) ([]byte, error) {
	reportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, err
	}
	anchor := reportData[:sha512.Size384]
	if len(supplied) > 0 && !bytes.Equal(supplied, anchor) {
		return nil, fmt.Errorf("ratls: expected report data %x does not bind the key; leave it unset and it is derived from the key", supplied)
	}
	return anchor, nil
}

// attestationAndKey pulls the pieces a certificate contributes to verification:
// its RA-TLS extension and the key that extension must bind.
func attestationAndKey(cert *x509.Certificate) (*Attestation, crypto.PublicKey, error) {
	att, err := ExtractAttestation(cert)
	if err != nil {
		return nil, nil, err
	}
	pub, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, nil, err
	}
	return att, pub, nil
}
