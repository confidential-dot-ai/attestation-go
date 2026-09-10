package ratls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// SNPReportSize is the exact size of an AMD SEV-SNP attestation report
// (ATTESTATION_REPORT, AMD SEV-SNP ABI Specification table 21).
const SNPReportSize = 0x4A0 // 1184 bytes

// snpReportDataOffset is the byte offset of the 64-byte REPORTDATA field within
// an ATTESTATION_REPORT.
const snpReportDataOffset = 0x50

// TEEType is the hardware family recorded in the extension. The values are
// wire format: 1 and 2 are written into issued certificates and parsed by
// deployed verifiers, so they can be extended but never renumbered.
//
// It names the family only. Which variant produced the evidence (bare-metal,
// Azure, GCP) is carried in the evidence itself and detected on parse, so
// adding a variant needs no new wire value.
type TEEType int

const (
	// TEETypeSEVSNP is AMD SEV-SNP: snp, az-snp, gcp-snp.
	TEETypeSEVSNP TEEType = 1
	// TEETypeTDX is Intel TDX: tdx, az-tdx, gcp-tdx.
	TEETypeTDX TEEType = 2
)

// String returns a human-readable platform name, or unknown(n) for a wire value
// this package does not define.
func (t TEEType) String() string {
	switch t {
	case TEETypeSEVSNP:
		return "AMD SEV-SNP"
	case TEETypeTDX:
		return "Intel TDX"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// Family returns the platform family this TEE type stands for, so callers can
// compare an extension against an evidence envelope without matching strings.
// An undefined wire value yields [teetypes.FamilyUnknown], which callers must
// treat as "no rules apply".
func (t TEEType) Family() teetypes.Family {
	switch t {
	case TEETypeSEVSNP:
		return teetypes.FamilySNP
	case TEETypeTDX:
		return teetypes.FamilyTDX
	default:
		return teetypes.FamilyUnknown
	}
}

// TEETypeFor returns the wire value for a platform tag, routing through
// [teetypes.PlatformType.Family] so a cloud overlay maps to the same value as
// its bare-metal counterpart. A tag with no family fails with
// [ErrUnsupportedTEE] rather than defaulting to one.
func TEETypeFor(p teetypes.PlatformType) (TEEType, error) {
	switch p.Family() {
	case teetypes.FamilySNP:
		return TEETypeSEVSNP, nil
	case teetypes.FamilyTDX:
		return TEETypeTDX, nil
	default:
		return 0, fmt.Errorf("%w: no RA-TLS TEE type for platform %q", ErrUnsupportedTEE, p)
	}
}

// Attestation is the TEE evidence carried by an RA-TLS certificate extension.
type Attestation struct {
	// TEEType is the platform family that produced the evidence.
	TEEType TEEType

	// Report is the evidence payload in one of the two shapes this extension
	// carries: raw SEV-SNP report bytes, or a JSON [teetypes.AttestationEvidence]
	// envelope. Build it with [EvidenceForExtension] rather than by hand;
	// [UnmarshalExtension] tells the shapes apart on the way back in.
	Report []byte

	// CertChain is DER-encoded platform collateral — for SEV-SNP the VCEK,
	// optionally followed by ASK and ARK. Verifying without it means fetching
	// the VCEK from AMD KDS, so an offline verifier needs it inline. It is not
	// trusted material: the verifier chains it to the AMD roots like any other
	// VCEK.
	CertChain []byte

	// embedded is the parsed envelope when Report carries one; nil when Report
	// holds a raw SEV-SNP report. Set on every construction path so producer
	// and consumer agree on the shape.
	embedded *teetypes.AttestationEvidence
}

// attestationASN1 is the DER encoding:
//
//	TEEAttestation ::= SEQUENCE {
//	    teeType     INTEGER,
//	    report      OCTET STRING,
//	    certChain   OCTET STRING
//	}
type attestationASN1 struct {
	TEEType   int
	Report    []byte
	CertChain []byte
}

// MarshalExtension encodes the attestation as a non-critical X.509 extension
// under oid, which the caller assigns from its own arc; this package claims no
// identifier. Non-critical so a TLS stack that does not know the OID still
// parses the certificate: the binding is enforced by whoever verifies the
// evidence, not by certificate parsing.
func (a *Attestation) MarshalExtension(oid asn1.ObjectIdentifier) (pkix.Extension, error) {
	if len(oid) == 0 {
		return pkix.Extension{}, errors.New("ratls: no extension OID")
	}
	value, err := asn1.Marshal(attestationASN1{
		TEEType:   int(a.TEEType),
		Report:    a.Report,
		CertChain: a.CertChain,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal attestation: %w", err)
	}
	return pkix.Extension{Id: oid, Critical: false, Value: value}, nil
}

// UnmarshalExtension decodes an extension value and normalizes the evidence it
// carries: an SEV-SNP report is unwrapped from its HCL envelope if it has one,
// and an embedded JSON envelope is parsed. Trailing bytes after the SEQUENCE
// are rejected, so a payload smuggled past the DER structure cannot ride along.
func UnmarshalExtension(der []byte) (*Attestation, error) {
	var raw attestationASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: unmarshal attestation: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after the attestation extension", ErrInvalidReport, len(rest))
	}
	return newAttestation(TEEType(raw.TEEType), raw.Report, raw.CertChain)
}

// newAttestation decides the evidence shape for both directions, so the
// producer ([NewAttestation]) and the verifier ([UnmarshalExtension]) cannot
// disagree about what a payload means.
func newAttestation(teeType TEEType, report, certChain []byte) (*Attestation, error) {
	if teeType != TEETypeSEVSNP && teeType != TEETypeTDX {
		return nil, fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, int(teeType))
	}
	att := &Attestation{TEEType: teeType, Report: report, CertChain: certChain}

	// Probe for the envelope first: SEV-SNP has both shapes, so only a payload
	// that is not an envelope is read as raw report bytes.
	embedded, err := parseEmbeddedEvidence(report)
	if err != nil {
		return nil, err
	}
	switch {
	case embedded != nil:
		if got := embedded.Platform.Family(); got != teeType.Family() {
			return nil, fmt.Errorf("%w: extension declares %s but carries %q evidence",
				ErrInvalidReport, teeType, embedded.Platform)
		}
		att.embedded = embedded
	case teeType == TEETypeSEVSNP:
		if att.Report, err = NormalizeSEVSNPReport(report); err != nil {
			return nil, err
		}
	default:
		// A TDX quote is verified against Intel collateral, not parsed here,
		// so there is no raw-bytes shape to fall back to. Refuse it at parse
		// time rather than carrying evidence no verifier can read.
		return nil, fmt.Errorf("%w: TDX evidence must be a JSON envelope, got raw bytes", ErrInvalidReport)
	}
	return att, nil
}

// parseEmbeddedEvidence returns the envelope raw encodes, or nil when raw is not
// JSON. An envelope missing its platform tag or payload is an error, not a
// fallback to the raw-report reading.
func parseEmbeddedEvidence(raw []byte) (*teetypes.AttestationEvidence, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil
	}
	var envelope teetypes.AttestationEvidence
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("ratls: parse embedded attestation evidence: %w", err)
	}
	if envelope.Platform == "" || len(envelope.Evidence) == 0 {
		return nil, fmt.Errorf("%w: embedded evidence has no platform or no payload", ErrInvalidReport)
	}
	envelope.Platform = teetypes.NormalizePlatform(string(envelope.Platform))
	return &envelope, nil
}

// EmbeddedEvidence returns the evidence envelope the extension carries, and
// true; it returns false when the extension carries a raw SEV-SNP report
// instead. Use [Attestation.Envelope] to get an envelope either way.
func (a *Attestation) EmbeddedEvidence() (teetypes.AttestationEvidence, bool) {
	if a.embedded == nil {
		return teetypes.AttestationEvidence{}, false
	}
	return *a.embedded, true
}

// ReportData returns the 64-byte REPORTDATA the report commits to, and true,
// for a raw SEV-SNP report. It returns false for envelope evidence, whose
// binding lives in a quote this package does not parse.
//
// It lets a caller reject a mismatched key before verifying. It is not itself
// a check: the bytes stay unverified until the report's signature is, so a
// match here proves nothing on its own.
func (a *Attestation) ReportData() ([]byte, bool) {
	if a.embedded != nil || a.TEEType != TEETypeSEVSNP || len(a.Report) < snpReportDataOffset+64 {
		return nil, false
	}
	return a.Report[snpReportDataOffset : snpReportDataOffset+64], true
}

// Envelope returns the evidence as a self-describing envelope, ready for
// [VerifyOffline] or an attestation service: the embedded
// envelope when there is one, otherwise the raw SEV-SNP report wrapped under
// [teetypes.PlatformSNP]. Inline collateral is carried as cert_chain.vcek, so
// an offline verifier need not reach AMD KDS.
//
// The wrapped tag is the bare-metal one even when the report came from a GCP
// guest: gcp-snp evidence is byte-identical and verifies by the same rules, and
// the raw-report shape does not record which it was.
func (a *Attestation) Envelope() (teetypes.AttestationEvidence, error) {
	if a.embedded != nil {
		return *a.embedded, nil
	}
	if a.TEEType != TEETypeSEVSNP {
		return teetypes.AttestationEvidence{}, fmt.Errorf("%w: %s evidence must be a JSON envelope", ErrInvalidReport, a.TEEType)
	}
	inner := struct {
		AttestationReport string     `json:"attestation_report"`
		CertChain         *certChain `json:"cert_chain,omitempty"`
	}{AttestationReport: base64.StdEncoding.EncodeToString(a.Report)}
	if len(a.CertChain) > 0 {
		inner.CertChain = &certChain{Vcek: base64.StdEncoding.EncodeToString(a.CertChain)}
	}
	raw, err := json.Marshal(inner)
	if err != nil {
		return teetypes.AttestationEvidence{}, fmt.Errorf("ratls: build snp evidence: %w", err)
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: raw}, nil
}

// certChain is the inline-collateral field of the SEV-SNP evidence object.
type certChain struct {
	Vcek string `json:"vcek"`
}

// ExtractAttestation parses the RA-TLS extension carried under oid out of a
// certificate, failing with [ErrNoAttestation] when there is none.
//
// It says nothing about the certificate itself: validity window, chain and
// self-signature are the caller's to check, and the evidence binds only the
// key, so every other field is unattested.
func ExtractAttestation(cert *x509.Certificate, oid asn1.ObjectIdentifier) (*Attestation, error) {
	if len(oid) == 0 {
		return nil, errors.New("ratls: no extension OID")
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return UnmarshalExtension(ext.Value)
		}
	}
	return nil, fmt.Errorf("%w (OID %s)", ErrNoAttestation, oid)
}

// ReportDataForKey computes the REPORTDATA that binds pub to a TEE:
// SHA-384(marshal(pub) || nonce), zero-padded to the 64-byte hardware field.
//
// A nil nonce is the certificate-lifetime binding a serving certificate
// carries: it has no per-connection value to commit to, and TLS
// proof-of-possession of the key supplies connection liveness. Pass a nonce
// when both sides agreed on one; a report from an earlier session then no
// longer satisfies the binding.
//
// The first [sha512.Size384] bytes are the anchor to send to an attestation
// service. A native platform zero-pads it back to 64 before comparing; a vTPM
// platform compares it byte for byte with the quote nonce, which is what the
// service was asked to bind.
func ReportDataForKey(pub crypto.PublicKey, nonce []byte) ([64]byte, error) {
	var reportData [64]byte
	keyBytes, err := marshalPublicKey(pub)
	if err != nil {
		return reportData, fmt.Errorf("ratls: marshal public key: %w", err)
	}
	h := sha512.New384()
	h.Write(keyBytes)
	if len(nonce) > 0 {
		h.Write(nonce)
	}
	copy(reportData[:], h.Sum(nil))
	return reportData, nil
}

// marshalPublicKey encodes pub for hashing into REPORTDATA. The encoding is
// part of the wire contract: ECDSA as PKIX DER, ed25519 as its raw 32 bytes.
func marshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case ed25519.PublicKey:
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type %T", pub)
	}
}

// publicKeyFromCert returns the certificate's public key, restricted to the
// types RA-TLS binds: ECDSA on P-256 or P-384, and ed25519. Any other type is
// refused, because this package has fixed no hashing encoding for it.
func publicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ratls: unsupported ECDSA curve %s", pub.Curve.Params().Name)
		}
		return pub, nil
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type %T in certificate", pub)
	}
}
