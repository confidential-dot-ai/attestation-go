// Package tpmcommon implements the Azure HCL (Host Compatibility Layer) + vTPM
// layer shared by the az-snp and az-tdx verifiers. It is a Go port of
// attestation-rs's tpm_common.rs, so the Go and Rust/WASM verifiers agree
// byte-for-byte on the Azure vTPM freshness chain:
//
//	TEE report (HW-signed) -> report_data == SHA-256(var_data)
//	    -> AK pub (from var_data) -> TPM quote signature
//	        -> quote extraData == nonce
//
// var_data is the HCL runtime data (a JWK JSON blob carrying the vTPM
// Attestation Key); the per-request nonce rides in the AK-signed TPM quote
// because the hardware report_data binds the AK, not the nonce.
package tpmcommon

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// --- HCL report layout ---

const (
	hclTEEReportOffset   = 0x20
	hclTEEReportSize     = 1184 // SNP and TDX both 1184
	hclVarDataHeaderSize = 20   // 5 little-endian u32s: total, count, report_type, version, content_length

	// HCLReportTypeSNP / HCLReportTypeTDX are the report_type values in the
	// var_data header.
	HCLReportTypeSNP = 2
	HCLReportTypeTDX = 4
)

// --- TPM constants ---

const (
	tpmAlgRSA      = 0x0001
	tpmAlgNull     = 0x0010
	tpmAttestMagic = 0xFF544347 // "\xFFTCG"
)

var rsaDefaultExponent = []byte{0x01, 0x00, 0x01}

// DecodeBase64URL decodes URL-safe base64, tolerating optional padding (some
// Azure evidence pads its hcl_report/td_quote, some does not). Mirrors
// attestation-rs decode_base64url, which trims '=' before decoding.
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// HCLReport is a parsed Azure HCL report.
type HCLReport struct {
	// TEEReport is the raw 1184-byte hardware report (SNP report or TD report).
	TEEReport []byte
	// ReportType is 2 (SNP) or 4 (TDX).
	ReportType uint32
	// VarData is the null-trimmed runtime data (JWK JSON with the vTPM AK).
	VarData []byte
}

// ParseHCLReport parses an HCL report into its TEE report, report type, and
// var_data. Layout: header(0x20) + TEE report(1184) + var_data header(20) +
// var_data content (null-padded).
func ParseHCLReport(hcl []byte) (*HCLReport, error) {
	teeEnd := hclTEEReportOffset + hclTEEReportSize
	contentStart := teeEnd + hclVarDataHeaderSize
	if len(hcl) < contentStart {
		return nil, fmt.Errorf("HCL report too short: %d < %d", len(hcl), contentStart)
	}
	if string(hcl[:4]) != "HCLA" {
		return nil, fmt.Errorf("invalid HCL magic: %x", hcl[:4])
	}
	header := hcl[teeEnd:contentStart]
	reportType := binary.LittleEndian.Uint32(header[8:12])
	contentLength := int(binary.LittleEndian.Uint32(header[16:20]))
	available := len(hcl) - contentStart
	if contentLength > available {
		return nil, fmt.Errorf("HCL content_length (%d) exceeds available data (%d)", contentLength, available)
	}
	content := hcl[contentStart : contentStart+contentLength]
	end := len(content)
	for end > 0 && content[end-1] == 0 {
		end-- // trim trailing null padding
	}
	if end == 0 {
		return nil, fmt.Errorf("HCL var_data is empty after null trimming")
	}
	return &HCLReport{
		TEEReport:  hcl[hclTEEReportOffset:teeEnd],
		ReportType: reportType,
		VarData:    content[:end],
	}, nil
}

// VerifyHCLVarDataBinding enforces report_data[:32] == SHA-256(var_data): how
// the HCL binds the vTPM AK material into the hardware-signed report.
func VerifyHCLVarDataBinding(reportData, varData []byte) error {
	if len(reportData) < 32 {
		return fmt.Errorf("report_data shorter than 32 bytes")
	}
	want := sha256.Sum256(varData)
	if subtle.ConstantTimeCompare(reportData[:32], want[:]) != 1 {
		return fmt.Errorf("HCL var_data binding failed: report_data[:32] != SHA-256(var_data)")
	}
	return nil
}

// --- vTPM quote ---

// TPMQuote is a decoded vTPM quote.
type TPMQuote struct {
	Signature []byte
	Message   []byte
	PCRs      [][]byte
}

// RawTPMQuote mirrors the hex-encoded tpm_quote object in Azure evidence JSON.
type RawTPMQuote struct {
	Signature string   `json:"signature"`
	Message   string   `json:"message"`
	PCRs      []string `json:"pcrs"`
}

// DecodeTPMQuote hex-decodes the wire form of a vTPM quote.
func DecodeTPMQuote(raw *RawTPMQuote) (*TPMQuote, error) {
	sig, err := hex.DecodeString(raw.Signature)
	if err != nil {
		return nil, fmt.Errorf("tpm_quote.signature hex: %w", err)
	}
	msg, err := hex.DecodeString(raw.Message)
	if err != nil {
		return nil, fmt.Errorf("tpm_quote.message hex: %w", err)
	}
	pcrs := make([][]byte, 0, len(raw.PCRs))
	for i, p := range raw.PCRs {
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("tpm_quote.pcrs[%d] hex: %w", i, err)
		}
		pcrs = append(pcrs, b)
	}
	return &TPMQuote{Signature: sig, Message: msg, PCRs: pcrs}, nil
}

type jwkKeySet struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func extractAKPubFromJWK(varData []byte) (*rsa.PublicKey, error) {
	var set jwkKeySet
	if err := json.Unmarshal(varData, &set); err != nil {
		return nil, fmt.Errorf("HCL var_data JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("HCL var_data JSON missing 'keys' array")
	}
	for _, k := range set.Keys {
		if k.Kid != "HCLAkPub" || k.Kty != "RSA" {
			continue
		}
		if k.N == "" || k.E == "" {
			return nil, fmt.Errorf("HCLAkPub missing 'n' or 'e' field")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("HCLAkPub 'n' base64: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("HCLAkPub 'e' base64: %w", err)
		}
		return rsaPubFromBytes(nBytes, eBytes)
	}
	return nil, fmt.Errorf("HCL var_data JSON does not contain HCLAkPub RSA key")
}

// extractAKPubFromTPM2BPublic parses a TPM2B_PUBLIC structure (synthetic test
// data fallback; real Azure evidence uses the JWK form).
func extractAKPubFromTPM2BPublic(varData []byte) (*rsa.PublicKey, error) {
	off := 0
	readU16 := func(field string) (uint16, error) {
		if off+2 > len(varData) {
			return 0, fmt.Errorf("truncated at %s", field)
		}
		v := binary.BigEndian.Uint16(varData[off : off+2])
		off += 2
		return v, nil
	}
	if _, err := readU16("TPM2B_PUBLIC size"); err != nil {
		return nil, err
	}
	algType, err := readU16("TPMT_PUBLIC type")
	if err != nil {
		return nil, err
	}
	if algType != tpmAlgRSA {
		return nil, fmt.Errorf("AK key type 0x%04x is not RSA", algType)
	}
	if _, err := readU16("nameAlg"); err != nil {
		return nil, err
	}
	off += 4 // objectAttributes
	authSize, err := readU16("authPolicy size")
	if err != nil {
		return nil, err
	}
	off += int(authSize)
	symAlg, err := readU16("symmetric alg")
	if err != nil {
		return nil, err
	}
	if symAlg != tpmAlgNull {
		off += 6
	}
	schemeAlg, err := readU16("scheme alg")
	if err != nil {
		return nil, err
	}
	if schemeAlg != tpmAlgNull {
		off += 2
	}
	if _, err := readU16("keyBits"); err != nil {
		return nil, err
	}
	if off+4 > len(varData) {
		return nil, fmt.Errorf("truncated at exponent")
	}
	expVal := binary.BigEndian.Uint32(varData[off : off+4])
	off += 4
	exponent := rsaDefaultExponent
	if expVal != 0 {
		exponent = []byte{byte(expVal >> 24), byte(expVal >> 16), byte(expVal >> 8), byte(expVal)}
	}
	modSize, err := readU16("modulus size")
	if err != nil {
		return nil, err
	}
	if off+int(modSize) > len(varData) {
		return nil, fmt.Errorf("truncated at modulus")
	}
	return rsaPubFromBytes(varData[off:off+int(modSize)], exponent)
}

func rsaPubFromBytes(modulus, exponent []byte) (*rsa.PublicKey, error) {
	if len(modulus) == 0 || len(exponent) == 0 {
		return nil, fmt.Errorf("empty RSA modulus or exponent")
	}
	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}, nil
}

// ExtractAKPub returns the vTPM AK public key from var_data, trying the real
// Azure JWK JSON form first and falling back to a raw TPM2B_PUBLIC.
func ExtractAKPub(varData []byte) (*rsa.PublicKey, error) {
	if pub, err := extractAKPubFromJWK(varData); err == nil {
		return pub, nil
	} else if pub2, err2 := extractAKPubFromTPM2BPublic(varData); err2 == nil {
		return pub2, nil
	} else {
		return nil, fmt.Errorf("extract AK pub: jwk: %v; tpm2b: %v", err, err2)
	}
}

// VerifyTPMSignature checks the AK's RSASSA-PKCS1-v1.5 / SHA-256 signature over
// the TPMS_ATTEST message (Azure vTPM AK is RSA-2048).
func VerifyTPMSignature(signature, message, varData []byte) error {
	pub, err := ExtractAKPub(varData)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		return fmt.Errorf("TPM RSA PKCS1v15 SHA-256: %w", err)
	}
	return nil
}

// ExtractTPMNonce returns the extraData (qualifyingData) of a TPMS_ATTEST
// message — where the relying party's nonce is carried on Azure.
func ExtractTPMNonce(message []byte) ([]byte, error) {
	if len(message) < 10 {
		return nil, fmt.Errorf("TPM attest message too short")
	}
	if binary.BigEndian.Uint32(message[0:4]) != tpmAttestMagic {
		return nil, fmt.Errorf("invalid TPM attest magic 0x%08X", binary.BigEndian.Uint32(message[0:4]))
	}
	off := 6
	signerSize, err := readBEU16(message, off, "qualifiedSigner size")
	if err != nil {
		return nil, err
	}
	off += 2 + int(signerSize)
	nonceSize, err := readBEU16(message, off, "extraData size")
	if err != nil {
		return nil, err
	}
	off += 2
	if off+int(nonceSize) > len(message) {
		return nil, fmt.Errorf("TPM attest truncated at nonce data")
	}
	return message[off : off+int(nonceSize)], nil
}

// VerifyTPMNonce enforces that the quote's extraData equals expected exactly
// (unpadded — Azure's TPM2B_DATA holds the raw nonce).
func VerifyTPMNonce(message, expected []byte) error {
	nonce, err := ExtractTPMNonce(message)
	if err != nil {
		return err
	}
	if len(nonce) != len(expected) {
		return fmt.Errorf("TPM nonce length mismatch: quote has %d bytes, expected %d", len(nonce), len(expected))
	}
	if subtle.ConstantTimeCompare(nonce, expected) != 1 {
		return fmt.Errorf("TPM nonce does not match request nonce (stale or replayed evidence)")
	}
	return nil
}

// CheckReportData verifies the TPM nonce against expected, returning nil (no
// expectation) or a non-nil *bool true. A mismatch is returned as an error.
func CheckReportData(message, expected []byte) (*bool, error) {
	if expected == nil {
		return nil, nil
	}
	if err := VerifyTPMNonce(message, expected); err != nil {
		return nil, err
	}
	return teetypes.Ptr(true), nil
}

// VerifyTPMPCRs confirms the quote's signed pcrDigest equals SHA-256 of the
// concatenated selected PCR values.
func VerifyTPMPCRs(message []byte, pcrs [][]byte) error {
	if len(pcrs) == 0 {
		return fmt.Errorf("no PCR values in TPM quote")
	}
	for i, pcr := range pcrs {
		if len(pcr) != 32 {
			return fmt.Errorf("PCR[%d] has unexpected size %d (expected 32)", i, len(pcr))
		}
	}
	selected, expectedDigest, err := parseQuoteInfo(message)
	if err != nil {
		return err
	}
	var concat []byte
	for _, idx := range selected {
		if idx >= len(pcrs) {
			return fmt.Errorf("PCR selection references PCR[%d] but only %d PCRs available", idx, len(pcrs))
		}
		concat = append(concat, pcrs[idx]...)
	}
	got := sha256.Sum256(concat)
	if subtle.ConstantTimeCompare(got[:], expectedDigest) != 1 {
		return fmt.Errorf("PCR digest in TPM quote does not match hash of PCR values")
	}
	return nil
}

// CheckInitData verifies PCR[8] == SHA-256(zeros_32 || expected), the TPM
// extend of the init-data hash. Returns nil when expected is nil.
func CheckInitData(pcrs [][]byte, expected []byte) (*bool, error) {
	if expected == nil {
		return nil, nil
	}
	if len(expected) != 32 {
		return nil, fmt.Errorf("expected_init_data_hash must be 32 bytes, got %d", len(expected))
	}
	if len(pcrs) <= 8 {
		return nil, fmt.Errorf("init_data check needs PCR[8] but only %d PCRs present", len(pcrs))
	}
	h := sha256.New()
	h.Write(make([]byte, 32))
	h.Write(expected)
	extended := h.Sum(nil)
	if subtle.ConstantTimeCompare(pcrs[8], extended) != 1 {
		return nil, fmt.Errorf("init_data mismatch: PCR[8] != SHA-256(0^32 || expected)")
	}
	return teetypes.Ptr(true), nil
}

func parseQuoteInfo(message []byte) ([]int, []byte, error) {
	if len(message) < 10 {
		return nil, nil, fmt.Errorf("TPMS_ATTEST too short")
	}
	off := 6
	signerSize, err := readBEU16(message, off, "qualifiedSigner size")
	if err != nil {
		return nil, nil, err
	}
	off += 2 + int(signerSize)
	extraSize, err := readBEU16(message, off, "extraData size")
	if err != nil {
		return nil, nil, err
	}
	off += 2 + int(extraSize)
	off += 17 // clockInfo
	off += 8  // firmwareVersion
	count, err := readBEU32(message, off, "PCR selection count")
	if err != nil {
		return nil, nil, err
	}
	off += 4
	var selected []int
	for i := uint32(0); i < count; i++ {
		if _, err := readBEU16(message, off, "PCR hash alg"); err != nil {
			return nil, nil, err
		}
		off += 2
		if off >= len(message) {
			return nil, nil, fmt.Errorf("truncated at PCR selection size")
		}
		selectSize := int(message[off])
		off++
		if off+selectSize > len(message) {
			return nil, nil, fmt.Errorf("truncated at PCR selection bitmap")
		}
		for byteIdx := 0; byteIdx < selectSize; byteIdx++ {
			b := message[off+byteIdx]
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					selected = append(selected, byteIdx*8+bit)
				}
			}
		}
		off += selectSize
	}
	digestSize, err := readBEU16(message, off, "PCR digest size")
	if err != nil {
		return nil, nil, err
	}
	off += 2
	if off+int(digestSize) > len(message) {
		return nil, nil, fmt.Errorf("truncated at PCR digest data")
	}
	return selected, message[off : off+int(digestSize)], nil
}

// ApplyTPMClaims overlays the vTPM data onto bare-platform claims: signed_data
// becomes the (null-trimmed) TPM nonce, and platform_data["tpm"] gets the PCR
// bank + nonce. Mirrors attestation-rs build_tpm_verification_result.
func ApplyTPMClaims(claims *teetypes.Claims, pcrs [][]byte, message []byte) {
	tpm := map[string]any{}
	for i, pcr := range pcrs {
		tpm[fmt.Sprintf("pcr%02d", i)] = hex.EncodeToString(pcr)
	}
	if nonce, err := ExtractTPMNonce(message); err == nil {
		tpm["nonce"] = hex.EncodeToString(nonce)
		claims.SignedData = stripTrailingNulls(nonce)
	}
	if claims.PlatformData == nil {
		claims.PlatformData = map[string]any{}
	}
	claims.PlatformData["tpm"] = tpm
}

func stripTrailingNulls(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}

func readBEU16(data []byte, off int, field string) (uint16, error) {
	if off < 0 || off+2 > len(data) {
		return 0, fmt.Errorf("truncated at %s", field)
	}
	return binary.BigEndian.Uint16(data[off : off+2]), nil
}

func readBEU32(data []byte, off int, field string) (uint32, error) {
	if off < 0 || off+4 > len(data) {
		return 0, fmt.Errorf("truncated at %s", field)
	}
	return binary.BigEndian.Uint32(data[off : off+4]), nil
}
