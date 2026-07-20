// Package tdx verifies bare-metal Intel TDX attestation evidence. The DCAP
// cryptography (quote signature, QE report, PCK certificate chain against the
// Intel SGX Root CA, and optional collateral: TCB info, QE identity, CRLs) is
// delegated to go-tdx-guest — the Go counterpart of the hand-rolled DCAP
// verifier in attestation-rs's tdx module. This package maps
// teetypes.VerifyParams onto go-tdx-guest's verify/validate options and
// normalizes the quote into teetypes.Claims.
package tdx

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	tabi "github.com/google/go-tdx-guest/abi"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
	tvalidate "github.com/google/go-tdx-guest/validate"
	tverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// TdxEvidence is the bare-metal TDX evidence payload.
type TdxEvidence struct {
	Quote      string `json:"quote"`                 // base64 (std) of the DCAP quote
	CCEventlog string `json:"cc_eventlog,omitempty"` // base64 (std), optional; replayed against RTMR[0-2]
}

// Options tunes DCAP verification.
type Options struct {
	// CheckRevocations fetches and checks PCK CRLs (requires network).
	CheckRevocations bool
	// GetCollateral fetches TCB info / QE identity collateral (requires network).
	GetCollateral bool
	// Getter fetches collateral. Nil → offline (signature + embedded-root chain).
	Getter trust.HTTPSGetter
	// Now is the verification time for certificate/collateral validity. Zero →
	// time.Now(). Pin it to verify older captured quotes whose PCK certs have
	// since expired.
	Now time.Time
}

// VerifyEvidence verifies a bare-metal TDX evidence envelope and returns
// normalized claims. When the envelope carries a CCEL event log, it is replayed
// against the quote's RTMRs (see ccel.go) to bind the log to the signed quote.
func VerifyEvidence(ev TdxEvidence, params teetypes.VerifyParams, opts Options) (*teetypes.VerificationResult, error) {
	if err := teetypes.CheckFieldSize("quote", len(ev.Quote)); err != nil {
		return nil, fmt.Errorf("tdx: %w", err)
	}
	if err := teetypes.CheckFieldSize("cc_eventlog", len(ev.CCEventlog)); err != nil {
		return nil, fmt.Errorf("tdx: %w", err)
	}
	quoteBytes, err := base64.StdEncoding.DecodeString(ev.Quote)
	if err != nil {
		return nil, fmt.Errorf("tdx: decoding quote: %w", err)
	}
	res, err := VerifyQuoteBytes(quoteBytes, params, teetypes.PlatformTDX, opts)
	if err != nil {
		return nil, err
	}
	if ev.CCEventlog == "" {
		return res, nil
	}

	ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
	if err != nil {
		return nil, fmt.Errorf("tdx: decoding cc_eventlog: %w", err)
	}
	// Replay against the RTMRs in the quote body, which VerifyQuoteBytes has
	// just verified as signed.
	rtmrs, err := quoteRTMRs(quoteBytes)
	if err != nil {
		return nil, err
	}
	rtmr3Match, err := VerifyCCELAgainstRTMRs(ccel, rtmrs[0], rtmrs[1], rtmrs[2], rtmrs[3])
	if err != nil {
		return nil, err
	}
	res.EventlogVerified = teetypes.Ptr(true)
	res.RTMR3ReplayMatch = teetypes.Ptr(rtmr3Match)
	return res, nil
}

// VerifyQuoteBytes verifies a raw DCAP quote: signature + PCK chain (go-tdx-guest
// verify) and field/policy validation (go-tdx-guest validate), then extracts
// claims. Shared by the tdx and aztdx packages.
func VerifyQuoteBytes(quoteBytes []byte, params teetypes.VerifyParams, platform teetypes.PlatformType, opts Options) (*teetypes.VerificationResult, error) {
	anyQuote, err := tabi.QuoteToProto(quoteBytes)
	if err != nil {
		return nil, fmt.Errorf("tdx: parsing quote: %w", err)
	}
	quote, ok := anyQuote.(*tpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("tdx: unsupported quote type %T (only QuoteV4 is supported)", anyQuote)
	}
	body := quote.GetTdQuoteBody()
	if body == nil {
		return nil, fmt.Errorf("tdx: quote has no TD report body")
	}

	// DCAP signature + PCK chain (+ collateral when requested).
	vOpts := &tverify.Options{
		CheckRevocations: opts.CheckRevocations,
		GetCollateral:    opts.GetCollateral,
		Getter:           opts.Getter,
		Now:              opts.Now,
	}
	if err := tverify.TdxQuote(quote, vOpts); err != nil {
		return nil, fmt.Errorf("tdx: DCAP verification failed: %w", err)
	}

	// Debug policy: TD_ATTRIBUTES bit 0.
	if td := body.GetTdAttributes(); len(td) >= 1 && td[0]&0x01 != 0 && !params.AllowDebug {
		return nil, fmt.Errorf("tdx: TD launched with debug attribute and AllowDebug is false")
	}

	// Field validation: report_data (64) and mr_config_id init-data (48).
	valOpts, err := validateOptions(params)
	if err != nil {
		return nil, err
	}
	if err := tvalidate.TdxQuote(quote, valOpts); err != nil {
		return nil, fmt.Errorf("tdx: field validation failed: %w", err)
	}

	res := &teetypes.VerificationResult{
		SignatureValid:     true,
		Platform:           platform,
		Claims:             extractClaims(quote),
		CollateralVerified: opts.GetCollateral,
	}
	if params.ExpectedReportData != nil {
		res.ReportDataMatch = teetypes.Ptr(true)
	}
	if params.ExpectedInitDataHash != nil {
		res.InitDataMatch = teetypes.Ptr(true)
	}
	if params.ExpectedLaunchDigest != nil {
		res.LaunchDigestMatch = teetypes.Ptr(true)
	}
	return res, nil
}

func validateOptions(params teetypes.VerifyParams) (*tvalidate.Options, error) {
	opts := &tvalidate.Options{}
	if d := params.ExpectedReportData; d != nil {
		if len(d) > 64 {
			return nil, fmt.Errorf("tdx: expected_report_data is %d bytes (max 64)", len(d))
		}
		opts.TdQuoteBodyOptions.ReportData = pad(d, 64)
	}
	if d := params.ExpectedInitDataHash; d != nil {
		if len(d) > 48 {
			return nil, fmt.Errorf("tdx: expected_init_data_hash is %d bytes (max 48 for MR_CONFIG_ID)", len(d))
		}
		opts.TdQuoteBodyOptions.MrConfigID = pad(d, 48)
	}
	if d := params.ExpectedLaunchDigest; d != nil {
		if len(d) != 48 {
			return nil, fmt.Errorf("tdx: expected_launch_digest is %d bytes (want 48 for MR_TD)", len(d))
		}
		opts.TdQuoteBodyOptions.MrTd = d
	}
	if rtmrs := params.ExpectedRTMRs; rtmrs != nil {
		if len(rtmrs) > 4 {
			return nil, fmt.Errorf("tdx: expected_rtmrs has %d entries (max 4)", len(rtmrs))
		}
		// go-tdx-guest compares RTMRs positionally and requires the slice to be
		// either empty or exactly 4 entries; a nil/empty entry at index i skips
		// RTMR[i]. Emit a 4-slot slice, placing each provided value at its index.
		out := make([][]byte, 4)
		for i, r := range rtmrs {
			if r != nil && len(r) != 48 {
				return nil, fmt.Errorf("tdx: expected_rtmrs[%d] is %d bytes (want 48)", i, len(r))
			}
			out[i] = r
		}
		opts.TdQuoteBodyOptions.Rtmrs = out
	}
	return opts, nil
}

// quoteRTMRs re-parses a verified quote and returns its four RTMRs. Used to
// replay the CCEL against values the DCAP signature has already covered.
func quoteRTMRs(quoteBytes []byte) ([4][]byte, error) {
	var out [4][]byte
	anyQuote, err := tabi.QuoteToProto(quoteBytes)
	if err != nil {
		return out, fmt.Errorf("tdx: parsing quote for RTMRs: %w", err)
	}
	quote, ok := anyQuote.(*tpb.QuoteV4)
	if !ok {
		return out, fmt.Errorf("tdx: unsupported quote type %T (only QuoteV4 is supported)", anyQuote)
	}
	rtmrs := quote.GetTdQuoteBody().GetRtmrs()
	if len(rtmrs) != 4 {
		return out, fmt.Errorf("tdx: quote has %d RTMRs (want 4)", len(rtmrs))
	}
	copy(out[:], rtmrs)
	return out, nil
}

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// extractClaims normalizes a TDX quote into teetypes.Claims (mirrors
// attestation-rs tdx::claims::extract_claims).
func extractClaims(quote *tpb.QuoteV4) teetypes.Claims {
	body := quote.GetTdQuoteBody()
	rtmrs := body.GetRtmrs()
	rtmr := func(i int) string {
		if i < len(rtmrs) {
			return hex.EncodeToString(rtmrs[i])
		}
		return ""
	}

	platformData := map[string]any{
		"quote_version":        quote.GetHeader().GetVersion(),
		"tee_type":             fmt.Sprintf("0x%x", quote.GetHeader().GetTeeType()),
		"mr_seam":              hex.EncodeToString(body.GetMrSeam()),
		"mrsigner_seam":        hex.EncodeToString(body.GetMrSignerSeam()),
		"seam_attributes":      hex.EncodeToString(body.GetSeamAttributes()),
		"td_attributes":        hex.EncodeToString(body.GetTdAttributes()),
		"td_attributes_parsed": parseTdAttributes(body.GetTdAttributes()),
		"xfam":                 hex.EncodeToString(body.GetXfam()),
		"mr_config_id":         hex.EncodeToString(body.GetMrConfigId()),
		"mr_owner":             hex.EncodeToString(body.GetMrOwner()),
		"mr_owner_config":      hex.EncodeToString(body.GetMrOwnerConfig()),
		"rtmr_0":               rtmr(0),
		"rtmr_1":               rtmr(1),
		"rtmr_2":               rtmr(2),
		"rtmr_3":               rtmr(3),
	}

	return teetypes.Claims{
		LaunchDigest: hex.EncodeToString(body.GetMrTd()),
		ReportData:   body.GetReportData(),
		SignedData:   stripTrailingNulls(body.GetReportData()),
		InitData:     body.GetMrConfigId(),
		TCB: teetypes.TcbInfo{
			Type:   "Tdx",
			TCBSvn: append([]byte(nil), body.GetTeeTcbSvn()...),
		},
		PlatformData: platformData,
	}
}

// parseTdAttributes decodes the TD_ATTRIBUTES bitflags into named booleans.
func parseTdAttributes(raw []byte) map[string]any {
	if len(raw) < 8 {
		return map[string]any{}
	}
	bits := binary.LittleEndian.Uint64(raw)
	bit := func(n uint) bool { return bits&(1<<n) != 0 }
	return map[string]any{
		"debug":           bit(0),
		"septve_disable":  bit(28),
		"protection_keys": bit(30),
		"key_locker":      bit(31),
		"perfmon":         bit(63),
	}
}

func stripTrailingNulls(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}
