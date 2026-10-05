package tdx

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
	testcases "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
	tverify "github.com/google/go-tdx-guest/verify"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// sampleCollateralTime is inside the validity window of go-tdx-guest's sample
// quote and collateral.
var sampleCollateralTime = time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)

func TestCheckAcceptedTCBStatuses(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{"unset", Options{}, ""},
		{"accepted with collateral", Options{GetCollateral: true, AcceptedTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxSWHardeningNeeded}}, ""},
		{"no collateral", Options{AcceptedTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}}, "requires GetCollateral"},
		{"revoked", Options{GetCollateral: true, AcceptedTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxRevoked}}, "cannot accept Revoked"},
		{"unknown", Options{GetCollateral: true, AcceptedTCBStatuses: []teetypes.TdxTcbStatus{"uptodate"}}, "unknown TDX TCB status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAcceptedTCBStatuses(tt.opts)
			if !errorContains(err, tt.wantErr) {
				t.Errorf("checkAcceptedTCBStatuses() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMatchTCBLevels(t *testing.T) {
	pck := pcs.PckCertTCB{PCESvn: 11, CPUSvnComponents: svns(16, 5)}
	// platformLevel requires tdx of every TDX component except index 1, the
	// module version, which Intel's levels leave at 0.
	platformLevel := func(status pcs.TcbComponentStatus, sgx, pce, tdx byte) pcs.TcbLevel {
		tdxComponents := components(16, tdx)
		tdxComponents[1].Svn = 0
		return pcs.TcbLevel{
			TcbStatus: status,
			Tcb: pcs.Tcb{
				SgxTcbcomponents: components(16, sgx),
				Pcesvn:           uint16(pce),
				TdxTcbcomponents: tdxComponents,
			},
		}
	}
	isvLevel := func(status pcs.TcbComponentStatus, isvsvn uint32) pcs.TcbLevel {
		return pcs.TcbLevel{TcbStatus: status, Tcb: pcs.Tcb{Isvsvn: isvsvn}}
	}
	info := pcs.TcbInfo{
		TcbLevels: []pcs.TcbLevel{
			platformLevel(pcs.TcbComponentStatusUpToDate, 5, 11, 4),
			platformLevel(pcs.TcbComponentStatusSwHardeningNeeded, 5, 11, 3),
			platformLevel(pcs.TcbComponentStatusOutOfDate, 0, 0, 0),
		},
		TdxModuleIdentities: []pcs.TdxModuleIdentity{{
			ID:        "TDX_01",
			TcbLevels: []pcs.TcbLevel{isvLevel(pcs.TcbComponentStatusUpToDate, 3), isvLevel(pcs.TcbComponentStatusOutOfDate, 0)},
		}},
	}
	qe := pcs.EnclaveIdentity{TcbLevels: []pcs.TcbLevel{isvLevel(pcs.TcbComponentStatusUpToDate, 8), isvLevel(pcs.TcbComponentStatusOutOfDate, 0)}}

	// teeTcbSvn builds a TEE_TCB_SVN with every SVN set to rest, after the
	// module ISVSVN and module version.
	teeTcbSvn := func(moduleSvn, moduleVersion, rest byte) []byte {
		b := svns(16, rest)
		b[0], b[1] = moduleSvn, moduleVersion
		return b
	}

	tests := []struct {
		name      string
		teeTcbSvn []byte
		pck       pcs.PckCertTCB
		qeIsvSvn  uint32
		want      []string
		wantErr   string
	}{
		{"all up to date", teeTcbSvn(4, 0, 4), pck, 8, []string{"platform=UpToDate", "QE=UpToDate"}, ""},
		{"lower TDX SVN falls to the next level", teeTcbSvn(3, 0, 3), pck, 8, []string{"platform=SWHardeningNeeded", "QE=UpToDate"}, ""},
		{"lower PCE SVN falls to the last level", teeTcbSvn(4, 0, 4), pcs.PckCertTCB{PCESvn: 10, CPUSvnComponents: svns(16, 5)}, 8, []string{"platform=OutOfDate", "QE=UpToDate"}, ""},
		{"lower SGX SVN falls to the last level", teeTcbSvn(4, 0, 4), pcs.PckCertTCB{PCESvn: 11, CPUSvnComponents: svns(16, 4)}, 8, []string{"platform=OutOfDate", "QE=UpToDate"}, ""},
		{"old QE", teeTcbSvn(4, 0, 4), pck, 7, []string{"platform=UpToDate", "QE=OutOfDate"}, ""},
		// With a module version, SVNs 0 and 1 belong to the module: the
		// platform match ignores them and the module identity rates them.
		{"module up to date", teeTcbSvn(3, 1, 4), pck, 8, []string{"platform=UpToDate", "TDX module=UpToDate", "QE=UpToDate"}, ""},
		{"module out of date", teeTcbSvn(2, 1, 4), pck, 8, []string{"platform=UpToDate", "TDX module=OutOfDate", "QE=UpToDate"}, ""},
		{"platform out of date with module up to date", teeTcbSvn(3, 1, 2), pcs.PckCertTCB{PCESvn: 10, CPUSvnComponents: svns(16, 5)}, 8, []string{"platform=OutOfDate", "TDX module=UpToDate", "QE=UpToDate"}, ""},
		{"unknown module", teeTcbSvn(3, 2, 4), pck, 8, nil, "no TDX module identity TDX_02"},
		{"short TEE_TCB_SVN", svns(15, 4), pck, 8, nil, "want 16"},
		{"short CPUSVN", teeTcbSvn(4, 0, 4), pcs.PckCertTCB{PCESvn: 11, CPUSvnComponents: svns(15, 5)}, 8, nil, "no platform TCB level matches"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			levels, err := matchTCBLevels(info, qe, tt.teeTcbSvn, tt.pck, tt.qeIsvSvn)
			if !errorContains(err, tt.wantErr) {
				t.Fatalf("matchTCBLevels() error = %v, want error containing %q", err, tt.wantErr)
			}
			var got []string
			for _, l := range levels {
				got = append(got, fmt.Sprintf("%s=%s", l.name, l.level.TcbStatus))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("matchTCBLevels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateTCBStatus(t *testing.T) {
	quote := sampleQuote(t)
	teeTcbSvn := quote.GetTdQuoteBody().GetTeeTcbSvn()
	chain, err := tverify.ExtractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}

	// recorderWith serves collateral whose single levels match the sample
	// quote with the given statuses and advisories.
	recorderWith := func(platform, module, qe pcs.TcbComponentStatus) *collateralRecorder {
		// pcs.HexBytes has no MarshalJSON, so the documents are built from
		// maps holding only the fields the evaluation reads.
		lowest := pcs.Tcb{SgxTcbcomponents: components(16, 0), TdxTcbcomponents: components(16, 0)}
		info := map[string]any{
			"tcbLevels": []pcs.TcbLevel{{Tcb: lowest, TcbStatus: platform, AdvisoryIDs: []string{"INTEL-SA-1", "INTEL-SA-2"}}},
		}
		if teeTcbSvn[1] > 0 {
			info["tdxModuleIdentities"] = []map[string]any{{
				"id":        fmt.Sprintf("TDX_%02x", teeTcbSvn[1]),
				"tcbLevels": []pcs.TcbLevel{{TcbStatus: module, AdvisoryIDs: []string{"INTEL-SA-2"}}},
			}}
		}
		qeIdentity := map[string]any{
			"tcbLevels": []pcs.TcbLevel{{TcbStatus: qe, AdvisoryIDs: []string{"INTEL-SA-3"}}},
		}
		r := newCollateralRecorder(testcases.TestGetter)
		r.bodies[pcs.TcbInfoURL(exts.FMSPC)] = mustJSON(t, map[string]any{"tcbInfo": info})
		r.bodies[pcs.QeIdentityURL()] = mustJSON(t, map[string]any{"enclaveIdentity": qeIdentity})
		return r
	}
	upToDate := pcs.TcbComponentStatusUpToDate
	hardening := pcs.TcbComponentStatusSwHardeningNeeded
	config := pcs.TcbComponentStatusConfigurationNeeded

	tests := []struct {
		name       string
		recorder   *collateralRecorder
		accepted   []teetypes.TdxTcbStatus
		wantStatus teetypes.TdxTcbStatus
		wantErr    string
	}{
		{"up to date", recorderWith(upToDate, upToDate, upToDate), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}, teetypes.TdxUpToDate, ""},
		{"platform needs hardening, accepted", recorderWith(hardening, upToDate, upToDate), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxSWHardeningNeeded}, teetypes.TdxSWHardeningNeeded, ""},
		{"platform needs hardening, refused", recorderWith(hardening, upToDate, upToDate), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}, "", "platform TCB status SWHardeningNeeded is not accepted"},
		{"QE needs configuration, refused", recorderWith(upToDate, upToDate, config), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxSWHardeningNeeded}, "", "QE TCB status ConfigurationNeeded is not accepted"},
		{"least favourable is reported", recorderWith(hardening, upToDate, config), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxSWHardeningNeeded, teetypes.TdxConfigurationNeeded}, teetypes.TdxConfigurationNeeded, ""},
		{"collateral not fetched", newCollateralRecorder(testcases.TestGetter), []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}, "", "was not fetched"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateTCBStatus(quote, tt.recorder, tt.accepted)
			if !errorContains(err, tt.wantErr) {
				t.Fatalf("evaluateTCBStatus() error = %v, want error containing %q", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.TCBStatus != tt.wantStatus || got.FMSPC != exts.FMSPC {
				t.Errorf("evaluateTCBStatus() = %+v, want status %s and FMSPC %s", got, tt.wantStatus, exts.FMSPC)
			}
			wantAdvisories := []string{"INTEL-SA-1", "INTEL-SA-2", "INTEL-SA-3"}
			if !slices.Equal(got.AdvisoryIDs, wantAdvisories) {
				t.Errorf("evaluateTCBStatus() advisories = %v, want %v", got.AdvisoryIDs, wantAdvisories)
			}
		})
	}
}

// TestVerifyQuoteBytes_TCBStatusPolicy runs the sample quote against its
// signed sample collateral, whose TCB levels the quote does not meet.
func TestVerifyQuoteBytes_TCBStatusPolicy(t *testing.T) {
	collateral := Options{GetCollateral: true, CheckRevocations: true, Getter: testcases.TestGetter, Now: sampleCollateralTime}
	withAccepted := collateral
	withAccepted.AcceptedTCBStatuses = []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxOutOfDate}

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{"go-tdx-guest status check", collateral, "failed TCB status check"},
		{"accepted statuses", withAccepted, "tdx: TCB status: no platform TCB level matches"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyQuoteBytes(testdata.RawQuote, teetypes.VerifyParams{AllowDebug: true}, teetypes.PlatformTDX, tt.opts)
			if !errorContains(err, tt.wantErr) {
				t.Errorf("VerifyQuoteBytes() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func sampleQuote(t *testing.T) *tpb.QuoteV4 {
	t.Helper()
	anyQuote, err := tabi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*tpb.QuoteV4)
	if !ok {
		t.Fatalf("sample quote is %T, want *QuoteV4", anyQuote)
	}
	return quote
}

func svns(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func components(n int, svn byte) []pcs.TcbComponent {
	c := make([]pcs.TcbComponent, n)
	for i := range c {
		c[i].Svn = svn
	}
	return c
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func errorContains(err error, want string) bool {
	if want == "" {
		return err == nil
	}
	return err != nil && strings.Contains(err.Error(), want)
}
