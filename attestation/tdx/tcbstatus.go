package tdx

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/google/go-tdx-guest/pcs"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
	tverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// tcbStatusOrder ranks the Intel TCB statuses from most to least favourable;
// a result reports the last-ranked status among its matched levels.
var tcbStatusOrder = []teetypes.TdxTcbStatus{
	teetypes.TdxUpToDate,
	teetypes.TdxSWHardeningNeeded,
	teetypes.TdxConfigurationNeeded,
	teetypes.TdxConfigurationAndSWHardeningNeeded,
	teetypes.TdxOutOfDate,
	teetypes.TdxOutOfDateConfigurationNeeded,
	teetypes.TdxRevoked,
}

// ParseTCBStatus returns the TdxTcbStatus spelled s, using Intel PCS
// spelling (for example "SWHardeningNeeded").
func ParseTCBStatus(s string) (teetypes.TdxTcbStatus, error) {
	status := teetypes.TdxTcbStatus(s)
	if !slices.Contains(tcbStatusOrder, status) {
		return "", fmt.Errorf("unknown TDX TCB status %q", s)
	}
	return status, nil
}

func checkAcceptedTCBStatuses(opts Options) error {
	if len(opts.AcceptedTCBStatuses) == 0 {
		return nil
	}
	if !opts.GetCollateral {
		return fmt.Errorf("tdx: AcceptedTCBStatuses requires GetCollateral")
	}
	for _, status := range opts.AcceptedTCBStatuses {
		if _, err := ParseTCBStatus(string(status)); err != nil {
			return fmt.Errorf("tdx: AcceptedTCBStatuses: %w", err)
		}
		if status == teetypes.TdxRevoked {
			return fmt.Errorf("tdx: AcceptedTCBStatuses cannot accept %s", status)
		}
	}
	return nil
}

// collateralRecorder keeps every response body go-tdx-guest fetches. Once the
// quote verifies, go-tdx-guest has checked the Intel signatures over exactly
// these bodies, so their TCB levels can be evaluated here.
type collateralRecorder struct {
	inner trust.HTTPSGetter

	mu     sync.Mutex
	bodies map[string][]byte
}

func newCollateralRecorder(inner trust.HTTPSGetter) *collateralRecorder {
	if inner == nil {
		// The same default go-tdx-guest falls back to.
		inner = trust.DefaultHTTPSGetter()
	}
	return &collateralRecorder{inner: inner, bodies: make(map[string][]byte)}
}

func (r *collateralRecorder) Get(url string) (map[string][]string, []byte, error) {
	return r.GetContext(context.Background(), url)
}

func (r *collateralRecorder) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	header, body, err := trust.GetWith(ctx, r.inner, url)
	if err == nil {
		r.mu.Lock()
		r.bodies[url] = body
		r.mu.Unlock()
	}
	return header, body, err
}

func (r *collateralRecorder) body(url string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bodies[url]
	if !ok {
		return nil, fmt.Errorf("tdx: collateral %s was not fetched", url)
	}
	return b, nil
}

// evaluateTCBStatus matches the verified quote against the recorded TCB info
// and QE identity, and requires every matched level's status to be accepted.
func evaluateTCBStatus(quote *tpb.QuoteV4, recorder *collateralRecorder, accepted []teetypes.TdxTcbStatus) (*teetypes.DcapVerificationStatus, error) {
	chain, err := tverify.ExtractChainFromQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("tdx: TCB status: %w", err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, fmt.Errorf("tdx: TCB status: PCK certificate extensions: %w", err)
	}
	tcbInfoBody, err := recorder.body(pcs.TcbInfoURL(exts.FMSPC))
	if err != nil {
		return nil, err
	}
	qeIdentityBody, err := recorder.body(pcs.QeIdentityURL())
	if err != nil {
		return nil, err
	}
	var tcbInfo pcs.TdxTcbInfo
	if err := json.Unmarshal(tcbInfoBody, &tcbInfo); err != nil {
		return nil, fmt.Errorf("tdx: TCB status: parse TCB info: %w", err)
	}
	var qeIdentity pcs.QeIdentity
	if err := json.Unmarshal(qeIdentityBody, &qeIdentity); err != nil {
		return nil, fmt.Errorf("tdx: TCB status: parse QE identity: %w", err)
	}
	qeIsvSvn := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport().GetIsvSvn()
	levels, err := matchTCBLevels(tcbInfo.TcbInfo, qeIdentity.EnclaveIdentity, quote.GetTdQuoteBody().GetTeeTcbSvn(), exts.TCB, qeIsvSvn)
	if err != nil {
		return nil, fmt.Errorf("tdx: TCB status: %w", err)
	}

	status := &teetypes.DcapVerificationStatus{FMSPC: exts.FMSPC}
	worst := -1
	for _, l := range levels {
		s := teetypes.TdxTcbStatus(l.level.TcbStatus)
		if !slices.Contains(accepted, s) {
			return nil, fmt.Errorf("tdx: %s TCB status %s is not accepted (accepted: %v)", l.name, s, accepted)
		}
		if rank := slices.Index(tcbStatusOrder, s); rank > worst {
			worst = rank
			status.TCBStatus = s
		}
		for _, id := range l.level.AdvisoryIDs {
			if !slices.Contains(status.AdvisoryIDs, id) {
				status.AdvisoryIDs = append(status.AdvisoryIDs, id)
			}
		}
	}
	return status, nil
}

type namedTCBLevel struct {
	name  string
	level pcs.TcbLevel
}

// matchTCBLevels selects, as Intel's quote verification library does, the
// first (highest) TCB level each component meets: the platform level from the
// PCK certificate's SGX SVNs and PCESVN and the quote's TEE_TCB_SVN, the TDX
// module level when TEE_TCB_SVN[1] names a module identity, and the QE level
// from the QE report's ISVSVN.
func matchTCBLevels(info pcs.TcbInfo, qe pcs.EnclaveIdentity, teeTcbSvn []byte, pck pcs.PckCertTCB, qeIsvSvn uint32) ([]namedTCBLevel, error) {
	if len(teeTcbSvn) != 16 {
		return nil, fmt.Errorf("TEE_TCB_SVN is %d bytes, want 16", len(teeTcbSvn))
	}
	platform, err := matchPlatformLevel(info.TcbLevels, teeTcbSvn, pck)
	if err != nil {
		return nil, err
	}
	levels := []namedTCBLevel{{"platform", platform}}

	if teeTcbSvn[1] > 0 {
		module, err := matchModuleLevel(info.TdxModuleIdentities, teeTcbSvn)
		if err != nil {
			return nil, err
		}
		levels = append(levels, namedTCBLevel{"TDX module", module})
	}

	qeLevel, ok := firstLevel(qe.TcbLevels, func(l pcs.TcbLevel) bool { return qeIsvSvn >= l.Tcb.Isvsvn })
	if !ok {
		return nil, fmt.Errorf("no QE identity TCB level matches QE ISVSVN %d", qeIsvSvn)
	}
	return append(levels, namedTCBLevel{"QE", qeLevel}), nil
}

func matchPlatformLevel(levels []pcs.TcbLevel, teeTcbSvn []byte, pck pcs.PckCertTCB) (pcs.TcbLevel, error) {
	// With a module identity in TEE_TCB_SVN[1], SVNs 0 and 1 are the module's
	// and are matched against its identity instead.
	start := 0
	if teeTcbSvn[1] > 0 {
		start = 2
	}
	level, ok := firstLevel(levels, func(l pcs.TcbLevel) bool {
		if len(l.Tcb.SgxTcbcomponents) != len(pck.CPUSvnComponents) || len(l.Tcb.TdxTcbcomponents) != len(teeTcbSvn) {
			return false
		}
		for i, c := range l.Tcb.SgxTcbcomponents {
			if pck.CPUSvnComponents[i] < c.Svn {
				return false
			}
		}
		if pck.PCESvn < l.Tcb.Pcesvn {
			return false
		}
		for i := start; i < len(teeTcbSvn); i++ {
			if teeTcbSvn[i] < l.Tcb.TdxTcbcomponents[i].Svn {
				return false
			}
		}
		return true
	})
	if !ok {
		return pcs.TcbLevel{}, fmt.Errorf("no platform TCB level matches the PCK certificate and TEE_TCB_SVN")
	}
	return level, nil
}

func matchModuleLevel(identities []pcs.TdxModuleIdentity, teeTcbSvn []byte) (pcs.TcbLevel, error) {
	id := "TDX_" + hex.EncodeToString(teeTcbSvn[1:2])
	for _, identity := range identities {
		if identity.ID != id {
			continue
		}
		level, ok := firstLevel(identity.TcbLevels, func(l pcs.TcbLevel) bool { return uint32(teeTcbSvn[0]) >= l.Tcb.Isvsvn })
		if !ok {
			return pcs.TcbLevel{}, fmt.Errorf("no %s TCB level matches module ISVSVN %d", id, teeTcbSvn[0])
		}
		return level, nil
	}
	return pcs.TcbLevel{}, fmt.Errorf("TCB info has no TDX module identity %s", id)
}

// firstLevel returns the first level meeting match; Intel lists levels from
// highest to lowest.
func firstLevel(levels []pcs.TcbLevel, match func(pcs.TcbLevel) bool) (pcs.TcbLevel, bool) {
	for _, l := range levels {
		if match(l) {
			return l, true
		}
	}
	return pcs.TcbLevel{}, false
}
