package remote

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// VerifyResponse is the body of a successful POST /verify.
//
// A 200 means the service found the evidence genuine: the hardware signature
// and its certificate chain verify. It does not mean the evidence satisfied
// the policy; that is Passed, and every caller must gate on it, which
// [Client.VerifyEnforced] does. Result carries the verified claims and the
// outcome of each check the request asked for, in the shape the in-process
// verifiers also produce, so pins read it the same way wherever the verdict
// came from. Checks keeps the service's per-rule outcomes that have no place
// in Result.
//
// On the wire the service answers {result, passed, token}, with result the
// platform's own result object; [VerifyResponse.UnmarshalJSON] maps that onto
// these fields and [VerifyResponse.MarshalJSON] produces it, so a stub can
// answer with this type.
type VerifyResponse struct {
	Result teetypes.VerificationResult
	Passed bool
	Checks ServiceChecks
	Token  *string
}

// ServiceChecks are the outcomes of the rules the service applied, as it
// reported them. A nil pointer means the request did not ask for that check.
// They are informational beside Result; [EnforceVerdict] reads them to name
// the rule a rejection failed.
type ServiceChecks struct {
	// Debug is whether the guest allows debug, AllowDebug whether the params
	// accepted that.
	Debug      bool
	AllowDebug bool
	// MigrateMA is whether the SEV-SNP guest policy allows a migration agent,
	// which the service never accepts.
	MigrateMA bool
	// VMPL is the privilege level the SEV-SNP report came from; MaxVMPL the
	// highest the params accepted.
	VMPL    uint32
	MaxVMPL uint32
	// MinTcbMet is whether the SEV-SNP TCB floor held.
	MinTcbMet *bool
	// CRLOK is whether no certificate in the chain is revoked.
	CRLOK *bool
	// TCBStatusAccepted is whether the TDX TCB status is one the params accept.
	TCBStatusAccepted *bool
	// PCRsMatch is whether every pinned vTPM PCR matched (Azure platforms).
	PCRsMatch *bool
	// EndorsementMatch is whether the firmware matched Google's launch
	// endorsement (GCP platforms).
	EndorsementMatch *bool
	// Collateral lists every piece of collateral the verdict used.
	Collateral []CollateralUsed
}

// CollateralUsed is one piece of vendor collateral (CRL, TCB info, QE
// identity, …) the service used and where it had it from.
type CollateralUsed struct {
	Name       string  `json:"name"`
	From       string  `json:"from"`
	Version    *uint64 `json:"version"`
	NextUpdate *int64  `json:"next_update"`
	// Current is whether the piece was within its validity window; Stale
	// whether it was past it but inside the grace period.
	Current bool `json:"current"`
	Stale   bool `json:"stale"`
	// Floor is the lowest version accepted, when one applies.
	Floor *uint64 `json:"floor,omitempty"`
}

// verifyWire is the body as the service writes it.
type verifyWire struct {
	Result resultWire `json:"result"`
	Passed bool       `json:"passed"`
	Token  *string    `json:"token,omitempty"`
}

// resultWire is the union of every platform's result object. The service
// flattens the platform result and tags it with "platform"; fields another
// platform does not have are absent.
type resultWire struct {
	Platform teetypes.PlatformType `json:"platform"`
	Claims   teetypes.Claims       `json:"claims"`

	ReportDataMatch *bool `json:"report_data_match"`
	// SEV-SNP names the init-data check host_data_match, TDX init_data_match.
	HostDataMatch *bool `json:"host_data_match,omitempty"`
	InitDataMatch *bool `json:"init_data_match,omitempty"`
	// SEV-SNP names the launch measurement check launch_digest_match, TDX
	// mrtd_match.
	LaunchDigestMatch         *bool                            `json:"launch_digest_match,omitempty"`
	MRTDMatch                 *bool                            `json:"mrtd_match,omitempty"`
	RTMRMatch                 []*bool                          `json:"rtmr_match,omitempty"`
	Debug                     bool                             `json:"debug"`
	AllowDebug                bool                             `json:"allow_debug"`
	MigrateMA                 *bool                            `json:"migrate_ma,omitempty"`
	VMPL                      *uint32                          `json:"vmpl,omitempty"`
	MaxVMPL                   *uint32                          `json:"max_vmpl,omitempty"`
	MinTcbMet                 *bool                            `json:"min_tcb_met,omitempty"`
	CRLOK                     *bool                            `json:"crl_ok"`
	TCBStatus                 *teetypes.DcapVerificationStatus `json:"tcb_status,omitempty"`
	TCBStatusAccepted         *bool                            `json:"tcb_status_accepted,omitempty"`
	MeasurementRegisters      *teetypes.MeasurementRegisters   `json:"measurement_registers,omitempty"`
	MeasurementRegistersMatch *bool                            `json:"measurement_registers_match,omitempty"`
	PCRsMatch                 *bool                            `json:"pcrs_match,omitempty"`
	EndorsementMatch          *bool                            `json:"endorsement_match,omitempty"`
	Collateral                []CollateralUsed                 `json:"collateral"`
}

// UnmarshalJSON reads the service's {result, passed, token}.
func (r *VerifyResponse) UnmarshalJSON(data []byte) error {
	var w verifyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	res := w.Result
	out := VerifyResponse{
		Passed: w.Passed,
		Token:  w.Token,
		Result: teetypes.VerificationResult{
			// The service answers 200 only for evidence whose signature and
			// chain verify; anything else is a 422.
			SignatureValid:  true,
			Platform:        res.Platform,
			Claims:          res.Claims,
			ReportDataMatch: res.ReportDataMatch,
			TCBStatus:       res.TCBStatus,
			// As for the in-process verifiers: whether revocation was
			// checked. The service reports crl_ok whenever it was.
			CollateralVerified:        res.CRLOK != nil,
			MeasurementRegisters:      res.MeasurementRegisters,
			MeasurementRegistersMatch: res.MeasurementRegistersMatch,
		},
		Checks: ServiceChecks{
			Debug:             res.Debug,
			AllowDebug:        res.AllowDebug,
			MinTcbMet:         res.MinTcbMet,
			CRLOK:             res.CRLOK,
			TCBStatusAccepted: res.TCBStatusAccepted,
			PCRsMatch:         res.PCRsMatch,
			EndorsementMatch:  res.EndorsementMatch,
			Collateral:        res.Collateral,
		},
	}
	if res.MigrateMA != nil {
		out.Checks.MigrateMA = *res.MigrateMA
	}
	if res.VMPL != nil {
		out.Checks.VMPL = *res.VMPL
	}
	if res.MaxVMPL != nil {
		out.Checks.MaxVMPL = *res.MaxVMPL
	}
	// One concept, two names: the field present is the platform's.
	switch {
	case res.HostDataMatch != nil:
		out.Result.InitDataMatch = res.HostDataMatch
	case res.InitDataMatch != nil:
		out.Result.InitDataMatch = res.InitDataMatch
	}
	switch {
	case res.LaunchDigestMatch != nil:
		out.Result.LaunchDigestMatch = res.LaunchDigestMatch
	case res.MRTDMatch != nil:
		out.Result.LaunchDigestMatch = res.MRTDMatch
	}
	if len(res.RTMRMatch) > 4 {
		return fmt.Errorf("remote: /verify result carries %d rtmr_match entries, want at most 4", len(res.RTMRMatch))
	}
	for i, m := range res.RTMRMatch {
		out.Result.SetRTMRMatch(i, m)
	}
	*r = out
	return nil
}

// MarshalJSON writes the service's {result, passed, token} from the mapped
// fields, so stubs and tests answer in the shape a client decodes. The
// platform family picks the field names, so Result.Platform must be set.
func (r VerifyResponse) MarshalJSON() ([]byte, error) {
	res := r.Result
	w := verifyWire{
		Passed: r.Passed,
		Token:  r.Token,
		Result: resultWire{
			Platform:                  res.Platform,
			Claims:                    res.Claims,
			ReportDataMatch:           res.ReportDataMatch,
			Debug:                     r.Checks.Debug,
			AllowDebug:                r.Checks.AllowDebug,
			CRLOK:                     r.Checks.CRLOK,
			TCBStatus:                 res.TCBStatus,
			TCBStatusAccepted:         r.Checks.TCBStatusAccepted,
			MeasurementRegisters:      res.MeasurementRegisters,
			MeasurementRegistersMatch: res.MeasurementRegistersMatch,
			PCRsMatch:                 r.Checks.PCRsMatch,
			EndorsementMatch:          r.Checks.EndorsementMatch,
			Collateral:                r.Checks.Collateral,
		},
	}
	if w.Result.Collateral == nil {
		w.Result.Collateral = []CollateralUsed{}
	}
	switch res.Platform.Family() {
	case teetypes.FamilySNP:
		w.Result.HostDataMatch = res.InitDataMatch
		w.Result.LaunchDigestMatch = res.LaunchDigestMatch
		w.Result.MigrateMA = teetypes.Ptr(r.Checks.MigrateMA)
		w.Result.VMPL = teetypes.Ptr(r.Checks.VMPL)
		w.Result.MaxVMPL = teetypes.Ptr(r.Checks.MaxVMPL)
		w.Result.MinTcbMet = r.Checks.MinTcbMet
	case teetypes.FamilyTDX:
		w.Result.InitDataMatch = res.InitDataMatch
		w.Result.MRTDMatch = res.LaunchDigestMatch
		w.Result.RTMRMatch = []*bool{res.RTMR0Match, res.RTMR1Match, res.RTMR2Match, res.RTMR3Match}
	default:
		return nil, fmt.Errorf("remote: a VerifyResponse needs a platform to pick its field names, got %q", res.Platform)
	}
	return json.Marshal(w)
}
