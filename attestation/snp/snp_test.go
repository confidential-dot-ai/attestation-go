package snp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/milan-report.bin
var milanReport []byte

//go:embed testdata/milan-vcek.der
var milanVcek []byte

//go:embed testdata/live-evidence-genoa.json
var genoaEvidence []byte

// TestVerifyReport_Milan exercises the full SNP verification core (report
// signature + ARK→ASK→VCEK chain against bundled Milan roots + policy validation
// + claims) on a real paired Milan report and VCEK. This is the shared path the
// az-snp verifier also drives.
func TestVerifyReport_Milan(t *testing.T) {
	report, vcek := milanReport, milanVcek

	res, err := VerifyReport(report, vcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if !res.SignatureValid || res.Platform != teetypes.PlatformSNP {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Claims.LaunchDigest) != 96 || res.Claims.TCB.Type != "Snp" || res.Claims.TCB.Snp == nil {
		t.Fatalf("unexpected claims: %+v", res.Claims)
	}

	// An absurd minimum-TCB floor must fail closed.
	hi := uint8(255)
	if _, err := VerifyReport(report, vcek, teetypes.VerifyParams{MinTCB: &teetypes.SnpTcb{Snp: hi}}, teetypes.PlatformSNP, MinReportVersionAzure, Options{}); err == nil {
		t.Fatal("absurd MinTCB should fail")
	}

	// A tampered report must fail the signature check.
	bad := append([]byte(nil), report...)
	bad[0x90] ^= 0xFF // flip a measurement byte
	if _, err := VerifyReport(bad, vcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{}); err == nil {
		t.Fatal("tampered report should fail")
	}
}

func TestVerifyEvidence_Errors(t *testing.T) {
	if _, err := VerifyEvidence(SnpEvidence{AttestationReport: "x"}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("missing vcek should fail")
	}
	if _, err := VerifyEvidence(SnpEvidence{AttestationReport: "!", CertChain: &SnpCertChain{Vcek: "AA"}}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("bad base64 report should fail")
	}
}

// TestVerifyEvidence_BareMetalEnvelope drives the bare-metal envelope path with a
// real Genoa-family fixture whose CPUID model (0xA0, Bergamo/Siena) go-sev-guest
// cannot classify offline. vcekProductRoots back-fills the Genoa roots from the
// VCEK certificate so verification succeeds end to end.
func TestVerifyEvidence_BareMetalEnvelope(t *testing.T) {
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(genoaEvidence, &env); err != nil {
		t.Fatal(err)
	}
	var ev SnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyEvidence(ev, teetypes.VerifyParams{}, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if !res.SignatureValid || res.Platform != teetypes.PlatformSNP {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Claims.LaunchDigest) != 96 || res.Claims.TCB.Type != "Snp" {
		t.Fatalf("unexpected claims: %+v", res.Claims)
	}
}

// genoaFixture returns the raw report and paired VCEK DER from the live
// Zen4c/Genoa evidence fixture.
func genoaFixture(t *testing.T) (report, vcek []byte) {
	t.Helper()
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(genoaEvidence, &env); err != nil {
		t.Fatal(err)
	}
	var ev SnpEvidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	report, err := base64.StdEncoding.DecodeString(ev.AttestationReport)
	if err != nil {
		t.Fatal(err)
	}
	vcek, err = base64.StdEncoding.DecodeString(ev.CertChain.Vcek)
	if err != nil {
		t.Fatal(err)
	}
	return report, vcek
}

// TestVerifyReportContext_FetchesZen4cVCEKFromGenoa is the regression test for
// the Siena `c8s verify` hang: a bare (VCEK-less) Zen4c report must resolve to
// the Genoa KDS URL and verify end to end. The fake getter serves the fixture's
// real VCEK under exactly that URL and 404s anything else, so a wrong product
// line (go-sev-guest derives "Unknown") fails the test.
func TestVerifyReportContext_FetchesZen4cVCEKFromGenoa(t *testing.T) {
	report, vcek := genoaFixture(t)
	rp, err := abi.ReportToProto(report)
	if err != nil {
		t.Fatal(err)
	}
	url := kds.VCEKCertURL("Genoa", rp.GetChipId(), kds.TCBVersion(rp.GetReportedTcb()))
	getter := test.SimpleGetter(map[string][]byte{url: vcek})

	res, err := VerifyReportContext(context.Background(), report, nil, teetypes.VerifyParams{},
		teetypes.PlatformSNP, MinReportVersion, Options{Getter: getter})
	if err != nil {
		t.Fatalf("VerifyReportContext with KDS fetch: %v", err)
	}
	if !res.SignatureValid || len(res.Claims.LaunchDigest) != 96 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// TestVerifyReportContext_KDSFailureIsCollateralError: a failing fetch must
// surface ErrCollateralUnavailable (so callers report availability, not a
// security verdict) and must return promptly when the context is cancelled
// even with a retrying getter — the original bug retried unbounded.
func TestVerifyReportContext_KDSFailureIsCollateralError(t *testing.T) {
	report, _ := genoaFixture(t)

	t.Run("fetch error wraps sentinel", func(t *testing.T) {
		_, err := VerifyReportContext(context.Background(), report, nil, teetypes.VerifyParams{},
			teetypes.PlatformSNP, MinReportVersion, Options{Getter: test.SimpleGetter(nil)})
		if !errors.Is(err, ErrCollateralUnavailable) {
			t.Fatalf("want ErrCollateralUnavailable, got %v", err)
		}
	})

	t.Run("cancelled ctx bounds a retrying getter", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		getter := &trust.RetryHTTPSGetter{MaxRetryDelay: time.Minute, Getter: test.SimpleGetter(nil)}
		start := time.Now()
		_, err := VerifyReportContext(ctx, report, nil, teetypes.VerifyParams{},
			teetypes.PlatformSNP, MinReportVersion, Options{Getter: getter})
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("cancelled ctx took %v, want prompt return", elapsed)
		}
		if !errors.Is(err, ErrCollateralUnavailable) {
			t.Fatalf("want ErrCollateralUnavailable, got %v", err)
		}
	})
}

// TestVerifyReport_MissingVCEKWithoutGetter pins the offline contract: no VCEK
// and no getter is an error, never an implicit network fetch.
func TestVerifyReport_MissingVCEKWithoutGetter(t *testing.T) {
	report, _ := genoaFixture(t)
	if _, err := VerifyReport(report, nil, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersion, Options{}); err == nil {
		t.Fatal("missing VCEK with no getter must fail")
	}
}

func TestKDSProductLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		fms  uint32
		want string // "" = expect an error
	}{
		{"Siena/Bergamo (Zen4c, model 0xA0) → Genoa", sienaFms, "Genoa"},
		{"Zen4c upper bound (family 0x19, model 0xAF)", 0x00aa0ff0, "Genoa"},
		{"Genoa proper (go-sev-guest's own table)", genoaFms, "Genoa"},
		{"Milan proper", 0x00a00f11, "Milan"},
		{"unknown family 0x1B", 0x00c00f00, ""},
		{"family 0x19 below Zen4c range (model 0x90)", 0x00a90f00, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kdsProductLine(tc.fms)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("kdsProductLine(%#x) = (%q, %v), want %q", tc.fms, got, err, tc.want)
			}
		})
	}
}

// TestVCEKProductRoots_Guards covers the cases where the VCEK product fallback
// must stay out of go-sev-guest's way and return no override.
func TestVCEKProductRoots_Guards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *spb.Report
		vcek   []byte
	}{
		{"v2 report (no CPUID)", &spb.Report{}, []byte{0x30}},
		{"v3 report without a VCEK", &spb.Report{Cpuid1EaxFms: sienaFms}, nil},
		{"classifiable v3 (Genoa)", &spb.Report{Cpuid1EaxFms: genoaFms}, []byte("ignored")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, err := vcekProductRoots(tc.report, tc.vcek)
			if err != nil || roots != nil {
				t.Fatalf("want (nil, nil); got (%v, %v)", roots, err)
			}
		})
	}
}

// Genoa-family CPUID_1_EAX values: genoaFms (family 0x19, model 0x11) is
// classifiable by go-sev-guest; sienaFms (model 0xA0, Zen4c) is not.
const (
	genoaFms = uint32(0x00a10f11)
	sienaFms = uint32(0x00aa0f02)
)

// TestVCEKProductRoots_GenoaVCEK proves the back-fill resolves an unclassifiable
// Zen4c CPUID (Siena, 0xA0) to the bundled Genoa roots by reading the product
// line from the VCEK certificate. The VCEK is minted by go-sev-guest's own
// test-only chain so the test is offline and deterministic.
func TestVCEKProductRoots_GenoaVCEK(t *testing.T) {
	signer, err := test.DefaultTestOnlyCertChain("Genoa", time.Now())
	if err != nil {
		t.Fatalf("DefaultTestOnlyCertChain: %v", err)
	}

	roots, err := vcekProductRoots(&spb.Report{Cpuid1EaxFms: sienaFms}, signer.Vcek.Raw)
	if err != nil {
		t.Fatalf("vcekProductRoots: %v", err)
	}

	// Roots must be keyed under the line go-sev-guest derives for the report
	// ("Unknown"), and the supplied root must be the bundled Genoa one.
	key := kds.ProductLineFromFms(sienaFms)
	if len(roots[key]) != 1 {
		t.Fatalf("want one root under %q; got %v", key, roots)
	}
	genoa, err := trust.GetDefaultRootCerts("Genoa")
	if err != nil {
		t.Fatalf("GetDefaultRootCerts(Genoa): %v", err)
	}
	if got := roots[key][0]; got.ProductLine != "Genoa" || got.ArkSev != genoa.ArkSev {
		t.Fatalf("supplied root is not the bundled Genoa root: %+v", got)
	}
}

// TestVCEKProductRoots_BadVCEK ensures an unclassifiable report carrying
// non-certificate VCEK bytes surfaces a parse error instead of silently
// skipping the back-fill.
func TestVCEKProductRoots_BadVCEK(t *testing.T) {
	if _, err := vcekProductRoots(&spb.Report{Cpuid1EaxFms: sienaFms}, []byte("not a certificate")); err == nil {
		t.Fatal("expected VCEK parse error, got nil")
	}
}

// TestValidateOptions covers the VerifyParams -> validate.Options mapping,
// including the report_data / init_data padding and size limits.
func TestValidateOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts, err := validateOptions(teetypes.VerifyParams{})
		if err != nil {
			t.Fatal(err)
		}
		if opts.VMPL == nil || *opts.VMPL != 0 {
			t.Errorf("VMPL = %v, want 0", opts.VMPL)
		}
		if !opts.GuestPolicy.SMT || !opts.GuestPolicy.MigrateMA || opts.GuestPolicy.Debug {
			t.Errorf("unexpected default guest policy: %+v", opts.GuestPolicy)
		}
		if opts.ReportData != nil || opts.HostData != nil {
			t.Errorf("expected no report_data/host_data; got %x / %x", opts.ReportData, opts.HostData)
		}
	})

	t.Run("report_data padded to 64", func(t *testing.T) {
		opts, err := validateOptions(teetypes.VerifyParams{ExpectedReportData: []byte{1, 2, 3}})
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte{1, 2, 3}, make([]byte, 61)...)
		if !bytes.Equal(opts.ReportData, want) {
			t.Errorf("report_data = %x, want %x", opts.ReportData, want)
		}
	})

	t.Run("init_data padded to 32 and debug honored", func(t *testing.T) {
		opts, err := validateOptions(teetypes.VerifyParams{ExpectedInitDataHash: []byte{9}, AllowDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(opts.HostData) != 32 || opts.HostData[0] != 9 {
			t.Errorf("host_data = %x, want 9 padded to 32", opts.HostData)
		}
		if !opts.GuestPolicy.Debug {
			t.Error("AllowDebug should set GuestPolicy.Debug")
		}
	})

	t.Run("MinTCB mapped", func(t *testing.T) {
		opts, err := validateOptions(teetypes.VerifyParams{MinTCB: &teetypes.SnpTcb{Bootloader: 1, Tee: 2, Snp: 3, Microcode: 4}})
		if err != nil {
			t.Fatal(err)
		}
		want := kds.TCBParts{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, UcodeSpl: 4}
		if opts.MinimumTCB != want {
			t.Errorf("MinimumTCB = %+v, want %+v", opts.MinimumTCB, want)
		}
	})

	t.Run("oversize inputs rejected", func(t *testing.T) {
		if _, err := validateOptions(teetypes.VerifyParams{ExpectedReportData: make([]byte, 65)}); err == nil {
			t.Error("report_data > 64 should error")
		}
		if _, err := validateOptions(teetypes.VerifyParams{ExpectedInitDataHash: make([]byte, 33)}); err == nil {
			t.Error("init_data_hash > 32 should error")
		}
	})

	t.Run("launch_digest mapped and size-checked", func(t *testing.T) {
		md := make([]byte, 48)
		md[0] = 0xAB
		opts, err := validateOptions(teetypes.VerifyParams{ExpectedLaunchDigest: md})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opts.Measurement, md) {
			t.Errorf("Measurement = %x, want %x", opts.Measurement, md)
		}
		if _, err := validateOptions(teetypes.VerifyParams{ExpectedLaunchDigest: make([]byte, 32)}); err == nil {
			t.Error("launch_digest != 48 bytes should error")
		}
	})
}

// TestVerifyReport_LaunchDigest pins the launch measurement on the real Milan
// fixture: feeding the report's own MEASUREMENT back must verify and set
// LaunchDigestMatch; a wrong digest must fail closed.
func TestVerifyReport_LaunchDigest(t *testing.T) {
	base, err := VerifyReport(milanReport, milanVcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("baseline VerifyReport: %v", err)
	}
	md, err := hex.DecodeString(base.Claims.LaunchDigest)
	if err != nil {
		t.Fatalf("decoding launch digest: %v", err)
	}

	res, err := VerifyReport(milanReport, milanVcek, teetypes.VerifyParams{ExpectedLaunchDigest: md}, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("VerifyReport with launch digest: %v", err)
	}
	if res.LaunchDigestMatch == nil || !*res.LaunchDigestMatch {
		t.Errorf("LaunchDigestMatch = %v, want true", res.LaunchDigestMatch)
	}

	wrong := append([]byte(nil), md...)
	wrong[0] ^= 0xFF
	if _, err := VerifyReport(milanReport, milanVcek, teetypes.VerifyParams{ExpectedLaunchDigest: wrong}, teetypes.PlatformSNP, MinReportVersionAzure, Options{}); err == nil {
		t.Fatal("wrong launch digest must be rejected")
	}
}

// TestVerifyReport_BindingFlags exercises the report_data / init_data binding
// reporting on the real Milan fixture: feeding the report's own values back must
// verify and set the match flags.
func TestVerifyReport_BindingFlags(t *testing.T) {
	base, err := VerifyReport(milanReport, milanVcek, teetypes.VerifyParams{}, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("baseline VerifyReport: %v", err)
	}

	params := teetypes.VerifyParams{
		ExpectedReportData:   base.Claims.ReportData,
		ExpectedInitDataHash: base.Claims.InitData,
	}
	res, err := VerifyReport(milanReport, milanVcek, params, teetypes.PlatformSNP, MinReportVersionAzure, Options{})
	if err != nil {
		t.Fatalf("VerifyReport with bindings: %v", err)
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		t.Errorf("ReportDataMatch = %v, want true", res.ReportDataMatch)
	}
	if res.InitDataMatch == nil || !*res.InitDataMatch {
		t.Errorf("InitDataMatch = %v, want true", res.InitDataMatch)
	}
}
