package armtls

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// legacyASN1 is the extension body as v0.8.0 verifiers, and the CDS issuer's
// verbatim copy of it, decode it.
type legacyASN1 struct {
	TEEType   int
	Report    []byte
	CertChain []byte
}

const tdxEnvelope = `{"platform":"tdx","evidence":{"quote":"AAAA"}}`

func digests(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "sha256:" + strings.Repeat(hex.EncodeToString([]byte{byte(i + 1)}), 32)
	}
	return out
}

func tdxAttestation(t *testing.T, list []string) *Attestation {
	t.Helper()
	att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{TEEType: wireTDX, Report: []byte(tdxEnvelope)}))
	if err != nil {
		t.Fatalf("UnmarshalExtension: %v", err)
	}
	att.RuntimeExtensions = list
	return att
}

func TestRuntimeExtensionsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		list []string
	}{
		{"absent", nil},
		{"empty is absent", []string{}},
		{"three digests", digests(3)},
		{"at the cap", digests(MaxRuntimeExtensions)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext, err := tdxAttestation(t, tc.list).MarshalExtension(testOID)
			if err != nil {
				t.Fatalf("MarshalExtension: %v", err)
			}
			got, err := UnmarshalExtension(ext.Value)
			if err != nil {
				t.Fatalf("UnmarshalExtension: %v", err)
			}
			want := tc.list
			if len(want) == 0 {
				want = nil
			}
			if !slices.Equal(got.RuntimeExtensions, want) || (want == nil && got.RuntimeExtensions != nil) {
				t.Fatalf("RuntimeExtensions = %q, want %q", got.RuntimeExtensions, want)
			}

			if len(tc.list) == 0 {
				legacy, err := asn1.Marshal(legacyASN1{TEEType: wireTDX, Report: []byte(tdxEnvelope)})
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(ext.Value, legacy) {
					t.Fatal("an extension without a list differs from the legacy encoding")
				}
			}

			// A verifier predating the field reads the rest unchanged.
			var legacy legacyASN1
			rest, err := asn1.Unmarshal(ext.Value, &legacy)
			if err != nil || len(rest) != 0 {
				t.Fatalf("legacy asn1.Unmarshal = %d trailing bytes, %v", len(rest), err)
			}
			if legacy.TEEType != wireTDX || string(legacy.Report) != tdxEnvelope {
				t.Fatalf("legacy decode = %+v", legacy)
			}
		})
	}
}

// A legacy extension decodes to a nil list.
func TestRuntimeExtensionsLegacyDecoding(t *testing.T) {
	legacy, err := asn1.Marshal(legacyASN1{TEEType: wireTDX, Report: []byte(tdxEnvelope)})
	if err != nil {
		t.Fatal(err)
	}
	att, err := UnmarshalExtension(legacy)
	if err != nil {
		t.Fatalf("UnmarshalExtension(legacy) = _, %v", err)
	}
	if att.RuntimeExtensions != nil {
		t.Fatalf("RuntimeExtensions = %q, want nil", att.RuntimeExtensions)
	}
}

func TestUnmarshalExtensionRejectsRuntimeExtensions(t *testing.T) {
	snpReport := mockapi.FakeSNPReport([]byte{})
	for _, tc := range []struct {
		name   string
		family teetypes.Family
		report []byte
		list   []string
	}{
		{"over the cap", teetypes.FamilyTDX, []byte(tdxEnvelope), digests(MaxRuntimeExtensions + 1)},
		{"digest-pinned reference", teetypes.FamilyTDX, []byte(tdxEnvelope), []string{"img@" + digests(1)[0]}},
		{"uppercase hex", teetypes.FamilyTDX, []byte(tdxEnvelope), []string{strings.ToUpper(digests(1)[0])}},
		{"tag", teetypes.FamilyTDX, []byte(tdxEnvelope), []string{"img:latest"}},
		{"list on SEV-SNP", teetypes.FamilySNP, snpReport, digests(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := wireTEEType(tc.family)
			if err != nil {
				t.Fatal(err)
			}
			der := marshalASN1(t, attestationASN1{TEEType: wire, Report: tc.report, RuntimeExtensions: tc.list})
			if _, err := UnmarshalExtension(der); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("UnmarshalExtension() = _, %v, want ErrInvalidReport", err)
			}
			if tc.family != teetypes.FamilyTDX {
				return
			}
			att := &Attestation{Family: tc.family, Report: tc.report, RuntimeExtensions: tc.list}
			if _, err := att.MarshalExtension(testOID); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("MarshalExtension() = _, %v, want ErrInvalidReport", err)
			}
		})
	}
}

// SEV-SNP has no runtime extends, so a producer setting the list
// unconditionally issues the same extension as one that never set it.
func TestMarshalExtensionOmitsListOnSNP(t *testing.T) {
	report := mockapi.FakeSNPReport([]byte{})
	bare, err := (&Attestation{Family: teetypes.FamilySNP, Report: report}).MarshalExtension(testOID)
	if err != nil {
		t.Fatalf("MarshalExtension(no list) = _, %v", err)
	}
	for _, list := range [][]string{digests(1), {"not a digest"}} {
		ext, err := (&Attestation{Family: teetypes.FamilySNP, Report: report, RuntimeExtensions: list}).MarshalExtension(testOID)
		if err != nil {
			t.Fatalf("MarshalExtension(%q) = _, %v", list, err)
		}
		if !slices.Equal(ext.Value, bare.Value) {
			t.Fatalf("MarshalExtension(%q) encodes the list on SEV-SNP", list)
		}
	}
}

// A full list keeps the extension well under the 64 KiB handshake message
// limit, leaving room for the evidence.
func TestRuntimeExtensionsSizeAtCap(t *testing.T) {
	ext, err := tdxAttestation(t, digests(MaxRuntimeExtensions)).MarshalExtension(testOID)
	if err != nil {
		t.Fatalf("MarshalExtension: %v", err)
	}
	const budget = 20 << 10
	if len(ext.Value) > budget {
		t.Fatalf("extension at the cap = %d bytes, want at most %d", len(ext.Value), budget)
	}
}

// The certificate carries three digests while the quote proves two: the
// verifier accepts the proven prefix, and refuses a list the register is not
// a prefix of.
func TestVerifyCertWithServiceReplaysRuntimeExtensions(t *testing.T) {
	anchor := []byte("operator")
	launch := hex.EncodeToString(make([]byte, 48))
	list := digests(3)
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), list[:2])

	stub := mockapi.New(t)
	verdict := mockapi.PassingVerdict(launch)
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": hex.EncodeToString(reg[:])}
	stub.SetVerdict(verdict)
	acceptAll := func(string) error { return nil }

	for _, tc := range []struct {
		name    string
		list    []string
		accept  func(string) error
		wantErr bool
	}{
		{"list ahead of the quote", list, acceptAll, false},
		{"pin without AcceptExtension", list, nil, true},
		{"not a prefix", []string{list[1], list[0], list[2]}, acceptAll, true},
		{"no list", nil, acceptAll, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := remote.Policy{Images: []remote.ImagePin{{Name: "node", Digest: make([]byte, 48), Anchor: anchor, AcceptExtension: tc.accept}}}
			cert, _ := certWithExtension(t, tdxAttestation(t, tc.list))
			_, err := VerifyCertWithService(context.Background(), remote.NewClient(stub.URL()), cert, testOID, nil, policy)
			if tc.wantErr {
				if !errors.Is(err, remote.ErrAnchorNotAllowed) {
					t.Fatalf("VerifyCertWithService() = _, %v, want ErrAnchorNotAllowed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyCertWithService() = _, %v", err)
			}
		})
	}
}

// An in-process Attestation is held to the rules UnmarshalExtension applies
// before its list reaches the service.
func TestVerifyWithServiceRejectsRuntimeExtensions(t *testing.T) {
	key := testKey(t)
	for _, tc := range []struct {
		name string
		att  *Attestation
	}{
		{"over the cap", tdxAttestation(t, digests(MaxRuntimeExtensions+1))},
		{"non-canonical entry", tdxAttestation(t, []string{"img:latest"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := newSpy(t, passingVerdict(nil))
			_, err := VerifyWithService(context.Background(), spy.service(), tc.att, &key.PublicKey, nil, remote.Policy{})
			if !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("VerifyWithService() = _, %v, want ErrInvalidReport", err)
			}
		})
	}
}

// SEV-SNP has no register to extend, so VerifyWithService ignores a list there,
// as MarshalExtension omits it; replayed against an anchor pin, a non-canonical
// entry would fail.
func TestVerifyWithServiceIgnoresRuntimeExtensionsOnSNP(t *testing.T) {
	key := testKey(t)
	anchor := []byte("operator")
	launch := make([]byte, 48)
	hostData := runtimemeasure.HostData(anchor)
	policy := remote.Policy{Images: []remote.ImagePin{{
		Name:            "node",
		Digest:          launch,
		Anchor:          anchor,
		AcceptExtension: func(string) error { return nil },
	}}}
	for _, list := range [][]string{digests(1), {"img:latest"}} {
		att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{}), RuntimeExtensions: list}
		verdict := passingVerdict(launch)
		verdict.Claims.InitData = hostData[:]
		spy := newSpy(t, verdict)
		if _, err := VerifyWithService(context.Background(), spy.service(), att, &key.PublicKey, nil, policy); err != nil {
			t.Fatalf("VerifyWithService(snp, %q) = _, %v, want nil", list, err)
		}
	}
}
