package armtls

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

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

// Without a list the encoding is byte-identical to the legacy one, and a
// legacy extension decodes to a nil list.
func TestRuntimeExtensionsLegacyEncoding(t *testing.T) {
	legacy, err := asn1.Marshal(legacyASN1{TEEType: wireTDX, Report: []byte(tdxEnvelope)})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := tdxAttestation(t, nil).MarshalExtension(testOID)
	if err != nil {
		t.Fatalf("MarshalExtension: %v", err)
	}
	if !slices.Equal(ext.Value, legacy) {
		t.Fatal("an extension without a list differs from the legacy encoding")
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
	for _, tc := range []struct {
		name string
		list []string
	}{
		{"over the cap", digests(MaxRuntimeExtensions + 1)},
		{"digest-pinned reference", []string{"img@" + digests(1)[0]}},
		{"uppercase hex", []string{strings.ToUpper(digests(1)[0])}},
		{"tag", []string{"img:latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := marshalASN1(t, attestationASN1{TEEType: wireTDX, Report: []byte(tdxEnvelope), RuntimeExtensions: tc.list})
			if _, err := UnmarshalExtension(der); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("UnmarshalExtension() = _, %v, want ErrInvalidReport", err)
			}
			att := tdxAttestation(t, tc.list)
			if _, err := att.MarshalExtension(testOID); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("MarshalExtension() = _, %v, want ErrInvalidReport", err)
			}
		})
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
	policy := remote.Policy{Images: []remote.ImagePin{{Name: "node", Digest: make([]byte, 48), Anchor: anchor}}}

	for _, tc := range []struct {
		name    string
		list    []string
		wantErr bool
	}{
		{"list ahead of the quote", list, false},
		{"not a prefix", []string{list[1], list[0], list[2]}, true},
		{"no list", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
