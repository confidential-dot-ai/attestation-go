package refvalues

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func operatorPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestAnchorRoundTripAndTupleIdentity(t *testing.T) {
	for _, family := range []teetypes.Family{teetypes.FamilyTDX, teetypes.FamilySNP} {
		t.Run(string(family), func(t *testing.T) {
			key := operatorPEM(t)
			// Equivalent keys with distinct PEM bytes are distinct launch anchors.
			rv := ReferenceValues{Family: family, Images: []remote.ImagePin{
				{Name: "server", Digest: mustHex(t, d1), Anchor: key},
				{Name: "agent", Digest: mustHex(t, d1), Anchor: append(bytes.Clone(key), '\n')},
			}}
			if family == teetypes.FamilyTDX {
				for i := range rv.Images {
					rv.Images[i].RTMRs = map[int][]byte{1: mustHex(t, r1), 2: mustHex(t, r2)}
				}
			}
			if !rv.HasAnchors() {
				t.Fatal("anchor pins were not reported")
			}
			if _, _, uniform := rv.Flatten(); uniform {
				t.Fatal("flat policy silently discarded anchors")
			}
			if !bytes.Equal(rv.Policy().Images[0].Anchor, key) {
				t.Fatal("Policy dropped anchor")
			}
			for _, format := range []func(ReferenceValues) ([]byte, error){Format, Render} {
				data, err := format(rv)
				if err != nil {
					t.Fatal(err)
				}
				for _, parse := range []func([]byte) (ReferenceValues, error){Parse, ParseRendered} {
					got, err := parse(data)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, rv) {
						t.Fatalf("policy changed on round trip: %+v", got)
					}
				}
			}
			missing, extra := Diff(ReferenceValues{Images: rv.Images[:1]}, ReferenceValues{Images: rv.Images[1:]})
			if len(missing) != 1 || len(extra) != 1 {
				t.Fatal("Diff ignored launch anchor")
			}
			rv.Images[1].Anchor = key
			if _, err := Format(rv); err == nil {
				t.Fatal("Format accepted duplicate complete tuple")
			}
		})
	}
}

func TestAnchorWireAndRenderedDocumentsFailClosed(t *testing.T) {
	key, err := json.Marshal(string(operatorPEM(t)))
	if err != nil {
		t.Fatal(err)
	}
	entry := `{"name":"image","measurement":"` + d1 + `","operator_key":` + string(key) + `}`
	valid := snpFile(entry)
	cases := map[string]string{
		"null anchor":         snpFile(`{"name":"image","measurement":"` + d1 + `","operator_key":null}`),
		"empty anchor":        snpFile(`{"name":"image","measurement":"` + d1 + `","operator_key":""}`),
		"nonstring anchor":    snpFile(`{"name":"image","measurement":"` + d1 + `","operator_key":42}`),
		"malformed anchor":    snpFile(`{"name":"image","measurement":"` + d1 + `","operator_key":"not PEM"}`),
		"unknown field":       strings.Replace(valid, `"name":`, `"anchor":"ignored","name":`, 1),
		"duplicate anchor":    strings.Replace(valid, `"operator_key":`, `"operator_key":null,"OPERATOR_KEY":`, 1),
		"duplicate tuple":     snpFile(entry + "," + strings.Replace(entry, "image", "other", 1)),
		"duplicate name":      snpFile(entry + "," + strings.Replace(entry, d1, d2, 1)),
		"trailing object":     valid + `{}`,
		"trailing garbage":    valid + `garbage`,
		"empty unknown field": `{"schema_version":"1","tee":"tdx","measurements":[],"operator_key":"ignored"}`,
		"empty duplicate key": `{"schema_version":"1","tee":"tdx","measurements":[],"MEASUREMENTS":[]}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			for _, parse := range []func([]byte) (ReferenceValues, error){Parse, ParseRendered} {
				if _, err := parse([]byte(data)); err == nil {
					t.Fatal("accepted malformed or lossy policy")
				}
			}
		})
	}
}

func TestFormatRefusesInvalidOrLossyPins(t *testing.T) {
	for name, mutate := range map[string]func(*remote.ImagePin){
		"empty anchor":           func(p *remote.ImagePin) { p.Anchor = []byte{} },
		"generic anchor not PEM": func(p *remote.ImagePin) { p.Anchor = []byte("generic bytes") },
		"short digest":           func(p *remote.ImagePin) { p.Digest = []byte{1} },
		"missing name":           func(p *remote.ImagePin) { p.Name = "" },
		"empty register":         func(p *remote.ImagePin) { p.RTMRs = map[int][]byte{1: {}} },
		"short register":         func(p *remote.ImagePin) { p.RTMRs = map[int][]byte{1: {1}} },
	} {
		t.Run(name, func(t *testing.T) {
			rv := ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{{Name: "image", Digest: mustHex(t, d1)}}}
			mutate(&rv.Images[0])
			for _, format := range []func(ReferenceValues) ([]byte, error){Format, Render} {
				if _, err := format(rv); err == nil {
					t.Fatal("formatted an invalid policy")
				}
			}
		})
	}
}

func TestFromFlagsRendersStrictlyWithoutDuplicatePins(t *testing.T) {
	rv := FromFlags([][]byte{mustHex(t, d1), mustHex(t, d1), mustHex(t, d2)}, nil)
	rv.Family = teetypes.FamilySNP
	data, err := Render(rv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRendered(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Images) != 2 || got.Images[0].Name == "" || got.Images[0].Name == got.Images[1].Name {
		t.Fatalf("legacy pins = %+v", got.Images)
	}
	if got.HasAnchors() {
		t.Fatal("flat flags invented an anchor")
	}
}

func TestFormatRTMRPinsIsStable(t *testing.T) {
	pins := map[int][]byte{3: mustHex(t, r2), 1: mustHex(t, r1)}
	formatted := FormatRTMRPins(pins)
	if !reflect.DeepEqual(formatted, []string{"1=" + r1, "3=" + r2}) {
		t.Fatalf("pins = %v", formatted)
	}
	got, err := ParseRTMRPins(formatted)
	if err != nil || !reflect.DeepEqual(got, pins) {
		t.Fatalf("roundtrip = %v, %v", got, err)
	}
}
