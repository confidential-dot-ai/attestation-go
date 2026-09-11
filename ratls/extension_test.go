package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// The wire values are read by deployed verifiers, so a renumbering here is a
// silent compatibility break.
func TestWireTEETypeValues(t *testing.T) {
	if wireSNP != 1 || wireTDX != 2 {
		t.Fatalf("wire values = (%d, %d), want (1, 2)", wireSNP, wireTDX)
	}
	if SNPReportSize != 0x4A0 {
		t.Fatalf("SNPReportSize = %#x, want 0x4A0 (1184)", SNPReportSize)
	}
}

// Every tag of a family maps to that family's one wire value, and back; a
// family this extension has no value for fails closed.
func TestWireTEETypeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		want     int
	}{
		{teetypes.PlatformSNP, wireSNP},
		{teetypes.PlatformAzSNP, wireSNP},
		{teetypes.PlatformGcpSNP, wireSNP},
		{teetypes.PlatformTDX, wireTDX},
		{teetypes.PlatformAzTDX, wireTDX},
		{teetypes.PlatformGcpTDX, wireTDX},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			family := tc.platform.Family()
			got, err := wireTEEType(family)
			if err != nil || got != tc.want {
				t.Fatalf("wireTEEType(%q) = %d, %v; want %d, nil", family, got, err, tc.want)
			}
			back, err := familyFromWire(got)
			if err != nil || back != family {
				t.Fatalf("familyFromWire(%d) = %q, %v; want %q, nil", got, back, err, family)
			}
		})
	}
}

func TestWireTEETypeFailsClosed(t *testing.T) {
	for _, p := range []teetypes.PlatformType{teetypes.PlatformDstack, "auto", ""} {
		if _, err := wireTEEType(p.Family()); !errors.Is(err, ErrUnsupportedTEE) {
			t.Errorf("wireTEEType(%q) err = %v, want ErrUnsupportedTEE", p, err)
		}
	}
	for _, v := range []int{0, 3, 99} {
		got, err := familyFromWire(v)
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Errorf("familyFromWire(%d) err = %v, want ErrUnsupportedTEE", v, err)
		}
		if got != teetypes.FamilyUnknown {
			t.Errorf("familyFromWire(%d) = %q on error, want FamilyUnknown", v, got)
		}
	}
}

func TestExtensionRoundTrip(t *testing.T) {
	report := mockapi.FakeSNPReport([]byte{1, 2, 3, 4})
	chain := []byte("fake-vcek-der")
	att := &Attestation{Family: teetypes.FamilySNP, Report: report, CertChain: chain}

	ext, err := att.MarshalExtension(testOID)
	if err != nil {
		t.Fatalf("MarshalExtension: %v", err)
	}
	if !ext.Id.Equal(testOID) {
		t.Errorf("extension OID = %v, want %v", ext.Id, testOID)
	}
	if ext.Critical {
		t.Error("extension is critical; a TLS stack that does not know the OID must still parse the certificate")
	}

	got, err := UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("UnmarshalExtension: %v", err)
	}
	if got.Family != teetypes.FamilySNP {
		t.Errorf("Family = %q, want %q", got.Family, teetypes.FamilySNP)
	}
	if !bytes.Equal(got.Report, report) {
		t.Error("Report did not survive the round trip")
	}
	if !bytes.Equal(got.CertChain, chain) {
		t.Error("CertChain did not survive the round trip")
	}
	if _, ok := got.EmbeddedEvidence(); ok {
		t.Error("EmbeddedEvidence() = true for a raw SEV-SNP report")
	}
}

func TestUnmarshalExtensionRejects(t *testing.T) {
	valid := marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: mockapi.FakeSNPReport([]byte{})})

	cases := []struct {
		name string
		der  []byte
		want error
	}{
		{"empty", nil, nil},
		{"garbage", []byte{0xFF, 0xFF}, nil},
		{"trailing bytes", append(bytes.Clone(valid), 0x00), ErrInvalidReport},
		{"unknown TEE type", marshalASN1(t, attestationASN1{TEEType: 99, Report: []byte("report")}), ErrUnsupportedTEE},
		{"truncated SNP report", marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: make([]byte, 100)}), ErrInvalidReport},
		{"oversized SNP report", marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: make([]byte, SNPReportSize+1)}), ErrInvalidReport},
		{"raw TDX bytes", marshalASN1(t, attestationASN1{TEEType: wireTDX, Report: []byte("variable-length-tdx-quote")}), ErrInvalidReport},
		{"envelope without platform", marshalASN1(t, attestationASN1{TEEType: wireTDX, Report: []byte(`{"evidence":{"quote":"AAAA"}}`)}), ErrInvalidReport},
		{"envelope without payload", marshalASN1(t, attestationASN1{TEEType: wireTDX, Report: []byte(`{"platform":"tdx"}`)}), ErrInvalidReport},
		{"TDX envelope under the SNP type", marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: []byte(`{"platform":"tdx","evidence":{"quote":"AAAA"}}`)}), ErrInvalidReport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalExtension(tc.der)
			if err == nil {
				t.Fatal("UnmarshalExtension accepted it")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// The two shapes coexist under one OID, so parsing must tell them apart without
// being told which to expect.
func TestUnmarshalExtensionShapes(t *testing.T) {
	report := mockapi.FakeSNPReport([]byte{1, 2, 3})

	t.Run("raw SEV-SNP report", func(t *testing.T) {
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: report}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		if !bytes.Equal(att.Report, report) {
			t.Fatal("report mismatch")
		}
	})

	t.Run("HCL-wrapped SEV-SNP report is unwrapped", func(t *testing.T) {
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
			TEEType: wireSNP,
			Report:  fakeHCLEnvelope(report, 128),
		}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		if !bytes.Equal(att.Report, report) {
			t.Fatal("HCL envelope was not unwrapped to the raw report")
		}
	})

	t.Run("TDX evidence envelope", func(t *testing.T) {
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
			TEEType: wireTDX,
			Report:  []byte(`{"platform":"tdx","evidence":{"quote":"AAAA"}}`),
		}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		env, ok := att.EmbeddedEvidence()
		if !ok || env.Platform != teetypes.PlatformTDX {
			t.Fatalf("EmbeddedEvidence() = (%q, %t), want (tdx, true)", env.Platform, ok)
		}
	})

	t.Run("platform tag is canonicalized", func(t *testing.T) {
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
			TEEType: wireSNP,
			Report:  []byte(`{"platform":" AZ-SNP ","evidence":{"hcl_report":"AAAA"}}`),
		}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		env, _ := att.EmbeddedEvidence()
		if env.Platform != teetypes.PlatformAzSNP {
			t.Fatalf("platform = %q, want az-snp", env.Platform)
		}
	})
}

func TestAttestationReportData(t *testing.T) {
	reportData := [64]byte{0xA1, 0xB2, 0xC3}

	t.Run("raw SEV-SNP report exposes REPORTDATA", func(t *testing.T) {
		att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport(reportData[:])}
		got, ok := att.ReportData()
		if !ok || !bytes.Equal(got, reportData[:]) {
			t.Fatalf("ReportData() = (%x, %t), want (%x, true)", got, ok, reportData[:])
		}
	})

	t.Run("minimum-length report is accepted", func(t *testing.T) {
		report := make([]byte, snp.ReportDataOffset+64)
		copy(report[snp.ReportDataOffset:], reportData[:])
		att := &Attestation{Family: teetypes.FamilySNP, Report: report}
		if got, ok := att.ReportData(); !ok || !bytes.Equal(got, reportData[:]) {
			t.Fatalf("ReportData() = (%x, %t), want (%x, true)", got, ok, reportData[:])
		}
	})

	t.Run("one byte short is refused", func(t *testing.T) {
		att := &Attestation{Family: teetypes.FamilySNP, Report: make([]byte, snp.ReportDataOffset+63)}
		if got, ok := att.ReportData(); ok || got != nil {
			t.Fatalf("ReportData() = (%x, %t), want (nil, false)", got, ok)
		}
	})

	t.Run("TDX is refused", func(t *testing.T) {
		att := &Attestation{Family: teetypes.FamilyTDX, Report: mockapi.FakeSNPReport(reportData[:])}
		if got, ok := att.ReportData(); ok || got != nil {
			t.Fatalf("ReportData() = (%x, %t), want (nil, false)", got, ok)
		}
	})

	t.Run("envelope evidence is refused", func(t *testing.T) {
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{
			TEEType: wireSNP,
			Report:  []byte(`{"platform":"az-snp","evidence":{"hcl_report":"AAAA"}}`),
		}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		if got, ok := att.ReportData(); ok || got != nil {
			t.Fatalf("ReportData() = (%x, %t), want (nil, false)", got, ok)
		}
	})
}

func TestEnvelope(t *testing.T) {
	report := mockapi.FakeSNPReport([]byte{7})

	t.Run("raw report is wrapped under the bare-metal tag", func(t *testing.T) {
		env, err := (&Attestation{Family: teetypes.FamilySNP, Report: report}).Envelope()
		if err != nil {
			t.Fatalf("Envelope: %v", err)
		}
		if env.Platform != teetypes.PlatformSNP {
			t.Fatalf("platform = %q, want snp", env.Platform)
		}
		var inner struct {
			AttestationReport string `json:"attestation_report"`
			CertChain         *struct {
				Vcek string `json:"vcek"`
			} `json:"cert_chain"`
		}
		if err := json.Unmarshal(env.Evidence, &inner); err != nil {
			t.Fatalf("unmarshal evidence: %v", err)
		}
		got, err := base64.StdEncoding.DecodeString(inner.AttestationReport)
		if err != nil {
			t.Fatalf("attestation_report is not standard base64: %v", err)
		}
		if !bytes.Equal(got, report) {
			t.Fatal("wrapped report mismatch")
		}
		if inner.CertChain != nil {
			t.Fatal("cert_chain present with no inline collateral")
		}
	})

	t.Run("inline collateral rides along", func(t *testing.T) {
		vcek := []byte("fake-vcek-der")
		env, err := (&Attestation{Family: teetypes.FamilySNP, Report: report, CertChain: vcek}).Envelope()
		if err != nil {
			t.Fatalf("Envelope: %v", err)
		}
		var inner struct {
			CertChain struct {
				Vcek string `json:"vcek"`
			} `json:"cert_chain"`
		}
		if err := json.Unmarshal(env.Evidence, &inner); err != nil {
			t.Fatalf("unmarshal evidence: %v", err)
		}
		got, err := base64.StdEncoding.DecodeString(inner.CertChain.Vcek)
		if err != nil || !bytes.Equal(got, vcek) {
			t.Fatalf("cert_chain.vcek = %q (%v), want the inline VCEK", inner.CertChain.Vcek, err)
		}
	})

	t.Run("embedded envelope is returned verbatim", func(t *testing.T) {
		raw := []byte(`{"platform":"az-snp","evidence":{"hcl_report":"AAAA"}}`)
		att, err := UnmarshalExtension(marshalASN1(t, attestationASN1{TEEType: wireSNP, Report: raw}))
		if err != nil {
			t.Fatalf("UnmarshalExtension: %v", err)
		}
		env, err := att.Envelope()
		if err != nil {
			t.Fatalf("Envelope: %v", err)
		}
		if env.Platform != teetypes.PlatformAzSNP || string(env.Evidence) != `{"hcl_report":"AAAA"}` {
			t.Fatalf("envelope = %+v, want the embedded az-snp evidence", env)
		}
	})

	t.Run("raw TDX has no envelope", func(t *testing.T) {
		_, err := (&Attestation{Family: teetypes.FamilyTDX, Report: report}).Envelope()
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("err = %v, want ErrInvalidReport", err)
		}
	})
}

func TestReportDataForKey(t *testing.T) {
	key := testKey(t)

	t.Run("SHA-384 of the key, zero-padded", func(t *testing.T) {
		got, err := ReportDataForKey(&key.PublicKey, nil)
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		keyBytes, err := marshalPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("marshalPublicKey: %v", err)
		}
		want := sha512.Sum384(keyBytes)
		if !bytes.Equal(got[:sha512.Size384], want[:]) {
			t.Errorf("ReportDataForKey()[:48] = %x, want %x", got[:sha512.Size384], want)
		}
		if !bytes.Equal(got[sha512.Size384:], make([]byte, 64-sha512.Size384)) {
			t.Errorf("ReportDataForKey()[48:] = %x, want zero padding", got[sha512.Size384:])
		}
	})

	t.Run("nonce changes the binding", func(t *testing.T) {
		bare, err := ReportDataForKey(&key.PublicKey, nil)
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		withNonce, err := ReportDataForKey(&key.PublicKey, []byte("nonce-a"))
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		again, err := ReportDataForKey(&key.PublicKey, []byte("nonce-a"))
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		other, err := ReportDataForKey(&key.PublicKey, []byte("nonce-b"))
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		if withNonce == bare {
			t.Error("nonce did not change REPORTDATA")
		}
		if withNonce != again {
			t.Error("the same nonce produced different REPORTDATA")
		}
		if withNonce == other {
			t.Error("different nonces produced the same REPORTDATA")
		}
	})

	t.Run("a different key gives a different binding", func(t *testing.T) {
		mine, err := ReportDataForKey(&key.PublicKey, nil)
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		theirs, err := ReportDataForKey(&testKey(t).PublicKey, nil)
		if err != nil {
			t.Fatalf("ReportDataForKey: %v", err)
		}
		if mine == theirs {
			t.Fatal("two keys share a binding")
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		if _, err := ReportDataForKey("not-a-key", nil); err == nil {
			t.Fatal("ReportDataForKey accepted a non-key")
		}
	})
}

func TestPublicKeyFromCert(t *testing.T) {
	cases := []struct {
		name    string
		curve   elliptic.Curve
		wantErr bool
	}{
		{"P-256", elliptic.P256(), false},
		{"P-384", elliptic.P384(), false},
		{"P-521", elliptic.P521(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1)}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatalf("create certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}
			if _, err := publicKeyFromCert(cert); (err != nil) != tc.wantErr {
				t.Fatalf("publicKeyFromCert err = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestExtractAttestation(t *testing.T) {
	t.Run("finds the extension", func(t *testing.T) {
		cert, _ := certWithExtension(t, &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{9})})
		att, err := ExtractAttestation(cert, testOID)
		if err != nil {
			t.Fatalf("ExtractAttestation: %v", err)
		}
		if att.Family != teetypes.FamilySNP {
			t.Fatalf("Family = %q, want %q", att.Family, teetypes.FamilySNP)
		}
	})

	t.Run("other OID", func(t *testing.T) {
		cert, _ := certWithExtension(t, &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{9})})
		if _, err := ExtractAttestation(cert, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 2}); !errors.Is(err, ErrNoAttestation) {
			t.Fatalf("err = %v, want ErrNoAttestation for an extension under another OID", err)
		}
	})

	t.Run("empty OID", func(t *testing.T) {
		cert, _ := certWithExtension(t, nil)
		if _, err := ExtractAttestation(cert, nil); err == nil {
			t.Fatal("ExtractAttestation accepted an empty OID")
		}
		att := &Attestation{Family: teetypes.FamilySNP, Report: mockapi.FakeSNPReport([]byte{})}
		if _, err := att.MarshalExtension(nil); err == nil {
			t.Fatal("MarshalExtension accepted an empty OID")
		}
	})

	t.Run("no extension", func(t *testing.T) {
		cert, _ := certWithExtension(t, nil)
		if _, err := ExtractAttestation(cert, testOID); !errors.Is(err, ErrNoAttestation) {
			t.Fatalf("err = %v, want ErrNoAttestation", err)
		}
	})
}
