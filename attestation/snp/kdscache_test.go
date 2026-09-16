package snp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

// errNotCached is what a fake getter returns to prove a cache hit never reached it.
var errNotCached = errors.New("network getter reached")

type countingGetter struct {
	calls int
	body  []byte
	err   error
}

func (g *countingGetter) Get(string) ([]byte, error) {
	g.calls++
	return g.body, g.err
}

const vcekURL = "https://kdsintf.amd.com/vcek/v1/Genoa/9277b37aaaca7412609cc472c9c59111a908021f805eca1bbe850e80f444e89901f16aef608af85bb57b0ae44f8945276a21df09d949187b8db7b71f624fd829?blSPL=12&teeSPL=0&snpSPL=28&ucodeSPL=28"

func TestCachingGetter_VCEKFetchedOnceThenServedFromDisk(t *testing.T) {
	dir := t.TempDir()
	next := &countingGetter{body: []byte("vcek-der")}
	g := NewCachingKDSGetter(dir, next)
	for i := 0; i < 3; i++ {
		b, err := g.Get(vcekURL)
		if err != nil || string(b) != "vcek-der" {
			t.Fatalf("call %d: got %q, %v", i, b, err)
		}
	}
	if next.calls != 1 {
		t.Fatalf("network getter reached %d times, want 1", next.calls)
	}
	// A fresh wrapper over the same directory (a later process) hits the disk copy.
	fresh := &countingGetter{err: errNotCached}
	if b, err := NewCachingKDSGetter(dir, fresh).Get(vcekURL); err != nil || string(b) != "vcek-der" {
		t.Fatalf("second process: got %q, %v", b, err)
	}
	if fresh.calls != 0 {
		t.Fatalf("second process reached the network %d times", fresh.calls)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".der" {
		t.Fatalf("cache dir holds %v, want one .der entry", entries)
	}
}

func TestCachingGetter_CRLsAndChainsAreNeverCached(t *testing.T) {
	for _, rawURL := range []string{
		kds.CrlLinkByKey("Genoa", abi.VcekReportSigner),
		kds.ProductCertChainURL(abi.VcekReportSigner, "Genoa"),
	} {
		next := &countingGetter{body: []byte("collateral")}
		g := NewCachingKDSGetter(t.TempDir(), next)
		for i := 0; i < 2; i++ {
			if _, err := g.Get(rawURL); err != nil {
				t.Fatal(err)
			}
		}
		if next.calls != 2 {
			t.Errorf("%s fetched %d times, want 2", rawURL, next.calls)
		}
	}
}

func TestCachingGetter_FetchFailureIsNotCachedAndPropagates(t *testing.T) {
	dir := t.TempDir()
	next := &countingGetter{err: errors.New("status 429")}
	g := NewCachingKDSGetter(dir, next)
	if _, err := g.Get(vcekURL); err == nil {
		t.Fatal("want the fetch error")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a failed fetch left %v in the cache", entries)
	}
	next.err, next.body = nil, []byte("late")
	if b, err := trust.GetWith(context.Background(), g, vcekURL); err != nil || string(b) != "late" {
		t.Fatalf("after recovery: got %q, %v", b, err)
	}
}

func TestCachingGetter_PublishFailureLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	next := &countingGetter{body: []byte("vcek-der")}
	g := NewCachingKDSGetter(dir, next).(*cachingGetter)
	// A directory at the final filename prevents renaming a file over it.
	if err := os.Mkdir(g.path(vcekURL), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if b, err := g.Get(vcekURL); err != nil || !bytes.Equal(b, next.body) {
			t.Fatalf("call %d: got %q, %v, want successful fetch", i, b, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || !entries[0].IsDir() {
			t.Fatalf("cache entries = %v, %v, want only the blocking directory", entries, err)
		}
	}
	if next.calls != 2 {
		t.Fatalf("fetches = %d, want 2 after failed cache publication", next.calls)
	}
}

func TestNewCachingKDSGetter_NoDirMeansPassThrough(t *testing.T) {
	next := &countingGetter{body: []byte("x")}
	if g := NewCachingKDSGetter("", next); g != next {
		t.Fatal("empty dir must return the wrapped getter itself")
	}
	unusable := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(unusable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if g := NewCachingKDSGetter(filepath.Join(unusable, "sub"), next); g != next {
		t.Fatal("an uncreatable dir must return the wrapped getter itself")
	}
}

func TestNewCachingKDSGetter_NilStaysOffline(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unused")
	if g := NewCachingKDSGetter(dir, nil); g != nil {
		t.Fatal("nil upstream getter must stay nil")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil getter created a cache directory: %v", err)
	}
}

type contextGetter struct {
	countingGetter
	ctx context.Context
	url string
}

func (g *contextGetter) GetContext(ctx context.Context, rawURL string) ([]byte, error) {
	g.ctx, g.url = ctx, rawURL
	return nil, ctx.Err()
}

func TestCachingGetter_ForwardsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, rawURL := range []string{vcekURL, kds.CrlLinkByKey("Genoa", abi.VcekReportSigner)} {
		next := &contextGetter{}
		g := NewCachingKDSGetter(t.TempDir(), next)
		if _, err := trust.GetWith(ctx, g, rawURL); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: error = %v, want context cancellation", rawURL, err)
		}
		if next.ctx != ctx || next.url != rawURL || next.calls != 0 {
			t.Fatalf("%s: context-aware upstream did not receive caller context and URL", rawURL)
		}
	}
}

// mapGetter is a fake KDS: it serves exactly the URLs it holds and counts hits.
type mapGetter struct {
	calls map[string]int
	body  map[string][]byte
}

func (g *mapGetter) Get(url string) ([]byte, error) {
	g.calls[url]++
	if b, ok := g.body[url]; ok {
		return b, nil
	}
	return nil, errors.New("404")
}

// TestCacheable_MatchesGoSevGuestURLShapes pins the classifier to the URLs
// go-sev-guest actually builds, so a format change upstream fails here rather
// than leaving the cache silently inert.
func TestCacheable_MatchesGoSevGuestURLShapes(t *testing.T) {
	chip := bytes.Repeat([]byte{0x92}, 64)
	tcb := kds.TCBVersion(0x1c00000000000012)
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{kds.VCEKCertURL("Genoa", chip, tcb), true},
		{kds.VLEKCertURL("Genoa", tcb), true},
		{kds.CrlLinkByKey("Genoa", abi.VcekReportSigner), false},
		{kds.ProductCertChainURL(abi.VcekReportSigner, "Genoa"), false},
	} {
		if got := cacheable(tc.url); got != tc.want {
			t.Errorf("cacheable(%s) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestCachingGetter_KeysUseFullURL(t *testing.T) {
	urls := []string{
		vcekURL,
		vcekURL + "&extra=1",
		"https://mirror.example" + vcekURL[len("https://kdsintf.amd.com"):],
	}
	next := &mapGetter{calls: map[string]int{}, body: map[string][]byte{}}
	for _, rawURL := range urls {
		next.body[rawURL] = []byte(rawURL)
	}
	g := NewCachingKDSGetter(t.TempDir(), next)
	for i := 0; i < 2; i++ {
		for _, rawURL := range urls {
			if b, err := g.Get(rawURL); err != nil || string(b) != rawURL {
				t.Fatalf("%s: got %q, %v", rawURL, b, err)
			}
		}
	}
	for _, rawURL := range urls {
		if next.calls[rawURL] != 1 {
			t.Errorf("%s fetched %d times, want 1", rawURL, next.calls[rawURL])
		}
	}
}

func TestVerifyReportContext_CachedVCEKStillVerified(t *testing.T) {
	report, vcek := genoaFixture(t)
	rp, err := abi.ReportToProto(report)
	if err != nil {
		t.Fatal(err)
	}
	rawURL := kds.VCEKCertURL("Genoa", rp.GetChipId(), kds.TCBVersion(rp.GetReportedTcb()))
	dir := t.TempDir()
	fake := &mapGetter{calls: map[string]int{}, body: map[string][]byte{rawURL: vcek}}
	verify := func(getter trust.HTTPSGetter) error {
		t.Helper()
		res, err := VerifyReportContext(context.Background(), report, nil, teetypes.VerifyParams{},
			teetypes.PlatformSNP, MinReportVersion, Options{Getter: getter})
		if err == nil && !res.SignatureValid {
			t.Fatal("successful verification did not validate the report signature")
		}
		return err
	}
	if err := verify(NewCachingKDSGetter(dir, fake)); err != nil {
		t.Fatalf("first verification with fetched VCEK: %v", err)
	}
	if fake.calls[rawURL] != 1 || len(fake.calls) != 1 {
		t.Fatalf("KDS calls = %v, want one VCEK fetch", fake.calls)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("cache entries = %v, %v, want one VCEK", entries, err)
	}
	cachePath := filepath.Join(dir, entries[0].Name())
	if cached, err := os.ReadFile(cachePath); err != nil || !bytes.Equal(cached, vcek) {
		t.Fatalf("cached bytes differ from fetched VCEK: %v", err)
	}

	offline := &countingGetter{err: errNotCached}
	if err := verify(NewCachingKDSGetter(dir, offline)); err != nil {
		t.Fatalf("fresh wrapper with upstream unavailable: %v", err)
	}
	// Alter the certificate signature while leaving its DER encoding intact.
	tampered := append([]byte(nil), vcek...)
	tampered[len(tampered)-1] ^= 1
	if err := os.WriteFile(cachePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify(NewCachingKDSGetter(dir, offline)); err == nil {
		t.Fatal("tampered cached VCEK passed verification")
	}
	if offline.calls != 0 {
		t.Fatalf("cached verification reached upstream %d times", offline.calls)
	}
}
