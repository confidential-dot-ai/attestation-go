package snp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/go-sev-guest/verify/trust"
)

type cachingGetter struct {
	dir  string
	next trust.HTTPSGetter
}

// NewCachingKDSGetter wraps next with an on-disk cache of AMD KDS endorsement
// certificates (VCEK/VLEK). The caller owns dir; no default directory is chosen.
// A nil next, empty dir, or directory that cannot be created returns next
// unchanged. Cache writes are best effort and do not prevent a successful fetch.
//
// Only endorsement-certificate URL paths are cached, keyed by the full URL.
// CRLs and certificate chains pass through to next on every request. Cached
// bytes remain untrusted: verification still validates the certificate against
// AMD's bundled roots. Context-aware upstream getters receive the caller's
// context on cache misses and pass-through requests.
func NewCachingKDSGetter(dir string, next trust.HTTPSGetter) trust.HTTPSGetter {
	if next == nil || dir == "" {
		return next
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return next
	}
	return &cachingGetter{dir: dir, next: next}
}

// endorsementPath matches the two KDS endorsement-certificate shapes go-sev-guest
// builds (kds.VCEKCertURL, kds.VLEKCertURL): /vcek/v1/<product>/<128 hex chip id>
// and /vlek/v1/<product>/cert, the TCB in the query. The CRL (/crl) and the
// ASK/ARK chain (/cert_chain) live beside them and are never cached.
var endorsementPath = regexp.MustCompile(`^/(vcek/v1/[^/]+/[0-9a-fA-F]{128}|vlek/v1/[^/]+/cert)$`)

// cacheable reports whether rawURL names an immutable endorsement certificate.
func cacheable(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return endorsementPath.MatchString(u.Path)
}

func (c *cachingGetter) path(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".der")
}

func (c *cachingGetter) Get(rawURL string) ([]byte, error) {
	return c.GetContext(context.Background(), rawURL)
}

func (c *cachingGetter) GetContext(ctx context.Context, rawURL string) ([]byte, error) {
	if !cacheable(rawURL) {
		return trust.GetWith(ctx, c.next, rawURL)
	}
	p := c.path(rawURL)
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return b, nil
	}
	b, err := trust.GetWith(ctx, c.next, rawURL)
	if err != nil {
		return nil, err
	}
	// Atomic publish so a concurrent reader never sees a partial file; a
	// failed write only costs the next caller a fetch.
	tmp, err := os.CreateTemp(c.dir, ".vcek-*")
	if err == nil {
		if _, werr := tmp.Write(b); werr == nil && tmp.Close() == nil {
			if rerr := os.Rename(tmp.Name(), p); rerr != nil {
				_ = os.Remove(tmp.Name())
			}
		} else {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}
	return b, nil
}
