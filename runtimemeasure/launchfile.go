package runtimemeasure

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// launchFileHash is the hash family f's launch binding commits a launch file
// under: SHA-384 on Intel TDX, SHA-256 (HOSTDATA) on AMD SEV-SNP.
func launchFileHash(f teetypes.Family) (func() hash.Hash, error) {
	switch f {
	case teetypes.FamilyTDX:
		return sha512.New384, nil
	case teetypes.FamilySNP:
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("%w: family %s has no launch binding", ErrUnknownPlatform, f)
	}
}

// LaunchFileDigest returns the digest family f's launch binding commits for
// file: 48-byte SHA-384 on Intel TDX, 32-byte SHA-256 on AMD SEV-SNP, where it
// is the HOSTDATA a launcher sets. Pass the file's exact bytes, as for [Seed].
// An empty file is refused: its digest is a public constant.
func LaunchFileDigest(f teetypes.Family, file []byte) ([]byte, error) {
	newHash, err := launchFileHash(f)
	if err != nil {
		return nil, err
	}
	if len(file) == 0 {
		return nil, fmt.Errorf("launch file is empty; a binding to no file proves nothing")
	}
	h := newHash()
	h.Write(file)
	return h.Sum(nil), nil
}

// ParseLaunchFileDigest decodes a [LaunchFileDigest] for family f written as
// lowercase hex, as [teetypes.ParseDigest] reads it, refusing what
// [CheckLaunchFileDigest] refuses.
func ParseLaunchFileDigest(f teetypes.Family, s string) ([]byte, error) {
	newHash, err := launchFileHash(f)
	if err != nil {
		return nil, err
	}
	digest, err := teetypes.ParseDigest(s, newHash().Size())
	if err != nil {
		return nil, err
	}
	if err := CheckLaunchFileDigest(f, digest); err != nil {
		return nil, err
	}
	return digest, nil
}

// CheckLaunchFileDigest refuses a digest not of family f's width, or one a
// guest launched with no init data, or an empty file, carries. The error reads
// after a field name.
func CheckLaunchFileDigest(f teetypes.Family, digest []byte) error {
	newHash, err := launchFileHash(f)
	if err != nil {
		return err
	}
	h := newHash()
	width := h.Size()
	if len(digest) != width {
		return fmt.Errorf("is %d bytes, want %d on %s", len(digest), width, f)
	}
	if bytes.Count(digest, []byte{0}) == width {
		return fmt.Errorf("is all zero, which equals a launch with no init data")
	}
	if bytes.Equal(digest, h.Sum(nil)) {
		return fmt.Errorf("is the digest of the empty file, which binds nothing")
	}
	return nil
}
