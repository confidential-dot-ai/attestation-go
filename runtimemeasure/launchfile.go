package runtimemeasure

import (
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// LaunchFileDigest returns the digest family f's launch binding commits for
// file: 48-byte SHA-384 on Intel TDX, where it is the MRCONFIGID a launcher
// sets, and 32-byte SHA-256 on AMD SEV-SNP, where it is the HOSTDATA. Pass the
// file's exact bytes: re-encoding, re-wrapping or a stripped trailing newline
// yields a different digest. An empty file is refused: its digest is a public
// constant.
func LaunchFileDigest(f teetypes.Family, file []byte) ([]byte, error) {
	b, err := familyBinding(f)
	if err != nil {
		return nil, err
	}
	return b.fileDigest(file)
}

// ParseLaunchFileDigest decodes a [LaunchFileDigest] for family f written as
// lowercase hex, as [teetypes.ParseDigest] reads it, refusing what
// [CheckLaunchFileDigest] refuses.
func ParseLaunchFileDigest(f teetypes.Family, s string) ([]byte, error) {
	b, err := familyBinding(f)
	if err != nil {
		return nil, err
	}
	digest, err := teetypes.ParseDigest(s, b.width)
	if err != nil {
		return nil, err
	}
	if err := b.checkDigest(digest); err != nil {
		return nil, err
	}
	return digest, nil
}

// CheckLaunchFileDigest refuses a digest not of family f's width, or one a
// guest launched with no init data, or an empty file, carries. The error reads
// after a field name.
func CheckLaunchFileDigest(f teetypes.Family, digest []byte) error {
	b, err := familyBinding(f)
	if err != nil {
		return err
	}
	return b.checkDigest(digest)
}
