package teetypes

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseDigest(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, sha512.Size384)
	got, err := ParseDigest(hex.EncodeToString(want), sha512.Size384)
	if err != nil {
		t.Fatalf("ParseDigest(sha384) = _, %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ParseDigest(sha384) = %x, want %x", got, want)
	}
	if _, err := ParseDigest(strings.Repeat("cd", sha256.Size), sha256.Size); err != nil {
		t.Errorf("ParseDigest(sha256) = _, %v", err)
	}
}

func TestParseDigestRejects(t *testing.T) {
	sha384 := strings.Repeat("ab", sha512.Size384)
	for _, tc := range []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"empty", "", sha512.Size384, "is 0 chars"},
		{"short", "abcd", sha512.Size384, "want 96 lowercase hex chars"},
		{"long", sha384 + "ab", sha512.Size384, "want 96 lowercase hex chars"},
		// Uppercase is a second spelling of one value, which byte-exact
		// comparison elsewhere would not match.
		{"uppercase", strings.ToUpper(sha384), sha512.Size384, "is not 96 lowercase hex chars"},
		{"mixed case", "A" + sha384[1:], sha512.Size384, "is not 96 lowercase hex chars"},
		{"not hex", strings.Repeat("zz", sha512.Size384), sha512.Size384, "is not 96 lowercase hex chars"},
		{"wrong width for the value", sha384, sha256.Size, "want 64 lowercase hex chars"},
		{"nonsense width", sha384, 0, "not positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDigest(tc.in, tc.width)
			if err == nil {
				t.Fatalf("ParseDigest = %x, nil; want an error", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseDigest error %q does not contain %q", err, tc.want)
			}
		})
	}
}
