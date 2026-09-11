package teetypes

import (
	"encoding/hex"
	"fmt"
)

// ParseDigest decodes exactly width bytes of lowercase hex, and is the one
// parser for every measurement value this module reads: a launch digest, an
// MRTD, an RTMR, a vTPM PCR, a pinned reference value from a config file or a
// command-line flag.
//
// Uppercase is rejected rather than folded. A measurement is compared byte for
// byte, and a value with two accepted spellings is a value two components can
// disagree about: one writes "AB…", another pins "ab…", and a pin that reads as
// enforced matches nothing. Callers that must tolerate a producer's spelling
// fold the string themselves before calling, which makes that tolerance
// visible at the call site.
//
// The error names the width in hex characters, so an operator retyping a
// rejected value knows what to type. Callers add their own context; the error
// text starts mid-sentence ("is 12 chars, want 96 lowercase hex chars") to read
// after a field name.
func ParseDigest(s string, width int) ([]byte, error) {
	if width <= 0 {
		return nil, fmt.Errorf("digest width %d is not positive", width)
	}
	want := 2 * width
	if len(s) != want {
		return nil, fmt.Errorf("is %d chars, want %d lowercase hex chars", len(s), want)
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, fmt.Errorf("is not %d lowercase hex chars", want)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil { // unreachable: every character passed the scan above
		return nil, fmt.Errorf("is not hex: %w", err)
	}
	return b, nil
}
