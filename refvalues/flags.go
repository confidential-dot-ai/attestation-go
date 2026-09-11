package refvalues

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ParseHexMeasurements parses a comma-separated list of hex-encoded launch
// digests into the byte form the reference values carry. Empty input returns
// nil; the caller decides whether to warn about pinning nothing.
func ParseHexMeasurements(raw string) ([][]byte, error) {
	return ParseHexMeasurementsList(strings.Split(raw, ","))
}

// ParseHexMeasurementsList parses hex-encoded launch digests — an SEV-SNP
// launch measurement or a TDX MRTD, both [DigestSize] bytes — into the byte
// form the reference values carry. Blank entries are skipped; an all-blank or
// empty slice returns nil.
//
// A digest must be lowercase: a reference value is compared byte for byte, so
// [teetypes.ParseDigest] refuses the second spelling rather than folding it.
func ParseHexMeasurementsList(raw []string) ([][]byte, error) {
	out := make([][]byte, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		decoded, err := teetypes.ParseDigest(p, DigestSize)
		if err != nil {
			return nil, fmt.Errorf("invalid hex measurement %q: %w", p, err)
		}
		out = append(out, decoded)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParseRTMRPins parses TDX RTMR pins of the form <index>=<sha384-hex> into the
// map form the reference values carry. Blank entries are skipped; an all-blank
// or empty slice returns nil (no pin).
//
// Only indices 1, 2 and 3 are pinnable: RTMR[0] carries the TD HOB, so it
// varies with the guest's vCPU and memory shape and a pin on it would deny
// guests by size rather than by identity.
//
// A pinned value must be lowercase hex, for the reason
// [teetypes.ParseDigest] gives.
func ParseRTMRPins(raw []string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idxStr, hexStr, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("rtmr pin %q: want <index>=<sha384-hex>", p)
		}
		idx, err := strconv.Atoi(strings.TrimSpace(idxStr))
		if err != nil {
			return nil, fmt.Errorf("rtmr pin %q: index is not a number: %w", p, err)
		}
		switch idx {
		case 1, 2, 3:
		case 0:
			return nil, fmt.Errorf("RTMR[0] is not pinnable: it carries the TD HOB, so it varies with the guest's vCPU and memory shape")
		default:
			return nil, fmt.Errorf("rtmr pin %q: index must be 1, 2 or 3", p)
		}
		if _, dup := out[idx]; dup {
			return nil, fmt.Errorf("RTMR[%d] pinned more than once", idx)
		}
		v, err := teetypes.ParseDigest(strings.TrimSpace(hexStr), DigestSize)
		if err != nil {
			return nil, fmt.Errorf("rtmr pin %d: value %w", idx, err)
		}
		out[idx] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParseRTMRPinsString parses a comma-separated list of <index>=<sha384-hex>
// RTMR pins (see [ParseRTMRPins]). Empty input returns nil.
func ParseRTMRPinsString(raw string) (map[int][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return ParseRTMRPins(strings.Split(raw, ","))
}
