package runtimemeasure

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// tdxImagePins is the complete TDX measurement identity of one guest image:
// MRTD (the TDVF firmware's measured regions) plus RTMR[1] (guest kernel /
// UKI image identity) and RTMR[2] (guest rootfs / UKI section chain). MRTD
// alone does not identify an image — two different guest images built against
// the same firmware share it — so the three registers are only meaningful as
// one tuple from one build.
type tdxImagePins struct {
	MRTD  [Size]byte
	RTMR1 [Size]byte
	RTMR2 [Size]byte
}

// imageManifest is the JSON subset loadTDXImageManifest reads. Extra fields are
// allowed (build manifests carry other data); the three registers are not
// optional. A confos build manifest nests them under "tdx"; the flat form is
// also accepted so a hand-written pin stays valid.
type imageManifest struct {
	MRTD  string           `json:"mrtd"`
	RTMR1 string           `json:"rtmr1"`
	RTMR2 string           `json:"rtmr2"`
	TDX   *tdxMeasurements `json:"tdx"`
}

type tdxMeasurements struct {
	MRTD  string `json:"mrtd"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// loadTDXImageManifest loads a TDX image pin — the MRTD + RTMR[1] + RTMR[2]
// tuple — atomically from one provenanced build-artifact manifest. The file
// must be a JSON object carrying all three fields ("mrtd", "rtmr1", "rtmr2")
// exactly once each, every one exactly 96 lowercase hex chars; a missing,
// repeated or malformed field fails the whole load, so a policy can never end
// up pinning part of an image, or a value other than the one it reads as. A
// generic artifact-hash manifest.json (file digests of build outputs) is not
// an image pin and is rejected by the same rule.
func loadTDXImageManifest(path string) (tdxImagePins, error) {
	var pins tdxImagePins
	data, err := os.ReadFile(path)
	if err != nil {
		return pins, fmt.Errorf("read image manifest: %w", err)
	}
	var m imageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return pins, fmt.Errorf("image manifest %s is not a JSON object: %w", path, err)
	}
	keys, err := rejectDuplicateKeys(data)
	if err != nil {
		return tdxImagePins{}, fmt.Errorf("image manifest %s: %w", path, err)
	}
	if m.TDX != nil {
		// The nested object would win over a flat tuple, so a flat register
		// next to it is a second spelling of the same pin: refuse the
		// ambiguity rather than pick one.
		for _, k := range keys {
			for _, reg := range []string{"mrtd", "rtmr1", "rtmr2"} {
				if strings.EqualFold(k, reg) {
					return tdxImagePins{}, fmt.Errorf("image manifest %s: %q is named both at the top level and under \"tdx\"; use one form", path, k)
				}
			}
		}
		m.MRTD, m.RTMR1, m.RTMR2 = m.TDX.MRTD, m.TDX.RTMR1, m.TDX.RTMR2
	}
	for _, f := range []struct {
		name string
		hex  string
		dst  *[Size]byte
	}{
		{"mrtd", m.MRTD, &pins.MRTD},
		{"rtmr1", m.RTMR1, &pins.RTMR1},
		{"rtmr2", m.RTMR2, &pins.RTMR2},
	} {
		if f.hex == "" {
			return tdxImagePins{}, fmt.Errorf(
				"image manifest %s: missing %q — a TDX image pin is the mrtd+rtmr1+rtmr2 tuple from one provenanced build-artifact manifest; a generic artifact-hash manifest.json is not it",
				path, f.name)
		}
		if err := decodeRegister(f.hex, f.dst); err != nil {
			return tdxImagePins{}, fmt.Errorf("image manifest %s: %q %w", path, f.name, err)
		}
	}
	return pins, nil
}

// rejectDuplicateKeys walks the whole document and fails on any key that
// repeats within its object, compared the way encoding/json matches struct
// fields: case-insensitively. Unmarshal keeps the last of two such keys, so
// "mrtd" followed by "MRTD" loads a value other than the one a reviewer read.
// It returns the top-level keys as written.
func rejectDuplicateKeys(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("manifest is not a JSON object")
	}
	return walkObject(dec)
}

// walkObject consumes an object whose opening brace has been read and returns
// its keys.
func walkObject(dec *json.Decoder) ([]string, error) {
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("manifest is not valid JSON: object key is %T", tok)
		}
		if slices.ContainsFunc(keys, func(seen string) bool { return strings.EqualFold(seen, key) }) {
			return nil, fmt.Errorf("duplicate %q key — a key may be named only once in any letter case, since JSON parsing would silently keep the last value", key)
		}
		keys = append(keys, key)
		if err := walkValue(dec); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	return keys, nil
}

// walkValue consumes one value, descending into objects and arrays so every
// nested object is checked too.
func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	switch tok {
	case json.Delim('{'):
		_, err := walkObject(dec)
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("manifest is not valid JSON: %w", err)
		}
	}
	return nil
}

// decodeRegister parses exactly 96 lowercase hex chars into a register value.
// Uppercase is rejected rather than folded: the manifest is a measurement
// reference, and accepting mixed case would let two spellings of one value
// slip past byte-exact comparisons elsewhere.
func decodeRegister(s string, dst *[Size]byte) error {
	if len(s) != Size*2 {
		return fmt.Errorf("is %d chars, want %d lowercase hex chars", len(s), Size*2)
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("is not %d lowercase hex chars", Size*2)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("is not hex: %w", err)
	}
	copy(dst[:], b)
	return nil
}
