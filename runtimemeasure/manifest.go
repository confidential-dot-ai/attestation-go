package runtimemeasure

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/internal/strictjson"
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
	keys, err := strictjson.RejectDuplicateKeys(data)
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

// decodeRegister parses one manifest register value into dst. See
// [teetypes.ParseDigest] for why uppercase is refused rather than folded.
func decodeRegister(s string, dst *[Size]byte) error {
	b, err := teetypes.ParseDigest(s, Size)
	if err != nil {
		return err
	}
	copy(dst[:], b)
	return nil
}
