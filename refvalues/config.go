package refvalues

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// SchemaVersion1 is the only measurements config schema version this package
// accepts. A future version is rejected, never guessed at.
const SchemaVersion1 = "1"

// wire mirrors the file exactly; validation happens against these fields so an
// absent value stays distinguishable from an empty one.
type wire struct {
	SchemaVersion string      `json:"schema_version"`
	TEE           string      `json:"tee"`
	Measurements  []wireImage `json:"measurements"`
}

type wireImage struct {
	Name        string    `json:"name"`
	Measurement *string   `json:"measurement,omitempty"`
	MRTD        *string   `json:"mrtd,omitempty"`
	RTMR        []*string `json:"rtmr,omitempty"`
}

// Load reads and validates a measurements config file. A missing or malformed
// file is an error, never an empty set: the caller asked for pinning.
func Load(path string) (ReferenceValues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("read measurements config: %w", err)
	}
	rv, err := Parse(data)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("measurements config %s: %w", path, err)
	}
	return rv, nil
}

// Parse validates a measurements config document. Parsing and linting apply
// the same rules, so a file that lints clean is the file every component
// loads. Errors name the JSON path they were found at.
func Parse(data []byte) (ReferenceValues, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return ReferenceValues{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f wire
	if err := dec.Decode(&f); err != nil {
		return ReferenceValues{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return ReferenceValues{}, fmt.Errorf("trailing data after the JSON object")
	}
	return f.validate()
}

func (f wire) validate() (ReferenceValues, error) {
	if f.SchemaVersion != SchemaVersion1 {
		return ReferenceValues{}, fmt.Errorf("schema_version %q, want %q", f.SchemaVersion, SchemaVersion1)
	}
	fam, err := teetypes.ParseFamily(f.TEE)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("tee %w", err)
	}
	// An empty list would pin nothing while reading as a pinned config;
	// omitting the flag is how an operator asks for no pinning.
	if len(f.Measurements) == 0 {
		return ReferenceValues{}, fmt.Errorf("measurements is empty: a config file must pin at least one image")
	}

	rv := ReferenceValues{Family: fam, Images: make([]remote.ImagePin, 0, len(f.Measurements))}
	names := make(map[string]bool, len(f.Measurements))
	tuples := make(map[string]int, len(f.Measurements))
	for i, we := range f.Measurements {
		img, err := we.validate(fam, i)
		if err != nil {
			return ReferenceValues{}, err
		}
		if names[img.Name] {
			return ReferenceValues{}, fmt.Errorf("measurements[%d]: duplicate name %q", i, img.Name)
		}
		names[img.Name] = true
		key := tupleKey(img)
		if prev, dup := tuples[key]; dup {
			return ReferenceValues{}, fmt.Errorf("measurements[%d] pins the same tuple as measurements[%d]", i, prev)
		}
		tuples[key] = i
		rv.Images = append(rv.Images, img)
	}
	return rv, nil
}

func (we wireImage) validate(fam teetypes.Family, i int) (remote.ImagePin, error) {
	at := fmt.Sprintf("measurements[%d]", i)
	if strings.TrimSpace(we.Name) == "" {
		return remote.ImagePin{}, fmt.Errorf("%s: name is required", at)
	}
	img := remote.ImagePin{Name: we.Name}

	switch fam {
	case teetypes.FamilySNP:
		if we.MRTD != nil || we.RTMR != nil {
			return remote.ImagePin{}, fmt.Errorf("%s: mrtd and rtmr are tdx fields, but tee is %q", at, teetypes.FamilySNP)
		}
		if we.Measurement == nil {
			return remote.ImagePin{}, fmt.Errorf("%s: measurement is required", at)
		}
		d, err := decodeRegister(*we.Measurement)
		if err != nil {
			return remote.ImagePin{}, fmt.Errorf("%s.measurement: %w", at, err)
		}
		img.Digest = d
	case teetypes.FamilyTDX:
		if we.Measurement != nil {
			return remote.ImagePin{}, fmt.Errorf("%s: measurement is a sev-snp field, but tee is %q", at, teetypes.FamilyTDX)
		}
		if we.MRTD == nil {
			return remote.ImagePin{}, fmt.Errorf("%s: mrtd is required", at)
		}
		d, err := decodeRegister(*we.MRTD)
		if err != nil {
			return remote.ImagePin{}, fmt.Errorf("%s.mrtd: %w", at, err)
		}
		img.Digest = d
		rtmrs, err := decodeRTMRs(we.RTMR, at)
		if err != nil {
			return remote.ImagePin{}, err
		}
		img.RTMRs = rtmrs
	default:
		return remote.ImagePin{}, fmt.Errorf("%s: tee %q has no known pin shape", at, fam)
	}
	return img, nil
}

func decodeRTMRs(raw []*string, at string) (map[int][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxRTMRs {
		return nil, fmt.Errorf("%s.rtmr has %d entries, want at most %d", at, len(raw), MaxRTMRs)
	}
	out := make(map[int][]byte, len(raw))
	for idx, v := range raw {
		if v == nil {
			continue
		}
		// RTMR[0] mixes the TD HOB and VMM ACPI tables, so it varies with the
		// VM shape and can never be pinned to a stable value.
		if idx == 0 {
			return nil, fmt.Errorf("%s.rtmr[0]: must be null — RTMR[0] varies with vCPU and memory shape", at)
		}
		if *v == "" {
			out[idx] = make([]byte, DigestSize)
			continue
		}
		d, err := decodeRegister(*v)
		if err != nil {
			return nil, fmt.Errorf("%s.rtmr[%d]: %w", at, idx, err)
		}
		out[idx] = d
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// decodeRegister requires lowercase hex of exactly one register width.
// Uppercase is rejected rather than folded so one register has one spelling.
func decodeRegister(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("%q is not lowercase hex", s)
	}
	if len(s) != hex.EncodedLen(DigestSize) {
		return nil, fmt.Errorf("is %d hex chars, want %d", len(s), hex.EncodedLen(DigestSize))
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("is not hex: %w", err)
	}
	return d, nil
}

// Format renders a set as a measurements config document. A pin it cannot
// render is an error, never dropped, so a set that formats is a set that
// [Parse] loads back.
func Format(rv ReferenceValues) ([]byte, error) {
	f := wire{SchemaVersion: SchemaVersion1, TEE: string(rv.Family)}
	for i, img := range rv.Images {
		we := wireImage{Name: img.Name}
		d := hex.EncodeToString(img.Digest)
		switch rv.Family {
		case teetypes.FamilySNP:
			if len(img.RTMRs) > 0 {
				return nil, fmt.Errorf("measurements[%d]: %d rtmr pin(s) on a %q image, which has no registers", i, len(img.RTMRs), teetypes.FamilySNP)
			}
			we.Measurement = &d
		case teetypes.FamilyTDX:
			we.MRTD = &d
			if len(img.RTMRs) > 0 {
				we.RTMR = make([]*string, MaxRTMRs)
				for idx, v := range img.RTMRs {
					if idx <= 0 || idx >= MaxRTMRs {
						return nil, fmt.Errorf("measurements[%d]: rtmr[%d] is not pinnable, want 1..%d", i, idx, MaxRTMRs-1)
					}
					h := hex.EncodeToString(v)
					we.RTMR[idx] = &h
				}
			}
		default:
			return nil, fmt.Errorf("tee %q, want %q or %q", rv.Family, teetypes.FamilySNP, teetypes.FamilyTDX)
		}
		f.Measurements = append(f.Measurements, we)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode measurements config: %w", err)
	}
	return append(out, '\n'), nil
}

// tupleKey is the identity a pin is matched on: the digest and its registers.
// The name is diagnostic only, so it is not part of the key.
func tupleKey(img remote.ImagePin) string {
	var b strings.Builder
	b.WriteString(hex.EncodeToString(img.Digest))
	for _, i := range slices.Sorted(maps.Keys(img.RTMRs)) {
		fmt.Fprintf(&b, "|%d=%s", i, hex.EncodeToString(img.RTMRs[i]))
	}
	return b.String()
}

// rejectDuplicateKeys fails a document that names any key twice. encoding/json
// keeps the last occurrence silently, so without this check the value a
// reviewer reads and the value a verifier loads can differ. The schema is two
// levels deep, so the document and each image are scanned directly.
func rejectDuplicateKeys(data []byte) error {
	key, err := duplicateKey(data)
	if err != nil {
		return err
	}
	if key != "" {
		return fmt.Errorf("duplicate key %q", key)
	}
	// Tolerant: a document whose shape is wrong is Parse's error to report.
	var doc struct {
		Measurements []json.RawMessage `json:"measurements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	for i, image := range doc.Measurements {
		key, err := duplicateKey(image)
		if err != nil {
			return err
		}
		if key != "" {
			return fmt.Errorf("duplicate key %q in measurements[%d]", key, i)
		}
	}
	return nil
}

// duplicateKey returns the first key obj names twice, or "" if it names none
// twice or is not an object.
func duplicateKey(obj []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	tok, err := dec.Token()
	if err != nil {
		return "", nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", nil
	}
	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("not valid JSON: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", fmt.Errorf("not valid JSON: object key is %T", keyTok)
		}
		if seen[key] {
			return key, nil
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", fmt.Errorf("not valid JSON: %w", err)
		}
	}
	return "", nil
}
