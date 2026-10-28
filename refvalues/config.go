package refvalues

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/internal/strictjson"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// The measurements config schema versions this package accepts. A future
// version is rejected, never guessed at. Schema 2 adds the per-entry
// launch_file field.
const (
	schemaVersion1 = "1"
	schemaVersion2 = "2"
)

// maxRTMRs is the number of TDX runtime measurement registers, and so the
// length of the config file's rtmr array.
const maxRTMRs = 4

// wire mirrors the file exactly; validation happens against these fields so an
// absent value stays distinguishable from an empty one.
type wire struct {
	SchemaVersion string      `json:"schema_version"`
	TEE           string      `json:"tee"`
	Measurements  []wireImage `json:"measurements"`
}

type wireImage struct {
	Name        string          `json:"name"`
	Measurement *string         `json:"measurement,omitempty"`
	MRTD        *string         `json:"mrtd,omitempty"`
	RTMR        []*string       `json:"rtmr,omitempty"`
	ApproverKey json.RawMessage `json:"approver_key,omitempty"`
	LaunchFile  json.RawMessage `json:"launch_file,omitempty"`
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
	return parse(data, false)
}

func parse(data []byte, allowEmpty bool) (ReferenceValues, error) {
	if _, err := strictjson.RejectDuplicateKeys(data); err != nil {
		return ReferenceValues{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f wire
	if err := dec.Decode(&f); err != nil {
		return ReferenceValues{}, fmt.Errorf("decode: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ReferenceValues{}, fmt.Errorf("trailing data after the JSON object")
	}
	return f.validate(allowEmpty)
}

func (f wire) validate(allowEmpty bool) (ReferenceValues, error) {
	switch f.SchemaVersion {
	case schemaVersion1, schemaVersion2:
	default:
		return ReferenceValues{}, fmt.Errorf("schema_version %q, want %q or %q", f.SchemaVersion, schemaVersion1, schemaVersion2)
	}
	fam, err := teetypes.ParseFamily(f.TEE)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("tee %w", err)
	}
	// An empty list would pin nothing while reading as a pinned config;
	// omitting the flag is how an operator asks for no pinning.
	if len(f.Measurements) == 0 && !allowEmpty {
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
	if err := checkLaunchFileSchema(f.SchemaVersion, rv); err != nil {
		return ReferenceValues{}, err
	}
	return rv, nil
}

// checkLaunchFileSchema requires a document pinning a launch file to declare
// schema 2. A schema 1 reader has no such field, so it must refuse the
// document rather than load it without the binding; schema 2 may pin none.
func checkLaunchFileSchema(version string, rv ReferenceValues) error {
	if pinsLaunchFile(rv) && version != schemaVersion2 {
		return fmt.Errorf("launch_file requires schema_version %q, got %q", schemaVersion2, version)
	}
	return nil
}

func (we wireImage) validate(fam teetypes.Family, i int) (remote.ImagePin, error) {
	at := fmt.Sprintf("measurements[%d]", i)
	if strings.TrimSpace(we.Name) == "" {
		return remote.ImagePin{}, fmt.Errorf("%s: name is required", at)
	}
	img := remote.ImagePin{Name: we.Name}
	if err := we.pinLaunchBinding(&img, at); err != nil {
		return remote.ImagePin{}, err
	}

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
		img.Registers = rtmrs
	default:
		return remote.ImagePin{}, fmt.Errorf("%s: tee %q has no known pin shape", at, fam)
	}
	return img, nil
}

// pinLaunchBinding reads the entry's launch binding: the approver key the
// guest was launched to trust, or the launch file it was launched with. Both
// pin the same hardware field, so an entry carries at most one.
func (we wireImage) pinLaunchBinding(img *remote.ImagePin, at string) error {
	switch {
	case we.ApproverKey != nil && we.LaunchFile != nil:
		return fmt.Errorf("%s: approver_key and launch_file both pin the launch binding, want at most one", at)
	case we.ApproverKey != nil:
		key, err := launchBytes(we.ApproverKey)
		if err != nil {
			return fmt.Errorf("%s.approver_key: %w", at, err)
		}
		if _, err := runtimemeasure.ParsePublicKeyPEM(key); err != nil {
			return fmt.Errorf("%s.approver_key: %w", at, err)
		}
		img.Anchor = key
	case we.LaunchFile != nil:
		file, err := launchBytes(we.LaunchFile)
		if err != nil {
			return fmt.Errorf("%s.launch_file: %w", at, err)
		}
		img.LaunchFile = file
	}
	return nil
}

// launchBytes takes the exact bytes of a launch binding field. The field stays
// a raw message so a JSON null is told apart from an absent field and refused
// here with every other value carrying no bytes: a binding to nothing proves
// nothing.
func launchBytes(raw json.RawMessage) ([]byte, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, err
	}
	if text == "" {
		return nil, fmt.Errorf("is empty")
	}
	return []byte(text), nil
}

func decodeRTMRs(raw []*string, at string) (map[int][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxRTMRs {
		return nil, fmt.Errorf("%s.rtmr has %d entries, want at most %d", at, len(raw), maxRTMRs)
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

// decodeRegister requires lowercase hex of exactly one register width. See
// [teetypes.ParseDigest] for why uppercase is refused rather than folded.
func decodeRegister(s string) ([]byte, error) {
	return teetypes.ParseDigest(s, DigestSize)
}

// Format renders a set as a measurements config document. A pin it cannot
// render is an error, never dropped, so a set that formats is a set that
// [Parse] loads back.
func Format(rv ReferenceValues) ([]byte, error) {
	f := wire{SchemaVersion: schemaVersionFor(rv), TEE: string(rv.Family)}
	for i, img := range rv.Images {
		we := wireImage{Name: img.Name}
		// The launch binding is validated once, by the f.validate call below:
		// it walks every entry through the same wireImage.validate the parse
		// path uses.
		if img.Anchor != nil {
			key, err := jsonString(img.Anchor)
			if err != nil {
				return nil, fmt.Errorf("measurements[%d].approver_key: %w", i, err)
			}
			we.ApproverKey = key
		}
		if img.LaunchFile != nil {
			file, err := jsonString(img.LaunchFile)
			if err != nil {
				return nil, fmt.Errorf("measurements[%d].launch_file: %w", i, err)
			}
			we.LaunchFile = file
		}
		d := hex.EncodeToString(img.Digest)
		switch rv.Family {
		case teetypes.FamilySNP:
			if len(img.Registers) > 0 {
				return nil, fmt.Errorf("measurements[%d]: %d rtmr pin(s) on a %q image, which has no registers", i, len(img.Registers), teetypes.FamilySNP)
			}
			we.Measurement = &d
		case teetypes.FamilyTDX:
			we.MRTD = &d
			if len(img.Registers) > 0 {
				we.RTMR = make([]*string, maxRTMRs)
				for idx, v := range img.Registers {
					if idx <= 0 || idx >= maxRTMRs {
						return nil, fmt.Errorf("measurements[%d]: rtmr[%d] is not pinnable, want 1..%d", i, idx, maxRTMRs-1)
					}
					if len(v) != DigestSize {
						return nil, fmt.Errorf("measurements[%d].rtmr[%d] is %d bytes, want %d", i, idx, len(v), DigestSize)
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
	if _, err := f.validate(false); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode measurements config: %w", err)
	}
	return append(out, '\n'), nil
}

// jsonString encodes exact bytes as a JSON string field. JSON replaces invalid
// UTF-8, which would change the launch binding, so such bytes are refused.
func jsonString(b []byte) (json.RawMessage, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	return json.Marshal(string(b))
}

// tupleKey is the identity a pin is matched on: digest, registers, and launch
// binding. The name is diagnostic only, so it is not part of the key.
func tupleKey(img remote.ImagePin) string {
	var b strings.Builder
	b.WriteString(hex.EncodeToString(img.Digest))
	for _, i := range slices.Sorted(maps.Keys(img.Registers)) {
		fmt.Fprintf(&b, "|%d=%s", i, hex.EncodeToString(img.Registers[i]))
	}
	if img.Anchor != nil {
		fmt.Fprintf(&b, "|anchor=%x", img.Anchor)
	}
	if img.LaunchFile != nil {
		fmt.Fprintf(&b, "|launch_file=%x", img.LaunchFile)
	}
	return b.String()
}

// schemaVersionFor names the schema version [Format] writes for rv: schema 1
// expresses every set that pins no launch file.
func schemaVersionFor(rv ReferenceValues) string {
	if pinsLaunchFile(rv) {
		return schemaVersion2
	}
	return schemaVersion1
}

// pinsLaunchFile reports whether any image pins a launch file, the binding
// schema 2 introduced.
func pinsLaunchFile(rv ReferenceValues) bool {
	for _, img := range rv.Images {
		if img.LaunchFile != nil {
			return true
		}
	}
	return false
}
