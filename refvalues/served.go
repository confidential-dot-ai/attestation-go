package refvalues

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Serve renders the set as a document describing what a component enforces.
// Unlike [Format] it accepts an empty set: a component that pins nothing is
// the state an operator most needs reported.
func Serve(rv ReferenceValues) ([]byte, error) {
	if len(rv.Images) == 0 {
		f := wire{SchemaVersion: SchemaVersion1, TEE: string(rv.Family), Measurements: []wireImage{}}
		out, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode served measurements: %w", err)
		}
		return append(out, '\n'), nil
	}
	return Format(rv)
}

// ParseServed decodes a document a component serves to describe the reference
// values it enforces. Unlike [Parse] it accepts an empty set, because a
// component that enforces nothing must still be readable. An operator's own
// config file takes [Parse] instead.
func ParseServed(data []byte) (ReferenceValues, error) {
	var f wire
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&f); err != nil {
		return ReferenceValues{}, fmt.Errorf("decode served measurements: %w", err)
	}
	if f.SchemaVersion != SchemaVersion1 {
		return ReferenceValues{}, fmt.Errorf("served schema_version %q, want %q", f.SchemaVersion, SchemaVersion1)
	}
	fam, err := teetypes.ParseFamily(f.TEE)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("served tee %w", err)
	}
	rv := ReferenceValues{Family: fam}
	for i, we := range f.Measurements {
		img, err := we.validate(fam, i)
		if err != nil {
			return ReferenceValues{}, err
		}
		rv.Images = append(rv.Images, img)
	}
	return rv, nil
}

// Diff reports the images each side pins and the other does not, matched on
// what decides admission: the digest and its registers. Names are diagnostic
// only, so two entries that name one image differently are still the same
// pin.
func Diff(want, got ReferenceValues) (missing, extra []remote.ImagePin) {
	index := func(rv ReferenceValues) map[string]remote.ImagePin {
		m := make(map[string]remote.ImagePin, len(rv.Images))
		for _, img := range rv.Images {
			m[tupleKey(img)] = img
		}
		return m
	}
	w, g := index(want), index(got)
	for k, img := range w {
		if _, ok := g[k]; !ok {
			missing = append(missing, img)
		}
	}
	for k, img := range g {
		if _, ok := w[k]; !ok {
			extra = append(extra, img)
		}
	}
	byTuple := func(a, b remote.ImagePin) int { return strings.Compare(tupleKey(a), tupleKey(b)) }
	slices.SortFunc(missing, byTuple)
	slices.SortFunc(extra, byTuple)
	return missing, extra
}
