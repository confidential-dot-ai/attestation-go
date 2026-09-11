// Package strictjson holds the JSON strictness the reference-value loaders
// need and encoding/json does not provide: a document that names one key twice
// is refused rather than silently resolved.
//
// encoding/json keeps the last of two same-named keys, and matches struct
// fields case-insensitively, so "mrtd" followed by "MRTD" loads a value other
// than the one a reviewer read. For a measurement reference — a manifest, a
// pin file — the value that loads and the value a reviewer approved must be the
// same one, which is what makes the extra pass worth making.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// RejectDuplicateKeys fails a document that names any key twice within one
// object, compared the way encoding/json matches struct fields:
// case-insensitively. Nested objects and objects inside arrays are checked too,
// so a duplicate anywhere in the document is refused.
//
// It returns the top-level keys as written, which a loader needs to tell two
// spellings of one field apart — a flat register beside the nested object that
// would win over it, say.
//
// A document that is not a JSON object has no keys to check and is reported as
// neither keys nor an error: the caller's decoder is what says what shape it
// expected.
func RejectDuplicateKeys(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil
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
			return nil, fmt.Errorf("not valid JSON: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("not valid JSON: object key is %T", tok)
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
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	return keys, nil
}

// walkValue consumes one value, descending into objects and arrays so every
// nested object is checked too.
func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
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
			return fmt.Errorf("not valid JSON: %w", err)
		}
	}
	return nil
}
