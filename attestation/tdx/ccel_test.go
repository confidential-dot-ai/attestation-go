package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// batchEvidence returns the {platform, evidence} entries of the live TDX
// fixture, each of which carries a real CCEL event log.
func batchEvidence(t *testing.T) []TdxEvidence {
	t.Helper()
	var batch []struct {
		Platform string      `json:"platform"`
		Evidence TdxEvidence `json:"evidence"`
	}
	if err := json.Unmarshal(tdxEvidenceBatch, &batch); err != nil {
		t.Fatalf("parsing batch fixture: %v", err)
	}
	out := make([]TdxEvidence, 0, len(batch))
	for _, e := range batch {
		out = append(out, e.Evidence)
	}
	if len(out) == 0 {
		t.Fatal("batch fixture is empty")
	}
	return out
}

// quoteRTMRsOf verifies the evidence and returns the quote's four RTMRs.
func quoteRTMRsOf(t *testing.T, ev TdxEvidence) [4][]byte {
	t.Helper()
	quoteBytes, err := base64.StdEncoding.DecodeString(ev.Quote)
	if err != nil {
		t.Fatalf("decoding quote: %v", err)
	}
	rtmrs, err := quoteRTMRs(quoteBytes)
	if err != nil {
		t.Fatalf("extracting RTMRs: %v", err)
	}
	return rtmrs
}

// TestParseCCEL_LiveFixture checks the parser against real CCEL blobs: every
// event must carry a 48-byte SHA-384 digest and target a valid MR index.
func TestParseCCEL_LiveFixture(t *testing.T) {
	for i, ev := range batchEvidence(t) {
		t.Run(fmt.Sprintf("entry-%d", i), func(t *testing.T) {
			ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
			if err != nil {
				t.Fatalf("decoding cc_eventlog: %v", err)
			}
			events, err := ParseCCEL(ccel)
			if err != nil {
				t.Fatalf("ParseCCEL: %v", err)
			}
			if len(events) == 0 {
				t.Fatal("expected a non-empty event log")
			}
			for j, e := range events {
				if len(e.SHA384Digest) != 48 {
					t.Errorf("event %d: digest is %d bytes, want 48", j, len(e.SHA384Digest))
				}
				if e.MRIndex < 1 || e.MRIndex > 4 {
					t.Errorf("event %d: MR index %d out of range 1..4", j, e.MRIndex)
				}
			}
		})
	}
}

// TestVerifyCCELAgainstRTMRs_LiveFixture is the core correctness check: the
// replayed boot-time registers must reproduce the values signed in the quote.
func TestVerifyCCELAgainstRTMRs_LiveFixture(t *testing.T) {
	for i, ev := range batchEvidence(t) {
		t.Run(fmt.Sprintf("entry-%d", i), func(t *testing.T) {
			ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
			if err != nil {
				t.Fatalf("decoding cc_eventlog: %v", err)
			}
			r := quoteRTMRsOf(t, ev)

			rtmr3Match, err := VerifyCCELAgainstRTMRs(ccel, r[0], r[1], r[2], r[3])
			if err != nil {
				t.Fatalf("live CCEL must replay to the quote's RTMR[0-2]: %v", err)
			}
			t.Logf("rtmr3 replay match: %v", rtmr3Match)

			// The replay must be non-trivial: a zeroed RTMR[0] would pass if the
			// parser silently produced no events.
			events, err := ParseCCEL(ccel)
			if err != nil {
				t.Fatalf("ParseCCEL: %v", err)
			}
			replayed := ReplayRTMRs(events)
			var zero [48]byte
			if replayed[0] == zero {
				t.Fatal("replayed RTMR[0] is all zeroes — the event log was not actually replayed")
			}
		})
	}
}

// TestVerifyCCELAgainstRTMRs_TamperedBootRTMR ensures a boot-time register
// mismatch is a hard failure.
func TestVerifyCCELAgainstRTMRs_TamperedBootRTMR(t *testing.T) {
	ev := batchEvidence(t)[0]
	ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
	if err != nil {
		t.Fatalf("decoding cc_eventlog: %v", err)
	}
	r := quoteRTMRsOf(t, ev)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("rtmr-%d", i), func(t *testing.T) {
			bad := [4][]byte{
				append([]byte(nil), r[0]...),
				append([]byte(nil), r[1]...),
				append([]byte(nil), r[2]...),
				append([]byte(nil), r[3]...),
			}
			bad[i][0] ^= 0xFF
			if _, err := VerifyCCELAgainstRTMRs(ccel, bad[0], bad[1], bad[2], bad[3]); err == nil {
				t.Fatalf("tampered RTMR[%d] must fail verification", i)
			}
		})
	}
}

// TestVerifyCCELAgainstRTMRs_RuntimeExtendedRTMR3 pins the ff879e5 semantics: a
// guest-side runtime extend changes RTMR[3] without a CCEL entry, so the replay
// diverges but verification must still succeed — reported, not enforced.
func TestVerifyCCELAgainstRTMRs_RuntimeExtendedRTMR3(t *testing.T) {
	ev := batchEvidence(t)[0]
	ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
	if err != nil {
		t.Fatalf("decoding cc_eventlog: %v", err)
	}
	r := quoteRTMRsOf(t, ev)

	// Simulate a runtime extend: RTMR[3] = SHA384(RTMR[3] || digest).
	h := sha512.New384()
	h.Write(r[3])
	h.Write(make([]byte, 48))
	extended := h.Sum(nil)

	rtmr3Match, err := VerifyCCELAgainstRTMRs(ccel, r[0], r[1], r[2], extended)
	if err != nil {
		t.Fatalf("runtime-extended RTMR[3] must not fail eventlog verification: %v", err)
	}
	if rtmr3Match {
		t.Fatal("rtmr3Match should be false after a runtime extend")
	}
}

// TestVerifyCCELAgainstRTMRs_TamperedEventlog flips a byte inside an event
// digest; the replay must then diverge from the signed RTMRs.
func TestVerifyCCELAgainstRTMRs_TamperedEventlog(t *testing.T) {
	ev := batchEvidence(t)[0]
	ccel, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
	if err != nil {
		t.Fatalf("decoding cc_eventlog: %v", err)
	}
	r := quoteRTMRsOf(t, ev)

	// Sanity: untampered log verifies.
	if _, err := VerifyCCELAgainstRTMRs(ccel, r[0], r[1], r[2], r[3]); err != nil {
		t.Fatalf("baseline CCEL should verify: %v", err)
	}

	// The first event's SHA-384 digest lives just past the Spec ID Event header
	// and the event2 header; flipping any byte of the log body must break the
	// replay. Locate it via the parser rather than hardcoding an offset.
	events, err := ParseCCEL(ccel)
	if err != nil {
		t.Fatalf("ParseCCEL: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events to tamper with")
	}
	needle := events[0].SHA384Digest
	idx := indexOf(ccel, needle)
	if idx < 0 {
		t.Fatal("could not locate the first event digest in the raw log")
	}
	tampered := append([]byte(nil), ccel...)
	tampered[idx] ^= 0x01

	if _, err := VerifyCCELAgainstRTMRs(tampered, r[0], r[1], r[2], r[3]); err == nil {
		t.Fatal("a tampered event digest must break the RTMR replay")
	}
}

// TestVerifyCCELAgainstRTMRs_Malformed covers the defensive parser paths.
func TestVerifyCCELAgainstRTMRs_Malformed(t *testing.T) {
	r := [4][]byte{make([]byte, 48), make([]byte, 48), make([]byte, 48), make([]byte, 48)}

	t.Run("too-short", func(t *testing.T) {
		if _, err := VerifyCCELAgainstRTMRs([]byte{1, 2, 3}, r[0], r[1], r[2], r[3]); err == nil {
			t.Fatal("a truncated CCEL must be rejected")
		}
	})

	t.Run("spec-id-size-overruns", func(t *testing.T) {
		blob := make([]byte, 64)
		// Spec ID Event size far beyond the buffer.
		blob[28], blob[29], blob[30], blob[31] = 0xFF, 0xFF, 0x00, 0x00
		if _, err := VerifyCCELAgainstRTMRs(blob, r[0], r[1], r[2], r[3]); err == nil {
			t.Fatal("an out-of-range Spec ID Event size must be rejected")
		}
	})

	t.Run("all-zero-padding-replays-empty", func(t *testing.T) {
		// A well-formed header followed by zero padding yields no events, so the
		// replay stays all-zero and must not match real RTMRs.
		blob := make([]byte, 4096)
		events, err := ParseCCEL(blob)
		if err != nil {
			t.Fatalf("ParseCCEL on zero padding: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("expected no events from zero padding, got %d", len(events))
		}
	})

	t.Run("wrong-rtmr-length", func(t *testing.T) {
		short := make([]byte, 32)
		if _, err := VerifyCCELAgainstRTMRs(make([]byte, 64), short, r[1], r[2], r[3]); err == nil {
			t.Fatal("a non-48-byte RTMR must be rejected")
		}
	})
}

// TestVerifyEvidence_EventlogWired proves the replay is reached from the
// evidence entry point and reflected in the result.
func TestVerifyEvidence_EventlogWired(t *testing.T) {
	ev := batchEvidence(t)[0]

	res, err := VerifyEvidence(ev, teetypes.VerifyParams{}, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if res.EventlogVerified == nil || !*res.EventlogVerified {
		t.Fatal("EventlogVerified should be true when a CCEL is present and replays")
	}
	if res.RTMR3ReplayMatch == nil {
		t.Fatal("RTMR3ReplayMatch should be reported when a CCEL is present")
	}

	// Evidence without an event log leaves both fields unset.
	noLog := TdxEvidence{Quote: ev.Quote}
	res, err = VerifyEvidence(noLog, teetypes.VerifyParams{}, Options{})
	if err != nil {
		t.Fatalf("VerifyEvidence without eventlog: %v", err)
	}
	if res.EventlogVerified != nil || res.RTMR3ReplayMatch != nil {
		t.Fatal("eventlog fields must be nil when no CCEL is supplied")
	}

	// A corrupted event log must fail the whole verification, not be ignored.
	corrupt := ev
	raw, err := base64.StdEncoding.DecodeString(ev.CCEventlog)
	if err != nil {
		t.Fatalf("decoding cc_eventlog: %v", err)
	}
	events, err := ParseCCEL(raw)
	if err != nil || len(events) == 0 {
		t.Fatalf("ParseCCEL: %v", err)
	}
	idx := indexOf(raw, events[0].SHA384Digest)
	if idx < 0 {
		t.Fatal("could not locate the first event digest")
	}
	tampered := append([]byte(nil), raw...)
	tampered[idx] ^= 0x01
	corrupt.CCEventlog = base64.StdEncoding.EncodeToString(tampered)

	if _, err := VerifyEvidence(corrupt, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("a tampered event log must fail VerifyEvidence")
	}

	// Non-base64 event log is a decode error, not a silent skip.
	bad := ev
	bad.CCEventlog = "!!!not-base64!!!"
	if _, err := VerifyEvidence(bad, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("an undecodable event log must fail VerifyEvidence")
	}
}

// TestVerifyEvidence_FieldSizeCap covers the per-field bound on the exported
// entry point.
func TestVerifyEvidence_FieldSizeCap(t *testing.T) {
	huge := strings.Repeat("A", teetypes.MaxEvidenceFieldSize+1)

	if _, err := VerifyEvidence(TdxEvidence{Quote: huge}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("an oversized quote must be rejected")
	}
	ev := batchEvidence(t)[0]
	if _, err := VerifyEvidence(TdxEvidence{Quote: ev.Quote, CCEventlog: huge}, teetypes.VerifyParams{}, Options{}); err == nil {
		t.Fatal("an oversized cc_eventlog must be rejected")
	}
}

func indexOf(haystack, needle []byte) int { return bytes.Index(haystack, needle) }
