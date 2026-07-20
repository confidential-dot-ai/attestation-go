package tdx

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// CCEL (CC Event Log) parsing and RTMR replay verification. Port of
// attestation-rs's tdx::ccel.
//
// The CCEL is a TCG2-format event log stored in the ACPI CCEL table at
// /sys/firmware/acpi/tables/data/CCEL. Each event targets an MR index (1-4,
// mapping to RTMR[0-3]) and carries a SHA-384 digest. Replaying the events from
// a zero-initialized state must reproduce the RTMR values in the TDX quote,
// which binds the (otherwise unauthenticated) event log to the signed quote.
//
// Only RTMR[0-2] (the boot-time registers) are enforced. RTMR[3] is the
// runtime-extendable register: the guest kernel's tdx_guest sysfs extend
// interface appends no CCEL entry (the log area is firmware-owned), so any
// legitimate runtime extend makes RTMR[3] unreplayable by construction. A
// RTMR[3] divergence is therefore reported, not treated as an error; relying
// parties pin quote.rtmr_3 directly via VerifyParams.ExpectedRTMRs.

// maxDigestAlgorithms caps the per-event digest count. The TCG spec allows ~3;
// a larger value means we have run off the end of the events into the padding
// of the (typically 64 KiB) ACPI table.
const maxDigestAlgorithms = 16

// TCG algorithm identifiers and their digest sizes.
const (
	algoSHA1   = 0x0004
	algoSHA256 = 0x000B
	algoSHA384 = 0x000C
	algoSHA512 = 0x000D
)

// CCELEvent is a parsed CCEL event.
type CCELEvent struct {
	// MRIndex is the measurement register index: 1=RTMR[0] .. 4=RTMR[3].
	MRIndex uint32
	// EventType is the TCG2 event type (e.g. 0x80000001 =
	// EV_EFI_VARIABLE_DRIVER_CONFIG).
	EventType uint32
	// SHA384Digest is the event's SHA-384 digest (48 bytes).
	SHA384Digest []byte
	// EventData is the raw event payload; its structure depends on EventType.
	EventData []byte
}

// digestSize returns the digest length for a TCG algorithm id.
func digestSize(algoID uint16) (int, bool) {
	switch algoID {
	case algoSHA384:
		return 48, true
	case algoSHA512:
		return 64, true
	case algoSHA256:
		return 32, true
	case algoSHA1:
		return 20, true
	default:
		return 0, false
	}
}

// exceeds reports whether reading n bytes at off would run past the end of b.
func exceeds(b []byte, off, n int) bool {
	return off < 0 || n < 0 || off+n > len(b)
}

// ParseCCEL parses a CCEL binary blob into its events.
//
// The first record is a TCG Spec ID Event header (EV_NO_ACTION at PCR 0) and is
// skipped; the remainder are TCG_PCR_EVENT2 structures. Parsing stops cleanly at
// the first truncated or terminator record, since the ACPI table is zero-padded
// well beyond the last real event.
func ParseCCEL(data []byte) ([]CCELEvent, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("tdx: CCEL data too short: %d bytes", len(data))
	}

	// Spec ID Event: 32-byte TCG_PCR_EVENT header, then eventSize bytes of data.
	eventSize := int(binary.LittleEndian.Uint32(data[28:32]))
	if eventSize < 0 {
		return nil, fmt.Errorf("tdx: CCEL Spec ID Event size overflow")
	}
	offset := 32 + eventSize
	if offset < 32 || offset > len(data) {
		return nil, fmt.Errorf("tdx: CCEL Spec ID Event size (%d) exceeds data (%d bytes)", eventSize, len(data))
	}

	var events []CCELEvent

	for offset < len(data) {
		if exceeds(data, offset, 8) {
			break
		}
		mrIndex := binary.LittleEndian.Uint32(data[offset : offset+4])
		eventType := binary.LittleEndian.Uint32(data[offset+4 : offset+8])

		pos := offset + 8
		if exceeds(data, pos, 4) {
			break
		}
		digestCount := binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4

		if digestCount > maxDigestAlgorithms {
			// Ran into padding / uninitialized region of the CCEL table.
			break
		}

		var sha384Digest []byte
		truncated := false

		for i := uint32(0); i < digestCount; i++ {
			if exceeds(data, pos, 2) {
				truncated = true
				break
			}
			algoID := binary.LittleEndian.Uint16(data[pos : pos+2])
			pos += 2

			size, known := digestSize(algoID)
			if !known {
				return nil, fmt.Errorf("tdx: unsupported CCEL digest algorithm 0x%04X at offset %d", algoID, pos)
			}
			if exceeds(data, pos, size) {
				truncated = true
				break
			}
			if algoID == algoSHA384 {
				sha384Digest = append([]byte(nil), data[pos:pos+size]...)
			}
			pos += size
		}
		if truncated {
			break
		}

		if exceeds(data, pos, 4) {
			break
		}
		eventDataSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if eventDataSize < 0 {
			return nil, fmt.Errorf("tdx: CCEL event_data_size overflow")
		}
		eventEnd := pos + eventDataSize
		if eventEnd < pos || eventEnd > len(data) {
			break
		}

		// Terminator record: type=0, mr=0, size=0.
		if eventType == 0 && mrIndex == 0 && eventDataSize == 0 {
			break
		}

		if len(sha384Digest) != 0 {
			events = append(events, CCELEvent{
				MRIndex:      mrIndex,
				EventType:    eventType,
				SHA384Digest: sha384Digest,
				EventData:    append([]byte(nil), data[pos:eventEnd]...),
			})
		}

		offset = eventEnd
	}

	return events, nil
}

// ReplayRTMRs replays events to compute the four RTMR values.
//
// Each RTMR starts as 48 zero bytes and is extended per event:
//
//	RTMR_new = SHA384(RTMR_old || event_digest)
//
// The result is indexed [RTMR[0], RTMR[1], RTMR[2], RTMR[3]].
func ReplayRTMRs(events []CCELEvent) [4][48]byte {
	var rtmrs [4][48]byte

	for _, ev := range events {
		// MR index 1-4 maps to RTMR[0-3]; anything else is not an RTMR extend.
		if ev.MRIndex < 1 || ev.MRIndex > 4 {
			continue
		}
		idx := ev.MRIndex - 1

		h := sha512.New384()
		h.Write(rtmrs[idx][:])
		h.Write(ev.SHA384Digest)
		copy(rtmrs[idx][:], h.Sum(nil))
	}

	return rtmrs
}

// VerifyCCELAgainstRTMRs replays ccelData and checks it reproduces the RTMR
// values from the TDX quote body.
//
// RTMR[0-2] are enforced: a mismatch is an error. RTMR[3] is only reported —
// see the package notes above on runtime extends — so rtmr3Match is false for
// any guest that extended RTMR[3] after boot, which is legitimate. Callers that
// care about RTMR[3] pin it via VerifyParams.ExpectedRTMRs, which is checked
// against the signed quote rather than the event log.
//
// Each rtmr argument must be 48 bytes.
func VerifyCCELAgainstRTMRs(ccelData []byte, rtmr0, rtmr1, rtmr2, rtmr3 []byte) (rtmr3Match bool, err error) {
	for i, r := range [][]byte{rtmr0, rtmr1, rtmr2, rtmr3} {
		if len(r) != 48 {
			return false, fmt.Errorf("tdx: RTMR[%d] is %d bytes (want 48)", i, len(r))
		}
	}

	events, err := ParseCCEL(ccelData)
	if err != nil {
		return false, err
	}
	replayed := ReplayRTMRs(events)

	for i, want := range [][]byte{rtmr0, rtmr1, rtmr2} {
		if subtle.ConstantTimeCompare(replayed[i][:], want) != 1 {
			return false, fmt.Errorf(
				"tdx: CCEL eventlog integrity check failed: RTMR[%d] mismatch: replayed=%s, quote=%s",
				i, hex.EncodeToString(replayed[i][:]), hex.EncodeToString(want),
			)
		}
	}

	return subtle.ConstantTimeCompare(replayed[3][:], rtmr3) == 1, nil
}
