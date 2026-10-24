package snp

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Kernel measurement registers for bare-metal SEV-SNP guests.
//
// A guest kernel with the measurement-register provider holds sixteen SHA-384
// registers and a log of every extend, and writes H ‖ C into the REPORT_DATA
// of every report it requests:
//
//	H = event_count (u32 LE) ‖ 12 zero bytes
//	C = SHA-384("snp-kmr-v1" ‖ H ‖ R[0] ‖ … ‖ R[15] ‖ caller_data)
//
// where caller_data is the 64 bytes the requester asked for. Registers start
// at zero; an extend with digest d is R[i] = SHA-384(R[i] ‖ d); each log
// entry is i (u8) ‖ d (48 bytes). The verifier replays the first event_count
// entries of the log and recomputes the commitment; the log itself is not
// signed, so only a log the report commits to counts.

const (
	// registerSize is the width of one register and of one extend digest.
	registerSize = sha512.Size384
	// eventLogEntrySize is one log entry: a register index and a digest.
	eventLogEntrySize = 1 + registerSize
	// commitmentHeaderSize is the width of H at the start of REPORT_DATA.
	commitmentHeaderSize = 16
	// reportDataSize is the width of REPORT_DATA and of the caller data.
	reportDataSize = 64
)

var commitmentTag = []byte("snp-kmr-v1")

// ReplayEventLog replays the first eventCount entries of log from zero
// registers and returns the sixteen registers. ok is false when the log has
// fewer entries than eventCount. A log that is not whole entries naming
// registers 0 to 15 is malformed, whatever the count.
func ReplayEventLog(log []byte, eventCount uint32) (registers [][]byte, ok bool, err error) {
	if len(log)%eventLogEntrySize != 0 {
		return nil, false, fmt.Errorf("snp: event log length %d is not whole entries", len(log))
	}
	entries := len(log) / eventLogEntrySize
	for i := range entries {
		if idx := log[i*eventLogEntrySize]; int(idx) >= teetypes.MeasurementRegisterCount {
			return nil, false, fmt.Errorf("snp: event log register index %d above %d", idx, teetypes.MeasurementRegisterCount-1)
		}
	}
	if uint64(entries) < uint64(eventCount) {
		return nil, false, nil
	}
	registers = make([][]byte, teetypes.MeasurementRegisterCount)
	for i := range registers {
		registers[i] = make([]byte, registerSize)
	}
	for i := range int(eventCount) {
		entry := log[i*eventLogEntrySize : (i+1)*eventLogEntrySize]
		r := registers[entry[0]]
		h := sha512.New384()
		h.Write(r)
		h.Write(entry[1:])
		copy(r, h.Sum(nil))
	}
	return registers, true, nil
}

// CommitmentReportData is the REPORT_DATA a provider kernel writes for the
// given register state and caller data: H ‖ C as described above. registers
// must hold sixteen 48-byte values and callerData 64 bytes.
func CommitmentReportData(eventCount uint32, registers [][]byte, callerData []byte) ([]byte, error) {
	if len(registers) != teetypes.MeasurementRegisterCount {
		return nil, fmt.Errorf("snp: %d registers, want %d", len(registers), teetypes.MeasurementRegisterCount)
	}
	if len(callerData) != reportDataSize {
		return nil, fmt.Errorf("snp: caller data is %d bytes, want %d", len(callerData), reportDataSize)
	}
	header := make([]byte, commitmentHeaderSize)
	binary.LittleEndian.PutUint32(header, eventCount)
	h := sha512.New384()
	h.Write(commitmentTag)
	h.Write(header)
	for i, r := range registers {
		if len(r) != registerSize {
			return nil, fmt.Errorf("snp: register %d is %d bytes, want %d", i, len(r), registerSize)
		}
		h.Write(r)
	}
	h.Write(callerData)
	return append(header, h.Sum(nil)...), nil
}

// VerifyCommitment returns the registers that reported (a report's
// REPORT_DATA) commits to together with callerData, replayed from log, or nil
// when reported is not that commitment. It errors only for a malformed log or
// malformed inputs.
func VerifyCommitment(reported, log, callerData []byte) (*teetypes.MeasurementRegisters, error) {
	if len(reported) != reportDataSize {
		return nil, fmt.Errorf("snp: REPORT_DATA is %d bytes, want %d", len(reported), reportDataSize)
	}
	eventCount := binary.LittleEndian.Uint32(reported)
	registers, ok, err := ReplayEventLog(log, eventCount)
	if err != nil || !ok {
		return nil, err
	}
	expected, err := CommitmentReportData(eventCount, registers, callerData)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(reported, expected) != 1 {
		return nil, nil
	}
	return &teetypes.MeasurementRegisters{EventCount: eventCount, Registers: registers}, nil
}

// checkMeasurementRegisters is the register-mode binding check: REPORT_DATA
// must commit to the event log and the caller data, and the replayed
// registers must equal the expected values, with every register past the
// expected list zero. The launch digest must already have been pinned and
// verified: on an image without the provider, guest root chooses REPORT_DATA
// and can commit to any registers.
func checkMeasurementRegisters(reported, log, callerData []byte, expected [][]byte) (*teetypes.MeasurementRegisters, error) {
	registers, err := VerifyCommitment(reported, log, callerData)
	if err != nil {
		return nil, err
	}
	if registers == nil {
		return nil, fmt.Errorf("snp: REPORT_DATA does not commit to the event log and the expected report data")
	}
	for i, got := range registers.Registers {
		want := make([]byte, registerSize)
		if i < len(expected) {
			want = expected[i]
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return nil, fmt.Errorf("snp: measurement register %d does not match the expected value", i)
		}
	}
	return registers, nil
}

// checkMeasurementRegisterParams rejects register-mode params that cannot be
// applied, before any verification: at most sixteen 48-byte expected values,
// report data of 1 to 64 bytes, a launch digest pin, and bare-metal snp.
func checkMeasurementRegisterParams(params teetypes.VerifyParams, platform teetypes.PlatformType) error {
	if !platform.HasMeasurementRegisters() {
		return fmt.Errorf("snp: measurement registers are bare-metal snp only, not %q", platform)
	}
	if n := len(params.MeasurementRegisters); n > teetypes.MeasurementRegisterCount {
		return fmt.Errorf("snp: %d expected measurement registers, want at most %d", n, teetypes.MeasurementRegisterCount)
	}
	for i, r := range params.MeasurementRegisters {
		if len(r) != registerSize {
			return fmt.Errorf("snp: expected measurement register %d is %d bytes, want %d", i, len(r), registerSize)
		}
	}
	if n := len(params.ExpectedReportData); n == 0 || n > reportDataSize {
		return fmt.Errorf("snp: measurement registers need expected_report_data of 1 to %d bytes, got %d", reportDataSize, n)
	}
	if params.ExpectedLaunchDigest == nil {
		return fmt.Errorf("snp: measurement registers need expected_launch_digest: without the provider image pinned, any register value can be forged")
	}
	return nil
}
