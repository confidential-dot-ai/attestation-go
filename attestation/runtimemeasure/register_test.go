package runtimemeasure

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestOpenByFamily(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		want     bool // a register exists
	}{
		{teetypes.PlatformTDX, true},
		{teetypes.PlatformAzTDX, true},
		{teetypes.PlatformGcpTDX, true},
		{teetypes.PlatformSNP, false},
		{teetypes.PlatformAzSNP, false},
		{teetypes.PlatformGcpSNP, false},
		{teetypes.PlatformDstack, false},
		{"nonsense", false},
	} {
		reg, err := Open(tc.platform)
		if tc.want {
			if err != nil {
				t.Errorf("Open(%q) = _, %v, want a register", tc.platform, err)
			}
			continue
		}
		if !errors.Is(err, ErrNoRegister) {
			t.Errorf("Open(%q) = _, %v, want ErrNoRegister", tc.platform, err)
		}
		if reg != nil {
			t.Errorf("Open(%q) returned a register alongside its error", tc.platform)
		}
	}
}

// The sysfs node behaves as a value cell in these tests: writes replace, reads
// return. That is enough to exercise the framing (width checks, error text);
// the hardware's append-only semantics are the kernel's, not this package's.
func tdxRegisterFile(t *testing.T, initial []byte) (Register, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rtmr3:sha384")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("seed register file: %v", err)
	}
	return TDXRegister(path), path
}

func TestTDXRegisterRoundTrip(t *testing.T) {
	want := sha512.Sum384([]byte("event"))
	reg, path := tdxRegisterFile(t, Zero[:])

	if err := reg.Extend(want[:]); err != nil {
		t.Fatalf("Extend: %v", err)
	}
	got, err := reg.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Errorf("Extension() = %x, want %x", got, want)
	}
	// The write must land as the raw event, not a re-encoding of it.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(onDisk, want[:]) {
		t.Errorf("on-disk = %x, want %x", onDisk, want)
	}
}

func TestTDXRegisterRejectsWrongWidths(t *testing.T) {
	reg, _ := tdxRegisterFile(t, Zero[:])
	if err := reg.Extend([]byte("short")); err == nil {
		t.Error("Extend(5 bytes) = nil, want an error")
	}

	short, _ := tdxRegisterFile(t, []byte("short"))
	if _, err := short.Extension(); err == nil {
		t.Error("Extension() on a truncated register = nil, want an error")
	}
}

func TestTDXRegisterMissingNode(t *testing.T) {
	reg := TDXRegister(filepath.Join(t.TempDir(), "absent"))
	if _, err := reg.Extension(); err == nil {
		t.Error("Extension() on a missing node = nil, want an error")
	}
	if err := reg.Extend(Zero[:]); err == nil {
		t.Error("Extend on a missing node = nil, want an error")
	}
}
