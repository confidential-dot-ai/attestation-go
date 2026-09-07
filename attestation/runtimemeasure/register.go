package runtimemeasure

import (
	"errors"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ErrNoRegister reports that the platform has no runtime measurement register.
// SEV-SNP guests commit their post-launch identity at launch instead (see
// HostDataForOperatorKey), so there is nothing to extend or read back locally.
// Callers gating on an extend must treat this as a hard stop, not a skip.
var ErrNoRegister = errors.New("platform has no runtime measurement register")

// Register is a guest's own runtime measurement register, as reached from
// inside that guest. It is the local device; [Binding] is the remote-verifiable
// view of the same value, read out of claims a verifier has accepted.
//
// Extend is append-only in hardware: a value once folded in cannot be removed,
// and a caller that extends the same event twice produces a different register
// than one that extends it once. Deduplication is the caller's job.
type Register interface {
	// Extend folds one event into the register: new = SHA384(reg ‖ event).
	// event must be Size bytes.
	Extend(event []byte) error

	// Extension returns the register's current value, Size bytes long.
	Extension() ([]byte, error)
}

// DefaultTDXRegisterPath is the kernel TSM node backing RTMR[3] on Intel TDX.
// Writing Size bytes to it performs TDG.MR.RTMR.EXTEND; reading returns the
// current register. Needs mainline Linux 6.16 or later.
const DefaultTDXRegisterPath = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

// Open returns the local runtime measurement register for p, or ErrNoRegister
// on a platform without one. Platform tags are compared by family, so the
// cloud overlays (az-tdx, gcp-tdx) resolve the same as bare-metal tdx.
func Open(p teetypes.PlatformType) (Register, error) {
	switch p.Family() {
	case teetypes.FamilyTDX:
		return TDXRegister(DefaultTDXRegisterPath), nil
	case teetypes.FamilySNP:
		return nil, fmt.Errorf("%q: %w", p, ErrNoRegister)
	default:
		// An unrecognized tag gets no register rather than a TDX one: this
		// module has no verifier for it, so nothing it reported could be
		// checked anyway.
		return nil, fmt.Errorf("unknown platform %q: %w", p, ErrNoRegister)
	}
}

// TDXRegister returns the RTMR[3] register backed by the TSM sysfs node at
// path. Pass DefaultTDXRegisterPath outside tests; [Open] does that for you.
func TDXRegister(path string) Register { return tdxRegister{path: path} }

type tdxRegister struct{ path string }

func (r tdxRegister) Extend(event []byte) error {
	if len(event) != Size {
		return fmt.Errorf("extend event is %d bytes, want %d", len(event), Size)
	}
	// O_WRONLY without O_CREATE: os.WriteFile would CREATE a missing node and
	// report success, so a guest whose kernel exposes no TSM node — or a
	// mistyped path — would measure nothing while believing it had extended.
	// The node takes one whole event per write; a short write is an error from
	// the kernel, not a partial extend.
	f, err := os.OpenFile(r.path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("extend %s: %w (is this a TDX guest with runtime measurement?)", r.path, err)
	}
	_, werr := f.Write(event)
	// Close reports write errors the kernel deferred, so it is checked and
	// reported rather than deferred away.
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("extend %s: %w", r.path, werr)
	}
	if cerr != nil {
		return fmt.Errorf("extend %s: %w", r.path, cerr)
	}
	return nil
}

func (r tdxRegister) Extension() ([]byte, error) {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (is this a TDX guest with runtime measurement?)", r.path, err)
	}
	if len(b) != Size {
		return nil, fmt.Errorf("read %s: got %d bytes, want %d", r.path, len(b), Size)
	}
	return b, nil
}
