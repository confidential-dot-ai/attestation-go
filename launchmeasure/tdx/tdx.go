package tdx

import (
	"fmt"

	gcetdx "github.com/google/gce-tcb-verifier/tdx"
)

// DigestLen is the length of an MRTD, in bytes. MRTD is a SHA-384, so this
// equals runtimemeasure.Size; the two packages stay independent because a
// launch measurement and a runtime register share only their hash function.
const DigestLen = 48

// launchOptions returns the only option set valid for a QEMU-launched TD.
//
// LaunchOptions is a GCE-shaped API and its other presets do NOT describe a
// QEMU VMM: MeasureAllRegions (LaunchOptionsDefaultTDHOBBug) models a Google
// hypervisor bug, and DisableUnacceptedMemory changes the TD HOB. Both produce
// a different digest, which no QEMU guest reports. The machine-type argument is
// unused by the library.
func launchOptions() *gcetdx.LaunchOptions { return gcetdx.LaunchOptionsDefault("") }

// MRTD returns the 48-byte TDX build-time measurement of a TDVF image.
func MRTD(firmware []byte) ([]byte, error) {
	d, err := gcetdx.MRTD(launchOptions(), firmware)
	if err != nil {
		return nil, fmt.Errorf("compute MRTD: %w", err)
	}
	return d[:], nil
}
