// Package runtimemeasure pins the conventions for runtime measurement: what a
// confidential guest commits after launch, and in what order.
//
// Runtime measurement is the counterpart to launch measurement. A launch
// measurement (MRTD on Intel TDX, the launch digest on AMD SEV-SNP) covers what
// booted and is fixed at launch. What a guest commits beside it can carry
// identity a launch measurement cannot: the anchor it was launched to trust,
// and the workloads it admitted.
//
// An anchor is whatever bytes distinguish one launch from another — a public
// key, a policy document, a configuration digest. This package hashes those
// bytes and says nothing about what they mean.
//
// Both families bind the anchor at launch, in an init-data field the launcher
// sets to the anchor's digest ([LaunchFileDigest]) and the measured initrd
// checks before it trusts the anchor:
//
//   - Intel TDX: MRCONFIGID = SHA-384(anchor), 48 bytes. RTMR[3], a hardware
//     append-only register, is a separate runtime log: it starts at [Zero] and
//     chains one extend per workload image ([Event], [Extend], [FromDigests]).
//     [Register] is the local device.
//   - AMD SEV-SNP: HOSTDATA = SHA-256(anchor), 32 bytes ([HostData]). There is
//     no runtime log, so [Register] reports [ErrNoRegister].
//
// Callers that only need "was this guest launched with my anchor" use
// [VerifyBinding], which resolves the difference and never asks the caller
// which platform it is on. Callers driving the register directly (an in-guest
// measurer) use [Register], with [Journal] on top of it to keep those extends
// exactly-once across restarts. A verifier holding the guest's own extension
// list, which may run ahead of the quote, uses [MatchBindingPrefix] to find the
// prefix RTMR[3] proves. Callers pinning which image booted, rather than what
// it was launched with, use [ImageIdentity].
package runtimemeasure

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
)

// Size is the byte length of the register and of every event (SHA-384).
const Size = 48

// Zero is the register's reset value at guest boot.
var Zero [Size]byte

// Event maps one workload image to its measurement event: SHA384 of the
// canonical digest string "sha256:<64-hex>".
func Event(canonicalDigest string) [Size]byte {
	return sha512.Sum384([]byte(canonicalDigest))
}

// Extend folds one event into a register value, mirroring the hardware extend
// primitive (on TDX, TDG.MR.RTMR.EXTEND): new = SHA384(reg ‖ event).
func Extend(reg, event [Size]byte) [Size]byte {
	h := sha512.New384()
	h.Write(reg[:])
	h.Write(event[:])
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// FromDigests computes the expected RTMR[3] value after measuring the given
// canonical image digests in order, starting from Zero. Each DISTINCT image
// is extended exactly once (the measurer dedups restarts/replicas before
// extending); callers pass the deduped, ordered set.
func FromDigests(canonicalDigests []string) [Size]byte {
	reg := Zero
	for _, d := range canonicalDigests {
		reg = Extend(reg, Event(d))
	}
	return reg
}

// HostDataSize is the byte length of the SEV-SNP HOSTDATA field, and so of the
// launch-time binding value on SNP (SHA-256).
const HostDataSize = 32

// HostData computes the SEV-SNP launch binding: the value a launcher commits
// as HOSTDATA when launching a guest for these anchor bytes.
//
//	HOSTDATA = SHA256(anchor)
//
// The host can set any value, but a verifier that checks HOSTDATA against the
// anchor it expects rejects a wrong-anchor launch. A guest launched with no
// anchor carries all-zero HOSTDATA, which no SHA-256 output equals, so that
// fails closed too.
//
// What HOSTDATA proves is which anchor the launcher committed, not that the
// guest honours it: the verifier must also pin a launch digest of an image
// known to check HOSTDATA and refuse any anchor that does not match it. The
// same holds for MRCONFIGID on TDX.
//
// anchor is the EXACT bytes committed, byte for byte, as for
// [LaunchFileDigest].
func HostData(anchor []byte) [HostDataSize]byte {
	return sha256.Sum256(anchor)
}

// CanonicalDigest strictly canonicalizes an image reference to the
// "sha256:<64-lowercase-hex>" form Event hashes. It accepts a bare canonical
// digest or a digest-pinned reference ("name@sha256:<hex>") and rejects
// everything else: tag references, uppercase hex, wrong digest lengths, and
// non-sha256 algorithms. Measurement events are byte-exact over this string,
// so any laxness here (case folding, tag resolution) would let two verifiers
// disagree about the same image.
func CanonicalDigest(ref string) (string, error) {
	digest := ref
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		if i == 0 {
			return "", fmt.Errorf("image ref %q has an empty name before %q", ref, "@")
		}
		digest = ref[i+1:]
	}
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return "", fmt.Errorf("%q is not digest-pinned: want \"sha256:<64-hex>\" or \"name@sha256:<64-hex>\" (tags and non-sha256 algorithms are rejected)", ref)
	}
	if len(hexPart) != 64 {
		return "", fmt.Errorf("%q: digest is %d hex chars, want 64", ref, len(hexPart))
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("%q: digest is not 64 lowercase hex chars", ref)
		}
	}
	return "sha256:" + hexPart, nil
}
