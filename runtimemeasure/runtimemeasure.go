// Package runtimemeasure pins the conventions for runtime measurement: what a
// confidential guest commits after launch, and in what order.
//
// Runtime measurement is the counterpart to launch measurement. A launch
// measurement (MRTD on Intel TDX, the launch digest on AMD SEV-SNP) covers what
// booted and is fixed at launch. What a guest commits afterwards can carry
// identity a launch measurement cannot: the anchor it was launched to trust,
// and the workloads it admitted.
//
// An anchor is whatever bytes distinguish one launch from another — a public
// key, a policy document, a configuration digest. This package hashes those
// bytes and says nothing about what they mean.
//
// The two families express all this differently, and the difference is the
// reason this package exists:
//
//   - Intel TDX has RTMR[3], a hardware append-only register. A guest seeds it
//     with the anchor digest ([Seed]), then chains zero or more per-workload
//     image extends on top ([Event], [Extend]). [Register] is the local device.
//   - AMD SEV-SNP has no runtime-extend register. The launcher commits the
//     anchor digest into the report's immutable HOSTDATA field at launch
//     ([HostData]), and per-workload extends do not exist, so [Register]
//     reports [ErrNoRegister] and Event/FromDigests do not apply.
//
// Callers that only need "was this guest launched with my anchor" use
// [VerifyBinding], which resolves the difference and never asks the caller
// which platform it is on. Callers driving the register directly (an in-guest
// measurer) use [Register].
//
// A verifier cannot interpret a TDX register without knowing its seed, so a
// guest launched with an anchor must be verified with
// FromDigestsSeeded(Seed(anchor), ...) rather than FromDigests.
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

// FromDigests computes the expected register value after measuring the given
// canonical image digests in order, starting from Zero. Each DISTINCT
// image is extended exactly once (the measurer dedups restarts/replicas
// before extending); callers pass the deduped, ordered set.
//
// Use FromDigestsSeeded for a guest launched with an anchor: its
// register does not start from Zero.
func FromDigests(canonicalDigests []string) [Size]byte {
	return FromDigestsSeeded(Zero, canonicalDigests)
}

// FromDigestsSeeded is FromDigests starting from an arbitrary register
// value, so per-workload extends can chain onto an anchor seed:
//
//	FromDigestsSeeded(Seed(anchor), digests)
func FromDigestsSeeded(seed [Size]byte, canonicalDigests []string) [Size]byte {
	reg := seed
	for _, d := range canonicalDigests {
		reg = Extend(reg, Event(d))
	}
	return reg
}

// Seed computes the TDX register value as it reads back on a guest launched
// with anchor bytes and no per-workload extends:
//
//	reg = SHA384( 0x00*48 ‖ SHA384(anchor) )
//
// anchor is whatever the guest was launched to trust — a public key, a policy
// document, a configuration digest. This package does not interpret it. The
// measured initrd hashes those bytes and extends the digest into the register
// before switch_root, so a remote party can tell offline which anchor the guest
// was launched for. An in-guest service re-derives the same value to confirm a
// staged on-disk copy is the one that was measured; see [VerifyBinding].
//
// anchor is the EXACT bytes the initrd hashed, byte for byte. Re-encoding,
// re-wrapping, or a stripped trailing newline yields a different digest and a
// silent verification failure. Where the bytes come from a file, pass the file
// contents through unmodified rather than round-tripping them through a parser.
func Seed(anchor []byte) [Size]byte {
	return Extend(Zero, sha512.Sum384(anchor))
}

// HostDataSize is the byte length of the SEV-SNP HOSTDATA field, and so of the
// launch-time binding value on SNP (SHA-256).
const HostDataSize = 32

// HostData computes the SEV-SNP launch-time binding: the value a launcher
// commits as HOSTDATA when launching a guest for these anchor bytes.
//
//	HOSTDATA = SHA256(anchor)
//
// It is the SNP counterpart of [Seed]. SNP has no runtime-extend register, so
// instead of a measured initrd extending the digest after launch, the
// (untrusted) launcher commits it at launch. The trust argument is unchanged:
// the host can set any value, but a verifier that checks HOSTDATA against the
// anchor it expects rejects a wrong-anchor launch, exactly as it would reject a
// wrong RTMR[3]. A guest launched with no anchor carries all-zero HOSTDATA,
// which no SHA-256 output equals, so that fails closed too.
//
// anchor is the EXACT bytes committed, with the same byte-for-byte requirement
// as [Seed].
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
