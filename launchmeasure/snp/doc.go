// Package snp predicts the AMD SEV-SNP launch measurement (launch digest) a
// QEMU guest will report, computed offline from the firmware and boot
// artifacts before the guest is ever started. It is the produce side of
// attestation: verifying a report tells you what a guest measured, this tells
// you what to expect it to measure.
//
// The digest is an iterative SHA-384 over the PAGE_INFO structure of every page
// the AMD-SP measures at launch, in the order the VMM presents them: the OVMF
// image, the pages named by OVMF's SEV metadata table (zero / secrets / cpuid /
// kernel-hashes), then one VMSA page per vCPU. Because a VMSA page carries the
// vCPU signature and is measured once per vCPU, guests differing only in vCPU
// count have different launch digests; so do guests whose measured kernel
// command line differs.
//
// The layouts covered are QEMU's: an OVMF image mapped below 4 GiB with -bios,
// publishing an OVMF footer table with an OVMF_SEV_META_DATA entry, -smp N
// vCPUs, and optionally the kernel/initrd/cmdline hash table QEMU writes under
// kernel-hashes=on. A VMM that populates pages in another order, or firmware
// with no SEV metadata table, is out of scope and rejected rather than
// measured into a plausible-looking wrong digest.
//
// OVMF parsing, the digest accumulator and the VMSA pages come from
// github.com/virtee/sev-snp-measure-go. What this package adds is the sev_hashes
// page kernel-hashes=on contributes, which that library has no entry point for,
// and bounds checks upstream's parser skips.
package snp
