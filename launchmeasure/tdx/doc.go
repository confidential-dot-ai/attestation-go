// Package tdx predicts the Intel TDX build-time measurement (MRTD) a guest
// reports, computed offline from the TDVF firmware image before the guest
// starts. It is the TDX counterpart to package snp.
//
// MRTD is an iterative SHA-384 the TDX module builds while the VMM adds the
// TD's initial pages: TDH.MEM.PAGE.ADD extends it with a page's GPA,
// TDH.MR.EXTEND with 256-byte chunks of that page's contents, and
// TDH.MR.FINALIZE completes it. The pages added pre-finalize are exactly those
// named by TDVF's metadata section table, so MRTD is a function of the TDVF
// binary alone.
//
// MRTD therefore does not cover the guest kernel, initrd, kernel command line,
// vCPU count or guest RAM size; those reach RTMR[0..2]. One MRTD covers every
// guest shape booting the same TDVF, confirmed against two live TDX guests
// with different vCPU counts. That asymmetry is why the two families are
// separate packages: an SNP launch digest is per guest shape, an MRTD is per
// firmware build.
//
// The digest itself comes from github.com/google/gce-tcb-verifier/tdx rather
// than a local reimplementation of the TDX Module Base Architecture
// Specification.
package tdx
