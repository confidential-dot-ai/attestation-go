# Go ↔ Rust verifier parity

This tracks how the Go evidence-envelope verifiers (`snp`, `tdx`, `az-snp`,
`az-tdx`, `gcp-*`) compare to the reference implementation in `attestation-rs`,
following a check-by-check audit of both codebases.

## Summary

The **core cryptography is at parity**: certificate chains to pinned AMD/Intel
roots, report/quote signatures, the QE report binding, the vTPM AK-to-hardware
binding, PCR recomputation, report_data/nonce freshness, VMPL=0, and debug-policy
gating all match. The shared vTPM layer (`tpmcommon`) and the dispatcher
(`teeverify`) are faithful ports, and the untrusted `platform` envelope tag
cannot select a weaker verification path.

The divergences are concentrated in **collateral / revocation / TCB policy** —
the checks that depend on live Intel/AMD collateral rather than static crypto —
and several are bounded by what `go-sev-guest` / `go-tdx-guest` expose.

## Fixed in this branch

| Item | Platform | What changed |
|------|----------|--------------|
| VLEK-signed reports were unverifiable (only `VcekCert` was ever populated → `ErrMissingVlek`) | snp, az-snp | `VerifyReport` now parses `SIGNER_INFO` and routes the endorsement cert to `VcekCert` or `VlekCert` (ARK→ASVK→VLEK). |
| az-snp could never reach CRL revocation (dispatcher called `VerifyEvidence` with no options) | az-snp | `azsnp.VerifyEvidence` takes `snp.Options`; the dispatcher threads `opts.SNP` through, so a `Getter`+`CheckRevocations` now enables VCEK revocation on the Azure path. |
| No way to pin the launch measurement / RTMRs | snp, tdx, az-snp, az-tdx | `VerifyParams` gains `ExpectedLaunchDigest` (→ SNP `MEASUREMENT` / TDX `MR_TD`) and `ExpectedRTMRs` (→ TDX `RTMRs`); result gains `LaunchDigestMatch`. Forwarded to the HW layer on the Azure paths too. |

## Known gaps — bounded by the upstream libraries

These require upstream support (or a hand-rolled reimplementation of DCAP/CRL
logic) and were intentionally **not** faked:

- **TDX TCB-status semantics & surfacing.** `go-tdx-guest`'s `TdxQuote` returns
  only `error` and hard-requires `UpToDate`, so (a) it cannot return the TCB
  status string (`DcapVerificationStatus`/`TCBStatus` stays unset), and (b) it
  is *stricter* than Rust, which accepts any non-`Revoked` status and hands it
  to the caller. Matching Rust would mean reimplementing collateral evaluation.
- **TDX collateral is opt-in** (`GetCollateral=false` by default), matching
  Rust's "no provider" default — but callers assuming parity must remember to
  enable it to get TCB-status / QE-identity / CRL checks.
- **SNP CRL checks the ASK serial, not the VCEK serial.** `go-sev-guest`'s
  `verifyCRL` explicitly declines to check VCEK serials; Rust checks the VCEK
  serial against the CRL.
- **FMC (Turin) min-TCB floor is not enforced.** `kds.TCBParts` has no FMC
  field, so a caller-supplied `MinTCB.FMC` cannot be mapped onto
  `validate.MinimumTCB`. Rust enforces it.

## Not yet ported

- **CCEL eventlog → RTMR replay** (TDX). Rust replays the CCEL to confirm it
  reproduces RTMR0-3; Go carries `cc_eventlog` but does not verify it. The RTMRs
  themselves are still signed in the quote, so this is bounded, but there is no
  cryptographic eventlog↔RTMR link. A focused follow-up.

## Separate concern — legacy GCE vTPM path

`attestation/verify.go` + `verify_sev.go` / `verify_tdx.go` is a distinct
`go-tpm-tools` proto-based verifier (not the evidence-envelope path). It is
materially weaker than both `snp.go`/`tdx.go` and the Rust reference (zero-value
options, no VMPL pin, no min-TCB, KDS fetch on) and should be reviewed
separately if still reachable in production.
