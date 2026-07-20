# Go ↔ Rust verifier parity

This tracks how the Go evidence-envelope verifiers (`snp`, `tdx`, `az-snp`,
`az-tdx`, `gcp-*`) compare to `attestation-rs`, following check-by-check audits
of both codebases (most recently 2026-07-20, against attestation-rs `e967531`).

## Summary

The **core cryptography is at parity**: certificate chains to pinned AMD/Intel
roots, report/quote signatures, the QE report binding, the vTPM AK-to-hardware
binding, PCR recomputation, report_data/nonce freshness, VMPL=0, and debug-policy
gating all match. The shared vTPM layer (`tpmcommon`) and the dispatcher
(`teeverify`) are faithful ports, and the untrusted `platform` envelope tag
cannot select a weaker verification path on either side.

Two things are worth stating plainly, because earlier revisions of this document
got them backwards:

1. **attestation-rs is not uniformly the stronger implementation.** On several
   verification-policy questions Go is now strictly stricter, and at least one
   Go security fix has no Rust counterpart (see "Where Go is ahead").
2. Divergences that *look* like Go deficiencies are often Rust fail-opens. The
   "Go is bounded by go-sev-guest / go-tdx-guest" framing is accurate for
   collateral plumbing, but not for policy enforcement.

## Where Go is ahead of attestation-rs

These are **not** Go gaps. They are listed so nobody "fixes" Go by relaxing it
toward the reference.

| Item | Platform | Status |
|------|----------|--------|
| **PCR[8] init-data spoof.** `CheckInitData` requires index 8 to be inside the quote's signed `pcrSelect` before trusting `pcrs[8]`. attestation-rs's `check_init_data` (`tpm_common.rs:650`) takes no quote message and indexes `tpm_pcrs[8]` unconditionally; since `verify_tpm_pcrs` only hashes *selected* PCRs, an unselected `pcrs[8]` is uncovered by the AK signature. Reachable in Rust natively **and** via the WASM entrypoints. | az-snp, az-tdx | Fixed in Go (#16). **Open in attestation-rs — reported upstream.** |
| **Expected-measurement mismatch is fatal.** Go pushes `ExpectedLaunchDigest` / `ExpectedRTMRs` into the upstream validator, so a mismatch is an error. Rust `main` records `Some(false)` and still returns `Ok` with `signature_valid: true` — a launch-measurement pin is advisory unless the caller inspects a nullable bool. | all | Go fail-closed. Rust's unmerged `fix/expected-refs-hard-fail` adopts Go's semantics. |
| **TDX TCB status.** go-tdx-guest hard-requires `UpToDate`. Rust accepts any non-`Revoked` status (`tdx/verify.rs:400`) and defers to the caller — and no in-tree Rust caller checks it. | tdx, az-tdx | Go fail-closed, Rust fail-open. Only bites when collateral is fetched. |
| **SNP TCB relationships.** Even with `PermitProvisionalFirmware: true`, go-sev-guest still enforces `committed ≤ current`, committed build/API ≤ current, cert TCB == reported TCB, and the launch-TCB floor. Rust has no committed/current/launch TCB checks at all — only a `reported_tcb` floor. | snp, az-snp | Go stronger. Note #14 relaxed Go *toward* Rust here; do not relax further. |
| **XFAM / TD_ATTRIBUTES reserved bits.** go-tdx-guest enforces the fixed-0/fixed-1 masks on every quote. Rust only surfaces these fields in claims. | tdx, az-tdx | Go stronger (defence in depth; the TDX module also enforces them). |

## Fixed in Go

| Item | Platform | What changed |
|------|----------|--------------|
| VLEK-signed reports were unverifiable (only `VcekCert` was ever populated → `ErrMissingVlek`) | snp, az-snp | `VerifyReport` parses `SIGNER_INFO` and routes the endorsement cert to `VcekCert` or `VlekCert` (ARK→ASVK→VLEK). |
| az-snp could never reach CRL revocation (dispatcher called `VerifyEvidence` with no options) | az-snp | `azsnp.VerifyEvidence` takes `snp.Options`; the dispatcher threads `opts.SNP` through. |
| No way to pin the launch measurement / RTMRs | snp, tdx, az-snp, az-tdx | `VerifyParams` gains `ExpectedLaunchDigest` (→ SNP `MEASUREMENT` / TDX `MR_TD`) and `ExpectedRTMRs`; mismatches are errors. |
| Init-data could be spoofed via an unselected PCR[8] | az-snp, az-tdx | `CheckInitData` re-derives the signed selection from the quote message and requires PCR 8 to be present. |
| **CCEL eventlog → RTMR replay** (was "not yet ported") | tdx | `tdx/ccel.go` parses the TCG2 event log and replays it into RTMR[0-3]. `VerifyEvidence` enforces RTMR[0-2] and reports RTMR[3]. |
| **`MinTCB.FMC` was silently dropped** | snp, az-snp | A caller-supplied FMC floor is now an explicit error instead of being ignored, so nobody believes they pinned a floor they did not get. |
| **No per-field size caps on direct calls** | tdx, az-snp, az-tdx | `teetypes.CheckFieldSize` (1 MiB, mirroring Rust's `MAX_EVIDENCE_FIELD_SIZE`) bounds `hcl_report`, `vcek`/`td_quote`/`quote`, `cc_eventlog`, and the vTPM quote fields. |

### CCEL replay semantics

The Go port follows attestation-rs `ff879e5`: **RTMR[0-2] are enforced, RTMR[3]
is reported only.** RTMR[3] is the runtime-extendable register and the guest
kernel's `tdx_guest` sysfs extend appends no CCEL entry, so a replay divergence
there is expected on any guest that runtime-extends — enforcing all four
registers would reject legitimate evidence.

Because this package is a pure library with no logger, the RTMR[3] outcome is
surfaced programmatically rather than via Rust's `log::warn!`:

- `VerificationResult.EventlogVerified` — nil when no event log was supplied;
  true when the replay reproduced RTMR[0-2]. A mismatch is an error.
- `VerificationResult.RTMR3ReplayMatch` — nil when no event log was supplied,
  else whether RTMR[3] replayed. **False is normal, not a failure.**

Pin RTMR[3] with `VerifyParams.ExpectedRTMRs`, which is checked against the
signed quote rather than the event log.

Scope note: only bare-metal `tdx` evidence carries `cc_eventlog`. The az-tdx
envelope has no event log in either implementation.

## Known gaps — bounded by the upstream libraries

These require upstream support (or a hand-rolled reimplementation of DCAP/CRL
logic) and were intentionally **not** faked:

- **SNP CRL checks the ASK serial, not the VCEK serial.** `go-sev-guest`'s
  `verifyCRL` explicitly declines to check VCEK serials (`VcekNotRevokedContext`
  discards its certificate argument); Rust checks the VCEK serial against the
  CRL. A revoked VCEK is accepted by Go even with `CheckRevocations: true`.
- **Turin is not verifiable in Go at all.** `go-sev-guest`'s OID table has no
  entry for the FMC extension `1.3.6.1.4.1.3704.1.3.9`, so a Turin VCEK fails
  certificate parsing before any crypto runs; it also requires a 64-byte HWID,
  while Turin uses a short (8-byte) CHIP_ID. Rust supports Turin fully
  (bundled Turin ARK/ASK/ASVK, FMC parsing, short HW_ID). This subsumes the
  `MinTCB.FMC` gap — the floor is unenforceable *and* the platform is
  unreachable.
- **TDX TCB status is not surfaced.** `go-tdx-guest`'s `TdxQuote` returns only
  `error`, so `TCBStatus` / `DcapVerificationStatus` stays unset even though the
  underlying check is stricter than Rust's (see "Where Go is ahead").
- **Go is TDX-v4 only.** Rust parses v4 and v5 (TDX 1.5, `tee_tcb_svn2`,
  `mr_servicetd`). Fails closed; an availability gap, not a security one.

## Remaining differences worth knowing

- **Collateral default.** Rust's `Verifier::new()` installs live cert and TDX
  collateral providers, so the convenience `attestation::verify()` does CRL /
  TCB-status / QE-identity checks by default. Go's `teeverify.Verify()` is
  offline by default (`Options{}`) and documents this; use `VerifyWithOptions`
  for collateral. Both are fail-open-by-default in the sense that a caller who
  never asks for collateral never gets it, but the defaults differ — do not
  assume parity here.
- **`CollateralVerified` semantics.** Go sets it from the request flags; Rust
  sets it from whether checks actually ran (`tcb_status.is_some()`).
- **Result shape.** Rust surfaces `mrtd_match` and `rtmr0..3_match`; Go folds
  MR_TD into `LaunchDigestMatch` and has no per-RTMR booleans. Since Go errors
  on mismatch, a missing boolean cannot hide a failed check — but the serialized
  shapes differ.
- **Envelope size cap.** Go caps the envelope at 1 MiB, Rust at 10 MiB (with a
  1 MiB per-field cap that Go now mirrors).
- **`ExpectedRTMRs` ergonomics.** Go accepts a slice shorter than 4 and treats
  the tail as unspecified, so passing 2 entries intending RTMR[2],RTMR[3]
  silently pins RTMR[0],RTMR[1]. Rust's flattened per-RTMR fields avoid the
  ambiguity.
- **`dstack`** is declared in `teetypes` but has no dispatcher case (fails
  closed); Rust verifies it via the TDX path.
- **NVIDIA GPU attestation** exists only in Rust. A Go verifier handed a
  GPU-bearing envelope ignores the GPU evidence rather than rejecting it —
  harmless today (no Go caller expects GPU claims), but it would become
  fail-open the moment one does.

## Separate concern — legacy GCE vTPM path

`attestation/verify.go` + `verify_sev.go` / `verify_tdx.go` is a distinct
`go-tpm-tools` proto-based verifier, not the evidence-envelope path. It is
materially weaker than both `snp.go`/`tdx.go` and the Rust reference:

- `verify_sev.go:24` sets **no VMPL pin**, so a report generated at VMPL 1-3 is
  accepted (the envelope path pins VMPL 0). Rust hard-rejects `vmpl != 0` on
  every path.
- `verify_tdx.go:17` passes empty validation options — **no debug gating**.
- Both run with zero-value verification options: KDS cert fetching on, no
  revocation checks.

**This path is reachable**: `attestation.VerifyAttestation` is exported and
re-exported as a C FFI symbol in `cmd/ffi/main.go`. It should either be hardened
(pin VMPL 0, gate debug, disable cert fetching) or removed if no consumer
remains.
