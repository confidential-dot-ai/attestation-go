# Confidential.AI Attestation Verification Library

A Go library for generating and verifying hardware attestations from Google Cloud confidential computing environments, supporting both AMD SEV-SNP and Intel TDX technologies.

## Features

- **Hardware Attestation Generation**: Generate attestations from confidential VMs
- **Attestation Verification**: Verify attestations with configurable nonce validation
- **Multi-TEE Support**: Compatible with AMD SEV-SNP and Intel TDX
- **C FFI Support**: Optional C-compatible shared library for integration with other languages

## Supported Technologies

- AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
- Intel TDX (Trust Domain Extensions)

## Evidence-envelope verification (`attestation/...`)

Alongside the original go-tpm-tools (GCE-style) flow in the `attestation`
package, the library verifies the self-describing `{platform, evidence}`
envelopes used by `attestation-rs` / c8s — the Go counterpart of the Rust
verifier, sharing the same `tpm_common` logic so the two agree byte-for-byte.

```go
import (
    "github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
    "github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Auto-detects the platform from the envelope and verifies offline.
res, err := teeverify.Verify(evidenceJSON, teetypes.VerifyParams{
    ExpectedReportData: nonce, // freshness; nil to skip
    AllowDebug:         false, // reject debug guests
})
// res.Claims.LaunchDigest, res.ReportDataMatch, res.Platform, ...
```

Packages: `teeverify` (dispatcher) · `snp`, `tdx` (bare-metal) · `azsnp`, `aztdx`
(Azure vTPM) · `tpmcommon` (HCL/vTPM layer) · `teetypes` (shared types).

## Runtime measurement (`runtimemeasure`)

Launch measurement covers what booted. Runtime measurement covers what the
guest committed afterwards — the *anchor* it was launched to trust, and the
workloads it admitted. An anchor is whatever bytes distinguish one launch from
another: a public key, a policy document, a configuration digest. The package
hashes those bytes and does not interpret them.

The two families express all this differently, and this package is the seam
that hides the difference:

| | Intel TDX | AMD SEV-SNP |
|---|---|---|
| Where the binding lives | RTMR[3], hardware append-only | HOSTDATA, fixed at launch |
| Width | 48 bytes (SHA-384) | 32 bytes (SHA-256) |
| Per-workload extends | Yes | None — `ErrNoRegister` |

Callers asking "was this guest launched with my anchor" never branch on
platform:

```go
import "github.com/confidential-dot-ai/attestation-go/runtimemeasure"

// res is a *teetypes.VerificationResult from teeverify.Verify.
// Pass nil digests for a guest that runs no workload measurer.
err := runtimemeasure.VerifyBinding(res, anchor, workloadDigests)
```

An in-guest measurer drives the register directly. `Open` returns
`ErrNoRegister` on SEV-SNP rather than a no-op, so a caller that must extend
fails closed:

```go
reg, err := runtimemeasure.Open(teetypes.PlatformTDX)
event := runtimemeasure.Event("sha256:...") // one workload image
err = reg.Extend(event[:])
current, err := reg.Extension()
```

Anchor bytes are hashed verbatim. Where they come from a file, pass the file
contents exactly as written — never round-tripped through a parser — or the
digest differs and verification fails silently.

An in-guest daemon that must extend exactly once per workload, across its own
restarts, keeps a `Journal`: a log of digests already extended, written before
each extend and reconciled against the register on open. A crash between the
two can only under-extend, which the open repairs. A register that matches
neither fold reports `ErrRegisterDiverged` and refuses further extends.

```go
j, err := runtimemeasure.OpenJournal("/run/measured", reg)
extended, err := j.MeasureOnce("sha256:...") // false when already journaled
```

A verifier checking a whole node pins the image with the manifest its build
published and the anchor with `VerifyBinding`. The manifest's shape names the
family, so the caller loads it without knowing which, and reads the pinned
values back through one interface. A "multi" build carries both shapes; name
the family with `LoadImageManifestFor` to pick a half:

```go
identity, err := runtimemeasure.LoadImageManifest("manifest.json") // an ImageIdentity, family detected
err = identity.Verify(res)                                        // MRTD+RTMR[1,2], or launch digest in the per-SMP set
err = runtimemeasure.VerifyBinding(res, anchor, workloadDigests)  // RTMR[3] or HOSTDATA

for _, v := range identity.LaunchDigests() { ... } // v.Label is "" on TDX, "smp4" on SNP
registers := identity.RTMRs()                      // RTMR[1] and RTMR[2] on TDX, none on SNP
```

`InitDataAnchor` reads the 32-byte init-data digest back out of a verified
result — SEV-SNP HOST_DATA verbatim, TDX MRCONFIGID with its zero padding
checked — for a guest asking which document it was launched with.

## attestation-api client (`apiclient`)

`teeverify` verifies evidence in this process. `apiclient` is the alternative:
it talks to **attestation-api**, the `attestation-rs` HTTP service that both
produces evidence on a confidential host and verifies it. Use it when the
evidence has to be generated locally, or when verification should follow the
service's collateral cache rather than this process's.

### Endpoints

| Method | Endpoint | Wrapper |
|---|---|---|
| `POST` | `/attest` | `Client.Attest` — produce evidence binding a report-data value |
| `POST` | `/verify` | `Client.Verify` — parse and check evidence, returning a report |
| `GET` | `/health` | `Client.Health` — status, platform, collateral cache stats |

### Producing evidence

Send the bare 48-byte SHA-384 digest; the service zero-extends it into the
platform's report-data field. `PlatformAuto` asks the service which TEE it is
on, so the caller need not know:

```go
c := apiclient.NewClient("unix:///run/attestation/attest.sock")

resp, err := c.Attest(ctx, apiclient.AttestRequest{
    ReportData: digest[:], // travels as base64, per encoding/json
    Platform:   apiclient.PlatformAuto,
})
evidence := resp.Envelope() // teetypes.AttestationEvidence
```

### Verifying evidence

**`/verify` returns a report, not a decision.** It says what the evidence
contained — including that the signature did not check out. A caller that reads
the report without gating on it accepts anything the service could parse. Use
`VerifyEvidence`, which enforces the verdict and then your reference values:

```go
resp, err := c.VerifyEvidence(ctx, evidence, apiclient.Policy{
    ExpectedReportData: digest[:],         // the bytes sent to /attest, verbatim
    AllowDebug:         false,             // a debug guest's memory is host-readable
    Images:             pins,              // whole-image pins: digest + registers
})
```

`Client.Verify` is the raw endpoint, for callers enforcing the verdict
themselves; `Client.VerifyEnforced` is the middle ground (verdict gated,
reference values not).

### Letting the service enforce measurements

`VerifyParams` can carry the expected measurements, in which case the service
refuses rather than reporting. It fails closed on both a mismatch and a pin the
evidence cannot answer — a register pin against SEV-SNP evidence, say — and
returns an `*APIError`.

The service names one concept twice, `expected_mrtd` on TDX and
`expected_launch_digest` on SEV-SNP. `SetExpectedMeasurements` picks the field
so callers do not:

```go
var params apiclient.VerifyParams
err := params.SetExpectedMeasurements(platform, launchMeasurement, map[int][]byte{
    1: rtmr1, // guest kernel image
    2: rtmr2, // kernel command line and rootfs chain
})
```

This pins **one** measurement. A policy that accepts any of several images
cannot be expressed server-side; use `Policy.Measurements` or `Policy.Images`
with `VerifyEvidence`, which checks the returned report instead.

### Pinning Azure vTPM PCRs

On an Azure confidential VM the launch measurement covers the Microsoft
paravisor image alone — the guest kernel and initrd measure into the **vTPM
PCRs**. Pinning only the launch measurement there proves the paravisor booted,
not which guest ran. `Policy.PCRs` closes that:

```go
resp, err := c.VerifyEvidence(ctx, evidence, apiclient.Policy{
    ExpectedReportData:   expected,
    Measurements:         launchDigests, // the paravisor
    PCRs:                 pcrPins,       // the guest OS, SHA-256
    ExpectedInitDataHash: initData,      // PCR[8] on az, HOST_DATA on snp, MRCONFIGID on tdx
})
```

PCR pins are checked alongside the launch measurement, not instead of it, so a
matching paravisor cannot excuse a wrong guest. Read individual registers from
verified claims with `teetypes.Claims.PCR(i)`.

The AK signature covers only the registers the quote selected; the rest of the
bank the attester supplies is its own word. The in-process verifiers publish
only selected registers, and `EnforcePCRs` re-reads the selection from the
evidence, so a pin on an unselected register is refused whatever the report
carries.

Both `Policy.PCRs` and `Policy.RTMRs` refuse a pin the platform cannot answer
rather than skipping it — reference values are per-platform, so a PCR pin
reaching bare-metal SNP means the wrong policy was loaded, and silently passing
would report it as enforced.

### Choosing an address

The `/verify` verdict is not signed, so the client trusts whatever answers.
Prefer a Unix-domain socket inside the trust boundary — a routable address lets
anything that can influence name resolution or routing answer in the service's
place. The socket's owner and mode are re-checked on **every dial**, so one
swapped or made world-writable after startup fails closed.

### Platform neutrality

Nothing here asks the caller which TEE it is on. The envelope's tag selects the
rules; tags are compared by family, so `az-*`/`gcp-*` route like their
bare-metal counterparts and an unknown tag fails closed.

`ExpectedReportData` is the value sent to `/attest`, passed verbatim: a native
verifier zero-pads it to the 64-byte hardware field, a vTPM verifier compares
it with the quote nonce as attested. There is no per-platform width to get
wrong.

A policy element the platform cannot answer is refused, never skipped, so a
policy is never reported as enforced when nothing checked it: `MinTcb` names
SEV-SNP components and fails on any other family, and register pins fail on a
platform without registers. A mixed fleet keeps one `Policy` per family.

| Platform tag | Status | Notes |
|---|---|---|
| `snp` | ✅ verify | bare-metal SEV-SNP; report sig + VCEK chain + policy via go-sev-guest |
| `az-snp` | ✅ verify | Azure vTPM: SNP report + var_data binding + TPM-quote nonce |
| `tdx` | ✅ verify | Intel TDX DCAP via go-tdx-guest |
| `az-tdx` | ✅ verify | Azure vTPM: TD quote + var_data binding + TPM-quote nonce |
| `gcp-snp`, `gcp-tdx` | ✅ verify | identical to bare-metal; platform tag is an attester claim, not proof of GCP origin |
| `dstack` | ⬜ not yet | — |

Limitations: collateral (CRL / Intel TCB status / QE identity) requires a
network `Getter` and is skipped offline (`CollateralVerified=false`);
guest-side generation (`attest`) for the envelope platforms is not implemented,
so these platforms verify only — launch-measurement *prediction* is
implemented, see `launchmeasure`; Turin FMC TCB and Genoa-family model `0xA0`
(Bergamo/Siena) offline root selection are gated by go-sev-guest support.

## Reference values (`refvalues`)

A verifier compares evidence against the images a deployment accepts. This
package holds that set in its three shapes — the measurements config file, the
flat digest and register lists older flags carry, and a build manifest — and
converts any of them into the `apiclient.Policy` the service enforces:

```go
rv, err := refvalues.Load("measurements.json") // {"schema_version":"1","tee":"tdx","measurements":[...]}
policy := rv.Policy()                            // Images pinned whole
pins, err := refvalues.FromImageManifest("build/manifest.json", "worker", teetypes.FamilyTDX)
```

`FromImageManifest` names the family because a build manifest may carry both;
it reads the pin through `runtimemeasure.LoadImageManifestFor`.

An image is one atomic tuple: SEV-SNP its launch digest, one pin per vCPU
count; TDX its MRTD with RTMR[1] and RTMR[2], never RTMR[0] or RTMR[3]. The
file names its family as `sev-snp` or `tdx` (`snp` is accepted; any known
platform tag parses through `teetypes.ParseFamily`).

## RA-TLS (`ratls`)

An X.509 extension, under an OID the caller assigns, that binds a TLS key to a
TEE: REPORTDATA is SHA-384 over the public key, and the evidence travels in the
certificate. Bare-metal and GCP SEV-SNP embed the raw AMD report; every other
platform embeds the JSON envelope, with the TDX event log stripped so the
certificate fits a TLS record.

```go
// Producer, with evidence from /attest bound to ReportDataForKey(pub, nil):
att, err := ratls.NewAttestation(resp.Envelope())
ext, err := att.MarshalExtension(myOID)

// Verifier, in-process or through the service:
res, err := ratls.VerifyCertOffline(cert, myOID, nonce, teetypes.VerifyParams{}, teeverify.Options{})
resp, err := ratls.VerifyCertWithService(ctx, client, cert, myOID, nonce, policy)
```

Certificate lifecycle — issuance, rotation, TLS configs — is the caller's.

## Launch measurement prediction (`launchmeasure/snp`, `launchmeasure/tdx`)

The producing side of the preceding reference values: what a guest image
*will* measure, computed offline from the firmware and boot artifacts.

```go
digest, err := snp.LaunchDigest(snp.Config{FirmwarePath: "OVMF.fd", VCPUs: 4, VCPUSig: sig, KernelHashes: &kh})
mrtd, err := tdx.MRTD(tdvfBytes)
```

An SNP launch digest is per guest shape (vCPU count, kernel hashes); a TDX
MRTD is per TDVF build, with the guest measuring into RTMR[0..2] instead. These
two packages pull `sev-snp-measure-go` and `gce-tcb-verifier`; nothing else in
the module depends on them.

## Test stub (`apiclient/apiclienttest`)

A stub attestation-api over HTTP or a Unix socket, driven through a real
`apiclient.Client`, for tests of anything that consumes the service.

## Installation

```bash
go get github.com/confidential-dot-ai/attestation-go/attestation
```

## Usage

### Go Library

```go
import "github.com/confidential-dot-ai/attestation-go/attestation"

// Generate an attestation
attestationBytes, err := attestation.Attest(opts)
if err != nil {
    log.Fatal(err)
}

// Verify an attestation
machineState, err := attestation.VerifyAttestation(
    attestationBytes,
    "binarypb",
    nonce,
    teeNonce,
)
if err != nil {
    log.Fatal(err)
}

// Process the verified machine state
fmt.Println("✅ Attestation successfully verified!")
```

### Example Usage

```go
// Read base64-encoded attestation data
encodedData, err := os.ReadFile("attestation.txt")
if err != nil {
    log.Fatal(err)
}

// Decode the attestation
attestationBytes, err := base64.StdEncoding.DecodeString(string(encodedData))
if err != nil {
    log.Fatal(err)
}

// Verify with a fixed nonce
nonce := []byte("fixed-deterministic-nonce-for-server")
machineState, err := attestation.VerifyAttestation(attestationBytes, "binarypb", nonce, nil)
if err != nil {
    log.Fatal(err)
}
```

## FFI Support (Optional)

For integration with other programming languages, the library can be built as a C-compatible shared library.

### Building FFI Library

```bash
# Build the FFI shared library
make ffi

# Build to custom directory
make ffi-custom CUSTOM_BUILD_DIR=path/to/directory

# Install system-wide (may require sudo)
make install

# Clean build artifacts
make clean
```

## License

MIT
