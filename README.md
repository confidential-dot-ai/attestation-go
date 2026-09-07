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
    ReportData: apiclient.NewBase64Bytes(digest[:]),
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
    ExpectedReportData: expected,          // full 64 bytes; width adapts per platform
    AllowDebug:         false,             // a debug guest's memory is host-readable
    Images:             pins,              // whole-image pins: digest + registers
})
```

`Client.Verify` is the raw endpoint, for callers enforcing the verdict
themselves; `Client.VerifyEnforced` is the middle ground (verdict gated,
reference values not).

### Choosing an address

The `/verify` verdict is not signed, so the client trusts whatever answers.
Prefer a Unix-domain socket inside the trust boundary — a routable address lets
anything that can influence name resolution or routing answer in the service's
place. The socket's owner and mode are re-checked on **every dial**, so one
swapped or made world-writable after startup fails closed.

### Platform neutrality

Nothing here asks the caller which TEE it is on. The envelope's tag selects the
rules; tags are compared by family, so `az-*`/`gcp-*` route like their
bare-metal counterparts and an unknown tag fails closed. Two per-platform
details the client handles so callers do not:

- **Report-data width.** A vTPM platform's quote nonce is the bare 48-byte
  digest; a native platform carries the 64-byte hardware field. Sending the
  wrong width fails evidence that is in fact correct.
- **`MinTcb`.** It names SEV-SNP components, so it is sent only with SNP
  evidence. Sending it with TDX would read as an enforced floor while pinning
  nothing.

| Platform tag | Status | Notes |
|---|---|---|
| `snp` | ✅ verify | bare-metal SEV-SNP; report sig + VCEK chain + policy via go-sev-guest |
| `az-snp` | ✅ verify | Azure vTPM: SNP report + var_data binding + TPM-quote nonce |
| `tdx` | ✅ verify | Intel TDX DCAP via go-tdx-guest |
| `az-tdx` | ✅ verify | Azure vTPM: TD quote + var_data binding + TPM-quote nonce |
| `gcp-snp`, `gcp-tdx` | ✅ verify | identical to bare-metal; platform tag is an attester claim, not proof of GCP origin |
| `dstack` | ⬜ not yet | — |

Limitations: collateral (CRL / Intel TCB status / QE identity) requires a network
`Getter` and is skipped offline (`CollateralVerified=false`); guest-side
generation (`attest`) for the envelope platforms is not implemented (verify
only); Turin FMC TCB and Genoa-family model `0xA0` (Bergamo/Siena) offline root
selection are gated by go-sev-guest support.

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
