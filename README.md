# Lunal Attestation

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
