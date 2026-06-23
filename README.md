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

### Verifying a bare SEV-SNP report

`VerifyAttestation` expects a full go-tpm-tools bundle (TPM quote + event log) as
produced on GCE. For callers that carry SEV-SNP evidence outside that envelope —
e.g. an RA-TLS certificate extension or a `/.well-known` attestation endpoint —
`VerifySNPReport` verifies a bare 1184-byte report plus an optional DER cert
chain (VCEK[ ‖ ASK ‖ ARK]) and returns the verified claims. It checks the AMD
signature chain before validating any field.

```go
claims, err := attestation.VerifySNPReport(report, certChainDER, &validate.Options{
    GuestPolicy: abi.SnpPolicy{SMT: true},
    ReportData:  expectedReportData, // 64 bytes; empty skips the binding check
}, nil) // nil verify.Options → bundled AMD roots, KDS fallback for missing certs
if err != nil {
    log.Fatal(err)
}
fmt.Printf("launch measurement: %x\n", claims.Measurement)
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
