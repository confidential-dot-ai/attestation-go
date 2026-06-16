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
