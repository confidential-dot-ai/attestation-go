package attestation_test

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	pb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/confidential-dot-ai/attestation-go/attestation"
)

func ExampleVerifyAttestation() {
	// Define command-line flags
	inputFile := flag.String("file", "testdata/attestation.txt", "Path to the base64-encoded attestation file")
	verbose := flag.Bool("verbose", false, "Print verbose output")
	flag.Parse()

	// Read the base64-encoded attestation file
	encodedData, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("Failed to read attestation file: %v", err)
	}

	// Decode the base64 data
	attestationBytes, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		log.Fatalf("Failed to decode base64 data: %v", err)
	}

	fmt.Printf("Successfully decoded %d bytes of attestation data\n", len(attestationBytes))

	// Use the same nonce that was used to generate the attestation
	nonce := []byte("fixed-deterministic-nonce-for-server")
	fmt.Printf("Using nonce from server: %s\n", string(nonce))

	// Verify the attestation
	// Since it's a TDX attestation and we're not using a specific TEE nonce,
	// we'll pass nil for teeNonce and let the verifier use the main nonce for TEE verification
	machineState, err := attestation.VerifyAttestation(attestationBytes, "binarypb", nonce, nil)
	if err != nil {
		log.Fatalf("Attestation verification failed: %v", err)
	}

	fmt.Println("✅ Attestation successfully verified!")

	// Print basic information about the machine state
	if *verbose {
		printMachineState(machineState)
	}
	// Output:
	// Successfully decoded 45983 bytes of attestation data
	// Using nonce from server: fixed-deterministic-nonce-for-server
	// ✅ Attestation successfully verified!
}

func printMachineState(machineState *pb.MachineState) {
	// Option 1: Using the protojson package (recommended)
	marshaler := protojson.MarshalOptions{
		Indent:    "  ", // Use 2 spaces for indentation
		Multiline: true,
	}

	jsonBytes, err := marshaler.Marshal(machineState)
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}

	fmt.Println("\n=== Machine State JSON ===")
	fmt.Println(string(jsonBytes))
}
