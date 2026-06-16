package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/confidential-dot-ai/attestation-go/attestation"
)

//export VerifyAttestationFFI
func VerifyAttestationFFI(attestationData *C.char, attestationLen C.int,
	formatStr *C.char,
	nonce *C.char, nonceLen C.int,
	teeNonce *C.char, teeNonceLen C.int) (*C.char, C.int) {
	// Convert C data to Go data
	attestationBytes := C.GoBytes(unsafe.Pointer(attestationData), attestationLen)
	format := C.GoString(formatStr)
	nonceBytes := C.GoBytes(unsafe.Pointer(nonce), nonceLen)
	teeNonceBytes := C.GoBytes(unsafe.Pointer(teeNonce), teeNonceLen)

	machineState, err := attestation.VerifyAttestation(attestationBytes, format, nonceBytes, teeNonceBytes)
	if err != nil {
		errorResponse := map[string]interface{}{
			"error":   err.Error(),
			"success": false,
		}
		jsonBytes, _ := json.Marshal(errorResponse)
		return C.CString(string(jsonBytes)), C.int(-1)
	}

	// Convert protobuf to JSON
	jsonBytes, err := protojson.Marshal(machineState)
	if err != nil {
		// Fallback: try standard JSON marshaling if protojson fails
		// This assumes your machineState struct has proper JSON tags
		jsonBytes2, err2 := json.Marshal(machineState)
		if err2 != nil {
			errorResponse := map[string]interface{}{
				"error":   fmt.Sprintf("Error serializing result: protojson: %v, json: %v", err, err2),
				"success": false,
			}
			jsonBytes, _ := json.Marshal(errorResponse)
			return C.CString(string(jsonBytes)), C.int(-1)
		}
		jsonBytes = jsonBytes2
	}

	return C.CString(string(jsonBytes)), C.int(len(jsonBytes))
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
