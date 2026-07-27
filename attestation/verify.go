package attestation

import (
	"crypto"
	"fmt"

	"github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-tdx-guest/proto/tdx"
	tv "github.com/google/go-tdx-guest/verify"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/attestation-go/attestation/internal/tdxtrust"
)

var (
	unmarshalOptions = prototext.UnmarshalOptions{DiscardUnknown: true}
)

// VerifyAttestation verifies a remote attestation report.
// It takes the attestation bytes, format (binarypb or textproto), nonce and teeNonce.
// Returns the verified machine state or an error if verification fails.
func VerifyAttestation(attestationBytes []byte, format string, nonce []byte, teeNonce []byte) (*pb.MachineState, error) {
	attestation := &pb.Attestation{}

	switch format {
	case "binarypb":
		err := proto.Unmarshal(attestationBytes, attestation)
		if err != nil {
			return nil, fmt.Errorf("fail to unmarshal attestation report: %v", err)
		}
	case "textproto":
		err := unmarshalOptions.Unmarshal(attestationBytes, attestation)
		if err != nil {
			return nil, fmt.Errorf("fail to unmarshal attestation report: %v", err)
		}
	default:
		return nil, fmt.Errorf("format should be either binarypb or textproto")
	}

	pub, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		return nil, err
	}
	cryptoPub, err := pub.Key()
	if err != nil {
		return nil, err
	}

	ms, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
	if err != nil {
		return nil, fmt.Errorf("verifying TPM attestation: %w", err)
	}

	err = verifyGceTechnology(attestation, nonce, teeNonce)
	if err != nil {
		return nil, fmt.Errorf("verifying TEE attestation: %w", err)
	}

	teeMS, err := parseTEEAttestation(attestation, ms.GetPlatform().Technology)
	if err != nil {
		return nil, fmt.Errorf("failed to parse machineState from TEE attestation: %w", err)
	}
	ms.TeeAttestation = teeMS.TeeAttestation

	return ms, nil
}

// parseTEEAttestation parses a machineState from TeeAttestation.
// For now it simply populates the machineState TeeAttestation field with the verified TDX/SNP data.
// In long term, it should parse a full machineState from TeeAttestation.
func parseTEEAttestation(attestation *pb.Attestation, tech pb.GCEConfidentialTechnology) (*pb.MachineState, error) {
	switch tech {
	case pb.GCEConfidentialTechnology_AMD_SEV_SNP:
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_SevSnpAttestation)
		if !ok {
			return nil, fmt.Errorf("TEE attestation is %T, expected a SevSnpAttestation", attestation.GetTeeAttestation())
		}
		return &pb.MachineState{
			TeeAttestation: &pb.MachineState_SevSnpAttestation{
				SevSnpAttestation: proto.Clone(tee.SevSnpAttestation).(*sevsnp.Attestation),
			}}, nil
	case pb.GCEConfidentialTechnology_INTEL_TDX:
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return nil, fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		return &pb.MachineState{
			TeeAttestation: &pb.MachineState_TdxAttestation{
				TdxAttestation: proto.Clone(tee.TdxAttestation).(*tdx.QuoteV4),
			}}, nil
	default:
		return &pb.MachineState{}, nil
	}
}

func verifyGceTechnology(attestation *pb.Attestation, nonce []byte, teeNonce []byte) error {
	if attestation.GetTeeAttestation() == nil {
		return nil
	}

	switch attestation.GetTeeAttestation().(type) {
	case *pb.Attestation_TdxAttestation:
		trustedRoots, err := tdxtrust.IntelSGXRootCAPool()
		if err != nil {
			return fmt.Errorf("initialize Intel TDX trust root: %w", err)
		}
		verification := tv.DefaultOptions()
		verification.TrustedRoots = trustedRoots
		var tdxOpts *verifyTdxOpts
		if len(teeNonce) != 0 {
			tdxOpts = &verifyTdxOpts{
				Validation:   tdxDefaultValidateOpts(teeNonce),
				Verification: verification,
			}
		} else {
			tdxOpts = &verifyTdxOpts{
				Validation:   tdxDefaultValidateOpts(nonce),
				Verification: verification,
			}
		}
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		return verifyTdxAttestation(tee.TdxAttestation, tdxOpts)

	case *pb.Attestation_SevSnpAttestation:
		var snpOpts *verifySnpOpts
		if len(teeNonce) != 0 {
			snpOpts = &verifySnpOpts{
				Validation:   sevSnpDefaultValidateOpts(teeNonce),
				Verification: &sv.Options{},
			}
		} else {
			snpOpts = &verifySnpOpts{
				Validation:   sevSnpDefaultValidateOpts(nonce),
				Verification: &sv.Options{},
			}
		}
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_SevSnpAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a SevSnpAttestation", attestation.GetTeeAttestation())
		}
		return verifySevSnpAttestation(tee.SevSnpAttestation, snpOpts)

	default:
		return fmt.Errorf("unknown attestation type: %T", attestation.GetTeeAttestation())
	}
}
