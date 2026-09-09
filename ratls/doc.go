// Package ratls binds a TLS key to a TEE with an X.509 certificate extension.
//
// The binding is one equality: the guest asks its hardware for an attestation
// report whose REPORTDATA is SHA-384 over the public key (see
// [ReportDataForKey]), and embeds that evidence in a certificate extension
// under an OID the caller assigns from its own arc. A relying party that verifies the evidence and
// recomputes the anchor knows the private key never left the TEE. Nothing here
// signs, issues, or rotates certificates; that is the caller's lifecycle to run.
//
// One extension carries two evidence shapes, auto-detected on parse, because
// the platforms differ in what can be verified from bytes alone:
//
//   - Bare-metal and GCP SEV-SNP embed the raw 1184-byte AMD report. It is
//     self-contained, so a verifier needs only the AMD key chain — no evidence
//     schema, no service.
//   - Everything else embeds the JSON evidence envelope
//     ([teetypes.AttestationEvidence]). Azure guests attest through a vTPM
//     quote that the raw hardware report does not carry, and TDX quotes are
//     verified against Intel collateral rather than parsed field by field.
//
// Azure SEV-SNP hides its report inside a Hyper-V HCL envelope;
// [NormalizeSEVSNPReport] unwraps it so the raw-report shape stays one shape.
// Bare-metal TDX event logs are ~85 KB and would push the certificate past a
// TLS record, so [EvidenceForExtension] strips them.
//
// Verification comes in two forms with the same key binding:
// [VerifyOffline] runs the verifiers in-process, and [VerifyWithService]
// forwards the envelope to an attestation service. Both refuse a platform tag
// they have no rules for rather than approving it under another platform's.
package ratls
