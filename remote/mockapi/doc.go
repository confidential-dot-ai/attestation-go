// Package mockapi serves a stub attestation-api, so tests of code that
// talks to the service through [remote] need neither a confidential host nor
// a hand-rolled fake server.
//
// [Stub] speaks the wire protocol, not the client's Go API: a test drives a
// real [remote.Client] against the stub's address, so the client's own
// encoding, error mapping and enforcement all run. The stub answers over plain
// HTTP ([New]) or a Unix socket ([NewUnix]), and [Stub.URL] returns an address
// [remote.NewClient] accepts either way. The socket form also exercises the
// ownership and mode checks that transport makes.
//
// What the stub models, and what it does not:
//
//   - POST /attest answers [FakeSNPEvidence]: a syntactically valid SEV-SNP
//     report binding the requested report data. It is not signed by anything,
//     so it passes evidence extraction and fails real verification. Whatever
//     platform the stub reports, the evidence bytes stay an SNP report.
//   - POST /verify answers a configured [Verdict] or [ErrorReply] without
//     reading the evidence. A test asserts on the recorded requests
//     ([Stub.VerifyRequests]), which is where the bindings production code
//     asked the service to check show up.
//   - GET /health answers ok with the stub's platform.
//
// Every 200 the real service sends reports success: refused evidence arrives as
// the 422 of [VerificationFailed], never as a false verdict field. A false in
// [Verdict] therefore models a service contradicting itself. Test it, because a
// caller must fail closed on it, but do not expect that shape in production.
package mockapi
