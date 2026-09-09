// Package apiclienttest serves a stub attestation-api, so tests of code that
// talks to the service through [apiclient] need neither a confidential host nor
// a hand-rolled fake server.
//
// [Stub] speaks the wire protocol, not the client's Go API: a test drives its
// real [apiclient.Client] against the stub's address, so the client's own
// encoding, error mapping and enforcement all run. The stub answers over plain
// HTTP ([New]) or a Unix socket ([NewUnix]); [Stub.URL] returns an address
// [apiclient.NewClient] accepts either way, and the socket form additionally
// exercises the ownership and mode checks that transport makes.
//
// What the stub models, and what it does not:
//
//   - POST /attest answers [FakeSNPEvidence]: a syntactically valid SEV-SNP
//     report binding the requested report data. It is not signed by anything,
//     so it passes evidence extraction and fails real verification. Whatever
//     platform the stub reports, the evidence bytes stay an SNP report.
//   - POST /verify answers a configured [Verdict] or [ErrorReply]; it does not
//     look at the evidence. A test asserts on the recorded requests
//     ([Stub.VerifyRequests]), which is what pins the bindings production code
//     asked the service to check.
//   - GET /health answers ok with the stub's platform.
//
// Every 200 the real service sends reports success: refused evidence arrives as
// the 422 of [VerificationFailed], never as a false verdict field. A false in
// [Verdict] therefore models a service contradicting itself — worth testing,
// because a caller must fail closed on it, but not a shape production emits.
package apiclienttest
