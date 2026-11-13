# Deep review using the local Go toolchain

## Scope and toolchain

This continuation uses the requested local executable `/usr/local/go/bin/go`:
**Go 1.27.3 darwin/arm64**, with `GOTOOLCHAIN=local` on every Go invocation,
including pinned analyzer tools and disposable-copy tests. No Go upgrade,
dependency change, staging, commit or release is performed on the source repo.
The historical Go 1.14/1.16/1.27.4 results are not rerun or claimed as results of
this local-toolchain continuation.

The preceding frozen candidate is
`.git/refactor-review/20261113T130214.057147Z/` (57 files, archive SHA-256
`ab2213397e602f8519f313192878d614d80859a48117a245d3478597033c5fa0`).
New regression assertions were also run against its production `manager.go`
and `securechannel/channel.go` in a disposable copy: they fail at the intended
assertions, not compilation. The prior candidate's passing report is historical.

## Reproduced defects and repairs

| Finding | Failure before repair | Repair / evidence |
| --- | --- | --- |
| Stale keepalive recovery | After automatic recovery completed, the failed keepalive started a second swap, discarding the newly healthy session. | Keepalive Echo validation and health assessment now share the same locked operation snapshot and one expected-session recovery path. `TestKeepAliveDoesNotReplaceRecoveredSessionAgain` uses a deterministic completed-recovery barrier, not scheduler luck. Invalid Echo/type and card-error keepalives still recover; normal business card errors still preserve healthy sessions. No business command is replayed. |
| Metadata for the wrong object | GET OBJECT INFO with ID `0x1234` / asymmetric-key accepted metadata for ID `0x1235` or an opaque object. | Bind metadata ID and supported native object type to the request. Do not guess mappings for future/pseudo-public object types. Fault-injection cases use literal wire offsets and valid SCP03 framing/MAC. |
| Inconsistent WRAP/UNWRAP success | WRAP of three bytes accepted 32 or 34 response bytes instead of 33; UNWRAP of a three-byte ciphertext payload accepted two or four plaintext bytes. | Bind successful lengths to nonce + encrypted prefix + payload + CCM tag overhead. Positive tests cover empty data, 3084-byte round trips and valid 3086-byte one-way WRAP. The emulator supplies response shapes only, not real CCM interoperability or entropy evidence. |
| Raw WRAP bypassed predictable response bounds | Manually assembling a WRAP request for 3087 plaintext bytes bypassed the constructor's limit, reached transport and then invalidated the session on the oversized reply. | Check this predictable response capacity in channel preflight as well. `TestImpossibleRawWrapResponseRejectedBeforeSending` verifies neither endpoint counter advances and the channel remains healthy. This does not introduce a complete schema validator for all raw commands. |

These repairs preserve public declarations. Request-bound validation extends
behavior decision B11; it remains an intentional rejection of previously
accepted inconsistent responses, not proof of behavior-preserving refactoring.

## Additional checks without speculative production changes

- `TestHTTPTransportDoesNotReplayConsumedCommand` uses a real local HTTP server,
  warms a pooled connection, fully consumes a POST, then drops its response.
  It verifies the connection was reused and no third POST was sent. Fifty race
  repetitions passed on the local Go runtime; no transport rewrite was needed.
  This is not a guarantee for arbitrary caller-supplied retrying transports.
- Keepalive/swap/concurrent-Destroy cases passed 100 targeted race repetitions;
  metadata/Wrap association cases passed 50. The CPU/shuffle stress suite also
  passed. These finite runs are not an exhaustive schedule proof.
- Reference inspection reconfirmed the YubiHSM variant uses the same encrypted
  counter IV for the request and response. No speculative standard-SCP03 IV
  change or fixed-transcript rewrite was made.
- Public-key, signature and certificate payloads remain low-level raw outputs:
  parsing a response is not a guarantee of on-curve points, valid signatures,
  certificate trust, or correct application policy. No new PKIX policy,
  algorithm API, firmware negotiation or key-query round trip was added.

## Verification and explicit security failure

The local native acceptance command is:

```sh
GOTOOLCHAIN=local VERIFY_STRESS=1 VERIFY_FUZZ=1 bash scripts/verify.sh
```

Pinned staticcheck v0.8.2, gosec v2.30.0 medium/high, source-API comparison,
fifteen Python tool tests, fourteen representative Go mutations, isolated
deferred-patch application and read-only independent transcript regeneration
passed separately. The native command deliberately leaves `VERIFY_EXTENDED=0`:
its NOT RUN line is not a pass; separate raw logs record those checks and their
actual local Go version. The frozen candidate's final native/downstream results
and file checks are associated with its private verification manifest.

**The local vulnerability gate did not pass.** `govulncheck` v1.9.0 reports
`GO-2026-6859` in `net/http@go1.27.3`, fixed in Go 1.27.4, and exits nonzero.
Its reported issue is "HTTP/1 server crash due to MaxBytesReader header race";
the scanner includes call paths through this library's HTTP client/interface
usage. Application exploitability is not independently demonstrated or ruled
out here, and the finding is not suppressed as a presumed false positive.
The scan also reports 26 unused required-module findings and zero findings in
other imported packages. Earlier patched-toolchain scan results do not certify
this local runtime. Library tests cannot remove a standard-library finding;
changing the local Go installation remains a separate user decision.

Physical HSM/firmware interoperability, remote CI execution, B1-B11 release
approval, and the unavailable original pre-refactor user-patch artifact remain
open. No amount of emulator, race or fuzz testing substitutes for those gates.
Private snapshots/logs may contain secrets and must not be committed or uploaded
as public CI artifacts.
