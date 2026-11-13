# Refactoring review remediation and acceptance

## Review-item disposition

| Item | Corrective action | Boundary |
| --- | --- | --- |
| 1. Mixed refactor/fix/feature scope | Core groups classified; nonessential additions physically moved to a separately tested patch. Unrelated go.sum cleanup undone. | No historical split commits are claimed; no commits were created. |
| 2. Overstated compatibility | B1–B11 behavior/migration ledger, external source contracts, and an API gate that checks report contents. | Source compatibility is not behavior or release approval. |
| 3. Self-proving tests | Literal wire/limit expectations, fixed independent transcript with read-only regeneration check, and fourteen mutation gates. | Emulator and generated vectors do not replace hardware evidence. |
| 4. Missing original checkpoint | Verified complete pre-remediation checkpoint; reusable private snapshot/verification tool with tests. | The older initial user patch cannot be reconstructed or certified retroactively. |
| 5. Undefined acceptance | Pinned verification commands, toolchains/actions, CI matrix, evidence record, and explicit NOT RUN output. | Hardware, remote CI and human approval remain separate gates. |

Earlier local executions are recorded in [verification-report.md](verification-report.md).
The subsequent boundary/compatibility review is recorded in [follow-up-review.md](follow-up-review.md).
The latest [local-Go deep review](local-go-review.md) records further fixes and
an explicit unresolved standard-library vulnerability finding on Go 1.27.3.

## Honest baseline and preservation boundary (review item 4)

Upstream baseline: `3b1fcb9aeed5fc5d52faf1cf6f4a85a021d48763`.
Before this remediation, a private checkpoint was created at
`.git/refactor-review/20261113T104849Z/`, with all 32 then-present worktree files,
including untracked tests and fixtures. The archive SHA-256 is
`04f5018146c460ae4ce34714cb74f9f455b92bf4dbc7849ed6982edd5d68fdcf`.
It also contains a file checksum/mode manifest, HEAD archive, binary diff,
index snapshot, staged diff, and status/untracked inventories. It was verified
before editing. Checkpoints can contain secrets and must not be committed or
uploaded as CI artifacts.

This is the **pre-remediation worktree**, not the original pre-refactor user
patch. That older patch has no independently retained Git checkpoint here.
We cannot reconstruct its exact contents or certify its complete preservation
from the present diff. The known existing Wrap entry points are retained and
covered by tests, but that is not a replacement for the missing historical
artifact. This evidentiary gap remains explicitly open, not marked repaired.

Future checkpoints include ignored files too and can be verified without
modifying the worktree:

```sh
python3 scripts/review_snapshot.py
python3 scripts/review_snapshot.py --verify .git/refactor-review/<checkpoint>
```

For recovery, verify first and inspect/extract into an empty private directory;
compare there before restoring selected files. Do not blindly overwrite the
worktree, replace its index, or run a destructive reset. Neither checkpoint nor
verification scripts stage files or create commits.

## Scope classification and disposition (items 1 and 5)

The candidate is deliberately described as fixes plus hardening, not pure
refactoring. Review these groups in order; they are suggested review/commit
boundaries, not a claim that historical commits already exist:

| Group | Files / concerns | Classification and disposition |
| --- | --- | --- |
| 1. Wire correctness and existing Wrap work | `commands/command.go`, `constructors.go`, `response.go`, limit constants and tests | Keep: panic/length/command-code fixes; preserve existing GenerateWrapKey / WrapData / UnwrapData / import/export functionality. Helpers are only structural support for those fixes. |
| 2. Connector boundary | `connector/http.go` and tests | Keep fixes for parsing, limits, buffer ownership and HTTP errors. Explicitly review new timeout/TLS/redirect/global-client policy as behavior changes B2/B3, not invisible refactoring. |
| 3. Secure-channel state | `securechannel/channel.go`, `util.go`, tests and fixed transcript | Keep serial access, RMAC/padding/framing validation and one-shot invalidation. AuthKey-based construction supports credential ownership; key wiping and Close behavior require decisions B1/B5/B6. |
| 4. Manager lifetime | `manager.go`, tests | Keep race/lifetime repairs and bounded single-swap reservation. Key-based construction avoids long-lived password retention; credential-rotation tracking prevents stale future authentication. Review B4/B9 explicitly. |
| 5. Evidence and contracts | `api_compat_test.go`, independent wire/vector tests, docs, scripts and CI | Keep: independent acceptance rules and reproducible gates. They are evidence, not implementation changes or claims of hardware validation. |
| Deferred features | `docs/deferred/protocol-conveniences.patch` | Removed from active Go code: additional filters, naming aliases and constants for unimplemented commands. Preserved as an independently applicable/tested feature patch; never applied by default. |

The unrelated removal of historical `go.sum` checksums was undone. `go.mod` and
production dependency versions are unchanged; upgrading them is a separate
compatibility/security decision. Do not reintroduce optional features merely to
make a removed-feature test compile; that test belongs to the deferred patch.

No generic new framework or performance improvement is claimed. The manager's
session interface is a private test seam. Its factory wrapper and fixed-array
key pointer preserve the existing public type's comparability, not a public
plugin or session-pool API.

## Compatibility decisions (item 2)

`compatibility.md` is the behavior ledger and migration guide. Source API checks
only certify declarations against the upstream baseline. They do not certify
unchanged timeout, shutdown, credential-retention, ownership or failure behavior.
B1–B11 must be acknowledged in release review; automated tests do not provide
product approval or choose a release version. Do not label this candidate as a
behavior-preserving drop-in refactor.

## State/locking invariants to review

1. `SessionManager.lock` protects its session reference, credential and destroyed
   state. `channelLock` protects an individual channel's keys/counter/MAC state.
   When both are needed, manager operations take the manager lock first.
2. Replacement authentication runs outside the manager lock. Installing it
   requires the lock and a fresh destroyed check. Only the detached old session
   is closed outside that lock.
3. Swap reservation and `swapWG.Add` occur under the manager lock before starting
   a background task. Destroy marks the manager destroyed under that same lock
   before waiting. A stale health check cannot replace a newer session.
4. A local command-validation error changes no secure-channel state. A response
   with valid SCP03 integrity consumes its counter even for an inner card error.
   Lost integrity/uncertain transport invalidates state; commands are never replayed.
5. Destroy waits for registered swaps and keepalive; concurrent Destroy callers
   wait on one completion signal. Bounded shutdown depends on connector timeouts,
   not on the library being able to cancel arbitrary application callbacks.

## Independent tests and anti-self-proof gates (item 3)

- `commands/legacy_wire_test.go`: literal command codes and bytes for unchanged
  wire contracts, not encoder-derived lengths or command constants.
- `commands/types_test.go`: independent numeric frame/ciphertext/inner limits
  3136 / 3120 / 3116. The earlier mistaken 3136-byte inner limit must fail.
- `securechannel/testdata/scp03.json`: fixed public known-answer transcript,
  independently reproduced with Python AES-CMAC/AES-CBC. Normal Go tests only
  read it; they do not regenerate an oracle to match a changed implementation.
- `generate_scp03.py --check`: verifies the fixed oracle without overwriting it.
  The generator cites a pinned Yubico source revision, uses public credentials,
  and is not a device capture. Its optional dependency is development-only.
- The Go emulator deliberately shares implementation helpers and is suitable
  for fault/state injection, **not** independent cryptographic proof.
- `scripts/verify-regressions.py`: in a disposable copy, reintroduces the wrong
  length limit, unrelated ACK acceptance, early request-buffer wiping, stale
  credential handling, premature concurrent Destroy return, ignored WRAP response
  overhead, lost URL escaping, changed nil/empty buffer behavior, and URL-credential
  logging. Each must fail
  at its intended test assertion; build errors or unrelated failures do not count.

## Repeatable acceptance commands (item 5)

Basic native gate, including race detection (uses the selected `go` toolchain):

```sh
GOTOOLCHAIN=local bash scripts/verify.sh
```

The project requires Go 1.27.3 or newer; CI uses 1.27.3. To use the installed
Go without automatic toolchain switching:

```sh
python3 -m venv /tmp/yubihsm-vector-env
/tmp/yubihsm-vector-env/bin/python3 -m pip install -r securechannel/testdata/requirements.txt
PATH="/tmp/yubihsm-vector-env/bin:$PATH" GOTOOLCHAIN=local \
  VERIFY_EXTENDED=1 VERIFY_STRESS=1 VERIFY_FUZZ=1 bash scripts/verify.sh
```

The gate prints the actual Go version, platform, base commit and worktree state;
explicitly disabled or unselected checks print **NOT RUN**, not PASS. Keep command
output with the reviewed commit/checkpoint. `verify-api.sh` also fails on a
nonempty incompatible-diff report, not merely a nonzero tool exit status.
All analyzer versions and the API tool version are pinned in the scripts. CI
pins actions to commits and runs Go 1.27.3, including race/stress/fuzz,
independent oracle regeneration, mutation, security and API checks. The old
Go 1.14/1.16 compatibility jobs have been removed. A workflow
file existing locally is not evidence that its remote jobs have passed.

Security interpretation must accompany the raw output:

- Gosec's gate is **medium/high severity**, not a claim that there are no LOW
  findings. Fixed-size `binary.Write` calls to `bytes.Buffer` cannot fail writes;
  historical option callbacks cannot return writer errors. Do not broadly
  suppress G104 or change public signatures simply to clear the scanner.
- Govulncheck must succeed on a patched toolchain. A report of zero reachable
  vulnerable symbols can still list vulnerabilities in unused packages of old
  dependency modules. Keep those warnings, do not relabel them as zero dependency
  vulnerabilities. The environment's Go 1.27.3 and patched 1.27.4 are not
  interchangeable scan baselines.

### Release acceptance checklist

- [ ] A reviewer acknowledges B1–B11, migration guidance, scope and release version.
- [ ] A checkpoint/commit identifies the exact candidate, including new files.
- [ ] Basic, source-API and full Go 1.27.3 gates pass for that candidate;
      selected/unselected checks and actual toolchain versions are recorded.
- [ ] Deferred features remain outside the core build and pass their isolated gate.
- [ ] Raw vulnerability output is retained and unused-package findings assessed.
- [ ] Physical device/firmware matrix: authentication, Echo, command errors,
      GenerateWrapKey/WrapData/UnwrapData, import/export, key rotation/reconnection,
      timeout ambiguity and shutdown. This is still NOT RUN without hardware.
- [ ] Original pre-refactor user patch preservation is independently confirmed,
      or the absence of that evidence is explicitly accepted by its owner.

This checklist is intentionally not pre-approved by the author or a passing test
runner. Historical provenance, hardware interoperability and release approval
cannot be manufactured by adding more unit tests.
