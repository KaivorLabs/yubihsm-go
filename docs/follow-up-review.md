# Follow-up boundary and compatibility review — 2026-11-13

Previous frozen candidate: `.git/refactor-review/20261113T111642.970194Z/`
(49 files, SHA-256 `3036123177181df9456073f08345ceb27745760a94a85b4092292f0b6db9b2b4`).
That checkpoint is preserved. Its earlier passing report does not certify these
subsequent edits. There are no new feature APIs in this follow-up. The subsequent
[local-Go deep review](local-go-review.md) records later changes and actual
Go 1.27.3 results; this report's earlier passing checks do not certify them.

## Reproduced defects and corrections

Each defect was reproduced before its correction, rather than inferred from a
passing implementation-coupled emulator.

| Finding | Failure observed before correction | Correction / acceptance test |
| --- | --- | --- |
| WRAP response capacity | 3087 plaintext bytes were accepted although their nonce + encrypted prefix + tag cannot fit in the secure response frame. | `CreateWrapDataCommand` now accounts for 30 response overhead bytes. `TestWrapDataAccountsForResponseOverhead` accepts 3086, rejects 3087. |
| Encoded trailing URL slash | A base ending in `proxy%2F` became `proxy/connector/api`, losing routing-significant escaping. | Append to the escaped path, then derive the matching decoded `Path`; keep `RawPath` consistent. `TestEndpointPreservesEncodedTrailingSlash` and an actual httptest request verify the URI sent on the wire. |
| Incomplete private checkpoint | An unreadable directory was silently skipped by `os.walk`, allowing a partial inventory to be certified. | Enumeration now propagates errors. `test_unreadable_directory_must_not_be_silently_omitted` fails before the fix and passes on a non-root POSIX host. An incomplete checkpoint directory without a valid manifest is not a backup. Unsupported file types also fail rather than being silently omitted. |
| Empty-buffer compatibility regression | Ownership copies changed non-nil empty payloads into nil, changing JSON from an empty base64 string to `null`. | Preserve ownership without collapsing empty/nil semantics. `empty_buffer_contract_test.go` was run against both upstream HEAD and the corrected candidate; both pass. The pre-fix candidate fails both tests. |
| Credential-bearing URL logs | Background swap errors printed a URL containing userinfo and path/query credentials, including a sensitive outer error wrapper. | All manager error-log sites use a helper that omits URL-error text. `TestBackgroundSwapLogDoesNotExposeConnectorCredentials` verifies actual background logging and unchanged caller-visible error identity. Non-URL custom errors and application logging remain the caller's responsibility. |
| False formatting failure for deletion | The verifier passed an index-listed but deleted Go file to gofmt, failing a valid uncommitted worktree. | Filter formatting input to existing files with NUL-safe paths. `test_tracked_deletion_is_not_sent_to_gofmt` runs the real verifier against a disposable Git copy, leaving the real index untouched. |

For firmware 2.4+, the secure inner limit is 3116 bytes. One-way WRAP can return
3086 plaintext bytes plus 30 overhead bytes. UNWRAP sends a two-byte key ID as
well, so its original plaintext capacity is 3084 bytes. A single-device round
trip must respect the smaller limit. On earlier firmware these values are
1998 / 1996 respectively; firmware-limit negotiation is still not implemented.
This correction does not claim to validate every manually assembled raw command
or every device-specific semantic restriction.

## Additional paths checked without speculative production changes

- `TestCredentialRotationDuringReplacementAuthentication`: pause a swap outside
  the manager lock, confirm rotation on the active session, then exercise both
  rejected old authentication and an accepted already-established session. The
  retained credential never rolls back, failed candidates close, a fresh swap
  receives the new key, and the business command is sent exactly once. Both
  outcomes passed repeated race tests; no unproven credential-epoch mechanism
  was added. Real firmware behavior still requires hardware verification.
- `TestHTTPResponseBodyLifecycle`: command and status endpoints, successful read,
  read failure, HTTP rejection, and Close failure. Bodies close exactly once;
  read/status errors are not overwritten by Close errors. These existing
  semantics were retained, not changed merely to improve a test count.
- Existing API declarations, caller-owned key/client policies, fixed SCP03
  transcript, maximum-size framing, malformed responses, shutdown races, and
  isolated deferred-patch application remain acceptance requirements.

## Continued request/response and isolation review

The intervening frozen candidate is
`.git/refactor-review/20261113T115045.875843Z/` (56 files, archive SHA-256
`7f38492bcd8952c86e23a936961bd953b15648db664693c2a1440d93907e26b3`).
Its passing logs do not certify the following later changes.

| Finding | Reproduced failure | Correction / evidence |
| --- | --- | --- |
| Success was bound only to opcode, not request parameters | A valid encrypted response could return 31/33 random bytes for a 32-byte request, different Echo contents, or a different explicitly requested wrap-key ID, all without an error. Plain Echo also accepted different contents. | Check exact Echo data/random count and the explicit ID of supported create/put/change-key operations. Encrypted inconsistencies fail closed; error messages do not print payloads. `response_contract_test.go` reproduces these cases with authenticated fault injection and checks all seven ID-returning operations. This is policy B11, not a source-API change. |
| Impossible random response sent anyway | A 3117-byte random request was sent and then invalidated the channel when its response exceeded frame capacity. | Reject counts over the independently established 3116 secure-inner limit before MAC/counter state changes or transport. Test both local rejection and successful 0/1/32/3116-byte response shapes, device-assigned IDs and legitimate card errors. Zero-length test responses are not a claim that every firmware accepts zero-byte requests. |
| Disposable verification copy was not reliably isolated | Overlaying a clone silently retained a deleted baseline file; replacing an existing file with a symlink failed. Conversely, copying a regular file through a baseline destination link overwrote a file outside the copy. | Remove tracked deletions, replace leaf links without following them, reject parent links/source-tree destinations and unsupported file types, and propagate source stat failures. Six tool tests cover real clone verification and these boundaries. Destination-link failures were also reproduced against the preserved 56-file helper using only temporary fixtures. |
| Snapshot type change went undetected | Replacing a regular file after archival with a symlink to identical bytes, with matching permissions, still produced a certified manifest. | Final revalidation checks regular-file/symlink type as well as mode/content/link target. `test_capture_rejects_regular_file_changed_to_matching_symlink` injects the change during a real temporary-repository capture and requires refusal without a valid manifest. This is not a claim of an atomic filesystem snapshot or protection against all concurrent writers; freeze edits during capture/verification. |

Request snapshots used for matching are privately serialized and best-effort
cleared; they are never passed to an HTTP transport, so this does not reintroduce
the earlier asynchronous request-body wiping bug. No general command schema,
new command API, algorithm policy or automatic retry is introduced. Unknown
application parsers still do not invalidate otherwise synchronized SCP03 state.
The emulator's zero-filled random payloads and assigned IDs are shape/state
fixtures, not evidence of device entropy, key generation or firmware behavior.
Directory/file layout transitions unsupported by the copy helper fail explicitly
rather than being silently tested against a different tree.

## Verification and remaining boundaries

At this review checkpoint the mutation gate had twelve Go variants. Besides the five original failures,
it must reject ignored WRAP overhead, dropped URL escaping, nil/empty regressions
in both response parsing and construction, credential-bearing URL logging,
ignored response-parameter checks and an oversized random request reaching the device.
Compilation errors and unrelated failures still do not count as successful kills.
The Python verification tests exercise real permissions and a real disposable
Git worktree; the permissions case is explicitly skipped on root/non-POSIX hosts,
not presented as tested there.

Use the pinned full modern gate from `refactoring-review.md`, compatibility
checks on Go 1.14.15 / 1.16.15, and downstream tests. The finalized private
checkpoint associates the exact source inventory with raw verification logs;
logs from the earlier 49-file checkpoint are historical, not reused as proof of
this candidate. Changed nil/empty behavior is a restored legacy contract, while
URL-log redaction and request-bound success checks are the explicit security
choices B10/B11. Current Python verification has fifteen tests in total; the
actual gate log records skips rather than converting them to passes.

No claim of exhaustive correctness is made. Physical YubiHSM integration,
firmware-limit negotiation, remote CI execution, release approval, and the
missing original pre-refactor user-patch artifact remain separate open gates.
Security scans must retain any unused-package vulnerability warnings and record
the actual patched toolchain. No staging, commits, or release are performed by
these checks on the actual source repository; Git fixtures are disposable.
