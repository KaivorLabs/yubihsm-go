# Compatibility and intentional behavior changes

Baseline: `3b1fcb9aeed5fc5d52faf1cf6f4a85a021d48763`.
This change set is **bug fixes plus security hardening**, not a behavior-preserving
pure refactor. A clean source-API comparison does not approve these changes for
release. They require explicit release review and the migration steps below.

## Preserved contracts

- Existing public function signatures and response type names remain available.
  In particular, keep the historical spellings `CreatePutWrapkeyCommand`,
  `CreatePutAuthkeyCommand`, `PutWrapkeyResponse`, and `PutAuthkeyResponse`.
- `HTTPConnector` still has exactly one `URL string` field. Existing literals and
  its `Connector` implementation remain source-compatible.
- `SessionManager` remains a comparable type, but copying a live manager or
  channel containing a mutex is unsupported.
- Existing manager error texts remain `sessionmanager has already been destroyed`
  and `no session available`; sentinels additionally support `errors.Is`.
- Valid legacy command encodings and public, non-secret password derivation
  vectors are fixed tests, not expectations calculated from the implementation.
  Empty Echo/random response payloads remain non-nil; Echo constructor inputs
  preserve nil versus non-nil empty slices, including their JSON representations.
- The existing Wrap work is retained: GenerateWrapKey, WrapData, UnwrapData,
  ExportWrapped, ImportWrapped, and their response parsing.

Source checks: `api_compat_test.go`, `commands/legacy_wire_test.go`,
`authkey/authkey_test.go`, and `bash scripts/verify-api.sh`.

## Behavior decisions (not source-API promises)

| ID | Intentional difference | Reason / migration | Executable evidence |
| --- | --- | --- | --- |
| B1 | Channel-owned `AuthKey` is zeroed and set to nil after authentication and on finalization. | Do not read it after authentication. If the application needs the credential, retain a separate caller-owned key and pass it to `NewSecureChannelWithAuthKey` / `NewSessionManagerWithAuthKey`; these copy it. Treat the retained key as a secret. | `TestAuthenticationKeyOwnershipContract` |
| B2 | Default connectors no longer inherit `http.DefaultClient` or `http.DefaultTransport` mutations. | Avoid process-global, potentially insecure transport configuration. Migrate custom roots, proxies, instrumentation, and timeout settings to `NewHTTPConnectorWithClient`. | `TestDefaultConnectorDoesNotInheritGlobalClient`, `TestDefaultClientDoesNotDependOnGlobalTransportType` |
| B3 | Default timeout is 30 seconds, HTTPS requires TLS 1.2+, and redirects are rejected. | Long RSA operations or trusted redirect deployments must supply an explicit client policy. A caller-supplied client is not silently tightened or mutated. | `TestDefaultHTTPClientSecurityPolicy`, `TestDefaultHTTPConnectorRejectsRedirects`, `TestCustomClientRetainsItsExplicitPolicies` |
| B4 | `Destroy` waits for active operations, swaps and keepalive; concurrent callers wait for the same shutdown. | Call it outside connector callbacks. Bound custom connector operations with timeouts; shutdown does not cancel arbitrary user code. | `TestSwapDoesNotInstallSessionAfterDestroy`, `TestConcurrentDestroyWaitsForSessionClose`, `TestProactiveSwapReservesBeforeGoroutineStart` |
| B5 | An uncertain transport error, invalid RMAC, malformed framing or padding makes a channel non-reusable; a manager schedules replacement. | The failed command is **never automatically replayed**. Reconcile potentially completed writes/key changes before explicitly retrying. Subsequent calls may fail until replacement finishes. | `TestTransportFailureInvalidatesSession`, `TestMalformedSecureResponsesInvalidateChannel`, `TestMalformedInnerFrameInvalidatesSession` |
| B6 | Successful CLOSE/RESET updates local state; `Close` clears local secrets even when the close cannot be confirmed. | `Close` is idempotent locally, not proof that the HSM acknowledged it. An unreachable device may retain its session until its inactivity timeout. | `TestDirectCloseCommandFinalizesChannel`, `TestCloseClearsSecretsEvenWhenRejected` |
| B7 | Invalid lengths, wrong response command codes, short keys and malformed empty ACKs now return errors instead of panic, truncation or false success. | Do not rely on malformed input being accepted. `BodyLength` saturates for an unrepresentable body; `Serialize` rejects invalid frames. Wire maximum is 3136 total bytes / 3116 secure inner bytes on firmware 2.4+, not a 3136-byte inner payload. | `TestOfficialMessageSizeLimits`, command/response tests, `TestAuthenticateRejectsUnrelatedSuccessResponse` |
| B8 | Constructors and parsed responses own copied buffers instead of retaining caller-owned mutable slices. | Do not mutate a command through its original constructor input, or a response through the original wire buffer. This does not make concurrent mutation of a `CommandMessage` supported. | `TestConstructorsCopyDirectDataInputs`, `TestConstructorsDoNotMutateLabelBackingArray`, `TestParseResponseOwnsPayloadMemory` |
| B9 | A confirmed change of this manager's symmetric authentication key updates the retained replacement credential. | A lost response is not confirmation. Reconcile uncertain credential changes externally; no blind retries are made. Failed changes or changes of another key do not update it. | `TestAuthenticationKeyRotationUpdatesReplacementCredential`, `TestCredentialRotationDuringReplacementAuthentication` |
| B10 | Manager background logs omit URL errors' formatted details, including outer wrappers. | Userinfo, path tokens and query credentials must not enter the process logger. Original returned errors and `errors.Is`/`errors.As` identity remain unchanged. This does not sanitize arbitrary non-URL errors supplied by custom connectors or callers' own logs. | `TestBackgroundSwapLogDoesNotExposeConnectorCredentials` |
| B11 | Echo contents, random byte counts, explicit IDs in supported create/put/change-key responses, metadata query IDs/native types, and WRAP/UNWRAP output lengths must match the request. Inconsistent encrypted successes invalidate the channel. Random requests over 3116 bytes and raw WRAP requests whose response cannot fit are rejected locally before consuming session state. | Matching opcode/RMAC is not proof of a matching result. Do not accept truncated random material or a different explicit object ID as success. ID zero still allows device allocation, and valid card errors remain synchronized. The uint16 random constructor signature is unchanged; send can return a local limit error. Reconcile inconsistent writes before retrying. | `TestEncryptedResponsesMustMatchRequestParameters`, `TestExplicitObjectIDResponseContracts`, `TestImpossibleRandomResponseRejectedBeforeSending`, `TestImpossibleRawWrapResponseRejectedBeforeSending`, `TestResponseContractsAllowAssignedIDsAndCardErrors`, `TestResponseContractsAllowMetadataAndWrapShapes` |

Example migration for an application-owned credential (never hardcode a real key):

```go
// Load key from the application's credential store. key is a 32-byte authkey.AuthKey.
sm, err := yubihsm.NewSessionManagerWithAuthKey(c, keyID, key)
if err != nil {
    return err
}
defer sm.Destroy()
// The manager owns a copy; the application remains responsible for key's lifetime.
```

## Limits on the claim

- Best-effort zeroing does not guarantee that Go, cryptographic primitives, or
  transports have retained no copies in memory.
- No physical YubiHSM results are present. A Python-generated independent
  transcript is not a captured or certified device transcript.
- Older firmware has a 2048-byte whole-frame / 2028-byte secure-inner limit.
  There is no firmware-limit negotiation in this change set. WRAP adds 30
  response bytes, limiting modern one-way plaintext to 3086 bytes; UNWRAP also
  sends a two-byte key ID, so round-trip plaintext is limited to 3084 bytes.
  Older-device applications must use 1998 / 1996 respectively.
- The build baseline is now **Go 1.27.3 or newer**, as requested. Go 1.14/1.16
  results in historical reports do not imply continued support. Applications
  using older Go must upgrade their toolchain; public API declaration checks
  do not establish compiler compatibility or a clean vulnerability scan.
- API convenience aliases, additional filter helpers, and constants for
  otherwise unimplemented commands are deferred, not part of the core release
  surface. See `deferred/README.md`.
