# yubihsm-go
Yubihsm-go is a minimal implementation of the securechannel and connector protocol of the YubiHSM2.

Requires **Go 1.27.3 or newer**. CI targets Go 1.27.3; older Go versions are no longer supported.

It also implements a simple SessionManager which keeps connections alive and swaps them if the maximum number of
messages is depleted.

Currently the following commands are implemented:

 * DeviceInfo
 * Reset
 * GenerateAsymmetricKey / PutAsymmetricKey
 * SignDataEddsa / SignDataEcdsa / SignDataPkcs1
 * ListObjects / GetObjectInfo / DeleteObject
 * GetPubKey / DeriveEcdh
 * Echo
 * ChangeAuthenticationKey / PutAuthenticationKey
 * GetOpaque / PutOpaque
 * SignAttestationCertificate
 * PutWrapKey / GenerateWrapKey
 * WrapData / UnwrapData
 * ExportWrapped / ImportWrapped
 * GetPseudoRandom
 * Authentication and session-related commands

Implementing new commands is really easy. Please consult `commands/constructors.go` and `commands/response.go` for reference.

Please submit a PR if you have implemented new commands or extended existing constructors.

## Session and transport behavior

Use a supported Go release with the latest security patches for deployment;
compatibility with an older compiler does not make that toolchain secure.

- Keepalive and secure commands are serialized. An uncertain transport failure,
  invalid RMAC, or malformed secure framing invalidates the session. The manager
  starts a replacement but **never retries the failed command**: it may already
  have executed on the HSM. Applications must reconcile non-idempotent operations.
- `Destroy()` waits for active requests, session replacements, and keepalive to
  finish. Custom connectors must use bounded timeouts for bounded shutdown.
- `NewSessionManagerWithAuthKey` accepts a raw 32-byte authentication key and
  copies it. The manager retains that credential for replacements; successfully
  changing its own symmetric Authentication Key also updates the retained key.
  Secret buffers are cleared on a best-effort basis, not as a guarantee that Go's
  runtime or cryptographic primitives leave no copies in memory.
- The default HTTP client uses a 30-second timeout, TLS 1.2+ for HTTPS, and rejects
  redirects. Use `NewHTTPConnectorWithClient` for custom trust roots, longer HSM
  operations, or another transport policy; that client's policies are your responsibility.
- Firmware 2.4+ permits complete frames up to 3136 bytes, leaving at most 3116
  bytes of inner data after SCP03 framing and padding. Earlier firmware has a
  2048-byte frame limit (2028 inner bytes). This library does not negotiate the
  older limit; applications targeting those devices must stay within it. WRAP
  adds 30 response bytes (nonce, prefix and MAC), so its firmware-2.4+ plaintext
  limit is 3086 bytes. UNWRAP also needs a two-byte key ID: a single-device
  wrap/unwrap round trip must stay within 3084 plaintext bytes (1996 on older firmware).
- Background session logs omit URL errors' details because URLs can contain
  credentials in userinfo, paths or queries. Original errors returned to callers
  are unchanged; callers and custom connectors must still avoid logging secrets.

## Refactoring review and verification

This candidate combines bug fixes and intentional security/behavior changes;
source-API compatibility does **not** imply unchanged runtime behavior. See the
[compatibility and migration ledger](docs/compatibility.md) and the
[scope, evidence, and acceptance checklist](docs/refactoring-review.md).
Nonessential additions are preserved in a [separate deferred patch](docs/deferred/README.md).
The [latest local-Go review](docs/local-go-review.md) records additional repairs
and the unresolved Go 1.27.3 standard-library vulnerability scan result.

Run `bash scripts/verify.sh` for native tests, race detection, formatting and vet.
Extended verification uses pinned tools and independent/mutation checks; the
review document lists prerequisites and the exact command. Unselected checks
and hardware integration are explicitly reported as **NOT RUN**.

## Example of usage

> **Security:** `"password"` below is the public factory-default credential and
> is suitable only for local examples. Replace or delete the factory
> Authentication Key before deployment; do not hardcode production credentials.

```go
c := connector.NewHTTPConnector("localhost:1234")
sm, err := yubihsm.NewSessionManager(c, 1, "password")
if err != nil {
	panic(err)
}
defer sm.Destroy()

// If you already manage a raw 32-byte authentication key, use
// yubihsm.NewSessionManagerWithAuthKey instead.
echoMessage := []byte("test")

command, err := commands.CreateEchoCommand(echoMessage)
if err != nil {
	panic(err)
}

resp, err := sm.SendEncryptedCommand(command)
if err != nil {
	panic(err)
}

parsedResp, matched := resp.(*commands.EchoResponse)
if !matched {
	panic("invalid response type")
}

if bytes.Equal(parsedResp.Data, echoMessage) {
	println("successfully echoed data")
} else {
	panic(errors.New("echoed message did not equal requested message"))
}

```
