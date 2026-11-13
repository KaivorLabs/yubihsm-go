#!/usr/bin/env python3
"""Ensure regression tests reject representative broken implementations.

Mutations run only in a disposable copy, after that copy passes baseline tests.
A compilation error, timeout, or unrelated test error is NOT a successful kill.
"""

from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
copy_worktree = runpy.run_path(str(ROOT / "scripts/verify-deferred.py"))["copy_worktree"]

MUTATIONS = [
    ("incorrect complete-frame limit", "commands/types.go",
     "MaxMessageLength = 3136", "MaxMessageLength = 3168",
     "./commands", "TestOfficialMessageSizeLimits", "incorrect frame/ciphertext/inner limits"),
    ("unrelated authentication ACK", "securechannel/channel.go",
     "if data[0] != byte(commands.ErrorResponseCode-commands.ResponseCommandOffset) &&",
     "if false && data[0] != byte(commands.ErrorResponseCode-commands.ResponseCommandOffset) &&",
     "./securechannel", "TestAuthenticateRejectsUnrelatedSuccessResponse",
     "unrelated response was accepted as successful authentication"),
    ("premature request-buffer wipe", "connector/http.go",
     '\tendpoint, err := connectorEndpoint(baseURL, "/connector/api")',
     '\tdefer func() { for i := range requestData { requestData[i] = 0 } }()\n'
     '\tendpoint, err := connectorEndpoint(baseURL, "/connector/api")',
     "./connector", "TestRequestBodyRemainsValidUntilTransportClosesIt",
     "transport saw corrupted request body"),
    ("stale replacement credential", "manager.go",
     "\t\ts.updateAuthenticationKeyLocked(c, resp)",
     "\t\t// mutation: do not update the retained credential",
     ".", "TestAuthenticationKeyRotationUpdatesReplacementCredential",
     "replacement authentication credential was not updated correctly"),
    ("concurrent Destroy returns early", "manager.go",
     "\t\t\t<-complete\n", "\t\t\t// mutation: do not wait\n",
     ".", "TestConcurrentDestroyWaitsForSessionClose",
     "concurrent Destroy returned before session close completed"),
    ("WRAP ignores response overhead", "commands/constructors.go",
     "if len(data) > MaxCommandDataLength-responseOverhead {",
     "if len(data) > MaxCommandDataLength-responseOverhead+28 {",
     "./commands", "TestWrapDataAccountsForResponseOverhead",
     "WRAP accepted plaintext whose successful response cannot fit"),
    ("encoded URL path is discarded", "connector/http.go",
     "\tparsed.RawPath = escapedPath", '\tparsed.RawPath = ""',
     "./connector", "TestEndpointPreservesEncodedTrailingSlash", "endpoint for"),
    ("empty response becomes nil", "commands/response.go",
     "\townedPayload := make([]byte, len(payload))\n\tcopy(ownedPayload, payload)\n\tpayload = ownedPayload",
     "\tpayload = append([]byte(nil), payload...)",
     "./commands", "TestEmptyResponsePreservesLegacyNonNilPayload", "changed legacy empty payload semantics"),
    ("empty constructor input becomes nil", "commands/constructors.go",
     "\tvar ownedData []byte\n\tif data != nil {\n\t\townedData = make([]byte, len(data))\n\t\tcopy(ownedData, data)\n\t}",
     "\townedData := append([]byte(nil), data...)",
     "./commands", "TestEchoConstructorPreservesNilVersusEmpty", "nil-versus-empty contract"),
    ("response parameter validation is ignored", "securechannel/channel.go",
     "if err := checkResponseParameters(commandData, decryptedResponse); err != nil {",
     "if err := checkResponseParameters(commandData, decryptedResponse); false && err != nil {",
     "./securechannel", "TestEncryptedResponsesMustMatchRequestParameters",
     "mismatched successful response parameters were accepted"),
    ("impossible random request reaches device", "securechannel/channel.go",
     "int(binary.BigEndian.Uint16(request[3:])) > commands.MaxCommandDataLength {",
     "int(binary.BigEndian.Uint16(request[3:])) > commands.MaxCommandDataLength+1 {",
     "./securechannel", "TestImpossibleRandomResponseRejectedBeforeSending",
     "local random-length error advanced or invalidated the session"),
    ("stale keepalive replaces recovered session", "manager.go",
     "\t\tif _, err := s.sendEncryptedCommand(command, true); errors.Is(err, ErrSessionManagerDestroyed) {\n\t\t\treturn\n\t\t}",
     "\t\tif _, err := s.sendEncryptedCommand(command, true); errors.Is(err, ErrSessionManagerDestroyed) {\n\t\t\treturn\n\t\t} else if err != nil {\n\t\t\t_ = s.swapSession()\n\t\t}",
     ".", "TestKeepAliveDoesNotReplaceRecoveredSessionAgain",
     "stale keepalive failure created 2 replacement sessions"),
    ("raw WRAP ignores response overhead", "securechannel/channel.go",
     "len(request)-5 > commands.MaxCommandDataLength-wrapOverhead {",
     "len(request)-5 > commands.MaxCommandDataLength-wrapOverhead+1 {",
     "./securechannel", "TestImpossibleRawWrapResponseRejectedBeforeSending",
     "local WRAP response-length error advanced or invalidated the session"),
    ("URL credentials are logged", "manager.go",
     '\t\tlog.Printf("%s; HTTP transport error (URL and details omitted)", message)',
     '\t\tlog.Printf("%s; err=%v", message, err)',
     ".", "TestBackgroundSwapLogDoesNotExposeConnectorCredentials",
     "background error logging exposed connector URL credentials"),
]

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="yubihsm-mutations-") as directory:
        tree = Path(directory)
        copy_worktree(tree)
        subprocess.run(["go", "test", "-mod=readonly", "-count=1", "./..."], cwd=tree, check=True, timeout=180)
        for name, filename, before, after, package, test, marker in MUTATIONS:
            path = tree / filename
            original = path.read_bytes()
            text = original.decode()
            if text.count(before) != 1:
                raise RuntimeError("mutation no longer matches uniquely: " + name)
            try:
                path.write_text(text.replace(before, after, 1))
                result = subprocess.run(
                    ["go", "test", "-mod=readonly", "-count=1", "-timeout=30s", "-run", "^" + test + "$", package],
                    cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90,
                )
                if result.returncode == 0 or "--- FAIL: " + test not in result.stdout or marker not in result.stdout:
                    raise RuntimeError("mutation was not rejected by the intended assertion: " + name + "\n" + result.stdout)
                print("KILLED:", name, "by", test, flush=True)
            finally:
                path.write_bytes(original)
    print("PASS: all representative mutations were rejected; core worktree unchanged.")
