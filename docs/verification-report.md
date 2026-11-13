# Local verification record — 2026-11-13

Historical record for the initial remediation checkpoint
`20261113T111642.970194Z` (49 files). Further review subsequently found additional
boundary/compatibility defects: see [follow-up-review.md](follow-up-review.md).
This earlier passing run must not be presented as verification of later edits.

This records the review-remediation candidate based on
`3b1fcb9aeed5fc5d52faf1cf6f4a85a021d48763`, not a released or committed version.
An exact final worktree checkpoint and raw verification logs are retained under
`.git/refactor-review/` locally; they are deliberately not published with source.
The original pre-remediation checkpoint remains verified and unchanged.

## Executed checks

| Check | Actual environment / selection | Result |
| --- | --- | --- |
| Full modern gate | Go 1.27.4, darwin/arm64; `VERIFY_EXTENDED=1 VERIFY_STRESS=1 VERIFY_FUZZ=1 bash scripts/verify.sh` | PASS |
| Basic unit tests / native race detector / vet / gofmt / module verification | Same patched toolchain; uncached tests | PASS |
| Concurrent stress | `-race -cpu=1,2,4 -shuffle=on -count=20 ./...` | PASS |
| Fuzz campaigns | Raw and declared-payload response parsing plus SCP03 unpadding; 20 seconds each, 4 workers | PASS; finite campaigns, not exhaustive proof |
| Independent oracle | Python 3.13; cryptography 46.0.3, cffi 2.0.0, pycparser 2.23; generator `--check` | PASS; fixed fixture not rewritten |
| Regression mutations | Five intentionally broken variants, each in a disposable copy after baseline tests passed | All five rejected at the intended assertion; no compile-error kills |
| Checkpoint tooling | Seven stdlib Python unit tests, including corruption, path, permissions, and untracked/ignored inventory cases | PASS |
| Source API declarations | Pinned apidiff against the recorded upstream baseline; nonempty incompatible output is a failure | PASS; not a behavioral-compatibility claim |
| Deferred feature patch | Applied only to disposable current-source copy, then uncached `go test ./...` | PASS; main worktree unchanged |
| Go 1.16 compatibility gate | Go 1.16.15, darwin/arm64; `VERIFY_RACE=0 bash scripts/verify.sh` | PASS; race/stress/fuzz/analyzers explicitly NOT RUN in this job |
| Declared minimum Go gate | Go 1.14.15, linux/amd64 in read-only source Docker mount; `VERIFY_RACE=0 bash scripts/verify.sh` | PASS; compatibility only, not deployment guidance |
| Foreign-platform builds | Go 1.27.4; linux/amd64, linux/arm64, windows/amd64, freebsd/amd64 using `-exec=true` | PASS for compilation only; OS tests NOT executed |
| Downstream vault | `immunix-old/immunix`: module replacement confirmed to this worktree; Go 1.27.4 `go test -race -count=1 ./pkg/vault` | PASS |

The Go 1.14 container was resolved and rerun using the pinned image digest:

```sh
docker run --rm --platform linux/amd64 \
  -e GOPROXY=https://proxy.golang.org,direct -e VERIFY_RACE=0 \
  --mount "type=bind,src=$PWD,dst=/src,readonly" -w /src \
  golang@sha256:1a7173b5b9a3af3e29a5837e0b2027e1c438fd1b83bbee8f221355087ad416d6 \
  bash scripts/verify.sh
```

## Security result, without overclaiming

- Staticcheck v0.8.2 passed.
- Gosec v2.30.0 passed its **medium/high** severity gate. This is not a zero-LOW-
  findings assertion; see the documented fixed-size buffer write limitations.
- Govulncheck v1.9.0 on **Go 1.27.4** reported zero reachable vulnerable symbols
  and zero findings in imported packages, but **26 findings in required modules'
  unused packages**. Those findings are not removed or suppressed by this work.
- The machine's default Go 1.27.3 is not the toolchain certified by this result.
  Future vulnerability database updates can change results; retain/review the raw
  output rather than only quoting this summary.

## Deliberately not certified

- Physical YubiHSM integration, firmware matrix, and real Wrap interoperability:
  **NOT RUN**. The independent transcript is generated, not captured from hardware.
- Remote GitHub Actions execution: **NOT RUN locally**. A pinned workflow is
  provided, but only actual remote job results establish that it passed there.
- Historical exact preservation of the initial pre-refactor user patch: no
  independent original artifact exists here. This remains an evidence gap.
- Product acceptance of behavior decisions B1–B9 and release/version approval:
  still requires human review. No commits, staging, or release were performed.
