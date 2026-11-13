#!/usr/bin/env bash
# Native checks. Optional modes are explicit: an omitted check is NOT a pass.
set -euo pipefail
cd "$(dirname "$0")/.."

for flag in VERIFY_RACE VERIFY_STRESS VERIFY_FUZZ VERIFY_EXTENDED; do
  value=${!flag:-}
  if [[ -n "$value" && "$value" != 0 && "$value" != 1 ]]; then
    printf 'Invalid %s=%q; expected 0 or 1\n' "$flag" "$value" >&2
    exit 2
  fi
done

printf 'Toolchain: '; go version
printf 'Target: '; go env GOOS GOARCH
printf 'Base: '; git rev-parse HEAD
printf 'Worktree (including untracked files):\n'
git status --short --untracked-files=all

gofmt_bin="$(go env GOROOT)/bin/gofmt"
# The index still lists tracked deletions in an uncommitted worktree. Check
# only existing files, while keeping NUL-safe handling for unusual filenames.
unformatted=$(git ls-files --cached --others --exclude-standard -z -- '*.go' |
  while IFS= read -r -d '' path; do
    if [[ -f "$path" ]]; then printf '%s\0' "$path"; fi
  done | xargs -0 "$gofmt_bin" -l)
if [[ -n "$unformatted" ]]; then
  printf 'Unformatted Go files:\n%s\n' "$unformatted" >&2
  exit 1
fi
git diff --check
# Fail if commands below require changing dependency files.
go mod verify
go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
if [[ ${VERIFY_RACE:-1} == 1 ]]; then
  go test -mod=readonly -race -count=1 ./...
else
  echo 'NOT RUN: race detector (VERIFY_RACE=0; compatibility-only job)'
fi
if [[ ${VERIFY_STRESS:-0} == 1 ]]; then
  go test -mod=readonly -race -cpu=1,2,4 -shuffle=on -count=20 ./...
else
  echo 'NOT RUN: stress suite (set VERIFY_STRESS=1)'
fi
if [[ ${VERIFY_FUZZ:-0} == 1 ]]; then
  for name in FuzzParseResponse FuzzParseResponseDeclaredPayload; do
    go test -mod=readonly ./commands -run '^$' -fuzz "^${name}$" -fuzztime="${FUZZTIME:-20s}" -parallel=4
  done
  go test -mod=readonly ./securechannel -run '^$' -fuzz '^FuzzUnpad$' -fuzztime="${FUZZTIME:-20s}" -parallel=4
else
  echo 'NOT RUN: fuzz campaigns (set VERIFY_FUZZ=1; requires Go 1.18+)'
fi
if [[ ${VERIFY_EXTENDED:-0} == 1 ]]; then
  go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
  # LOW/G104 buffer-write findings are documented, not claimed to be absent.
  go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -quiet -severity=medium ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
  bash scripts/verify-api.sh
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py'
  python3 securechannel/testdata/generate_scp03.py --check
  python3 scripts/verify-regressions.py
  python3 scripts/verify-deferred.py
else
  echo 'NOT RUN: pinned analyzers, API comparison, vector regeneration, mutation and deferred-patch checks (set VERIFY_EXTENDED=1)'
fi
echo 'PASS: selected automated checks only; NOT RUN: physical YubiHSM integration.'
