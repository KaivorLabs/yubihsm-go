#!/usr/bin/env bash
# Source API gate only. Behavior changes are reviewed separately in docs/.
set -euo pipefail
cd "$(dirname "$0")/.."
base=${1:-3b1fcb9aeed5fc5d52faf1cf6f4a85a021d48763}
base=$(git rev-parse --verify "${base}^{commit}")
root=$PWD
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/base"
git archive "$base" | tar -x -C "$tmp/base"
tool=golang.org/x/exp/cmd/apidiff@v0.0.0-20261112173441-d10d3b464990
module=github.com/certusone/yubihsm-go
printf 'API tool: %s\nBase commit: %s\n' "$tool" "$base"
(cd "$tmp/base" && go run "$tool" -m -w "$tmp/base.api" "$module")
(cd "$root" && go run "$tool" -m -w "$tmp/current.api" "$module")
# apidiff can report differences with exit code zero: inspect its output too.
go run "$tool" -m -incompatible "$tmp/base.api" "$tmp/current.api" > "$tmp/incompatible.txt"
if [[ -s "$tmp/incompatible.txt" ]]; then
  python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text(), end="")' "$tmp/incompatible.txt"
  echo 'FAIL: incompatible source API changes' >&2
  exit 1
fi
echo 'PASS: source API declarations; this does NOT certify behavioral compatibility.'
