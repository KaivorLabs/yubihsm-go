# Deferred protocol convenience features

`protocol-conveniences.patch` preserves additions that were introduced while
reviewing the refactor but are not required for its correctness/security fixes:

- `NewCapabilitiesOption` / `NewAlgorithmOption` list filters;
- preferred-case constructor/response aliases for the existing `Wrapkey` and
  `Authkey` names;
- names for additional commands, algorithms, capability bits and object types
  without corresponding new high-level command implementations;
- tests for those additions.

They are removed from active Go files. Existing historical APIs and the original
Wrap work remain. This patch does **not** restore all other pre-remediation code:
all core bug fixes and behavior decisions continue to apply.

Review/test it independently, without changing the main worktree:

```sh
python3 scripts/verify-deferred.py
```

If deliberately accepted as a separate feature change, on a protected branch:

```sh
git apply --check docs/deferred/protocol-conveniences.patch
git apply docs/deferred/protocol-conveniences.patch
gofmt -w commands
bash scripts/verify.sh
```

Do not apply it to the main worktree as part of verification or treat these unreleased
names as existing public compatibility promises. If subsequent changes make the
patch stop applying, re-review and regenerate it intentionally; do not force-apply
or silently drop its tests.
