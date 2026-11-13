#!/usr/bin/env python3
"""Apply the deferred feature patch in a disposable tree, never the worktree."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def copy_worktree(destination):
    destination = destination.resolve()
    source_root = ROOT.resolve()
    if destination == source_root or source_root in destination.parents:
        raise ValueError("test-copy destination must be outside the source worktree")
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).split(b"\0")
    for name in sorted(set(paths) - {b""}):
        source = ROOT / os.fsdecode(name)
        target = destination / os.fsdecode(name)
        try:
            source_mode = source.lstat().st_mode
        except FileNotFoundError:
            source_mode = None
        # A clone used by verifier tests may already contain a baseline file
        # or symlink. Never follow destination links outside the private copy.
        for parent in target.relative_to(destination).parents:
            if (destination / parent).is_symlink():
                raise ValueError("test-copy destination contains a parent symlink: " + str(parent))
        if source_mode is None:
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.exists():
                raise ValueError("unsupported directory deletion in test copy: " + str(target))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        if stat.S_ISLNK(source_mode):
            if target.exists():
                if target.is_dir():
                    raise ValueError("unsupported directory replacement in test copy: " + str(target))
                target.unlink()
            target.symlink_to(os.readlink(source))
        elif stat.S_ISREG(source_mode):
            if target.is_dir():
                raise ValueError("unsupported directory replacement in test copy: " + str(target))
            shutil.copy2(source, target)
        else:
            raise ValueError("unsupported source file type in test copy: " + str(source))


if __name__ == "__main__":
    patch = ROOT / "docs/deferred/protocol-conveniences.patch"
    with tempfile.TemporaryDirectory(prefix="yubihsm-deferred-") as directory:
        tree = Path(directory)
        copy_worktree(tree)
        for args in (["git", "apply", "--check", str(patch)], ["git", "apply", str(patch)],
                     ["go", "test", "-mod=readonly", "-count=1", "./..."]):
            subprocess.run(args, cwd=tree, check=True)
    print("PASS: deferred features apply and pass tests in isolation; core worktree unchanged.")
