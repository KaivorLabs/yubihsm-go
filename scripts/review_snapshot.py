#!/usr/bin/env python3
"""Capture/verify a private worktree checkpoint, including untracked files.

Archives may contain secrets. They stay under the Git directory, never in the
source tree. This does not reconstruct an unavailable historical user patch.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify(checkpoint):
    manifest = json.loads((checkpoint / "manifest.json").read_text())
    archive_path = checkpoint / "worktree.tar.gz"
    if digest(archive_path) != manifest["archive_sha256"]:
        raise ValueError("archive checksum mismatch")
    seen = set()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            if member.name in seen or Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                raise ValueError("unsafe or duplicate archive path: " + member.name)
            seen.add(member.name)
            expected = manifest["files"][member.name]
            # gettarinfo may include file-type bits; tar headers store permissions.
            if member.mode & 0o7777 != expected["mode"] & 0o7777:
                raise ValueError("file mode mismatch: " + member.name)
            if member.isfile():
                data = archive.extractfile(member).read()
                if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                    raise ValueError("file checksum mismatch: " + member.name)
            elif not member.issym() or member.linkname != expected.get("symlink"):
                raise ValueError("unexpected archive member: " + member.name)
    if seen != set(manifest["files"]):
        raise ValueError("archive inventory mismatch")
    print("Verified checkpoint:", checkpoint)
    print("Files:", len(seen), "Archive SHA-256:", manifest["archive_sha256"])


def raise_walk_error(error):
    # os.walk otherwise ignores unreadable directories and certifies a partial
    # inventory as complete. Never accept a checkpoint we could not enumerate.
    raise error


def worktree_files(root, gitdir):
    paths = []
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=raise_walk_error):
        directory = Path(directory)
        for name in list(dirs):
            path = directory / name
            if path == root / ".git" or path == gitdir:
                dirs.remove(name)
            elif path.is_symlink():
                dirs.remove(name)
                names.append(name)
        for name in names:
            path = directory / name
            if path != root / ".git":
                paths.append(path)
    return sorted(paths)


def capture():
    os.umask(0o077)
    gitdir = Path(git("rev-parse", "--absolute-git-dir").decode().strip())
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    checkpoint = gitdir / "refactor-review" / stamp
    checkpoint.mkdir(parents=True, mode=0o700)
    files = {}
    inventory = worktree_files(ROOT, gitdir)
    with tarfile.open(checkpoint / "worktree.tar.gz", "w:gz") as archive:
        for path in inventory:
            rel = path.relative_to(ROOT).as_posix()
            info = archive.gettarinfo(str(path), arcname=rel)
            if info.issym():
                archive.addfile(info)
                files[rel] = {"symlink": info.linkname, "mode": info.mode & 0o7777}
            elif info.isfile():
                data = path.read_bytes()
                archive.addfile(info, io.BytesIO(data))
                files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "mode": info.mode & 0o7777}
            else:
                raise ValueError("unsupported file type: " + rel)
    for filename, args in {
        "head-to-worktree.patch": ("diff", "--binary", "HEAD"),
        "index.patch": ("diff", "--cached", "--binary"),
        "status.txt": ("status", "--porcelain=v1", "--untracked-files=all"),
        "untracked.txt": ("ls-files", "--others", "--exclude-standard"),
    }.items():
        (checkpoint / filename).write_bytes(git(*args))
    if (gitdir / "index").exists():
        shutil.copy2(gitdir / "index", checkpoint / "index.snapshot")
    (checkpoint / "head.tar").write_bytes(git("archive", "HEAD"))
    manifest = {
        "captured_at_utc": stamp,
        "base_commit": git("rev-parse", "HEAD").decode().strip(),
        "scope": "Current worktree checkpoint; NOT the unavailable original pre-refactor user patch.",
        "archive_sha256": digest(checkpoint / "worktree.tar.gz"),
        "files": files,
    }
    # Refuse to certify a mixed snapshot if files were added, deleted or changed.
    if worktree_files(ROOT, gitdir) != inventory:
        raise ValueError("worktree inventory changed during capture")
    for rel, expected in files.items():
        path = ROOT / rel
        mode = path.lstat().st_mode
        if ("sha256" in expected and not stat.S_ISREG(mode)) or ("symlink" in expected and not stat.S_ISLNK(mode)):
            raise ValueError("file type changed during capture: " + rel)
        if mode & 0o7777 != expected["mode"]:
            raise ValueError("file permissions changed during capture: " + rel)
        if "sha256" in expected and digest(path) != expected["sha256"]:
            raise ValueError("file changed during capture: " + rel)
        if "symlink" in expected and os.readlink(path) != expected["symlink"]:
            raise ValueError("symlink changed during capture: " + rel)
    (checkpoint / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    verify(checkpoint)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path, help="verify an existing checkpoint without restoring it")
    args = parser.parse_args()
    if args.verify:
        verify(args.verify.resolve())
    else:
        capture()
