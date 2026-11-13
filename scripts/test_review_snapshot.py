"""Regression tests for checkpoint verification; only creates temporary files."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

snapshot = runpy.run_path(str(Path(__file__).with_name("review_snapshot.py")))
verify = snapshot["verify"]
worktree_files = snapshot["worktree_files"]


class SnapshotVerificationTests(unittest.TestCase):
    def fixture(self, root, names=("file.txt",), recorded_mode=stat.S_IFREG | 0o640):
        data = b"public snapshot test data\n"
        archive_path = root / "worktree.tar.gz"
        files = {}
        with tarfile.open(archive_path, "w:gz") as archive:
            for name in names:
                info = tarfile.TarInfo(name)
                info.mode = 0o640
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
                files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "mode": recorded_mode}
        (root / "manifest.json").write_text(json.dumps({
            "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(), "files": files,
        }))
        return archive_path

    def test_inventory_includes_untracked_and_ignored_but_not_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gitdir = root / ".git"
            gitdir.mkdir()
            (gitdir / "private-metadata").write_text("must not be archived")
            (root / ".gitignore").write_text("ignored.txt\n")
            (root / "ignored.txt").write_text("must be archived despite ignore rule")
            (root / "untracked.txt").write_text("must be archived")
            names = [path.name for path in worktree_files(root, gitdir)]
            self.assertEqual(names, [".gitignore", "ignored.txt", "untracked.txt"])

    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "requires non-root POSIX permissions")
    def test_unreadable_directory_must_not_be_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            protected.mkdir()
            (protected / "not-in-git.txt").write_text("must not be silently lost")
            protected.chmod(0)
            try:
                with self.assertRaises(PermissionError):
                    worktree_files(root, root / ".git")
            finally:
                protected.chmod(0o700)

    def test_linked_worktree_git_file_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").write_text("gitdir: /private/git-metadata\n")
            (root / "source.go").write_text("package fixture\n")
            self.assertEqual(worktree_files(root, Path("/private/git-metadata")), [root / "source.go"])

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlink modes")
    def test_capture_rejects_regular_file_changed_to_matching_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "file.txt"
            source.write_bytes(b"public identical bytes\n")
            outside = Path(directory) / "outside.txt"
            outside.write_bytes(source.read_bytes())
            replacement = Path(directory) / "replacement-link"
            replacement.symlink_to(outside)
            source.chmod(replacement.lstat().st_mode & 0o7777)  # Mode/hash cannot detect the type change.
            subprocess.run(["git", "add", "file.txt"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            "commit", "-qm", "fixture"], cwd=root, check=True)
            capture = runpy.run_path(str(Path(__file__).with_name("review_snapshot.py")))["capture"]
            capture.__globals__["ROOT"] = root
            original_addfile = tarfile.TarFile.addfile

            def replace_after_archive(archive, member, fileobj=None):
                original_addfile(archive, member, fileobj)
                if member.name == "file.txt" and member.isfile():
                    source.unlink()
                    replacement.replace(source)

            old_umask = os.umask(0o077)
            try:
                with mock.patch.object(tarfile.TarFile, "addfile", replace_after_archive):
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, "file type changed during capture"):
                            capture()
                self.assertEqual(list((root / ".git/refactor-review").glob("*/manifest.json")), [])
            finally:
                os.umask(old_umask)

    def test_legacy_manifest_with_file_type_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                verify(root)

    def test_archive_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.fixture(root)
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
                verify(root)

    def test_permission_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, recorded_mode=0o600)
            with self.assertRaisesRegex(ValueError, "file mode mismatch"):
                verify(root)

    def test_duplicate_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, names=("file.txt", "file.txt"))
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate archive path"):
                verify(root)

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, names=("../outside.txt",))
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate archive path"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
