"""Exercise the real verification script against a disposable Git worktree."""

import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
copy_worktree = runpy.run_path(str(ROOT / "scripts/verify-deferred.py"))["copy_worktree"]


class VerificationWorktreeTests(unittest.TestCase):
    def overlay_fixture(self, root):
        source, target = root / "source", root / "target"
        source.mkdir()
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        isolated_copy = runpy.run_path(str(ROOT / "scripts/verify-deferred.py"))["copy_worktree"]
        isolated_copy.__globals__["ROOT"] = source
        return source, target, isolated_copy

    def test_overlay_removes_tracked_worktree_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target, overlay = self.overlay_fixture(Path(directory))
            (source / "deleted.go").write_text("package fixture\n")
            subprocess.run(["git", "add", "deleted.go"], cwd=source, check=True)
            (source / "deleted.go").unlink()
            (target / "deleted.go").write_text("stale baseline file must not survive\n")
            overlay(target)
            self.assertFalse((target / "deleted.go").exists(), "overlay silently restored a deleted source file")

    @unittest.skipUnless(os.name == "posix", "requires filesystem symlinks")
    def test_overlay_replaces_existing_file_with_broken_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target, overlay = self.overlay_fixture(Path(directory))
            (source / "reference.go").symlink_to("missing-target")
            subprocess.run(["git", "add", "reference.go"], cwd=source, check=True)
            (target / "reference.go").write_text("stale baseline file\n")
            overlay(target)
            self.assertTrue((target / "reference.go").is_symlink())
            self.assertEqual(os.readlink(target / "reference.go"), "missing-target")

    @unittest.skipUnless(os.name == "posix", "requires filesystem symlinks")
    def test_overlay_does_not_write_through_destination_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, overlay = self.overlay_fixture(root)
            (source / "regular.go").write_text("current candidate\n")
            subprocess.run(["git", "add", "regular.go"], cwd=source, check=True)
            outside = root / "outside"
            outside.write_text("must remain unchanged\n")
            (target / "regular.go").symlink_to(outside)
            overlay(target)
            self.assertEqual(outside.read_text(), "must remain unchanged\n")
            self.assertFalse((target / "regular.go").is_symlink())
            self.assertEqual((target / "regular.go").read_text(), "current candidate\n")

    @unittest.skipUnless(os.name == "posix", "requires filesystem symlinks")
    def test_overlay_rejects_destination_parent_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, overlay = self.overlay_fixture(root)
            (source / "nested").mkdir()
            (source / "nested/current.go").write_text("current candidate\n")
            subprocess.run(["git", "add", "nested/current.go"], cwd=source, check=True)
            outside = root / "outside"
            outside.mkdir()
            (target / "nested").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "parent symlink"):
                overlay(target)
            self.assertEqual(list(outside.iterdir()), [])

    def test_overlay_rejects_source_as_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _, overlay = self.overlay_fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, "outside the source worktree"):
                overlay(source)

    def test_tracked_deletion_is_not_sent_to_gofmt(self):
        with tempfile.TemporaryDirectory(prefix="yubihsm-verify-test-") as directory:
            tree = Path(directory) / "repo"
            subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(tree)], check=True, timeout=30)
            copy_worktree(tree)
            fixture = tree / "commands/deleted_format_fixture.go"
            fixture.write_text("package commands\n")
            subprocess.run(["git", "add", "commands/deleted_format_fixture.go"], cwd=tree, check=True)
            fixture.unlink()
            env = dict(os.environ, VERIFY_RACE="0", VERIFY_STRESS="0", VERIFY_FUZZ="0", VERIFY_EXTENDED="0")
            result = subprocess.run(["bash", "scripts/verify.sh"], cwd=tree, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("AD commands/deleted_format_fixture.go", result.stdout)
            self.assertIn("PASS: selected automated checks only", result.stdout)
            self.assertIn("NOT RUN: physical YubiHSM integration", result.stdout)


if __name__ == "__main__":
    unittest.main()
