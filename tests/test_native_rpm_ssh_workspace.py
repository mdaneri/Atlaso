"""Native Linux no-follow inventory and original-root cleanup checks.

Uses unittest so the same tests can run on a minimal Photon tool VM without
installing Python test dependencies there.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import native_rpm_ssh_workspace as workspace


@unittest.skipUnless(os.name == "posix", "Linux descriptor and ownership semantics")
class WorkspaceTests(unittest.TestCase):
    """Exercise actual native directories, links, identities and deletion boundaries."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="atlaso-ssh-fixture-")
        self.parent = Path(self.temporary.name)
        self.boot = self.parent / "boot-id"
        self.boot.write_text("original-boot")
        self.patches = [patch.object(workspace, "PARENT", self.parent), patch.object(workspace, "BOOT_ID", self.boot)]
        for item in self.patches:
            item.start()
        self.request = {"scope": "a" * 32 + "-admit", "task_id": "fixture-task", "source_commit": "b" * 40}
        self.original = workspace.execute({**self.request, "operation": "create"})
        self.root = Path(self.original["path"])

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def call(self, operation, **fields):
        """Invoke the workspace owner with its original independent selectors.

        Args:
            operation: Fixed native workspace operation under test.
            **fields: Exact relative selectors for that operation.
        """
        if operation == "remove" and "expected_catalog" not in fields:
            fields["expected_catalog"] = self.call("catalog")["sha256"]
        return workspace.execute({**self.request, "operation": operation, "original": self.original, **fields})

    def test_original_is_persisted_before_first_input_and_collision_refuses(self):
        self.assertTrue((self.root / "ownership.json").is_file())
        with self.assertRaises(FileExistsError):
            workspace.execute({**self.request, "operation": "create"})

    def test_changed_boot_refuses_even_when_path_and_inode_match(self):
        self.boot.write_text("different-boot")
        with self.assertRaisesRegex(ValueError, "original_identity_changed"):
            self.call("remove")
        self.assertTrue(self.root.exists())

    def test_same_path_root_replacement_is_preserved(self):
        retained = self.parent / "retained-original"
        self.root.rename(retained)
        self.root.mkdir(mode=0o700)
        sentinel = self.root / "unrelated"
        sentinel.write_text("preserve")
        with self.assertRaisesRegex(ValueError, "original_identity_changed"):
            self.call("remove")
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertTrue((retained / "ownership.json").exists())

    def test_unknown_symlink_refuses_export_and_cleanup_without_reading_target(self):
        private = self.parent / "private-sentinel"
        private.write_text("never-read-or-delete")
        (self.root / "link").symlink_to(private)
        with self.assertRaisesRegex(ValueError, "path_changed"):
            self.call("files", paths=["link"])
        with self.assertRaisesRegex(ValueError, "link_or_special"):
            self.call("remove")
        self.assertEqual(private.read_text(), "never-read-or-delete")
        self.assertTrue((self.root / "ownership.json").exists())

    def test_hardlink_and_special_file_refuse_inventory(self):
        private = self.parent / "private"
        private.write_bytes(b"private")
        os.link(private, self.root / "hardlink")
        with self.assertRaisesRegex(ValueError, "link_or_special"):
            workspace.inventory(self.root)
        (self.root / "hardlink").unlink()
        os.mkfifo(self.root / "fifo")
        with self.assertRaisesRegex(ValueError, "link_or_special"):
            workspace.inventory(self.root)

    def test_parent_escape_and_absolute_input_are_rejected(self):
        for path in ("../private", "/etc/passwd", "files/../../private", "files\\private"):
            with self.assertRaises(ValueError):
                self.call("files", paths=[path])

    def test_foreign_task_or_source_cannot_adopt_original_workspace(self):
        for field, value in (("task_id", "another-task"), ("source_commit", "c" * 40)):
            with self.assertRaisesRegex(ValueError, "original_identity_changed"):
                workspace.execute({**self.request, field: value, "operation": "remove", "original": self.original})
        self.assertTrue(self.root.exists())

    def test_new_ordinary_entry_after_final_native_result_blocks_cleanup(self):
        expected = self.call("catalog")["sha256"]
        (self.root / "unexpected").write_text("preserve")
        with self.assertRaisesRegex(ValueError, "inventory_changed_before_release"):
            self.call("remove", expected_catalog=expected)
        self.assertTrue((self.root / "ownership.json").exists())

    def test_bound_inventory_and_cleanup_preserve_neighbor(self):
        neighbor = self.parent / "neighbor"
        neighbor.mkdir()
        (neighbor / "keep").write_text("preserve")
        directory = self.root / "metadata"
        directory.mkdir()
        (directory / "repomd.xml").write_bytes(b"public metadata")
        rows = self.call("files", paths=["metadata"])["metadata"]
        self.assertEqual(rows[0]["size"], len(b"public metadata"))
        self.assertTrue(self.call("remove")["remote_root_absent"])
        self.assertFalse(self.root.exists())
        self.assertEqual((neighbor / "keep").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
