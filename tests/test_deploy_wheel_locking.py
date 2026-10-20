"""Native POSIX interoperation of the wheel and Appliance Update deployment locks."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import select
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "Requires native POSIX flock, shell, and /proc")
class DeploymentLockTests(unittest.TestCase):
    """Use real lock descriptors and a separate deployment shell process."""

    def setUp(self):
        """Create isolated lock state beneath the caller-selected test output root."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        loader = importlib.machinery.SourceFileLoader(
            "deployment_lock_helper", str(ROOT / "scripts/appliance/atlaso-helper")
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.helper = importlib.util.module_from_spec(spec)
        loader.exec_module(self.helper)
        self.helper.ATLASO_DEPLOYMENT_LOCK_PATH = self.root / "mutation.lock"
        for name in (
            "ATLASO_UPDATE_FINALIZER_PATH", "ATLASO_UPDATE_STATUS_PATH",
            "ATLASO_UPDATE_MAINTENANCE_PATH", "ATLASO_UPDATE_STATUS_MARKER_PATH",
            "ATLASO_UPDATE_RESTART_GATE_PATH",
        ):
            setattr(self.helper, name, self.root / name)
        original_fstat = os.fstat

        def fixture_owner(descriptor):
            """Model root mode/ownership while retaining native type and link count.

            Args:
                descriptor: Real fixture lock descriptor.
            """
            metadata = original_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFMT(metadata.st_mode) | 0o600, st_nlink=metadata.st_nlink,
                st_uid=0, st_gid=0,
            )

        self.owner = patch.object(self.helper.os, "fstat", fixture_owner)
        self.owner.start()
        self.addCleanup(self.owner.stop)
        stub = self.root / "installed-helper.sh"
        stub.write_text("exit 0\n", encoding="utf-8")
        source = (ROOT / "scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
        lock = source.split(
            "# Lock-capable installed helpers share this inode for the whole update action.\n", 1
        )[1].split("# Refuse before RPM", 1)[0]
        lock = lock.replace("/opt/atlaso/bin/atlaso-helper", "sh " + shlex.quote(str(stub)))
        lock = lock.replace("/run/atlaso-appliance-mutation.lock", str(self.helper.ATLASO_DEPLOYMENT_LOCK_PATH))
        # CI runs without root and WSL's Windows mount need not preserve chmod.
        # Root ownership/mode are modeled; type/link checks, inode comparisons
        # and flock use the real filesystem and independent shell process.
        self.shell = (
            "set -eu\nstat() { if [ \"$2\" = '%u:%g:%a:%h' ]; then "
            "printf '0:0:600:1\\n'; else command stat \"$@\"; fi; }\n"
            + lock + "\nprintf 'acquired\\n'\nread -r release\n"
        )

    def test_update_blocks_wheel_and_releases_on_failure(self):
        """Refuse wheel mutation until every nested update owner has exited."""
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            with self.helper._appliance_update_deployment_guard("apply"):
                with self.helper._appliance_update_deployment_guard("status-publish"):
                    result = subprocess.run(
                        ["sh", "-c", self.shell], input="release\n", text=True,
                        capture_output=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn("acquired", result.stdout)
                raise RuntimeError("fixture failure")
        result = subprocess.run(
            ["sh", "-c", self.shell], input="release\n", text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "acquired")

    def test_wheel_blocks_update_before_handler_and_allows_ordinary_startup(self):
        """Hold the real deployment shell open across independent helper attempts."""
        with subprocess.Popen(
            ["sh", "-c", self.shell], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as deploy:
            try:
                self.assertTrue(select.select([deploy.stdout], [], [], 10)[0])
                self.assertEqual(deploy.stdout.readline().strip(), "acquired")
                with patch.object(self.helper, "_handle_appliance_update_locked") as mutate:
                    for action in ("apply", "sync-sources", "status-publish", "status-finish", "restart-service"):
                        self.assertEqual(self.helper._handle_appliance_update(action, []), 75)
                    mutate.assert_not_called()
                # Deployment's own service restarts must not deadlock with
                # no-op startup guards. Recovery evidence removes this exemption.
                for action in ("guard-release", "recover-release"):
                    with self.helper._appliance_update_deployment_guard(action):
                        pass
                    self.helper.ATLASO_UPDATE_FINALIZER_PATH.write_text("retained", encoding="utf-8")
                    with self.assertRaises(BlockingIOError):
                        with self.helper._appliance_update_deployment_guard(action):
                            self.fail("recovery entered while deployment owned the lock")
                    self.helper.ATLASO_UPDATE_FINALIZER_PATH.unlink()
            finally:
                deploy.communicate("release\n", timeout=10)
            self.assertEqual(deploy.returncode, 0)

    def test_legacy_helper_fails_closed(self):
        """An installed helper without the lock protocol cannot admit deployment."""
        (self.root / "installed-helper.sh").write_text("exit 2\n", encoding="utf-8")
        result = subprocess.run(
            ["sh", "-c", self.shell], input="release\n", text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("lacks deployment locking", result.stderr)
        self.assertFalse(self.helper.ATLASO_DEPLOYMENT_LOCK_PATH.exists())

    def test_helper_capability_is_rechecked_under_lock(self):
        """Refuse when an updater replaced the helper before exclusive acquisition."""
        counter = self.root / "capability-checked"
        (self.root / "installed-helper.sh").write_text(
            f"if [ -e {shlex.quote(str(counter))} ]; then exit 2; fi\n"
            f"touch {shlex.quote(str(counter))}\n", encoding="utf-8",
        )
        result = subprocess.run(
            ["sh", "-c", self.shell], input="release\n", text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no longer supports deployment locking", result.stderr)
        self.assertNotIn("acquired", result.stdout)
        with self.helper._appliance_update_deployment_guard("apply"):
            pass

    def test_unsafe_lock_objects_are_preserved(self):
        """Never follow a symlink or adopt a multiply linked mutation lock."""
        target = self.root / "retained"
        target.write_text("unchanged", encoding="utf-8")
        lock = self.helper.ATLASO_DEPLOYMENT_LOCK_PATH
        lock.symlink_to(target)
        with self.assertRaises(OSError):
            with self.helper._appliance_update_deployment_guard("apply"):
                self.fail("unsafe lock admitted")
        result = subprocess.run(
            ["sh", "-c", self.shell], input="release\n", text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("deployment lock is unsafe", result.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")
        lock.unlink()
        os.link(target, lock)
        with self.assertRaises(ValueError):
            with self.helper._appliance_update_deployment_guard("apply"):
                self.fail("multiply linked lock admitted")
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
