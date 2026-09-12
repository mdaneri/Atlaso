"""Exercise depot publication permissions on a real POSIX filesystem."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from atlaso.app.services.vcf_depot_permissions import (
    prepare_downloaded_depot_permissions,
)


@unittest.skipUnless(os.name == "posix", "POSIX appliance permission semantics")
class DepotPermissionsTests(unittest.TestCase):
    """Keep public artifacts readable while rejecting filesystem indirection."""

    def setUp(self):
        """Create an isolated store in the test runner's configured temporary root."""
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("ATLASO_PERMISSION_TEST_ROOT"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = self.root / "depot"
        self.prod = self.store / "PROD"
        self.prod.mkdir(parents=True)

    def test_restrictive_creation_and_existing_artifacts(self):
        """Repair companions created under 0027 without changing private files."""
        secret = self.store / "private.txt"
        secret.write_text("synthetic private state")
        secret.chmod(0o600)
        previous = os.umask(0o027)
        try:
            component = self.prod / "COMP" / "VSP"
            component.mkdir(parents=True)
            for name in ("schema.yaml", "platform.tar", "existing.ova"):
                (component / name).write_text("public artifact")
        finally:
            os.umask(previous)
        (component / "existing.ova").chmod(0o644)
        self.assertEqual(stat.S_IMODE((component / "platform.tar").stat().st_mode), 0o640)
        self.assertGreater(prepare_downloaded_depot_permissions(str(self.store)), 0)
        for path in (self.prod, self.prod / "COMP", component):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o555, 0o555)
        for path in component.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        self.assertEqual(prepare_downloaded_depot_permissions(str(self.store)), 0)

    def test_rejects_links_without_changing_external_file(self):
        """Do not repair symlinks or shared inodes that can affect private data."""
        external = self.root / "private.txt"
        external.write_text("synthetic private state")
        external.chmod(0o600)
        link = self.prod / "artifact"
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    link.symlink_to(external)
                else:
                    os.link(external, link)
                try:
                    with self.assertRaises(OSError):
                        prepare_downloaded_depot_permissions(str(self.store))
                    self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o600)
                finally:
                    link.unlink()

    @unittest.skipUnless(getattr(os, "geteuid", lambda: -1)() == 0, "Requires isolated cross-account read check")
    def test_unrelated_reader_gains_access_only_to_public_artifact(self):
        """An nginx-like unrelated UID can read repaired content, not private state."""
        self.root.chmod(0o755)
        self.store.chmod(0o755)
        self.prod.chmod(0o755)
        artifact = self.prod / "platform.tar"
        private = self.store / "private.txt"
        for path in (artifact, private):
            path.write_text("synthetic content")
            path.chmod(0o640)

        def can_read(path):
            """Read with no owner or group relationship to the downloaded file.

            Args:
                path: Candidate public or private file.
            """
            return subprocess.run(
                ["/bin/cat", "--", str(path)],
                user=65534, group=65534, extra_groups=[], capture_output=True, check=False,
            ).returncode == 0

        self.assertFalse(can_read(artifact))
        prepare_downloaded_depot_permissions(str(self.store))
        self.assertTrue(can_read(artifact))
        self.assertFalse(can_read(private))

    def test_rejects_directory_links(self):
        """Do not traverse a linked component or linked PROD root."""
        external = self.root / "private"
        external.mkdir(mode=0o700)
        link = self.prod / "component"
        link.symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError):
            prepare_downloaded_depot_permissions(str(self.store))
        link.unlink()
        self.prod.rmdir()
        self.prod.symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError):
            prepare_downloaded_depot_permissions(str(self.store))
        self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)

    def test_rejects_special_file_without_blocking(self):
        """Do not open FIFOs during permission reconciliation."""
        os.mkfifo(self.prod / "pipe")
        with self.assertRaises(OSError):
            prepare_downloaded_depot_permissions(str(self.store))

    def test_absent_prod_and_relative_store(self):
        """Allow absent published content but reject ambiguous store paths."""
        self.prod.rmdir()
        self.assertEqual(prepare_downloaded_depot_permissions(str(self.store)), 0)
        with self.assertRaises(ValueError):
            prepare_downloaded_depot_permissions("relative")
