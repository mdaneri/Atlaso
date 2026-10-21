"""Native POSIX interoperation of the wheel and Appliance Update deployment locks."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import select
import shlex
import stat
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
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
        self.lock_shell = (
            "set -eu\nstat() { if [ \"$2\" = '%u:%g:%a:%h' ]; then "
            "printf '0:0:600:1\\n'; else command stat \"$@\"; fi; }\n"
            + lock
        )
        self.shell = self.lock_shell + "\nprintf 'acquired\\n'\nread -r release\n"

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
                        output = io.StringIO()
                        with redirect_stdout(output):
                            self.assertEqual(self.helper._handle_appliance_update(action, []), 73)
                        self.assertEqual(json.loads(output.getvalue()), {"status": "deployment-busy", "mutation_started": False})
                    mutate.assert_not_called()
                # Derive every updater pre-start action from the canonical units,
                # including the bootstrap hooks installed by wheel deployment.
                actions = set()
                for unit in (ROOT / "image/common/systemd").iterdir():
                    if not unit.is_file():
                        continue
                    for line in unit.read_text(encoding="utf-8").splitlines():
                        prefix = "ExecStartPre=+/opt/atlaso/bin/atlaso-helper appliance-update "
                        if line.startswith(prefix):
                            actions.add(line.removeprefix(prefix).split()[0])
                self.assertIn("bootstrap-data-disk-safety", actions)
                self.assertIn("bootstrap-port-forwarding", actions)
                self.assertIn("recover-release", actions)
                self.assertIn("guard-release", actions)
                evidence = (
                    self.helper.ATLASO_UPDATE_FINALIZER_PATH,
                    self.helper.ATLASO_UPDATE_STATUS_PATH,
                    self.helper.ATLASO_UPDATE_MAINTENANCE_PATH,
                    self.helper.ATLASO_UPDATE_STATUS_MARKER_PATH,
                    self.helper.ATLASO_UPDATE_RESTART_GATE_PATH,
                )
                for action in sorted(actions):
                    with patch.object(self.helper, "_handle_appliance_update_locked", return_value=0) as startup:
                        self.assertEqual(self.helper._handle_appliance_update(action, []), 0)
                        startup.assert_called_once_with(action, [])
                    # Every durable and volatile evidence source removes the
                    # exemption before any startup handler can mutate the host.
                    for retained in evidence:
                        retained.write_text("retained", encoding="utf-8")
                        with patch.object(self.helper, "_handle_appliance_update_locked") as startup:
                            with redirect_stdout(io.StringIO()):
                                self.assertEqual(self.helper._handle_appliance_update(action, []), 73)
                            startup.assert_not_called()
                        retained.unlink()
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

    def test_outer_systemd_dispatch_refuses_before_preflight(self):
        """Wheel contention cannot prepare directories, stop units, or spawn a child."""
        with subprocess.Popen(
            ["sh", "-c", self.shell], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as deploy:
            try:
                self.assertTrue(select.select([deploy.stdout], [], [], 10)[0])
                self.assertEqual(deploy.stdout.readline().strip(), "acquired")
                with ExitStack() as patches:
                    patches.enter_context(patch.dict(os.environ, {"ATLASO_HELPER_USE_SYSTEMD_RUN": "1"}))
                    patches.enter_context(patch.object(self.helper.shutil, "which", return_value="/usr/bin/systemd-run"))
                    # Side effects stay behind the real outer lock, including
                    # bounded-check dispatch even without the opt-in flag.
                    preflight = patches.enter_context(patch.object(self.helper, "_privileged_powershell_environment"))
                    stop = patches.enter_context(patch.object(self.helper, "_quiesce_appliance_update_status_unit"))
                    child = patches.enter_context(patch.object(self.helper, "_run"))
                    for action in ("check", "apply", "sync-sources", "status-publish", "status-finish"):
                        with self.subTest(action=action):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                result = self.helper.main([
                                    "atlaso-helper", "appliance-update", action, "--real",
                                    "job_012345abcdef" if action.startswith("status-") else str(self.root / "config.json"),
                                ])
                            self.assertEqual(result, 73)
                            self.assertEqual(json.loads(output.getvalue().splitlines()[-1]), {
                                "status": "deployment-busy", "mutation_started": False,
                            })
                    preflight.assert_not_called()
                    stop.assert_not_called()
                    child.assert_not_called()
            finally:
                deploy.communicate("release\n", timeout=10)
            self.assertEqual(deploy.returncode, 0)

    def test_outer_systemd_lock_covers_preflight_child_and_cleanup(self):
        """Real parent admission excludes wheel deployment until dispatch unwinds."""
        events = []

        def excluded(stage):
            """Assert an independent deployer remains excluded at this stage.

            Args:
                stage: Side effect observed within the admitted systemd wrapper.
            """
            result = subprocess.run(
                ["sh", "-c", self.shell], input="release\n", text=True,
                capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            events.append(stage)

        def environment():
            """Model environment mutation only after outer admission."""
            excluded("environment")
            return dict.fromkeys(("HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"), "/unused")

        def child(command, **kwargs):
            """Model synchronous child execution and nested shared admission.

            Args:
                command: Transient helper command.
                **kwargs: Bounded transport options.
            """
            with self.helper._appliance_update_deployment_guard("check"):
                excluded("child")
            return subprocess.CompletedProcess(command, 0, "", "")

        with ExitStack() as patches:
            patches.enter_context(patch.object(self.helper, "_privileged_powershell_environment", environment))
            patches.enter_context(patch.object(self.helper, "_run", child))
            patches.enter_context(patch.object(self.helper, "_quiesce_appliance_update_status_unit", lambda _job: excluded("stop")))
            patches.enter_context(patch.object(self.helper, "_quiesce_appliance_update_unit", lambda *_args, **_kwargs: excluded("quiesce")))
            patches.enter_context(patch.object(self.helper, "_cleanup_stale_photon_repository_views", lambda **_kwargs: excluded("cleanup")))
            for action in ("check", "status-publish", "status-finish"):
                events.clear()
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(self.helper._run_real_action_with_systemd(
                        "appliance-update", action,
                        ["job_012345abcdef" if action.startswith("status-") else str(self.root / "config.json")],
                    ), 0)
                self.assertEqual(events, ["environment", "child", "quiesce", "cleanup"] if action == "check" else ["stop", "environment", "child"])
            # An exception after admission releases the parent lock as well.
            patches.enter_context(patch.object(self.helper, "_run", side_effect=OSError("fixture failure")))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(self.helper._run_real_action_with_systemd("appliance-update", "apply", []), 75)
        result = subprocess.run(
            ["sh", "-c", self.shell], input="release\n", text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_io_failure_after_admission_is_not_a_retryable_conflict(self):
        """A handler I/O failure cannot claim that no update work was admitted."""
        output = io.StringIO()
        with patch.object(self.helper, "_handle_appliance_update_locked", side_effect=BlockingIOError):
            with redirect_stdout(output):
                self.assertEqual(self.helper._handle_appliance_update("apply", []), 75)
        self.assertNotIn("deployment-busy", output.getvalue())

    def test_normal_and_failure_handoffs_release_before_worker_start(self):
        """Run shipped handoff/trap code with an independent worker lock attempt."""
        source = (ROOT / "scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
        body = source.split("$deployScript = @'\n", 1)[1].split("\n'@", 1)[0]
        readiness = body.split("# Verify web readiness before reopening update admission to the worker.\n", 1)[1]
        recovery = "restore_services_on_exit() {" + body.split("restore_services_on_exit() {", 1)[1].split(
            "\ntrap restore_services_on_exit EXIT", 1
        )[0]
        lock = shlex.quote(str(self.helper.ATLASO_DEPLOYMENT_LOCK_PATH))
        worker = (
            'systemctl() { if [ "$*" = "restart atlaso-worker.service" ]; then '
            f"flock --shared --nonblock {lock} -c 'echo worker-admitted'; else return 0; fi; }}\n"
            "curl() { return 0; }\ntimeout_seconds=1\npoll_seconds=1\n"
        )
        for name, code, expected in (
            ("normal", readiness, 0),
            ("failure", recovery + "\natlaso_was_active=true\nworker_was_active=true\n"
             "app_history_cutover_in_progress=false\nset +e\nfalse\nrestore_services_on_exit\n", 1),
        ):
            with self.subTest(handoff=name):
                result = subprocess.run(
                    ["sh", "-c", self.lock_shell + worker + code], input="", text=True,
                    capture_output=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn("worker-admitted", result.stdout)


if __name__ == "__main__":
    unittest.main()
