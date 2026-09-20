"""Exercise producer quiescence, complete legacy preservation and cutover recovery."""

import ast
import gzip
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from atlaso.app.services import app_history_cutover as cutover
from atlaso.app.services import producer_log_history as history


class Controller:
    """Model deployment ownership while using real files and SQLite transactions."""

    def __init__(self):
        """Begin with both producers running and no selected immutable store."""
        self.running = cutover.UNITS
        self.selected = None
        self.actions = []
        self.fail_resume = False

    def active_units(self):
        """Return the currently active producer set."""
        return self.running

    def stop(self):
        """Record a complete two-producer shutdown."""
        self.actions.append("stop")
        self.running = ()

    def assert_stopped(self):
        """Reject migration while either producer is still running."""
        assert not self.running

    def configured_store(self):
        """Return the atomically selected runtime store."""
        return self.selected

    def publish(self, path):
        """Select only an activated database while both producers are stopped.

        Args:
            path: New immutable producer store.
        """
        self.assert_stopped()
        assert history.source_active(path, "app")
        self.actions.append("publish")
        self.selected = path

    def resume(self, units):
        """Model startup failure after one producer has already emitted a record.

        Args:
            units: Previously active unit set.
        """
        self.actions.append("resume")
        self.running = units
        if self.fail_resume:
            history.append(self.selected, "app", ["new acknowledged runtime record"], writer="web", revision=1)
            raise ValueError("injected startup failure")


@pytest.fixture
def roots(tmp_path):
    """Create isolated owning directories beneath the registered test root.

    Args:
        tmp_path: Pytest fixture rooted beneath the task's disposable inventory.
    """
    logs, runtime, preserved = (tmp_path / name for name in ("logs", "runtime", "preserved"))
    for path in (logs, runtime, preserved):
        path.mkdir()
    return logs / "atlaso.log", runtime, preserved


def test_cutover_preserves_all_rotations_and_publishes_before_resume(roots):
    """Preserve compressed and plain bytes in exact oldest-first order.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    legacy, runtime, preserved = roots
    older = legacy.with_suffix(".log.2.gz")
    older.write_bytes(gzip.compress(b"oldest\n-----BEGIN PRIVATE KEY-----\n"))
    legacy.with_suffix(".log.1").write_bytes(b"synthetic key body\n-----END PRIVATE KEY-----\n")
    legacy.write_bytes(b"latest\n")
    original = {path.name: path.read_bytes() for path in legacy.parent.iterdir()}
    controller = Controller()
    result = cutover.run_cutover(*roots, controller)
    assert controller.actions == ["stop", "publish", "resume"]
    assert controller.running == cutover.UNITS
    assert controller.selected == result.store
    page = history.read_page(result.store, "app")
    assert page.lines[0] == "oldest" and page.lines[-1] == "latest"
    assert "synthetic key body" not in "\n".join(page.lines)
    manifest = json.loads((result.preservation / "inventory.json").read_text())
    assert [item["name"] for item in manifest] == ["atlaso.log.2.gz", "atlaso.log.1", "atlaso.log"]
    for entry in manifest:
        assert (result.preservation / entry["name"]).read_bytes() == original[entry["name"]]
        assert entry["sha256"] == hashlib.sha256(original[entry["name"]]).hexdigest()
        assert (legacy.parent / entry["name"]).read_bytes() == original[entry["name"]]


@pytest.mark.parametrize("names", [
    ["atlaso.log", "atlaso.log.2"],
    ["atlaso.log.1"],
    ["atlaso.log", "atlaso.log.1", "atlaso.log.1.gz"],
    ["atlaso.log", "atlaso.log.2026-09-19"],
    ["atlaso.log", "atlaso.log.01"],
])
def test_unknown_or_incomplete_rotations_restore_legacy_without_publication(roots, names):
    """Never silently discard an ambiguous retained legacy file.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
        names: Unsupported or incomplete rotation filenames.
    """
    legacy, runtime, preserved = roots
    for name in names:
        (legacy.parent / name).write_bytes(b"retained\n")
    controller = Controller()
    with pytest.raises(ValueError):
        cutover.run_cutover(*roots, controller)
    assert controller.selected is None
    assert controller.running == cutover.UNITS
    assert "publish" not in controller.actions
    assert len(list(legacy.parent.iterdir())) == len(names)


def test_empty_first_boot_import_is_activated(roots):
    """An explicit empty inventory is valid first-boot evidence.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    controller = Controller()
    controller.running = ()
    result = cutover.run_cutover(*roots, controller, already_stopped=True)
    assert result.through == 0
    assert history.source_active(result.store, "app")
    assert controller.actions == ["publish"]


def test_import_failure_retains_original_and_attempt_evidence(roots, monkeypatch):
    """Digest failure refuses cutover without erasing original or preserved bytes.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
        monkeypatch: Fixture injecting a mismatched inventory digest.
    """
    legacy, runtime, preserved = roots
    raw = b"x" * 65537 + b"\n"
    legacy.write_bytes(raw)
    controller = Controller()
    importer = history.import_legacy
    monkeypatch.setattr(history, "import_legacy", lambda path, source, snapshots: importer(
        path, source, [(snapshot, "0" * 64) for snapshot, digest in snapshots]
    ))
    with pytest.raises(ValueError, match="digest"):
        cutover.run_cutover(*roots, controller)
    first_attempt = next(preserved.iterdir())
    assert (first_attempt / legacy.name).read_bytes() == raw
    assert legacy.read_bytes() == raw
    assert controller.selected is None and controller.running == cutover.UNITS
    legacy.write_bytes(b"new legacy record\n")
    monkeypatch.setattr(history, "import_legacy", importer)
    cutover.run_cutover(*roots, controller)
    assert len(list(preserved.iterdir())) == 2
    assert (first_attempt / legacy.name).read_bytes() == raw


def test_truncated_gzip_restores_legacy_producers(roots):
    """A decoder failure keeps evidence and restores the old runtime selection.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    legacy, runtime, preserved = roots
    legacy.write_bytes(b"latest\n")
    legacy.with_suffix(".log.1.gz").write_bytes(gzip.compress(b"older\n")[:-5])
    controller = Controller()
    with pytest.raises(EOFError):
        cutover.run_cutover(*roots, controller)
    assert controller.running == cutover.UNITS
    assert controller.selected is None
    assert len(list(preserved.iterdir())) == 1


def test_ambiguous_publication_never_resumes_old_producers(roots, monkeypatch):
    """A successful selection followed by failed durability stays stopped.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
        monkeypatch: Fixture injecting publication failure after selection.
    """
    controller = Controller()
    publish = controller.publish

    def ambiguous(path):
        """Model successful rename followed by failed directory flush.

        Args:
            path: Activated new store selected by the publication.
        """
        publish(path)
        raise OSError("injected directory durability failure")

    monkeypatch.setattr(controller, "publish", ambiguous)
    with pytest.raises(OSError, match="durability"):
        cutover.run_cutover(*roots, controller)
    assert controller.selected is not None
    assert not controller.running
    assert "resume" not in controller.actions


def test_unreadable_existing_selection_stays_stopped(roots, monkeypatch):
    """Ambiguous selection cannot be treated as an uncommitted first migration.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
        monkeypatch: Fixture injecting failure while reading the selection.
    """
    controller = Controller()

    def unreadable():
        """Model a malformed existing configuration without exposing its bytes."""
        raise ValueError("selection requires reconciliation")

    monkeypatch.setattr(controller, "configured_store", unreadable)
    with pytest.raises(ValueError, match="reconciliation"):
        cutover.run_cutover(*roots, controller)
    assert not controller.running
    assert "resume" not in controller.actions


def test_resume_failure_keeps_selected_new_records_and_stops_producers(roots):
    """Never roll back to a legacy mirror after an acknowledged producer record.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    legacy, runtime, preserved = roots
    legacy.write_bytes(b"legacy\n")
    controller = Controller()
    controller.fail_resume = True
    with pytest.raises(ValueError, match="startup failure"):
        cutover.run_cutover(*roots, controller)
    assert not controller.running
    assert history.read_page(controller.selected, "app").lines == ("legacy", "new acknowledged runtime record")
    controller.fail_resume = False
    first = controller.selected
    cutover.run_cutover(*roots, controller)
    assert controller.selected == first
    assert len(list(preserved.iterdir())) == 1


def test_if_needed_keeps_healthy_existing_producers_running(roots):
    """A later release validates the selected store without a second restart.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    controller = Controller()
    first = cutover.run_cutover(*roots, controller)
    controller.actions.clear()
    result = cutover.run_cutover(*roots, controller, if_needed=True)
    assert result.store == first.store
    assert controller.actions == []
    assert controller.running == cutover.UNITS


def test_if_needed_stops_interrupted_existing_capture(roots):
    """Idempotent release validation cannot skip an unprepared interrupted input.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    controller = Controller()
    first = cutover.run_cutover(*roots, controller)
    controller.actions.clear()
    with closing(sqlite3.connect(first.store)) as connection, connection:
        connection.execute("INSERT INTO capture_pending VALUES ('app','web',1,NULL)")
    with pytest.raises(ValueError, match="interrupted-record"):
        cutover.run_cutover(*roots, controller, if_needed=True)
    assert controller.actions == ["stop"]
    assert not controller.running


def test_changed_inventory_is_rejected_before_import(roots):
    """Detect an unexpected writer adding a rotation during preservation.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    legacy, runtime, preserved = roots
    legacy.write_bytes(b"legacy\n")
    calls = 0

    def stopped():
        """Inject drift between initial inventory and the second quiescence check."""
        nonlocal calls
        calls += 1
        if calls == 2:
            legacy.with_suffix(".log.1").write_bytes(b"unexpected\n")

    with pytest.raises(ValueError, match="inventory changed"):
        cutover.preserve(legacy, preserved, stopped)
    assert not (preserved / "inventory.json").exists()


def test_no_start_or_stop_in_successful_already_stopped_cutover(roots):
    """Keep ownership of service restart with the outer deployment transaction.

    Args:
        roots: Isolated legacy, runtime and preservation paths.
    """
    controller = Controller()
    with pytest.raises(AssertionError):
        cutover.run_cutover(*roots, controller, already_stopped=True)
    assert not controller.actions


@pytest.mark.parametrize("changes", [{"MainPID": "12"}, {"ControlPID": "15"},
                                    {"Job": "8"}, {"ActiveState": "activating"}])
def test_systemd_quiescence_requires_process_and_job_absence(tmp_path, monkeypatch, changes):
    """A merely inactive-looking main process is insufficient cutover proof.

    Args:
        tmp_path: Isolated configured environment path.
        monkeypatch: Fixture replacing process inspection.
        changes: Conflicting systemd state to reject.
    """
    controller = cutover.SystemdController(tmp_path / "app-history.env")
    state = {"ActiveState": "inactive", "MainPID": "0", "ControlPID": "0", "Job": ""} | changes
    monkeypatch.setattr(controller, "_state", lambda unit: state)
    with pytest.raises(ValueError, match="fully stopped"):
        controller.assert_stopped()


def test_environment_publication_is_no_replacement_and_single_selection(tmp_path):
    """Never overwrite a competing configuration; both units consume one selection.

    Args:
        tmp_path: Isolated dedicated environment parent.
    """
    target = tmp_path / "app-history.env"
    controller = cutover.SystemdController(target)
    first = Path("/var/lib/atlaso/log-history/app/first/app.sqlite")
    controller.publish(first)
    assert controller.configured_store() == first
    with pytest.raises(ValueError, match="changed before publication"):
        controller.publish(Path("/var/lib/atlaso/log-history/app/second/app.sqlite"))
    assert controller.configured_store() == first


def test_missing_shared_environment_hook_refuses_before_stopping(tmp_path, monkeypatch):
    """Prevent successful publication when a producer would ignore the selection.

    Args:
        tmp_path: Isolated environment pathname.
        monkeypatch: Fixture replacing systemd inspection.
    """
    controller = cutover.SystemdController(tmp_path / "app-history.env")
    calls = []

    def run(*arguments):
        """Model an installed unit missing its history EnvironmentFile.

        Args:
            *arguments: Controller-owned systemctl operation.
        """
        calls.append(arguments)
        return "/etc/atlaso/atlaso.env (ignore_errors=no)"

    monkeypatch.setattr(controller, "_run", run)
    with pytest.raises(ValueError, match="must load"):
        controller.active_units()
    assert all(arguments[0] == "show" for arguments in calls)


def test_service_and_generated_override_keep_direct_process_identity():
    """Every supported producer launch consumes the selection without a wrapper."""
    for name, command in (("atlaso.service", "-m uvicorn atlaso.app.main:app"),
                          ("atlaso-worker.service", "-m atlaso.app.worker")):
        unit = Path("image/common/systemd", name).read_text(encoding="utf-8")
        assert unit.index("EnvironmentFile=/etc/atlaso/atlaso.env") < unit.index(
            "EnvironmentFile=-/etc/atlaso/app-history.env")
        starts = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        assert len(starts) == 1 and command in starts[0]
        assert "cutover" not in starts[0]
    source = Path("scripts/appliance/atlaso-helper").read_text(encoding="utf-8")
    parsed = ast.parse(source)
    function = next(node for node in parsed.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_atlaso_service_loopback_dropin")
    namespace = {"ATLASO_UVICORN_COMMAND": (
        "/opt/atlaso/.venv/bin/python -m uvicorn atlaso.app.main:app --host {host} --port {port}")}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "atlaso-helper", "exec"), namespace)
    generated = namespace["_atlaso_service_loopback_dropin"]("127.0.0.1", 8000)
    assert "EnvironmentFile=-/etc/atlaso/app-history.env\n" in generated
    assert "ExecStart=/opt/atlaso/.venv/bin/python -m uvicorn" in generated


def test_provision_imports_before_any_producer_enable():
    """Image provisioning performs migration in an independent stopped transaction."""
    source = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    stopped = source.index("systemctl stop atlaso-worker.service atlaso.service")
    started = source.index("systemd-run --quiet --wait --collect --unit=atlaso-app-history-cutover")
    invocation = source.index("-I -m atlaso.app.services.app_history_cutover")
    enabled = source.index("systemctl enable atlaso\n")
    assert stopped < started < invocation < enabled
    assert "--property=EnvironmentFile=/etc/atlaso/atlaso.env" in source[started:enabled]
    assert "--already-stopped --prepare-roots" in source[started:enabled]


def test_wheel_deploy_imports_between_shutdown_and_restart_with_failure_guard():
    """Deployment preserves stopped state if migration publication is uncertain."""
    source = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    stopped = source.index("systemctl stop atlaso-worker.service atlaso.service")
    guarded = source.index("app_history_cutover_in_progress=true")
    invocation = source.index("-I -m atlaso.app.services.app_history_cutover")
    resumed = source.index("systemctl restart atlaso\n")
    assert stopped < guarded < invocation < resumed
    guard_end = source.index("app_history_cutover_in_progress=false", guarded)
    assert invocation < guard_end < resumed
    external = source.index('"$python" -I -m atlaso.app.services.external_history_lifecycle install')
    assert guard_end < external < resumed
    restore = source[source.index("restore_services_on_exit() {"):source.index("trap restore_services_on_exit EXIT")]
    guard = restore.index('if [ "$app_history_cutover_in_progress" = "true" ]; then')
    assert guard < restore.index("systemctl stop atlaso.service atlaso-worker.service")
    assert restore.index('exit "$exit_status"') < restore.index("systemctl restart atlaso.service")



def test_systemd_environment_files_accepts_multiline_values(tmp_path, monkeypatch):
    """Accept systemd's one EnvironmentFiles value per output line.

    Args:
        tmp_path: Private selection pathname.
        monkeypatch: Scoped systemd output replacement.
    """
    controller = cutover.SystemdController(tmp_path / "app-history.env")

    def run(*arguments):
        """Return installed systemd output without exposing environment contents.

        Args:
            *arguments: Fixed controller inspection arguments.
        """
        if "--property=EnvironmentFiles" in arguments:
            return f"/etc/atlaso/atlaso.env (ignore_errors=no)\n{controller.environment} (ignore_errors=yes)\n"
        return "ActiveState=inactive\nMainPID=0\nControlPID=0\nJob=\n"

    monkeypatch.setattr(controller, "_run", run)
    assert controller.active_units() == ()
