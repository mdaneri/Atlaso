"""Exercise installed external capture orchestration with isolated producer models."""

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from atlaso.app.services import external_history_lifecycle as lifecycle
from atlaso.app.services import producer_log_history as history


def _nginx_fixture(tmp_path, monkeypatch):
    """Prepare an isolated Nginx writer and fixed lifecycle roots.

    Args:
        tmp_path: Test-owned complete lifecycle directory.
        monkeypatch: Replace only fixed appliance paths and service operations.
    """
    root, logs = tmp_path / "state", tmp_path / "logs"
    root.mkdir(mode=0o700)
    logs.mkdir()
    for key, value in {"ROOT": root, "NGINX_LOGS": logs, "NGINX_GENERATIONS": logs / ".atlaso-history",
                       "NGINX_STORE": root / "nginx.sqlite"}.items():
        monkeypatch.setattr(lifecycle, key, value)
    monkeypatch.setattr(lifecycle, "_vendor_rotation_check", lambda: None)
    monkeypatch.setattr(lifecycle, "nginx_writers_closed", lambda _: True)
    count = []

    def reopen():
        """Simulate regular writes to the newly reopened pair."""
        count.append(True)
        for name in ("access.log", "error.log"):
            (logs / name).write_text(f"after-reopen-{len(count)}\n", encoding="utf-8")

    monkeypatch.setattr(lifecycle, "reopen_nginx_logs", reopen)
    for name in ("access.log", "error.log"):
        (logs / name).write_text("initial\n", encoding="utf-8")
    return root, logs, count


def test_installed_collector_imports_complete_legacy_and_continues(tmp_path, monkeypatch):
    """Initial activation includes old archives, then every sealed live generation.

    Args:
        tmp_path: Test-owned lifecycle and source state.
        monkeypatch: Bind fixed paths and model the service's supported reopen.
    """
    root, logs, count = _nginx_fixture(tmp_path, monkeypatch)
    (logs / "access.log.1").write_text("oldest\n", encoding="utf-8")
    with lifecycle.lifecycle_lock(root):
        lifecycle.collect_nginx()
    assert history.source_active(lifecycle.NGINX_STORE, "nginx-access")
    assert history.source_active(lifecycle.NGINX_STORE, "nginx-error")
    assert history.read_page(lifecycle.NGINX_STORE, "nginx-access").lines == ("oldest", "initial")
    with lifecycle.lifecycle_lock(root):
        lifecycle.collect_nginx()
    assert history.read_page(lifecycle.NGINX_STORE, "nginx-access").lines == (
        "oldest", "initial", "after-reopen-1")
    assert (logs / "access.log.1").read_text() == "oldest\n"
    assert (logs / ".atlaso-history/0000000000000000/access.log").read_text() == "initial\n"
    assert len(count) == 2
    assert json.loads((root / "nginx-state.json").read_text())["next"] == 2


def test_collector_restarts_pending_generation_without_duplicate_rows(tmp_path, monkeypatch):
    """A timer killed after capture resumes its pending generation before rotating.

    Args:
        tmp_path: Test-owned lifecycle and source state.
        monkeypatch: Inject a lost final collection acknowledgment.
    """
    root, _, count = _nginx_fixture(tmp_path, monkeypatch)
    lifecycle.collect_nginx()
    original = lifecycle.capture_generation

    def lost(store, directory):
        """Commit input then lose the collector's final acknowledgment.

        Args:
            store: Prepared producer database.
            directory: Proven sealed generation.
        """
        original(store, directory)
        raise OSError("synthetic interrupted collector")

    monkeypatch.setattr(lifecycle, "capture_generation", lost)
    with pytest.raises(OSError, match="interrupted"):
        lifecycle.collect_nginx()
    assert json.loads((root / "nginx-state.json").read_text())["pending"] == "0000000000000001"
    monkeypatch.setattr(lifecycle, "capture_generation", original)
    lifecycle.collect_nginx()
    assert len(count) == 2
    assert history.read_page(lifecycle.NGINX_STORE, "nginx-access").lines == ("initial", "after-reopen-1")
    assert json.loads((root / "nginx-state.json").read_text())["pending"] is None


def test_collector_rejects_external_owner_before_renaming(tmp_path, monkeypatch):
    """Incompatible existing retention is preserved instead of silently replaced.

    Args:
        tmp_path: Test-owned lifecycle and source state.
        monkeypatch: Report an existing external rotation owner.
    """
    _, logs, count = _nginx_fixture(tmp_path, monkeypatch)

    def conflict():
        """Model an explicitly detected conflicting rotation policy."""
        raise lifecycle.RotationConflict("synthetic existing owner")

    monkeypatch.setattr(lifecycle, "_vendor_rotation_check", conflict)
    with pytest.raises(lifecycle.RotationConflict):
        lifecycle.collect_nginx()
    assert (logs / "access.log").read_text() == "initial\n"
    assert not count
    assert not lifecycle.NGINX_STORE.exists()


@pytest.mark.parametrize(("name", "content"), [
    ("etc/logrotate.d/nginx", "/var/log/nginx/*.log {\nweekly\nrotate 4\n}\n"),
    ("etc/logrotate.conf", "/var/log/*/*.log {\ndaily\n}\n"),
    ("etc/cron.daily/rotate-frontdoor", "nginx -s reopen\n"),
    ("etc/systemd/system/custom.service", "[Service]\nExecStart=/bin/kill -USR1 nginx\n"),
    ("etc/cron.daily/custom", "/usr/sbin/logrotate /opt/site/rotation.conf\n"),
])
def test_rotation_owner_discovery_rejects_conflicts(tmp_path, name, content):
    """Supported cron, vendor, file and service inventories detect another owner.

    Args:
        tmp_path: Test-owned filesystem root.
        name: Installed configuration pathname within that root.
        content: Synthetic external rotation configuration.
    """
    path = tmp_path / name
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    with pytest.raises(lifecycle.RotationConflict):
        lifecycle.check_rotation_owners(tmp_path)


def test_rotation_discovery_accepts_unrelated_ntp_and_stock_nginx(tmp_path):
    """Stock Nginx reload and unrelated NTP rotation do not claim these logs.

    Args:
        tmp_path: Test-owned filesystem root.
    """
    contents = {
        "etc/logrotate.d/ntpsec.conf": "/var/log/ntpsec/*.log {\nweekly\n}\n",
        "usr/lib/systemd/system/nginx.service": "[Service]\nExecStart=/usr/sbin/nginx\nExecReload=/usr/sbin/nginx -s reload\n",
        "usr/lib/systemd/system/logrotate.timer": "[Unit]\nDescription=Daily logrotate timer\n",
        "usr/lib/systemd/system/logrotate.service": "[Service]\nExecStart=/usr/sbin/logrotate /etc/logrotate.conf\n",
    }
    for name, content in contents.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    lifecycle.check_rotation_owners(tmp_path)


def test_kms_cutover_preserves_old_logs_then_enables_capture(tmp_path, monkeypatch):
    """KMS retains its raw stream while importing history before service resume.

    Args:
        tmp_path: Test-owned KMS runtime and private preservation directories.
        monkeypatch: Replace fixed paths, account ownership, and systemd operations.
    """
    root, logs = tmp_path / "state", tmp_path / "kmip"
    root.mkdir(mode=0o700)
    logs.mkdir(mode=0o700)
    environment = tmp_path / "history.env"
    history_root = tmp_path / "kms-history"
    store = history_root / "history.sqlite"
    monkeypatch.setattr(lifecycle, "ROOT", root)
    monkeypatch.setattr(lifecycle, "KMS_LOGS", logs)
    monkeypatch.setattr(lifecycle, "KMS_STORE", store)
    monkeypatch.setattr(lifecycle, "KMS_HISTORY_ROOT", history_root)
    monkeypatch.setattr(lifecycle, "KMS_ENVIRONMENT", environment)
    monkeypatch.setattr(lifecycle.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(lifecycle.importlib, "import_module", lambda _: SimpleNamespace(
        getpwnam=lambda _: SimpleNamespace(pw_uid=root.stat().st_uid, pw_gid=root.stat().st_gid),
        geteuid=lambda: root.stat().st_uid, chown=lambda *args: None))
    (logs / "server.log").write_text("kms retained\n", encoding="utf-8")
    calls = []

    def systemctl(*arguments):
        """Model a stable active service and its verified shutdown.

        Args:
            *arguments: Lifecycle-owned systemctl arguments.
        """
        calls.append(arguments)
        if "--property=LoadState,ActiveState" in arguments:
            return "LoadState=loaded\nActiveState=active\n"
        if "--property=EnvironmentFiles" in arguments:
            return str(environment) + " (ignore_errors=yes)\n"
        if arguments[0] == "show":
            return "ActiveState=inactive\nMainPID=0\nControlPID=0\nJob=\n"
        if arguments[0] == "start":
            assert history.source_active(store, "kms")
            assert environment.read_text() == f"ATLASO_KMS_LOG_HISTORY_PATH={store}\n"
        return ""

    monkeypatch.setattr(lifecycle, "_systemctl", systemctl)
    lifecycle.prepare_kms(resume=True)
    assert history.read_page(store, "kms").lines == ("kms retained",)
    assert (logs / "server.log").read_text() == "kms retained\n"
    assert (root / "kms-legacy/server.log").read_text() == "kms retained\n"
    assert calls[-1] == ("start", "atlaso-kmip.service")


@pytest.mark.parametrize("prepared", [False, True])
def test_existing_kms_store_checks_pending_capture_under_writer_lock(tmp_path, monkeypatch, prepared):
    """Selected KMS state recovers only already sanitized input under its lock.

    Args:
        tmp_path: Owned selected KMS store and lifecycle state.
        monkeypatch: Bind fixed paths and observe capture lock ownership.
        prepared: Whether the interrupted formatter durably staged sanitized input.
    """
    store, environment = tmp_path / "history.sqlite", tmp_path / "history.env"
    history.initialize(store)
    history.import_legacy(store, "kms", [])
    boundary = history.read_page(store, "kms")
    history.activate_source(store, "kms", generation=boundary.generation, through=0)
    with sqlite3.connect(store) as db:
        db.execute("INSERT INTO capture_pending VALUES ('kms','service',1,NULL)")
    if prepared:
        history.append(store, "kms", ["retained prepared event"], writer="service", revision=1, prepare_only=True)
    environment.write_text(f"ATLASO_KMS_LOG_HISTORY_PATH={store}\n", encoding="utf-8")
    state_path = tmp_path / "kms-state.json"
    state_path.write_text('{"schema":1,"phase":"published","previous_active":true}', encoding="utf-8")
    original_state = state_path.read_bytes()
    monkeypatch.setattr(lifecycle, "ROOT", tmp_path)
    monkeypatch.setattr(lifecycle, "KMS_STORE", store)
    monkeypatch.setattr(lifecycle, "KMS_ENVIRONMENT", environment)
    calls = []

    def systemctl(*arguments):
        """Observe that failed validation never resumes the selected producer.

        Args:
            *arguments: Fixed service operation or inspection.
        """
        calls.append(arguments)
        if "--property=EnvironmentFiles" in arguments:
            return f"{environment} (ignore_errors=yes)"
        return "LoadState=loaded\nActiveState=inactive\n"

    finish = history._finish_prepared_capture

    def checked_finish(path, source):
        """Require the writer lock to exclude capture during recovery validation.

        Args:
            path: Selected KMS store.
            source: Fixed KMS source identifier.
        """
        with sqlite3.connect(path.with_suffix(".capture-lock.sqlite"), timeout=0) as lock:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                lock.execute("BEGIN IMMEDIATE")
        finish(path, source)

    monkeypatch.setattr(lifecycle, "_systemctl", systemctl)
    monkeypatch.setattr(history, "_finish_prepared_capture", checked_finish)
    if prepared:
        lifecycle.prepare_kms(resume=True)
        assert history.read_page(store, "kms").lines == ("retained prepared event",)
        assert calls[-1] == ("start", "atlaso-kmip.service")
        assert json.loads(state_path.read_text())["phase"] == "complete"
    else:
        with pytest.raises(ValueError, match="interrupted-record recovery"):
            lifecycle.prepare_kms(resume=True)
        assert all(call[0] == "show" for call in calls)
        assert state_path.read_bytes() == original_state
        with sqlite3.connect(store) as db:
            assert db.execute("SELECT prepared FROM capture_pending WHERE source='kms'").fetchone() == (None,)


def test_units_preserve_nginx_main_process_and_bound_timer(tmp_path, monkeypatch):
    """A separate oneshot and timer leave stock Nginx lifecycle directives intact.

    Args:
        tmp_path: Test-owned systemd unit installation directory.
        monkeypatch: Bind the fixed unit root to the owned fixture.
    """
    monkeypatch.setattr(lifecycle, "UNIT_ROOT", tmp_path)
    lifecycle.install_units()
    assert not (tmp_path / "nginx.service").exists()
    service = (tmp_path / lifecycle.SERVICE).read_text()
    timer = (tmp_path / lifecycle.TIMER).read_text()
    assert "Type=oneshot" in service and "external_history_lifecycle collect" in service
    assert "TimeoutStartSec=120" in service and "ReadWritePaths=/var/log/nginx " in service
    assert "OnUnitInactiveSec=5s" in timer
    assert f"EnvironmentFile=-{lifecycle.KMS_ENVIRONMENT}" in (
        tmp_path / "atlaso-kmip.service.d/atlaso-log-history.conf").read_text()


def test_deployment_hooks_include_external_capture():
    """Image and KMS Apply invoke migration before runtime capture is required."""
    root = Path(__file__).resolve().parents[1]
    provision = (root / "image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    helper = (root / "scripts/appliance/atlaso-helper").read_text(encoding="utf-8")
    assert "external_history_lifecycle install" in provision
    assert '"atlaso.app.services.external_history_lifecycle", "kms-cutover"' in helper
    assert "EnvironmentFile=-/etc/atlaso/kmip/history.env" in helper


def test_collector_lock_excludes_second_lifecycle_owner(tmp_path):
    """An overlapping timer/install cannot advance the generation ledger twice.

    Args:
        tmp_path: Test-owned lifecycle lock database directory.
    """
    with lifecycle.lifecycle_lock(tmp_path):
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with lifecycle.lifecycle_lock(tmp_path):
                pytest.fail("second lifecycle owner acquired the held writer lock")
