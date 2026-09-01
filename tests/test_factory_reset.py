"""Verify the complete, crash-safe Atlaso factory-reset transaction."""

import builtins
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.factory_reset import (
    FactoryResetError,
    _ca_private_key_paths,
    _remove_retired_ca_private_keys,
    _scrub_retained_credentials,
    _seed_factory_host_interfaces,
    finalize_factory_reset,
    run_factory_reset,
)
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
    CaCertificate,
    DnsRecord,
    DnsSettings,
    Job,
    PhysicalInterface,
    Setting,
    User,
    VcfDepotDownloadProfile,
)
from atlaso.app.seed import FACTORY_RESET_SETTING_KEY, seed_initial_data
from atlaso.app.services.networking import HostPhysicalInterface


def test_factory_reset_transaction_lock_rejects_overlapping_posix_runner(
    tmp_path,
    monkeypatch,
):
    """A competing appliance runner cannot enter or alter the active transaction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    class ContendedFcntl:
        """Model an already-held nonblocking appliance file lock."""

        LOCK_EX = 1
        LOCK_NB = 2
        LOCK_UN = 4

        @staticmethod
        def flock(_descriptor, operation):
            """Reject every lock acquisition.

            Args:
                _descriptor: Open transaction-lock descriptor.
                operation: Requested flock operation flags.
            """
            if operation != ContendedFcntl.LOCK_UN:
                raise BlockingIOError

    original_import = builtins.__import__

    def import_with_contended_fcntl(name, *args, **kwargs):
        """Return the contended fcntl test double.

        Args:
            name: Module name requested by import.
            *args: Additional import arguments.
            **kwargs: Additional import keyword arguments.
        """
        if name == "fcntl":
            return ContendedFcntl
        return original_import(name, *args, **kwargs)

    state_directory = tmp_path / "factory-reset"
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset.os, "name", "posix")
    monkeypatch.setattr(builtins, "__import__", import_with_contended_fcntl)

    with pytest.raises(FactoryResetError, match="already running"):
        with factory_reset._factory_reset_transaction_lock():
            pytest.fail("contending runner must not enter the transaction")


def test_factory_reset_runner_waits_for_admission_lock(monkeypatch):
    """The detached runner tolerates the scheduler's bounded lock handoff race.

    Args:
        monkeypatch: Pytest fixture used to record runner lock admission.
    """
    import atlaso.app.factory_reset as factory_reset

    observed_waits: list[float] = []

    @contextmanager
    def fake_lock(*, wait_seconds=0):
        """Record the bounded wait and admit the test runner.

        Args:
            wait_seconds: Maximum lock handoff wait requested by the runner.
        """
        observed_waits.append(wait_seconds)
        yield

    monkeypatch.setattr(factory_reset, "_factory_reset_transaction_lock", fake_lock)
    monkeypatch.setattr(
        factory_reset,
        "_run_factory_reset_locked",
        lambda **_kwargs: {"state": "succeeded"},
    )

    result = factory_reset.run_factory_reset(manage_services=False)

    assert result == {"state": "succeeded"}
    assert observed_waits == [factory_reset.FACTORY_RESET_RUNNER_LOCK_WAIT_SECONDS]


def test_helper_factory_reset_runner_uses_installed_database_url(monkeypatch, tmp_path):
    """Console recovery inherits the appliance database path without sourcing secrets.

    Args:
        monkeypatch: Pytest fixture used to isolate the helper process environment.
        tmp_path: Temporary directory provided for the installed runtime fixtures.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    python = tmp_path / "python"
    python.write_bytes(b"python")
    environment_path = tmp_path / "atlaso.env"
    environment_path.write_text(
        "ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/obsolete.db\n"
        "ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/atlaso.db\n"
        "ATLASO_SECRET_KEY=must-not-be-imported-by-the-helper\n"
        "export ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/shell-only.db\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}
    monkeypatch.setenv("ATLASO_DATABASE_URL", "sqlite:////data/caller-override.db")
    monkeypatch.delenv("ATLASO_SECRET_KEY", raising=False)
    monkeypatch.setattr(helper, "ATLASO_FACTORY_RESET_PYTHON", python)
    monkeypatch.setattr(helper, "ATLASO_ENV_PATH", environment_path)

    def run(command, *, env=None, **_kwargs):
        """Capture the exact child environment selected for console recovery.

        Args:
            command: Command selected for the factory-reset runtime.
            env: Explicit child-process environment.
            **_kwargs: Additional command-runner options unused by this test.
        """
        captured["command"] = command
        captured["environment"] = env
        return subprocess.CompletedProcess(command, 0, "complete", "")

    monkeypatch.setattr(helper, "_run", run)

    result = helper._factory_reset_runner(boot_resume=True)

    assert result.returncode == 0
    assert captured["command"] == [str(python), "-m", "atlaso.app.factory_reset"]
    child_environment = captured["environment"]
    assert isinstance(child_environment, dict)
    assert child_environment["ATLASO_DATABASE_URL"] == "sqlite:////var/lib/atlaso/atlaso.db"
    assert child_environment["ATLASO_FACTORY_RESET_BOOT_RESUME"] == "1"
    assert "ATLASO_SECRET_KEY" not in child_environment


def test_helper_factory_reset_runner_fails_when_database_url_is_unavailable(monkeypatch, tmp_path):
    """Console recovery never falls back to the development database path.

    Args:
        monkeypatch: Pytest fixture used to isolate the helper process environment.
        tmp_path: Temporary directory provided for the installed runtime fixtures.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    python = tmp_path / "python"
    python.write_bytes(b"python")
    environment_path = tmp_path / "atlaso.env"
    environment_path.write_text("ATLASO_ENVIRONMENT=appliance\n", encoding="utf-8")
    monkeypatch.delenv("ATLASO_DATABASE_URL", raising=False)
    monkeypatch.setattr(helper, "ATLASO_FACTORY_RESET_PYTHON", python)
    monkeypatch.setattr(helper, "ATLASO_ENV_PATH", environment_path)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("factory-reset runtime must not start"),
    )

    result = helper._factory_reset_runner(boot_resume=True)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "ATLASO_DATABASE_URL is missing from the Atlaso appliance environment.\n"
    )


def test_helper_factory_reset_runner_rejects_environment_file_escapes(monkeypatch, tmp_path):
    """Console recovery fails closed when systemd value decoding would be required.

    Args:
        monkeypatch: Pytest fixture used to isolate the helper process environment.
        tmp_path: Temporary directory provided for the installed runtime fixtures.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    python = tmp_path / "python"
    python.write_bytes(b"python")
    environment_path = tmp_path / "atlaso.env"
    environment_path.write_text(
        "ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/control\\ plane.db\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_FACTORY_RESET_PYTHON", python)
    monkeypatch.setattr(helper, "ATLASO_ENV_PATH", environment_path)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("factory-reset runtime must not start"),
    )

    result = helper._factory_reset_runner(boot_resume=True)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "ATLASO_DATABASE_URL uses unsupported EnvironmentFile escape syntax.\n"
    )


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor paths")
def test_factory_reset_runner_pins_admitted_state_directory(tmp_path):
    """Runner state remains bound to the admitted directory after replacement.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    (state_directory / "request.json").write_text(
        json.dumps({"schema_version": 1, "state": "scheduled"}),
        encoding="utf-8",
    )
    descriptor = os.open(
        state_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    token = factory_reset._PINNED_FACTORY_RESET_DIRECTORY_FD.set(descriptor)
    admitted_directory = tmp_path / "admitted-factory-reset"
    outside_directory = tmp_path / "outside"
    try:
        state_directory.rename(admitted_directory)
        outside_directory.mkdir()
        state_directory.symlink_to(outside_directory, target_is_directory=True)

        factory_reset._update_request("building", "Building factory state.")

        admitted = json.loads(
            (admitted_directory / "request.json").read_text(encoding="utf-8")
        )
        assert admitted["state"] == "building"
        assert list(outside_directory.iterdir()) == []
    finally:
        factory_reset._PINNED_FACTORY_RESET_DIRECTORY_FD.reset(token)
        os.close(descriptor)


def test_factory_reset_stops_transient_helper_restart_and_automation_units(monkeypatch):
    """Reset quiesces helper actions, both delayed restarts, and automation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    commands: list[list[str]] = []
    automation_units = [
        "atlaso-automation-20260815230000123456.service",
        "atlaso-automation-20260815230100654321.service",
    ]
    helper_units = [
        "atlaso-helper-action-0123456789abcdef0123456789abcdef.service",
        "atlaso-helper-action-fedcba9876543210fedcba9876543210.service",
    ]
    helper_inventories = [[helper_units[0]], [helper_units[1]], []]
    management_restart_timer = "atlaso-management-ui-restart.timer"
    management_restart_service = "atlaso-management-ui-restart.service"
    restart_timer = "atlaso-update-restart-20260820152500123456.timer"
    restart_service = "atlaso-update-restart-20260820152500123456.service"

    def fake_run(command, **_kwargs):
        """Return a bounded systemd inventory and stopped-state verification.

        Args:
            command: Exact system command arguments.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        if command[1] == "list-units":
            if command[-1] == "atlaso-helper-action-*.service":
                stdout = "\n".join(
                    f"{unit} loaded active running Atlaso helper action"
                    for unit in helper_inventories.pop(0)
                )
            elif command[-1] == "atlaso-management-ui-restart.timer":
                stdout = (
                    f"{management_restart_timer} loaded active waiting "
                    "Atlaso management restart"
                )
            elif command[-1] == "atlaso-management-ui-restart.service":
                stdout = (
                    f"{management_restart_service} loaded active running "
                    "Atlaso management restart"
                )
            elif command[-1] == "atlaso-update-restart-*.timer":
                stdout = f"{restart_timer} loaded active waiting Atlaso update restart"
            elif command[-1] == "atlaso-update-restart-*.service":
                stdout = f"{restart_service} loaded active running Atlaso update restart"
            else:
                stdout = "\n".join(
                    f"{unit} loaded active running Atlaso automation"
                    for unit in automation_units
                )
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if command[1] == "is-active":
            return subprocess.CompletedProcess(command, 3, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(factory_reset.subprocess, "run", fake_run)
    staging_cleared: list[bool] = []
    monkeypatch.setattr(
        factory_reset,
        "_clear_automation_transient_staging",
        lambda: staging_cleared.append(True),
    )

    factory_reset._stop_application_services(boot_resume=False)

    assert commands[0] == [
        "systemctl",
        "stop",
        "atlaso-worker.service",
        "atlaso.service",
        "atlaso-console.service",
    ]
    assert commands[1][-1] == "atlaso-helper-action-*.service"
    assert commands[2] == ["systemctl", "stop", helper_units[0]]
    assert commands[3] == ["systemctl", "is-active", "--quiet", helper_units[0]]
    assert commands[4][-1] == "atlaso-helper-action-*.service"
    assert commands[5] == ["systemctl", "stop", helper_units[1]]
    assert commands[6] == ["systemctl", "is-active", "--quiet", helper_units[1]]
    assert commands[7][-1] == "atlaso-helper-action-*.service"
    assert commands[8][-1] == "atlaso-management-ui-restart.timer"
    assert commands[9] == ["systemctl", "stop", management_restart_timer]
    assert commands[10] == [
        "systemctl",
        "is-active",
        "--quiet",
        management_restart_timer,
    ]
    assert commands[11][-1] == "atlaso-management-ui-restart.service"
    assert commands[12] == ["systemctl", "stop", management_restart_service]
    assert commands[13] == [
        "systemctl",
        "is-active",
        "--quiet",
        management_restart_service,
    ]
    application_services = [
        "atlaso-worker.service",
        "atlaso.service",
        "atlaso-console.service",
    ]
    assert commands[14] == ["systemctl", "stop", *application_services]
    assert commands[15:18] == [
        ["systemctl", "is-active", "--quiet", service]
        for service in application_services
    ]
    assert commands[18][-1] == "atlaso-update-restart-*.timer"
    assert commands[19] == ["systemctl", "stop", restart_timer]
    assert commands[20] == ["systemctl", "is-active", "--quiet", restart_timer]
    assert commands[21][-1] == "atlaso-update-restart-*.service"
    assert commands[22] == ["systemctl", "stop", restart_service]
    assert commands[23] == ["systemctl", "is-active", "--quiet", restart_service]
    assert commands[24][-1] == "atlaso-automation-*.service"
    assert commands[25] == ["systemctl", "stop", *automation_units]
    assert commands[26:] == [
        ["systemctl", "is-active", "--quiet", automation_units[0]],
        ["systemctl", "is-active", "--quiet", automation_units[1]],
    ]
    assert staging_cleared == [True]


def test_factory_reset_clears_automation_staging_after_quiescence(tmp_path, monkeypatch):
    """Reset removes interrupted script and run data from bounded roots.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace fixed appliance paths.
    """
    import atlaso.app.factory_reset as factory_reset

    script_directory = tmp_path / "automation" / "scripts"
    run_directory = tmp_path / "automation" / "runs"
    script_directory.mkdir(parents=True)
    (script_directory / "managed-script.py").write_text("secret", encoding="utf-8")
    run_home = run_directory / "20260820152500123456"
    run_home.mkdir(parents=True)
    (run_home / "output.txt").write_text("secret output", encoding="utf-8")
    monkeypatch.setattr(factory_reset, "AUTOMATION_SCRIPT_DIRECTORY", script_directory)
    monkeypatch.setattr(factory_reset, "AUTOMATION_RUN_DIRECTORY", run_directory)

    factory_reset._clear_automation_transient_staging()

    assert list(script_directory.iterdir()) == []
    assert list(run_directory.iterdir()) == []


def test_factory_reset_rejects_symlinked_automation_staging(tmp_path, monkeypatch):
    """Reset fails closed instead of clearing through a staging-root symlink.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace fixed appliance paths.
    """
    import atlaso.app.factory_reset as factory_reset

    target = tmp_path / "outside"
    target.mkdir()
    (target / "preserved.txt").write_text("preserve", encoding="utf-8")
    linked_scripts = tmp_path / "scripts"
    linked_scripts.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(factory_reset, "AUTOMATION_SCRIPT_DIRECTORY", linked_scripts)
    monkeypatch.setattr(
        factory_reset,
        "AUTOMATION_RUN_DIRECTORY",
        tmp_path / "missing-runs",
    )

    with pytest.raises(factory_reset.FactoryResetError, match="directory is unsafe"):
        factory_reset._clear_automation_transient_staging()

    assert (target / "preserved.txt").read_text(encoding="utf-8") == "preserve"


def test_factory_reset_fails_if_management_restart_revives_application(monkeypatch):
    """Reset rejects activation when a delayed restart revives Atlaso.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Model Atlaso becoming active after restart-unit cancellation.

        Args:
            command: Exact system command arguments.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        if command[1] == "is-active" and command[-1] == "atlaso.service":
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[1] == "is-active":
            return subprocess.CompletedProcess(command, 3, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(factory_reset.subprocess, "run", fake_run)
    monkeypatch.setattr(factory_reset, "_stop_transient_helper_action_units", lambda: None)
    monkeypatch.setattr(factory_reset, "_require_terminal_release_update", lambda: None)
    monkeypatch.setattr(factory_reset, "_stop_transient_management_restart_units", lambda: None)
    monkeypatch.setattr(factory_reset, "_stop_transient_update_restart_units", lambda: None)
    monkeypatch.setattr(factory_reset, "_stop_transient_automation_units", lambda: None)

    with pytest.raises(factory_reset.FactoryResetError, match="application service"):
        factory_reset._stop_application_services(boot_resume=False)

    application_services = [
        "atlaso-worker.service",
        "atlaso.service",
        "atlaso-console.service",
    ]
    assert commands[:2] == [
        ["systemctl", "stop", *application_services],
        ["systemctl", "stop", *application_services],
    ]
    assert commands[2:] == [
        ["systemctl", "is-active", "--quiet", "atlaso-worker.service"],
        ["systemctl", "is-active", "--quiet", "atlaso.service"],
    ]


def test_factory_reset_fails_closed_when_helper_actions_do_not_quiesce(monkeypatch):
    """Reset refuses activation when the bounded helper family never drains.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    unit = "atlaso-helper-action-0123456789abcdef0123456789abcdef.service"
    inventories = iter([[unit], [unit]])
    stopped: list[list[str]] = []
    monkeypatch.setattr(factory_reset, "HELPER_ACTION_QUIESCE_MAX_PASSES", 1)
    monkeypatch.setattr(
        factory_reset,
        "_inventory_transient_units",
        lambda **_kwargs: next(inventories),
    )
    monkeypatch.setattr(
        factory_reset,
        "_stop_and_verify_transient_units",
        lambda units, **_kwargs: stopped.append(units),
    )

    with pytest.raises(factory_reset.FactoryResetError, match="could not quiesce"):
        factory_reset._stop_transient_helper_action_units()

    assert stopped == [[unit]]


@pytest.mark.parametrize(
    ("payload", "blocked"),
    [
        ({"status": "transaction_pending", "transaction_recovery": {}}, True),
        ({"status": "restart_pending", "transaction_recovery": {}}, True),
        ({"status": "rollback_pending", "transaction_recovery": {}}, True),
        ({"status": "activation_committed", "transaction_recovery": {}}, True),
        (
            {"status": "failed", "rolled_back": False, "transaction_recovery": {}},
            True,
        ),
        ({"status": "succeeded", "rolled_back": False}, False),
        ({"status": "failed", "rolled_back": True}, False),
        ({"status": "failed", "rolled_back": False}, False),
    ],
)
def test_factory_reset_requires_definitive_release_transaction(
    tmp_path,
    monkeypatch,
    payload,
    blocked,
):
    """Reset admits only definitive release evidence without pending recovery.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated state.
        monkeypatch: Pytest fixture used to replace the fixed finalizer path.
        payload: Release finalizer shape under test.
        blocked: Whether the shape must block factory reset.
    """
    import atlaso.app.factory_reset as factory_reset

    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(factory_reset, "APPLIANCE_UPDATE_FINALIZER_PATH", finalizer)

    if blocked:
        with pytest.raises(FactoryResetError, match="definitive terminal state"):
            factory_reset._require_terminal_release_update()
    else:
        factory_reset._require_terminal_release_update()


def test_factory_reset_release_preflight_fails_closed_for_invalid_evidence(tmp_path, monkeypatch):
    """Unreadable release evidence cannot be erased by reset staging cleanup.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated state.
        monkeypatch: Pytest fixture used to replace the fixed finalizer path.
    """
    import atlaso.app.factory_reset as factory_reset

    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(factory_reset, "APPLIANCE_UPDATE_FINALIZER_PATH", finalizer)

    with pytest.raises(FactoryResetError, match="cannot verify"):
        factory_reset._require_terminal_release_update()


def test_fallback_sqlite_replacement_serializes_an_earlier_writer(tmp_path):
    """The fallback waits for an earlier writer and then removes its pre-reset row.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated SQLite files.
    """
    import sqlite3
    import threading

    from atlaso.app.factory_reset import _replace_sqlite_database_contents

    live_path = tmp_path / "live.db"
    candidate_path = tmp_path / "candidate.db"
    for path, value in ((live_path, "old"), (candidate_path, "factory")):
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO records (value) VALUES (?)", (value,))
            connection.commit()

    writer = sqlite3.connect(live_path, check_same_thread=False, timeout=5)
    writer.execute("INSERT INTO records (value) VALUES ('pre-reset-late-commit')")
    completed = threading.Event()
    failures: list[BaseException] = []

    def replace() -> None:
        """Run the transactional replacement in a competing thread."""
        try:
            _replace_sqlite_database_contents(live_path, candidate_path)
        except BaseException as exc:  # noqa: BLE001 - preserve thread failure for the assertion.
            failures.append(exc)
        finally:
            completed.set()

    thread = threading.Thread(target=replace)
    thread.start()
    assert not completed.wait(0.1)
    writer.commit()
    writer.close()
    assert completed.wait(5)
    thread.join()

    assert failures == []
    with sqlite3.connect(live_path) as connection:
        assert connection.execute("SELECT id, value FROM records").fetchall() == [
            (1, "factory")
        ]
        assert connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'records'"
        ).fetchone() == (1,)


def test_fallback_replacement_clears_credentials_staged_during_candidate(
    tmp_path,
    monkeypatch,
):
    """A successful fallback discards process-local staging added during reset.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated SQLite files.
        monkeypatch: Pytest fixture used to replace candidate construction.
    """
    from datetime import UTC, datetime

    import atlaso.app.factory_reset as factory_reset
    from atlaso.app.services.ldap import (
        LDAP_PENDING_PASSWORDS,
        LDAP_PENDING_RECOVERY_PAYLOADS,
    )
    from atlaso.app.services.local_users import (
        pending_os_password_snapshot,
        restore_pending_os_password_snapshot,
    )

    database_path = tmp_path / "atlaso.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    def build_candidate(*_args, **_kwargs):
        """Model credentials staged by overlapping requests during candidate work.

        Args:
            *_args: Positional candidate arguments ignored by the test double.
            **_kwargs: Keyword candidate arguments ignored by the test double.
        """
        restore_pending_os_password_snapshot(
            {"late-user": ("late-password", datetime.now(UTC))}
        )
        LDAP_PENDING_PASSWORDS[41] = "late-ldap-password"
        LDAP_PENDING_RECOVERY_PAYLOADS[42] = b"late-recovery-payload"
        return 16

    monkeypatch.setattr(factory_reset, "_candidate_database", build_candidate)
    monkeypatch.setattr(
        factory_reset,
        "_replace_sqlite_database_contents",
        lambda *_args, **_kwargs: None,
    )
    try:
        with session_factory() as db:
            assert factory_reset.replace_database_with_factory_candidate(
                db,
                database_url=f"sqlite:///{database_path}",
                adapter=SystemAdapter(dry_run=True),
            ) == 16

        assert pending_os_password_snapshot() == {}
        assert LDAP_PENDING_PASSWORDS == {}
        assert LDAP_PENDING_RECOVERY_PAYLOADS == {}
    finally:
        restore_pending_os_password_snapshot({})
        LDAP_PENDING_PASSWORDS.clear()
        LDAP_PENDING_RECOVERY_PAYLOADS.clear()
        engine.dispose()


def test_factory_reset_scrubs_credentials_outside_apply_staging(tmp_path, monkeypatch):
    """Reset removes retained SSH and Web Terminal credentials without touching payloads.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    authorized_keys = tmp_path / "authorized_keys"
    terminal_requests = tmp_path / "web-terminal" / "requests"
    terminal_private_key = tmp_path / "web-terminal-ca"
    terminal_public_key = tmp_path / "web-terminal-ca.pub"
    development_sudoers = tmp_path / "sudoers.d" / "atlaso-test-vm-admin"
    local_users_home = tmp_path / "users"
    bootstrap_ssh = local_users_home / "admin" / ".ssh"
    root_ssh = tmp_path / "root" / ".ssh"
    ldap_recovery = tmp_path / "ldap" / "recovery"
    authorized_keys.mkdir()
    terminal_requests.mkdir(parents=True)
    bootstrap_ssh.mkdir(parents=True)
    root_ssh.mkdir(parents=True)
    ldap_recovery.mkdir(parents=True)
    development_sudoers.parent.mkdir(parents=True)
    for path in (
        authorized_keys / "vcf-backup",
        terminal_requests / "request.json",
        terminal_private_key,
        terminal_public_key,
        development_sudoers,
        bootstrap_ssh / "authorized_keys",
        bootstrap_ssh / "authorized_keys2",
        root_ssh / "authorized_keys",
        root_ssh / "authorized_keys2",
        ldap_recovery / "ldap-recovery-20260821040800.tar.gz",
    ):
        path.write_text("credential", encoding="utf-8")
    retained_home_file = local_users_home / "admin" / "profile.ps1"
    retained_home_file.write_text("retained payload", encoding="utf-8")
    retained_root_ssh_config = root_ssh / "config"
    retained_root_ssh_config.write_text("retained root SSH config", encoding="utf-8")
    synced_directories: list[Path] = []

    monkeypatch.setattr(factory_reset, "VCF_BACKUPS_AUTHORIZED_KEYS_DIRECTORY", authorized_keys)
    monkeypatch.setattr(factory_reset, "WEB_TERMINAL_REQUEST_DIRECTORY", terminal_requests)
    monkeypatch.setattr(
        factory_reset,
        "WEB_TERMINAL_CREDENTIAL_PATHS",
        (terminal_private_key, terminal_public_key),
    )
    monkeypatch.setattr(factory_reset, "LOCAL_USERS_HOME_DIRECTORY", local_users_home)
    monkeypatch.setattr(factory_reset, "ROOT_SSH_DIRECTORY", root_ssh)
    monkeypatch.setattr(factory_reset, "LDAP_RECOVERY_DIRECTORY", ldap_recovery)
    monkeypatch.setattr(factory_reset, "DEVELOPMENT_ADMIN_SUDOERS_PATH", development_sudoers)
    monkeypatch.setattr(
        factory_reset,
        "get_settings",
        lambda: SimpleNamespace(bootstrap_admin_username="admin"),
    )
    monkeypatch.setattr(
        factory_reset,
        "_fsync_directory",
        synced_directories.append,
    )
    _scrub_retained_credentials()

    assert list(authorized_keys.iterdir()) == []
    assert list(terminal_requests.iterdir()) == []
    assert not terminal_private_key.exists()
    assert not terminal_public_key.exists()
    assert not development_sudoers.exists()
    assert not (bootstrap_ssh / "authorized_keys").exists()
    assert not (bootstrap_ssh / "authorized_keys2").exists()
    assert not (root_ssh / "authorized_keys").exists()
    assert not (root_ssh / "authorized_keys2").exists()
    assert list(ldap_recovery.iterdir()) == []
    assert retained_home_file.read_text(encoding="utf-8") == "retained payload"
    assert retained_root_ssh_config.read_text(encoding="utf-8") == "retained root SSH config"
    expected_synced_directories = {
        authorized_keys,
        terminal_requests,
        terminal_private_key.parent,
        development_sudoers.parent,
        bootstrap_ssh,
        root_ssh,
    }
    if os.name != "posix":
        expected_synced_directories.add(ldap_recovery)
    assert set(synced_directories) == expected_synced_directories


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX directory descriptors")
def test_factory_reset_fsyncs_posix_ldap_recovery_directory(tmp_path, monkeypatch):
    """LDAP export removal synchronizes its pinned directory descriptor.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to record descriptor synchronization.
    """
    import atlaso.app.factory_reset as factory_reset

    recovery_directory = tmp_path / "ldap" / "recovery"
    recovery_directory.mkdir(parents=True)
    (recovery_directory / "ldap-recovery.tar.gz").write_text(
        "password hashes",
        encoding="utf-8",
    )
    recovery_inode = recovery_directory.stat().st_ino
    synced_inodes: list[int] = []
    monkeypatch.setattr(
        factory_reset.os,
        "fsync",
        lambda descriptor: synced_inodes.append(os.fstat(descriptor).st_ino),
    )

    factory_reset._clear_symlink_resistant_directory(
        recovery_directory,
        label="LDAP recovery staging",
    )

    assert list(recovery_directory.iterdir()) == []
    assert recovery_inode in synced_inodes


def test_factory_reset_rejects_symlinked_ldap_recovery_staging(tmp_path, monkeypatch):
    """Reset never follows a replacement LDAP recovery directory.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace fixed appliance paths.
    """
    import atlaso.app.factory_reset as factory_reset

    outside = tmp_path / "outside"
    outside.mkdir()
    archive = outside / "ldap-recovery.tar.gz"
    archive.write_text("password hashes", encoding="utf-8")
    linked_recovery = tmp_path / "recovery"
    linked_recovery.symlink_to(outside, target_is_directory=True)

    with pytest.raises(FactoryResetError, match="directory is unsafe"):
        factory_reset._clear_symlink_resistant_directory(
            linked_recovery,
            label="LDAP recovery staging",
        )

    assert archive.read_text(encoding="utf-8") == "password hashes"


def test_factory_reset_rejects_unsafe_root_authorization_entry(tmp_path, monkeypatch):
    """Reset fails closed rather than recursively deleting a root SSH entry.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    root_ssh = tmp_path / "root" / ".ssh"
    (root_ssh / "authorized_keys").mkdir(parents=True)
    monkeypatch.setattr(factory_reset, "ROOT_SSH_DIRECTORY", root_ssh)

    with pytest.raises(factory_reset.FactoryResetError, match="root SSH authorization entry"):
        factory_reset._scrub_root_authorized_keys()

    assert (root_ssh / "authorized_keys").is_dir()


def test_factory_reset_durably_clears_apply_staging(tmp_path, monkeypatch):
    """Reset synchronizes the apply root after removing staged secrets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    apply_root = tmp_path / "apply"
    staged_directory = apply_root / "local-users"
    staged_directory.mkdir(parents=True)
    (staged_directory / "atlaso-users.json").write_text("secret", encoding="utf-8")
    synced_directories: list[Path] = []
    real_path = factory_reset.Path
    monkeypatch.setattr(
        factory_reset,
        "Path",
        lambda value: apply_root if value == "/var/lib/atlaso/apply" else real_path(value),
    )
    monkeypatch.setattr(factory_reset, "_require_terminal_release_update", lambda: None)
    monkeypatch.setattr(
        factory_reset,
        "_fsync_directory",
        synced_directories.append,
    )

    factory_reset._clear_apply_staging()

    assert list(apply_root.iterdir()) == []
    assert synced_directories == [apply_root]


def test_factory_reset_preserves_pending_release_finalizer_before_staging_cleanup(
    tmp_path,
    monkeypatch,
):
    """A pending release manifest survives the final recursive-cleanup guard.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated state.
        monkeypatch: Pytest fixture used to replace fixed appliance paths.
    """
    import atlaso.app.factory_reset as factory_reset

    apply_root = tmp_path / "apply"
    finalizer = apply_root / "appliance-update" / "finalizer-status.json"
    staged_secret = apply_root / "local-users" / "atlaso-users.json"
    finalizer.parent.mkdir(parents=True)
    staged_secret.parent.mkdir(parents=True)
    finalizer.write_text(
        json.dumps({"status": "transaction_pending", "transaction_recovery": {}}),
        encoding="utf-8",
    )
    staged_secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(factory_reset, "APPLIANCE_UPDATE_FINALIZER_PATH", finalizer)
    real_path = factory_reset.Path
    monkeypatch.setattr(
        factory_reset,
        "Path",
        lambda value: apply_root if value == "/var/lib/atlaso/apply" else real_path(value),
    )

    with pytest.raises(FactoryResetError, match="definitive terminal state"):
        factory_reset._clear_apply_staging()

    assert finalizer.is_file()
    assert staged_secret.is_file()


def test_factory_reset_removes_only_retired_ca_private_keys(tmp_path, monkeypatch):
    """Reset removes old bounded CA keys while preserving factory-state paths.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    managed_root = tmp_path / "etc" / "atlaso"
    retired_key = managed_root / "https" / "retired.key"
    retained_key = managed_root / "ca" / "factory.key"
    for path in (retired_key, retained_key):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private key material", encoding="utf-8")
    monkeypatch.setattr(factory_reset, "CA_MANAGED_PATH_BASE", managed_root)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with test_session() as source_db:
        source_db.add_all(
            [
                CaCertificate(common_name="retired", key_path=str(retired_key)),
                CaCertificate(common_name="factory", key_path=str(retained_key)),
            ]
        )
        source_db.commit()
        source_paths = _ca_private_key_paths(source_db)
    with test_session() as candidate_db:
        candidate_db.execute(
            CaCertificate.__table__.delete().where(CaCertificate.common_name == "retired")
        )
        candidate_db.commit()
        candidate_paths = _ca_private_key_paths(candidate_db)

    _remove_retired_ca_private_keys(source_paths - candidate_paths)

    assert not retired_key.exists()
    assert retained_key.read_text(encoding="utf-8") == "private key material"
    engine.dispose()


def test_managed_factory_reset_retains_marker_until_readiness(tmp_path, monkeypatch):
    """A real reset cannot publish success before its post-restart finalizer.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    database_path.write_bytes(b"database")
    credentials_path = state_directory / "credentials.json"
    state_directory.mkdir()
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "admin_action": "keep",
                "root_action": "keep",
            }
        ),
        encoding="utf-8",
    )
    scheduled: list[tuple[str, ...]] = []
    credential_removal_states: list[str] = []
    login_cleanup_events: list[str] = []
    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    monkeypatch.setattr(
        factory_reset,
        "_factory_reset_credential_plan",
        lambda: {"admin_action": "keep", "root_action": "keep"},
    )
    monkeypatch.setattr(factory_reset, "_stop_application_services", lambda **_kwargs: None)
    monkeypatch.setattr(factory_reset, "_candidate_database", lambda *_args, **_kwargs: 16)
    monkeypatch.setattr(factory_reset, "_replace_database", lambda *_args: None)
    monkeypatch.setattr(factory_reset, "_clear_apply_staging", lambda: None)
    monkeypatch.setattr(
        factory_reset,
        "_scrub_retained_credentials",
        lambda: login_cleanup_events.append("credentials scrubbed"),
    )
    monkeypatch.setattr(
        SystemAdapter,
        "terminate_factory_reset_login_sessions",
        lambda _adapter: login_cleanup_events.append("sessions terminated")
        or AdapterResult(
            command=["factory-reset", "terminate-login-sessions"],
            dry_run=False,
        ),
    )
    real_remove_credentials = factory_reset._remove_factory_reset_credentials

    def remove_credentials_after_marker() -> None:
        """Record the durable phase visible when credentials are removed."""
        marker = json.loads((state_directory / "request.json").read_text(encoding="utf-8"))
        credential_removal_states.append(marker["state"])
        real_remove_credentials()

    monkeypatch.setattr(
        factory_reset,
        "_remove_factory_reset_credentials",
        remove_credentials_after_marker,
    )
    monkeypatch.setattr(
        factory_reset,
        "_schedule_readiness_finalizer",
        lambda: scheduled.append(("readiness",)),
    )

    result = factory_reset._run_factory_reset_locked(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=False),
        manage_services=True,
    )

    assert result["state"] == "awaiting_readiness"
    assert result["applied_unit_count"] == 16
    assert (state_directory / "request.json").is_file()
    assert not (state_directory / "last-result.json").exists()
    assert credential_removal_states == ["awaiting_readiness"]
    assert not credentials_path.exists()
    assert scheduled == [("readiness",)]
    assert login_cleanup_events == ["credentials scrubbed", "sessions terminated"]


def test_factory_reset_readiness_requires_ssh_service():
    """Post-scrub readiness restores and verifies factory SSH admission."""
    import atlaso.app.factory_reset as factory_reset

    assert "sshd.service" in factory_reset.FACTORY_RESET_REQUIRED_SERVICES


def test_factory_reset_preflight_uses_generated_config_validators(monkeypatch):
    """Real preflight validates generated nginx and sshd artifacts without applying them.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    calls: list[tuple[str, str, tuple[object, ...]]] = []

    def fake_helper_result(
        _adapter,
        group: str,
        action: str,
        *args: object,
        **_kwargs: object,
    ) -> AdapterResult:
        """Record one generated-config helper call.

        Args:
            _adapter: Adapter instance receiving the method call.
            group: Helper command group.
            action: Helper action.
            *args: Helper positional arguments.
            **_kwargs: Helper keyword arguments ignored by the test double.
        """
        calls.append((group, action, args))
        return AdapterResult(command=[group, action], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", fake_helper_result)
    adapter = factory_reset._ValidationOnlyAdapter()

    adapter.apply_appliance_settings_config("/tmp/appliance.json")
    adapter.apply_vcf_backup_config("/tmp/backups.conf")
    adapter.apply_public_services_config("/tmp/public.conf")

    assert calls == [
        ("appliance-settings", "preflight", ("/tmp/appliance.json",)),
        ("vcf-backups", "preflight", ("/tmp/backups.conf",)),
        ("public-services", "preflight", ("/tmp/public.conf",)),
    ]


def test_factory_reset_readiness_finalizer_is_detached(monkeypatch):
    """The finalizer must release its caller before trying to acquire the reset lock.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        """Record one systemd-run command.

        Args:
            command: Exact command arguments.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(factory_reset.shutil, "which", lambda _command: "/usr/bin/systemd-run")
    monkeypatch.setattr(factory_reset.subprocess, "run", fake_run)

    factory_reset._schedule_readiness_finalizer()

    assert len(commands) == 1
    assert "--collect" in commands[0]
    assert "--no-block" in commands[0]
    assert commands[0][-4:] == [sys.executable, "-m", "atlaso.app.factory_reset", "finalize"]


def test_factory_reset_finalizer_requires_stable_management_readiness(tmp_path, monkeypatch):
    """Terminal success follows two consecutive service and OpenAPI readiness samples.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "awaiting_readiness",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "waiting",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    credentials_path = state_directory / "credentials.json"
    credentials_path.write_text("lingering secret plan", encoding="utf-8")
    samples = iter([False, True, True])
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: next(samples))

    result = finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not request_path.exists()
    assert not credentials_path.exists()
    assert json.loads((state_directory / "last-result.json").read_text(encoding="utf-8"))["state"] == "succeeded"


def test_factory_reset_finalizer_retains_failed_marker_when_readiness_never_stabilizes(
    tmp_path,
    monkeypatch,
):
    """A restart or OpenAPI failure remains resumable and never publishes success.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "awaiting_readiness",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "waiting",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    monotonic = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: False)
    monkeypatch.setattr(factory_reset.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(FactoryResetError, match="did not stabilize"):
        finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert json.loads(request_path.read_text(encoding="utf-8"))["state"] == "failed"
    assert not (state_directory / "last-result.json").exists()


def test_factory_reset_finalizer_retries_post_commit_failure(tmp_path, monkeypatch):
    """A failed readiness attempt resumes activation instead of rebuilding defaults.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "failed",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "readiness failed",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: True)

    result = finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not request_path.exists()


def test_factory_host_inventory_is_stable_across_startup_refresh(tmp_path):
    """Factory reset baselines every host NIC in its final desired posture.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'atlaso.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(
            db,
            include_examples=False,
            factory_defaults=True,
            commit=False,
        )
        _seed_factory_host_interfaces(
            db,
            [
                HostPhysicalInterface(
                    name="eth0",
                    mac_address="00:50:56:00:00:01",
                    driver="vmxnet3",
                    speed="10 Gbps",
                    host_ip_cidr="192.168.167.249/24",
                    host_ipv6_cidr=None,
                    host_mtu=1500,
                    host_admin_state="up",
                    oper_state="up",
                ),
                HostPhysicalInterface(
                    name="eth1",
                    mac_address="00:50:56:00:00:02",
                    driver="vmxnet3",
                    speed="10 Gbps",
                    host_ip_cidr=None,
                    host_ipv6_cidr=None,
                    host_mtu=1500,
                    host_admin_state="up",
                    oper_state="up",
                ),
            ],
        )
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()

        assert [interface.name for interface in interfaces] == ["eth0", "eth1"]
        assert interfaces[0].mac_address == "00:50:56:00:00:01"
        assert interfaces[0].ip_cidr == "192.168.49.1/24"
        assert interfaces[0].admin_state == "up"
        assert interfaces[1].role == "unused"
        assert interfaces[1].ip_cidr is None
        assert interfaces[1].admin_state == "down"
        assert {interface.desired_state_source for interface in interfaces} == {"factory-reset"}
    engine.dispose()


def test_complete_factory_reset_replaces_database_and_establishes_baselines(
    tmp_path,
    monkeypatch,
):
    """Factory reset removes prior records and leaves every apply unit current.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    depot_payload = tmp_path / "depot" / "payload.bin"
    backup_payload = tmp_path / "backups" / "backup.bin"
    storage_payload = tmp_path / "storage" / "volume.bin"
    for payload in (depot_payload, backup_payload, storage_payload):
        payload.parent.mkdir(parents=True, exist_ok=True)
        payload.write_bytes(b"preserve-me")

    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        from atlaso.app.ui import save_appliance_apply_baselines

        save_appliance_apply_baselines(
            db,
            {"retired-legacy-unit": {"fingerprint": "pre-reset-state"}},
        )
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        db.add(User(username="remove-me", role="admin"))
        db.add(
            ApiToken(
                jti="remove-token",
                name="remove-token",
                owner_user_id=admin.id,
                owner_username=admin.username,
                role="admin",
                scopes="admin:all",
                expires_at=admin.created_at,
                token_hash="remove-hash",
            )
        )
        db.add(AuditEvent(actor="remove-me", action="remove-audit", resource_type="test"))
        db.add(Job(id="remove-job", type="managed-script", status="succeeded", created_by="remove-me"))
        db.add(Setting(key="remove.setting", value="remove-value"))
        db.commit()
    engine.dispose()

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    monkeypatch.setenv("ATLASO_APPLIANCE_FQDN", "deployment.example.test")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_CIDR", "dhcp")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED", "true")
    monkeypatch.setenv("ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS", "")
    get_settings.cache_clear()
    adapter = SystemAdapter(dry_run=True)
    runtime_cleanup_calls: list[bool] = []
    monkeypatch.setattr(
        adapter,
        "reset_factory_network_runtime",
        lambda: runtime_cleanup_calls.append(True)
        or AdapterResult(command=["atlaso-helper", "factory-reset", "reset-network-runtime"], dry_run=True),
    )
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=adapter,
        manage_services=False,
    )

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert runtime_cleanup_calls == [True]
    assert not (state_directory / "request.json").exists()
    assert json.loads((state_directory / "last-result.json").read_text(encoding="utf-8"))["state"] == "succeeded"
    for payload in (depot_payload, backup_payload, storage_payload):
        assert payload.read_bytes() == b"preserve-me"

    replacement_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    replacement_session = sessionmaker(
        bind=replacement_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    with replacement_session() as db:
        assert {user.username for user in db.execute(select(User)).scalars()} == {
            "admin",
            "vcf-backup",
            "vcf-depot",
        }
        assert db.execute(select(ApiToken)).scalars().all() == []
        assert db.execute(select(AuditEvent)).scalars().all() == []
        assert db.execute(select(Job)).scalars().all() == []
        assert db.execute(select(VcfDepotDownloadProfile)).scalars().all() == []
        assert db.execute(
            select(Setting).where(Setting.key == FACTORY_RESET_SETTING_KEY)
        ).scalar_one().value == "complete"
        assert db.execute(select(Setting).where(Setting.key == "remove.setting")).scalar_one_or_none() is None
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert appliance_settings.fqdn == "core.atlaso.internal"
        assert appliance_settings.management_https_enabled is False
        assert appliance_settings.root_ssh_enabled is False
        assert appliance_settings.external_dns_servers == "1.1.1.1\n9.9.9.9"
        management_interface = db.execute(select(PhysicalInterface)).scalar_one()
        assert management_interface.ipv4_method == "static"
        assert management_interface.ip_cidr == "192.168.49.1/24"
        assert management_interface.gateway is None
        assert management_interface.ipv6_enabled is False
        assert management_interface.ipv6_cidr is None
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert dns_settings.upstream_servers == "1.1.1.1\n9.9.9.9"
        from atlaso.app.ui import appliance_apply_units, load_appliance_apply_baselines

        verified_units = appliance_apply_units(db, reconcile=False)
        assert [unit["label"] for unit in verified_units if unit["changed"]] == []
        assert set(load_appliance_apply_baselines(db)) == {
            unit["id"] for unit in verified_units
        }
    replacement_engine.dispose()


def test_complete_factory_reset_publishes_factory_management_binding_immediately(
    client,
    tmp_path,
    monkeypatch,
):
    """Reset admission follows the applied factory binding without a reconciliation delay.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.database as database
    import atlaso.app.factory_reset as factory_reset
    from atlaso.app.services.appliance_settings import APPLIANCE_DNS_RECORD_DESCRIPTION
    from atlaso.app.ui import appliance_apply_units, save_appliance_apply_baselines

    database_path = tmp_path / "atlaso-test.db"
    old_ipv4 = "192.168.167.249"
    old_ipv6 = "2001:db8::249"
    monkeypatch.setenv("ATLASO_ENVIRONMENT", "appliance")
    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(tmp_path / "factory-reset"))
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    get_settings.cache_clear()

    with database.SessionLocal() as db:
        management = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        management.ip_cidr = f"{old_ipv4}/24"
        management.host_ip_cidr = f"{old_ipv4}/24"
        management.ipv6_enabled = True
        management.ipv6_cidr = f"{old_ipv6}/64"
        management.host_ipv6_cidr = f"{old_ipv6}/64"
        save_appliance_apply_baselines(
            db,
            {
                "network": {
                    "config_preview": f"""[physical_interfaces]
interface=eth0
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr={old_ipv4}/24
  ipv6_enabled=true
  ipv6_cidr={old_ipv6}/64
  access_management_ui_enabled=false
"""
                }
            },
        )
        db.commit()

    old_headers = {"host": old_ipv4}
    login_page = client.get("/ui/management/login", headers=old_headers)
    assert login_page.status_code == 200
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/ui/management/login",
        headers=old_headers,
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert client.get("/ui/management/dashboard", headers=old_headers).status_code == 200

    # Dispose pooled handles before the reset atomically replaces the SQLite file, matching service restart.
    database.engine.dispose()
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=True),
        manage_services=False,
    )
    database.engine.dispose()
    assert result["state"] == "succeeded"

    for headers in (
        {"host": "192.168.49.1"},
        {"host": "core.atlaso.internal"},
    ):
        immediate = client.get(
            "/ui/management/dashboard",
            headers=headers,
            follow_redirects=False,
        )
        repeated = client.get(
            "/ui/management/dashboard",
            headers=headers,
            follow_redirects=False,
        )
        for response in (immediate, repeated):
            assert response.status_code == 303
            assert response.headers["location"].startswith("/ui/management/login")

    assert client.get(
        "/ui/management/dashboard",
        headers={"host": old_ipv4},
        follow_redirects=False,
    ).status_code == 404
    assert client.get(
        "/ui/management/dashboard",
        headers={"host": f"[{old_ipv6}]"},
        follow_redirects=False,
    ).status_code == 404

    with database.SessionLocal() as db:
        app_owned_records = db.execute(
            select(DnsRecord).where(
                DnsRecord.description == APPLIANCE_DNS_RECORD_DESCRIPTION
            )
        ).scalars().all()
        assert [
            (record.hostname, record.record_type, record.address)
            for record in app_owned_records
        ] == [("core.atlaso.internal", "A", "192.168.49.1")]
        assert [
            unit["label"]
            for unit in appliance_apply_units(db, reconcile=False)
            if unit["changed"]
        ] == []
        db.add(
            PhysicalInterface(
                name="eth1",
                mac_address="00:50:56:00:00:02",
                host_ip_cidr="192.168.50.1/24",
                host_mtu=1500,
                host_admin_state="up",
                ip_cidr="192.168.50.1/24",
                admin_state="up",
                oper_state="up",
                role="access",
                mode="access",
                access_management_ui_enabled=False,
            )
        )
        db.commit()

    access_headers = {"host": "192.168.50.1"}
    assert client.get("/ui/management/dashboard", headers=access_headers).status_code == 404
    assert client.get("/ui/public", headers=access_headers).status_code == 200


def test_complete_factory_reset_retains_recovery_marker_after_failure(
    tmp_path,
    monkeypatch,
):
    """An interrupted reset keeps the old database and a resumable marker.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        db.add(User(username="retained-after-failure", role="admin"))
        db.commit()
    engine.dispose()

    class FailingAdapter(SystemAdapter):
        """Fail the first activation after candidate validation."""

        def __init__(self) -> None:
            super().__init__(dry_run=True)

        def apply_local_users_config(self, config_path: str):
            """Inject one Local Users activation failure.

            Args:
                config_path: Staged Local Users configuration path.
            """
            result = super().apply_local_users_config(config_path)
            return type(result)(
                command=result.command,
                dry_run=True,
                stderr="injected activation failure",
                returncode=1,
            )

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    import pytest

    with pytest.raises(Exception, match="Local Users"):
        run_factory_reset(
            database_url=f"sqlite:///{database_path}",
            adapter=FailingAdapter(),
            manage_services=False,
        )

    marker = json.loads((state_directory / "request.json").read_text(encoding="utf-8"))
    assert marker["state"] == "failed"
    retained_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    retained_session = sessionmaker(bind=retained_engine)
    with retained_session() as db:
        assert db.execute(
            select(User).where(User.username == "retained-after-failure")
        ).scalar_one() is not None
    retained_engine.dispose()


def test_complete_factory_reset_resumes_after_post_replacement_interruption(
    tmp_path,
    monkeypatch,
):
    """A failure after atomic replacement can idempotently finish on resume.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        db.add(Setting(key="removed-before-resume", value="yes"))
        db.commit()
    engine.dispose()

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    replace_database = factory_reset._replace_database

    def interrupt_after_replace(source, candidate):
        """Inject an interruption immediately after database replacement.

        Args:
            source: Installed database path.
            candidate: Validated replacement database path.
        """
        replace_database(source, candidate)
        raise FactoryResetError("injected post-replacement interruption")

    monkeypatch.setattr(factory_reset, "_replace_database", interrupt_after_replace)
    with pytest.raises(FactoryResetError, match="post-replacement"):
        run_factory_reset(
            database_url=f"sqlite:///{database_path}",
            adapter=SystemAdapter(dry_run=True),
            manage_services=False,
        )

    marker = json.loads((state_directory / "request.json").read_text(encoding="utf-8"))
    assert marker["state"] == "failed"
    interrupted_engine = create_engine(f"sqlite:///{database_path}")
    with sessionmaker(bind=interrupted_engine)() as db:
        assert db.execute(
            select(Setting).where(Setting.key == "removed-before-resume")
        ).scalar_one_or_none() is None
    interrupted_engine.dispose()

    monkeypatch.setattr(factory_reset, "_replace_database", replace_database)
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=True),
        manage_services=False,
    )

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not (state_directory / "request.json").exists()
