"""Exercise recovery service ordering and unchanged legacy-data rejection."""

import io
import json
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from atlaso.app.kmip.legacy import assert_legacy_empty
from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("enabled", [False, True])
def test_nonempty_legacy_blocks_apply_before_service_or_file_changes(tmp_path, monkeypatch, enabled):
    """Both Apply modes preserve populated legacy bytes without invoking a writer.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
        enabled: Desired KMS listener state for the scenario.
    """
    helper = load_helper_module()
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    database = legacy / "pykmip.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE objects(id INTEGER PRIMARY KEY)")
        db.execute("INSERT INTO objects VALUES(1)")
    before = database.read_bytes()
    config = tmp_path / "server.json"
    config.write_text(json.dumps({"enabled": enabled}))
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", tmp_path / "runtime")
    monkeypatch.setattr(helper, "_validate_kms_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda: assert_legacy_empty(legacy, tmp_path / "missing.conf"))
    monkeypatch.setattr(helper, "_run", lambda *_args, **_kwargs: pytest.fail("legacy rejection reached a service mutation"))
    with pytest.raises(ValueError):
        helper._handle_kms_locked("apply", [str(config)])
    assert database.read_bytes() == before
    assert not (tmp_path / "runtime").exists()


@pytest.mark.parametrize("action,child_success", [("recovery-export", True), ("recovery-export", False), ("recovery-import", False), ("recovery-import", True)])
def test_recovery_quiesces_both_writers_and_restores_or_keeps_offline(monkeypatch, capsys, action, child_success):
    """No result is returned until service restoration or offline import completes.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        capsys: Capsys supplied to this operation.
        action: Fixed supported privileged helper action.
        child_success: Child success supplied to this operation.
    """
    helper = load_helper_module()
    initial = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (False, False)}
    states = dict(initial)
    commands = []
    proofs = []
    monkeypatch.setattr(helper, "_kms_service_snapshot", lambda unit: states[unit])
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda **kwargs: proofs.append(kwargs))
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic-target")
    monkeypatch.setattr(helper, "_ensure_kms_service_identity", lambda **_kwargs: (SimpleNamespace(pw_uid=1000), SimpleNamespace(gr_gid=1000)))

    def run(command, **kwargs):
        """Run.

        Args:
            command: Command supplied to this operation.
            **kwargs: Kwargs supplied to this operation.
        """
        commands.append(command)
        action_name, unit = command[1], command[-1]
        active, enabled = states[unit]
        states[unit] = (False if "--now" in command else action_name == "restart" if action_name in {"restart", "stop"} else active,
                        action_name == "enable" if action_name in {"enable", "disable"} else enabled)
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
        """Child.

        Args:
            request: Validated helper request containing operation and service posture.
        """
        if request["action"] == "service-capture":
            assert states == initial
            return subprocess.CompletedProcess([], 0, json.dumps({"states": initial}), "")
        if request["action"] == "service-finish":
            assert states == initial
            return subprocess.CompletedProcess([], 0, "{}", "")
        assert not any(active for active, _ in states.values())
        assert request["secrets_key"] == "synthetic-target"
        return subprocess.CompletedProcess([], 0 if child_success else 2, "{}", "sensitive child diagnostics excluded")

    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_kms_recovery_child", child)
    payload = {"passphrase": "synthetic-passphrase", "trust": {}} if action == "recovery-export" else {"passphrase": "synthetic-passphrase", "archive": "synthetic-archive"}
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps(payload)))
    result = helper._handle_kms_recovery(action, [])
    assert result == (0 if child_success else 2)
    assert proofs == [{}, {"stopped": True}]
    if action == "recovery-import" and child_success:
        assert not any(active or enabled for active, enabled in states.values())
    else:
        assert states == initial
    output = capsys.readouterr()
    assert "synthetic-target" not in output.out + output.err
    assert "sensitive child diagnostics" not in output.out + output.err
    assert all("synthetic" not in " ".join(command) for command in commands)


@pytest.mark.parametrize("action", ["apply", "status", "listener-status", "recovery-export", "recovery-import"])
def test_unavailable_operation_lock_refuses_without_dispatch(monkeypatch, action):
    """Unsupported locking never falls back to an unguarded store mutation.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        action: KMIP operation which must never bypass unavailable locking.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "fcntl", None)
    monkeypatch.setattr(helper, "_handle_kms_locked", lambda *_args: pytest.fail("unguarded dispatch"))
    monkeypatch.setattr(helper, "_handle_kms_recovery", lambda *_args: pytest.fail("unguarded recovery"))
    assert helper._handle_kms(action, []) == 2


@pytest.mark.parametrize("action", ["recovery-export", "recovery-import"])
def test_live_recovery_main_returns_one_json_document(monkeypatch, capsys, action):
    """The actual CLI path must remain consumable by the control plane parser.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        capsys: Capsys supplied to this operation.
        action: Fixed supported privileged helper action.
    """
    helper = load_helper_module()

    def dispatch(observed, args):
        """Dispatch.

        Args:
            observed: Observed supplied to this operation.
            args: Args supplied to this operation.
        """
        assert (observed, args) == (action, [])
        print(json.dumps({"archive": "synthetic"}))
        return 0

    monkeypatch.setattr(helper, "_handle_kms", dispatch)
    assert helper.main(["atlaso-helper", "kms", action, "--real"]) == 0
    assert json.loads(capsys.readouterr().out) == {"archive": "synthetic"}


def test_export_restoration_false_success_retains_checkpoint(monkeypatch, capsys):
    """A restart that exits zero but never becomes healthy cannot finish recovery.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        capsys: Capsys supplied to this operation.
    """
    helper = load_helper_module()
    states = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (False, False)}
    children = []
    monkeypatch.setattr(helper, "_kms_service_snapshot", lambda unit: states[unit])
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic")
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)

    def run(command, **_kwargs):
        """Run.

        Args:
            command: Command supplied to this operation.
            **_kwargs: Kwargs supplied to this operation.
        """
        unit = command[-1]
        if command[1] == "stop":
            states[unit] = (False, states[unit][1])
        # Intentionally claim restart success while leaving the service inactive.
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
        """Child.

        Args:
            request: Validated helper request containing operation and service posture.
        """
        children.append(request["action"])
        document = {"states": states} if request["action"] == "service-capture" else {"archive": "synthetic"}
        return subprocess.CompletedProcess([], 0, json.dumps(document), "")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_kms_recovery_child", child)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps({"passphrase": "synthetic-passphrase", "trust": {}})))
    assert helper._handle_kms_recovery("recovery-export", []) == 2
    assert children == ["service-capture", "export"]
    assert not capsys.readouterr().out


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_factory_reset_recovery_rejects_unsafe_anchor_before_mutation(tmp_path, monkeypatch, kind):
    """A redirected or non-directory anchor cannot expand reset's removal scope.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
        kind: Kind supplied to this operation.
    """
    helper = load_helper_module()
    anchor = tmp_path / "recovery"
    outside = tmp_path / "preserved"
    outside.mkdir()
    sentinel = outside / "retained"
    sentinel.write_bytes(b"unchanged")
    if kind == "file":
        anchor.write_bytes(b"unchanged")
    else:
        try:
            anchor.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("Host does not permit creating directory symlinks")
    monkeypatch.setattr(helper, "KMS_RECOVERY_DIR", anchor)
    with pytest.raises(ValueError, match="recovery directory is unsafe"):
        helper._remove_factory_reset_kmip_recovery()
    assert sentinel.read_bytes() == b"unchanged"
    assert anchor.exists()


def test_factory_reset_recovery_partial_failure_remains_retryable(tmp_path, monkeypatch):
    """Interrupted retained-candidate deletion cannot report completion or block retry.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    helper = load_helper_module()
    anchor = tmp_path / "recovery"
    candidate = anchor / "candidate-synthetic"
    candidate.mkdir(parents=True)
    (candidate / "kek.json").write_bytes(b"synthetic custody")
    (anchor / "pending.json").write_bytes(b"synthetic pending marker")
    monkeypatch.setattr(helper, "KMS_RECOVERY_DIR", anchor)
    original = helper.shutil.rmtree
    attempts = 0

    def interrupted(*args, **kwargs):
        """Interrupted.

        Args:
            *args: Args supplied to this operation.
            **kwargs: Kwargs supplied to this operation.
        """
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic interrupted deletion")
        return original(*args, **kwargs)

    monkeypatch.setattr(helper.shutil, "rmtree", interrupted)
    if hasattr(original, "avoids_symlink_attacks"):
        interrupted.avoids_symlink_attacks = original.avoids_symlink_attacks
    with pytest.raises(OSError):
        helper._remove_factory_reset_kmip_recovery()
    assert candidate.exists()
    assert helper._remove_factory_reset_kmip_recovery() is True
    assert not anchor.exists()
    assert helper._remove_factory_reset_kmip_recovery() is False


def test_factory_reset_absent_recovery_requires_durable_parent_readback(tmp_path, monkeypatch):
    """An unlink whose flush failed must be flushed again before reset can advance.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "KMS_RECOVERY_DIR", tmp_path / "absent-recovery")
    attempts = []

    def sync(parent):
        """Sync.

        Args:
            parent: Parent supplied to this operation.
        """
        attempts.append(parent)
        if len(attempts) == 1:
            raise OSError("synthetic directory-flush failure")

    monkeypatch.setattr(helper, "_fsync_factory_reset_directory", sync)
    with pytest.raises(OSError):
        helper._remove_factory_reset_kmip_recovery()
    assert helper._remove_factory_reset_kmip_recovery() is False
    assert attempts == [tmp_path, tmp_path]


@pytest.mark.parametrize("action,child_timeout", [("recovery-export", False), ("recovery-export", True), ("recovery-import", True)])
def test_outer_recovery_budget_covers_slow_operation_and_restoration(monkeypatch, capsys, action, child_timeout):
    """Slow bounded child and service calls leave enough time for restoration.

    Args:
        monkeypatch: Pytest fixture replacing subprocesses and the clock.
        capsys: Pytest fixture capturing the single safe helper response.
        action: Recovery operation exercised under worst-case bounded latency.
        child_timeout: Whether the operational child exhausts its inner timeout.
    """
    from atlaso.app.services.kmip_recovery import RECOVERY_HELPER_TIMEOUT_SECONDS

    helper = load_helper_module()
    elapsed = 0
    initial = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (True, True)}
    states = dict(initial)
    restored = []

    def advance(seconds):
        """Advance the synthetic clock without sleeping.

        Args:
            seconds: Bounded operation latency to account for.
        """
        nonlocal elapsed
        elapsed += seconds
        assert elapsed < RECOVERY_HELPER_TIMEOUT_SECONDS

    def snapshot(unit):
        """Return the service state after a maximally slow supported probe.

        Args:
            unit: Writer whose service state is observed.
        """
        advance(30)
        return states[unit]

    def legacy(**_kwargs):
        """Budget conservative legacy checks without reading a real store.

        Args:
            **_kwargs: Optional stopped-writer proof request.
        """
        advance(90)

    def run(command, **kwargs):
        """Run a simulated bounded service command and update its posture.

        Args:
            command: Exact service command emitted by recovery.
            **kwargs: Explicit timeout supplied by the helper.
        """
        advance(kwargs["timeout"])
        operation, unit = command[1], command[-1]
        active, enabled = states[unit]
        states[unit] = (False if "--now" in command else operation == "restart" if operation in {"restart", "stop"} else active,
                        operation == "enable" if operation in {"enable", "disable"} else enabled)
        restored.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
        """Consume a whole child budget, including checkpoint and finish calls.

        Args:
            request: Isolated recovery operation dispatched by the helper.
        """
        advance(120)
        if request["action"] == "service-capture":
            return subprocess.CompletedProcess([], 0, json.dumps({"states": initial}), "")
        if request["action"] in {"export", "import"} and child_timeout:
            raise subprocess.TimeoutExpired("synthetic recovery", 120)
        return subprocess.CompletedProcess([], 0, "{}", "")

    monkeypatch.setattr(helper, "_kms_service_snapshot", snapshot)
    monkeypatch.setattr(helper, "_kms_legacy_check", legacy)
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic")
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_kms_recovery_child", child)
    monkeypatch.setattr(helper.time, "sleep", advance)
    monkeypatch.setattr(helper, "_ensure_kms_service_identity", lambda **_kwargs: (SimpleNamespace(pw_uid=1000), SimpleNamespace(gr_gid=1000)))
    payload = {"passphrase": "synthetic", "trust": {}} if action == "recovery-export" else {"passphrase": "synthetic", "archive": "synthetic"}
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps(payload)))
    assert helper._handle_kms_recovery(action, []) == (2 if child_timeout else 0)
    assert states == initial
    assert elapsed > 180
    assert ["systemctl", "restart", "atlaso-kmip.service"] in restored
    capsys.readouterr()


@pytest.mark.parametrize("command_timeout", [None, 30])
def test_recovery_identity_commands_accept_bounded_timeout(monkeypatch, command_timeout):
    """Bound recovery account creation without changing ordinary callers.

    Args:
        monkeypatch: Pytest fixture replacing account tools and lookup functions.
        command_timeout: Explicit recovery bound or ordinary caller default.
    """
    helper = load_helper_module()
    calls = []

    def run(command, **kwargs):
        """Record account commands without creating any host identity.

        Args:
            command: Account tool and fixed reconciliation arguments.
            **kwargs: Optional subprocess budget forwarded by the helper.
        """
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_kms_service_identity_available", lambda: (False, False))
    monkeypatch.setattr(helper, "_command_path", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1000))
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1000))
    helper._ensure_kms_service_identity(command_timeout=command_timeout)
    assert len(calls) == 2
    assert all(options == ({} if command_timeout is None else {"timeout": 30}) for _command, options in calls)


@pytest.mark.parametrize("pending_present", [False, True])
def test_rejected_archive_releases_restored_checkpoint_for_corrected_input(monkeypatch, capsys, pending_present):
    """A rejected archive cannot strand its binding after verified restoration.

    Args:
        monkeypatch: Pytest fixture isolating service operations and checkpoint custody.
        capsys: Pytest fixture capturing safe helper responses.
        pending_present: Whether publication has already created pending custody.
    """
    helper = load_helper_module()
    initial = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (False, False)}
    states = dict(initial)
    checkpoint = None
    finishes = []

    def run(command, **_kwargs):
        """Apply the simulated systemd posture change without host mutation.

        Args:
            command: Bounded writer service operation.
            **_kwargs: Explicit helper subprocess timeout.
        """
        operation, unit = command[1], command[-1]
        active, enabled = states[unit]
        states[unit] = (False if "--now" in command else operation == "restart" if operation in {"restart", "stop"} else active,
                        operation == "enable" if operation in {"enable", "disable"} else enabled)
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
        """Model exclusive checkpoint binding and a rejected followed by valid archive.

        Args:
            request: Fixed recovery action and request-bound payload.
        """
        nonlocal checkpoint
        if request["action"] == "service-capture":
            if checkpoint is not None and checkpoint != request["binding"]:
                return subprocess.CompletedProcess([], 2, "", "")
            checkpoint = request["binding"]
            return subprocess.CompletedProcess([], 0, json.dumps({"states": initial}), "")
        if request["action"] == "service-finish":
            assert states == initial
            finishes.append(checkpoint)
            checkpoint = None
            return subprocess.CompletedProcess([], 0, "{}", "")
        return subprocess.CompletedProcess([], 2 if request["archive"] == "invalid" else 0, "{}", "")

    lexists = helper.os.path.lexists
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: pending_present if str(path) == "/var/lib/atlaso-kmip-recovery/pending.json" else lexists(path))
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_kms_service_snapshot", lambda unit: states[unit])
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic")
    monkeypatch.setattr(helper, "_ensure_kms_service_identity", lambda **_kwargs: (SimpleNamespace(pw_uid=1000), SimpleNamespace(gr_gid=1000)))
    monkeypatch.setattr(helper, "_kms_recovery_child", child)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps({"passphrase": "synthetic", "archive": "invalid"})))
    assert helper._handle_kms_recovery("recovery-import", []) == 2
    if pending_present:
        assert checkpoint is not None and not finishes
        assert not states["atlaso-kmip.service"][0]
        capsys.readouterr()
        return
    assert states == initial and checkpoint is None and len(finishes) == 1
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps({"passphrase": "synthetic", "archive": "corrected"})))
    assert helper._handle_kms_recovery("recovery-import", []) == 0
    assert checkpoint is not None
    assert not any(active or enabled for active, enabled in states.values())
    capsys.readouterr()
