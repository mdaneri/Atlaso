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
    """Both Apply modes preserve populated legacy bytes without invoking a writer."""
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
    """No result is returned until service restoration or offline import completes."""
    helper = load_helper_module()
    initial = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (False, False)}
    states = dict(initial)
    commands = []
    proofs = []
    monkeypatch.setattr(helper, "_kms_service_snapshot", lambda unit: states[unit])
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda **kwargs: proofs.append(kwargs))
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic-target")
    monkeypatch.setattr(helper, "_ensure_kms_service_identity", lambda: (SimpleNamespace(pw_uid=1000), SimpleNamespace(gr_gid=1000)))

    def run(command, **kwargs):
        commands.append(command)
        action_name, unit = command[1], command[-1]
        active, enabled = states[unit]
        states[unit] = (False if "--now" in command else action_name == "restart" if action_name in {"restart", "stop"} else active,
                        action_name == "enable" if action_name in {"enable", "disable"} else enabled)
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
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


def test_unavailable_operation_lock_refuses_without_dispatch(monkeypatch):
    """Unsupported locking never falls back to an unguarded store mutation."""
    helper = load_helper_module()
    monkeypatch.setattr(helper, "fcntl", None)
    monkeypatch.setattr(helper, "_handle_kms_locked", lambda *_args: pytest.fail("unguarded dispatch"))
    assert helper._handle_kms("apply", ["synthetic"]) == 2


@pytest.mark.parametrize("action", ["recovery-export", "recovery-import"])
def test_live_recovery_main_returns_one_json_document(monkeypatch, capsys, action):
    """The actual CLI path must remain consumable by the control plane parser."""
    helper = load_helper_module()

    def dispatch(observed, args):
        assert (observed, args) == (action, [])
        print(json.dumps({"archive": "synthetic"}))
        return 0

    monkeypatch.setattr(helper, "_handle_kms", dispatch)
    assert helper.main(["atlaso-helper", "kms", action, "--real"]) == 0
    assert json.loads(capsys.readouterr().out) == {"archive": "synthetic"}


def test_export_restoration_false_success_retains_checkpoint(monkeypatch, capsys):
    """A restart that exits zero but never becomes healthy cannot finish recovery."""
    helper = load_helper_module()
    states = {"atlaso-kmip.service": (True, True), "atlaso-kms.service": (False, False)}
    children = []
    monkeypatch.setattr(helper, "_kms_service_snapshot", lambda unit: states[unit])
    monkeypatch.setattr(helper, "_kms_legacy_check", lambda **_kwargs: None)
    monkeypatch.setattr(helper, "_kms_secrets_key", lambda: "synthetic")
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)

    def run(command, **_kwargs):
        unit = command[-1]
        if command[1] == "stop":
            states[unit] = (False, states[unit][1])
        # Intentionally claim restart success while leaving the service inactive.
        return subprocess.CompletedProcess(command, 0, "", "")

    def child(request):
        children.append(request["action"])
        document = {"states": states} if request["action"] == "service-capture" else {"archive": "synthetic"}
        return subprocess.CompletedProcess([], 0, json.dumps(document), "")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_kms_recovery_child", child)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps({"passphrase": "synthetic-passphrase", "trust": {}})))
    assert helper._handle_kms_recovery("recovery-export", []) == 2
    assert children == ["service-capture", "export"]
    assert not capsys.readouterr().out
