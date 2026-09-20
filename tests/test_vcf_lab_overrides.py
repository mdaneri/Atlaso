"""Exercise fixed property edits, reviewed state, custody and failure outcomes."""

import json
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import AuditEvent, Setting, User, Vault, VaultEntry
from atlaso.app.services import vcf_lab_overrides as lab
from atlaso.app.services.vcf_lab_remote import (
    KEYS,
    PropertyError,
    edit_properties,
    properties,
)


@pytest.mark.parametrize(
    "desired", [{"esa": "true"}, {"nic": "false"}, {"esa": "true", "nic": "false"}]
)
@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_property_edits_are_idempotent_and_preserve_unrelated_bytes(desired, ending):
    original = b"# vendor configuration\r\nsecret.example=keep-this-value" + ending
    changed = edit_properties(original, desired)
    assert changed.endswith(original)
    assert edit_properties(changed, desired) == changed
    values, _ = properties(changed)
    assert all(values[key] == value for key, value in desired.items())
    assert edit_properties(changed, dict.fromkeys(desired)) == original


def test_existing_properties_and_unselected_values():
    original = (
        f"# keep\n{KEYS['esa']} = false\n{KEYS['nic']}: true\ntail=x\n"
    ).encode()
    changed = edit_properties(original, {"esa": "true"})
    assert properties(changed)[0] == {"esa": "true", "nic": "true"}
    assert f"{KEYS['nic']}: true\n".encode() in changed
    assert changed.count(KEYS["esa"].encode()) == 1
    reverted = edit_properties(changed, {"esa": "false"})
    assert properties(reverted)[0] == {"esa": "false", "nic": "true"}


@pytest.mark.parametrize(
    "text",
    [
        f"{KEYS['esa']}=true\n{KEYS['esa']}=false\n",
        f"{KEYS['esa']}=true\nvsan\\.esa.sddc.managed.disk.claim=false\n",
        "vsan.esa.sddc.managed.disk.\\\nclaim=true\n",
        f"{KEYS['esa']}=unexpected-secret\n",
        f"{KEYS['esa']}=true\x00",
    ],
)
def test_ambiguous_properties_fail_closed_without_disclosing_content(text):
    with pytest.raises(PropertyError) as error:
        edit_properties(text.encode(), {"esa": "true"})
    assert "unexpected-secret" not in str(error.value)


def test_escaped_key_is_updated_not_duplicated():
    changed = edit_properties(
        b"vsan\\.esa.sddc.managed.disk.claim=false\n", {"esa": "true"}
    )
    assert changed == f"{KEYS['esa']}=true\n".encode()


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        vault = Vault(name="Lab", created_by="admin")
        session.add(vault)
        session.add(
            User(username="admin", role="admin", roles_json='["admin"]', enabled=True)
        )
        session.flush()
        for identifier, username, uri in [
            (1, "admin@local", "https://vcf.example.test"),
            (2, "root", "ssh://vcf.example.test"),
        ]:
            session.add(
                VaultEntry(
                    id=identifier,
                    vault_id=vault.id,
                    key=str(identifier),
                    secret_type="vcf_password",
                    username=username,
                    uris_json=json.dumps([uri]),
                    encrypted_value="never-decrypt-this",
                    created_by="admin",
                )
            )
        session.commit()

        @contextmanager
        def session_factory():
            yield session

        monkeypatch.setattr(lab, "SessionLocal", session_factory)
        yield session
    engine.dispose()


@pytest.fixture
def values():
    return {
        "api_entry_id": 1,
        "api_uri_index": 1,
        "ssh_entry_id": 2,
        "ssh_uri_index": 1,
        "tls_fingerprint": "confirmed-tls",
        "ssh_fingerprint": "confirmed-ssh",
        "confirmed": True,
        "selections": ["esa", "nic"],
    }


@pytest.fixture
def state(monkeypatch):
    current = {
        "target": "vcf.example.test",
        "role": "VcfInstaller",
        "version": "9.1.1.0",
        "revision": "a" * 64,
        "values": {"esa": None, "nic": "true"},
        "service_active": True,
        "warning": lab.WARNING,
    }
    monkeypatch.setattr(lab, "inspect_target", lambda *args: dict(current))
    monkeypatch.setattr(lab, "inspect_properties", lambda *args: dict(current))
    return current


def test_matching_vault_endpoints_required(db, values):
    assert lab.target_from_values(db, values).host == "vcf.example.test"
    db.get(VaultEntry, 2).uris_json = '["ssh://other.example.test"]'
    with pytest.raises(lab.LabOverrideError, match="same hostname"):
        lab.target_from_values(db, values)


@pytest.mark.parametrize("role", ["VcfInstaller", "SddcManager"])
@pytest.mark.parametrize(
    "version", ["9.0.0.0", "9.0.1.0.24962180", "9.0.2", "9.1.0", "9.1.1"]
)
def test_supported_families_and_roles(db, values, monkeypatch, role, version):
    class Api:
        def __init__(self, *args, **kwargs):
            assert kwargs["expected_fingerprint"] == "confirmed-tls"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def appliance_info(self):
            return {"role": role, "version": version}

    monkeypatch.setattr(lab, "VcfDepotApiClient", Api)
    monkeypatch.setattr(lab, "decrypt_secret", lambda value: "test-only-secret")
    assert lab.appliance_info(
        db, lab.target_from_values(db, values), "confirmed-tls"
    ) == {"role": role, "version": version}


@pytest.mark.parametrize(
    "version", ["9.2.0", "9.10.0", "8.0.0", "9.1", "unknown", "9.1.1 malicious"]
)
def test_unsupported_versions(db, values, monkeypatch, version):
    class Api:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def appliance_info(self):
            return {"role": "VcfInstaller", "version": version}

    monkeypatch.setattr(lab, "VcfDepotApiClient", Api)
    monkeypatch.setattr(lab, "decrypt_secret", lambda value: "test-only-secret")
    with pytest.raises(lab.LabOverrideError, match="Only detected"):
        lab.appliance_info(db, lab.target_from_values(db, values), "confirmed-tls")


def test_review_binds_actor_and_is_single_use(db, values, state):
    target = lab.target_from_values(db, values)
    reviewed = lab.review(db, "admin", target, values)
    assert len(reviewed["changes"]) == 2
    with pytest.raises(lab.LabOverrideError, match="another operator"):
        lab.enqueue(db, "other", reviewed["token"])
    job = lab.enqueue(db, "admin", reviewed["token"])
    assert "never-decrypt-this" not in job.task_config_json
    with pytest.raises(lab.LabOverrideError, match="already submitted"):
        lab.enqueue(db, "admin", reviewed["token"])
    other = lab.review(db, "admin", target, values)
    with pytest.raises(lab.LabOverrideError, match="Another operation"):
        lab.enqueue(db, "admin", other["token"])


def test_tampered_expired_and_unconfirmed_reviews(db, values, state, monkeypatch):
    target = lab.target_from_values(db, values)
    with pytest.raises(lab.LabOverrideError, match="Confirm both"):
        lab.review(db, "admin", target, {**values, "confirmed": False})
    reviewed = lab.review(db, "admin", target, values)
    with pytest.raises(lab.LabOverrideError, match="expired or changed"):
        lab.enqueue(db, "admin", reviewed["token"] + "tampered")
    import itsdangerous.timed

    real_time = itsdangerous.timed.time.time
    monkeypatch.setattr(itsdangerous.timed.time, "time", lambda: real_time() + 601)
    with pytest.raises(lab.LabOverrideError, match="expired or changed"):
        lab.enqueue(db, "admin", reviewed["token"])


@pytest.mark.parametrize("failure", ["restart", "exception", "drift", "success"])
def test_job_outcomes_preserve_recovery_state(db, values, state, monkeypatch, failure):
    reviewed = lab.review(db, "admin", lab.target_from_values(db, values), values)
    job = lab.enqueue(db, "admin", reviewed["token"])
    calls = []

    def remote(*args):
        calls.append(args[-1])
        if failure == "exception":
            raise RuntimeError("secret that must not be logged")
        return {
            "ok": failure != "restart",
            "changed": True,
            "values": {"esa": "true", "nic": "false"},
            "service_active": failure != "restart",
        }

    monkeypatch.setattr(lab, "remote", remote)
    monkeypatch.setattr(
        lab,
        "appliance_info",
        lambda *args: {"role": state["role"], "version": state["version"]},
    )
    if failure == "drift":
        state["revision"] = "b" * 64
    lab.run_job(job.id)
    db.refresh(job)
    assert job.status == ("succeeded" if failure == "success" else "failed")
    assert "secret that" not in (job.error or "")
    assert not list(
        db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%")))
    )
    assert json.loads(job.task_config_json)["previous"] == {"esa": None, "nic": "true"}
    assert bool(calls) == (failure != "drift")
    for key in ("esa", "nic"):
        owner = db.scalar(
            select(Setting).where(
                Setting.key == lab._property_owner_key(values["ssh_fingerprint"], key)
            )
        )
        assert (owner.value if owner else None) == (job.id if calls else None)
    if failure == "restart":
        assert json.loads(job.result)["property_verified"] is True
        assert json.loads(job.result)["service_active"] is False


def test_revert_preserves_original_default_and_refuses_drift(db, values, state):
    target = lab.target_from_values(db, values)
    reviewed = lab.review(db, "admin", target, values)
    job = lab.enqueue(db, "admin", reviewed["token"])
    job.status = "failed"  # Restart failure can still need a revert.
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key),
                value=job.id,
            )
        )
    db.commit()
    state["values"] = {"esa": "true", "nic": "false"}
    revert = lab.review(db, "admin", target, {**values, "source_job_id": job.id})
    assert {change["id"]: change["value"] for change in revert["changes"]} == {
        "esa": None,
        "nic": "true",
    }
    state["values"] = {"esa": "false", "nic": "false"}
    with pytest.raises(lab.LabOverrideError, match="overwrite another edit"):
        lab.review(db, "admin", target, {**values, "source_job_id": job.id})


def test_review_requires_nonempty_allowlisted_selection(db, values, state):
    target = lab.target_from_values(db, values)
    for selected in [[], ["arbitrary"], ["esa", "esa"]]:
        with pytest.raises(lab.LabOverrideError):
            lab.review(db, "admin", target, {**values, "selections": selected})


def test_unverified_write_is_not_claimed_as_revertible(db, values, state):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "failed"
    db.commit()
    state["values"] = {"esa": "true", "nic": "false"}
    with pytest.raises(lab.LabOverrideError, match="no verified managed change"):
        lab.review(db, "admin", target, {**values, "source_job_id": job.id})


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("revert", [False, True])
def test_restart_recovery_never_replays_remote_changes(
    db, values, state, dispatched, revert
):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    if dispatched:
        job.status = "running"
    if revert:
        plan = json.loads(job.task_config_json)
        plan["source_job_id"] = "original-operation"
        job.task_config_json = json.dumps(plan)
    job.result = '{"error":"sensitive-remote-output"}'
    db.commit()
    assert lab.recover_interrupted_jobs(db) == 1
    assert job.status == "failed"
    held = list(db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))))
    assert bool(held) is dispatched
    assert "Interrupted" in job.error
    event = db.scalar(select(AuditEvent).where(AuditEvent.resource_id == job.id))
    assert event.actor == "admin" and event.success is False
    assert event.action == (
        "revert_vcf_lab_overrides" if revert else "apply_vcf_lab_overrides"
    )
    detail = json.loads(event.detail)
    assert detail["target"] == target.host
    assert detail["version"] == state["version"]
    assert detail["remote_outcome"] == ("unknown" if dispatched else "not_dispatched")
    assert "sensitive-remote-output" not in event.detail
    assert "never-decrypt-this" not in event.detail
    assert lab.recover_interrupted_jobs(db) == 0
    assert (
        len(
            list(db.scalars(select(AuditEvent).where(AuditEvent.resource_id == job.id)))
        )
        == 1
    )


def test_worker_rechecks_administrator_before_remote_credentials(
    db, values, state, monkeypatch
):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    db.scalar(select(User).where(User.username == "admin")).enabled = False
    db.commit()
    calls = []
    monkeypatch.setattr(lab, "inspect_target", lambda *args: calls.append("remote"))
    lab.run_job(job.id)
    assert job.status == "failed"
    assert "no longer authorized" in job.error
    assert calls == []


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "restart_failure",
        "restart_timeout",
        "readback_failure",
        "drift",
        "noop",
    ],
)
def test_remote_transaction_permissions_restart_and_readback(
    tmp_path, monkeypatch, mode
):
    """Run the actual transaction with only Linux OS/service boundaries substituted."""
    import os
    import stat
    import subprocess
    import sys
    from types import SimpleNamespace

    from atlaso.app.services import vcf_lab_remote as remote

    path = tmp_path / "application-prod.properties"
    path.write_bytes(b"vendor.setting=untouched\n")
    if mode == "noop":
        path.write_bytes(edit_properties(path.read_bytes(), {"esa": "true"}))
    monkeypatch.setattr(remote, "CONFIG_PATH", str(path))
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(os, "O_DIRECTORY", 0, raising=False)
    monkeypatch.setattr(sys.modules[remote.__name__], "active", lambda: True)
    monkeypatch.setitem(
        sys.modules,
        "fcntl",
        SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None),
    )
    modes = []
    owners = []
    attributes = []
    monkeypatch.setattr(
        os, "fchown", lambda fd, uid, gid: owners.append((uid, gid)), raising=False
    )
    real_fchmod = os.fchmod

    def record_fchmod(fd, mode):
        modes.append(mode)
        real_fchmod(fd, mode)

    monkeypatch.setattr(os, "fchmod", record_fchmod)
    monkeypatch.setattr(os, "listxattr", lambda p: ["user.test"], raising=False)
    monkeypatch.setattr(os, "getxattr", lambda p, key: b"attribute", raising=False)
    monkeypatch.setattr(
        os,
        "setxattr",
        lambda p, key, value: attributes.append((key, value)),
        raising=False,
    )
    real_open, real_replace = os.open, os.replace

    def mapped_open(name, flags, *args, **kwargs):
        if str(name) == "/run/lock/atlaso-vcf-lab.lock":
            name = tmp_path / "lock"
        if name == path.parent:
            name = tmp_path / "directory-fsync-surrogate"
            flags = os.O_CREAT | os.O_RDWR
        return real_open(name, flags, *args, **kwargs)

    def replace(source, destination):
        real_replace(source, destination)
        if mode == "readback_failure":
            path.write_bytes(b"vendor.setting=concurrently-modified\n")

    monkeypatch.setattr(os, "open", mapped_open)
    monkeypatch.setattr(os, "replace", replace)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if mode == "restart_timeout":
            raise subprocess.TimeoutExpired(command, 90)
        return SimpleNamespace(returncode=1 if mode == "restart_failure" else 0)

    monkeypatch.setattr(subprocess, "run", run)
    inspected = remote.operate({"action": "inspect"})
    before = path.stat()
    assert calls == []
    if mode == "drift":
        path.write_bytes(b"changed=after-review\n")
    request = {
        "action": "write",
        "revision": inspected["revision"],
        "desired": {"esa": "true"},
    }
    if mode in {"drift", "readback_failure"}:
        with pytest.raises(PropertyError):
            remote.operate(request)
        assert calls == []
        return
    outcome = remote.operate(request)
    assert outcome["ok"] == (mode in {"success", "noop"})
    assert outcome["changed"] == (mode != "noop")
    assert path.read_bytes().endswith(b"vendor.setting=untouched\n")
    assert outcome["values"]["esa"] == "true"
    if mode == "noop":
        assert calls == modes == owners == attributes == []
    else:
        assert calls == [["systemctl", "restart", "domainmanager"]]
        assert owners == [(before.st_uid, before.st_gid)]
        assert modes == [stat.S_IMODE(before.st_mode)]
        assert attributes == [("user.test", b"attribute")]


def test_remote_fingerprint_mismatch_never_authenticates(db, values, monkeypatch):
    calls = []

    class Transport:
        def __init__(self, sock):
            pass

        def start_client(self, **kwargs):
            pass

        def get_remote_server_key(self):
            return object()

        def auth_password(self, *args):
            calls.append("auth")

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(
        lab.socket, "create_connection", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(lab.paramiko, "Transport", Transport)
    monkeypatch.setattr(lab, "ssh_fingerprint", lambda key: "different")
    monkeypatch.setattr(lab, "decrypt_secret", lambda value: calls.append("decrypt"))
    with pytest.raises(lab.LabOverrideError, match="host key changed"):
        lab.remote(
            db, lab.target_from_values(db, values), "confirmed", {"action": "inspect"}
        )
    assert calls == ["closed"]


def test_ui_requires_admin_csrf_and_explicit_acknowledgement(client, monkeypatch):
    from tests.routers.ui.helpers import login

    login(client)
    page = client.get("/vcf-helper")
    assert "data-vcf-lab-form" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    path = "/ui/management/vcf-helper/lab-overrides/execute"
    assert client.post(path, json={}).status_code == 403
    response = client.post(
        path, json={"acknowledged": False}, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == 409
    assert "acknowledgement" in response.json()["detail"]
    response = client.post(
        path,
        json={"acknowledged": True, "token": "fake"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 409
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.username == "admin"))
        user.role = "service-admin"
        user.roles_json = roles_to_json(["service-admin"])
        session.commit()
    assert (
        client.get("/ui/management/vcf-helper/lab-overrides/history").status_code == 403
    )
    assert client.post(path, json={}, headers={"X-CSRF-Token": csrf}).status_code == 403


def test_remote_editor_remains_compatible_with_vcf_python():
    """Do not send Atlaso Python 3.14-only syntax to VCF Python 3.10."""
    import ast
    from pathlib import Path

    from atlaso.app.services import vcf_lab_remote

    ast.parse(Path(vcf_lab_remote.__file__).read_text(), feature_version=(3, 10))


@pytest.mark.parametrize("suffix", [b"", b"=value", b" value", b":value"])
def test_long_escaped_unrelated_keys_are_preserved(suffix):
    original = b"\\:" * 100000 + suffix + b"\n"
    assert edit_properties(original, {"esa": "true"}).endswith(original)


def test_probe_keeps_ssh_recovery_available_without_tls(db, values, monkeypatch):
    monkeypatch.setattr(lab, "probe_remote_ssh_host", lambda *args: "confirmed-ssh")

    def unavailable(*args):
        raise OSError("offline")

    monkeypatch.setattr(lab, "tls_sha256_fingerprint", unavailable)
    assert lab.probe(lab.target_from_values(db, values))["tls_fingerprint"] == ""


@pytest.mark.parametrize("role", ["VcfInstaller", "SddcManager"])
def test_revert_reviews_and_executes_without_api(db, values, state, monkeypatch, role):
    state["role"] = role
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "failed"
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key),
                value=job.id,
            )
        )
    for lock in db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))):
        db.delete(lock)
    db.commit()
    state["values"] = {"esa": "true", "nic": "false"}
    state["service_active"] = False

    def unavailable(*args):
        raise lab.LabOverrideError("API unavailable")

    monkeypatch.setattr(lab, "inspect_target", unavailable)
    monkeypatch.setattr(lab, "appliance_info", unavailable)
    reviewed = lab.review(
        db, "admin", target, {**values, "source_job_id": job.id, "tls_fingerprint": ""}
    )
    assert "original verified" in reviewed["identity_source"]
    recovery = lab.enqueue(db, "admin", reviewed["token"])
    assert json.loads(recovery.task_config_json)["tls_fingerprint"] == "confirmed-tls"
    calls = []

    def restore(*args):
        calls.append(args[-1])
        return {
            "ok": True,
            "changed": True,
            "values": {"esa": None, "nic": "true"},
            "service_active": True,
        }

    monkeypatch.setattr(lab, "remote", restore)
    ticks = iter([0, 121])
    monkeypatch.setattr(lab.time, "monotonic", lambda: next(ticks))
    lab.run_job(recovery.id)
    db.refresh(recovery)
    assert calls[0]["desired"] == {"esa": None, "nic": "true"}
    assert recovery.status == "failed"
    result = json.loads(recovery.result)
    assert result["property_verified"] is True
    assert result["api_ready"] is False


def test_apply_rechecks_service_before_writing(db, values, state, monkeypatch):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    state["service_active"] = False
    calls = []
    monkeypatch.setattr(lab, "remote", lambda *args: calls.append(args))
    lab.run_job(job.id)
    assert job.status == "failed"
    assert "stopped after review" in job.error
    assert calls == []
    assert json.loads(job.result)["property_verified"] is False


@pytest.mark.parametrize("superseded_key", ["esa", "nic"])
def test_revert_rejects_superseded_property_with_matching_values(
    db, values, state, superseded_key
):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "succeeded"
    job.result = json.dumps({"changed": True, "property_verified": True})
    state["values"] = {"esa": "true", "nic": "false"}
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key),
                value=job.id,
            )
        )
    db.commit()
    reviewed = lab.review(db, "admin", target, {**values, "source_job_id": job.id})
    db.scalar(
        select(Setting).where(
            Setting.key
            == lab._property_owner_key(values["ssh_fingerprint"], superseded_key)
        )
    ).value = "later-write-or-revert"
    db.commit()
    with pytest.raises(lab.LabOverrideError, match="superseded"):
        lab.review(db, "admin", target, {**values, "source_job_id": job.id})
    for lock in db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))):
        db.delete(lock)
    db.commit()
    recovery = lab.enqueue(db, "admin", reviewed["token"])
    lab.run_job(recovery.id)
    assert recovery.status == "failed"
    assert "superseded" in recovery.error


def test_history_retains_old_property_owners_beyond_recent_limit(db, values, state):
    from datetime import timedelta

    from atlaso.app.models import Job, utcnow

    target = lab.target_from_values(db, values)
    baseline = lab.enqueue(
        db, "admin", lab.review(db, "admin", target, values)["token"]
    )
    baseline.created_at = utcnow() - timedelta(days=10)
    baseline.status = "succeeded"
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key),
                value=baseline.id,
            )
        )
    for index in range(55):
        db.add(
            Job(
                id=f"recent-{index:02}",
                type=lab.JOB_TYPE,
                status="failed",
                created_by="admin",
                task_config_json=baseline.task_config_json,
                created_at=utcnow() + timedelta(seconds=index),
            )
        )
    db.commit()
    history = lab.history(db)
    identifiers = [job["id"] for job in history]
    assert len(identifiers) == 51
    assert identifiers.count(baseline.id) == 1
    assert identifiers[-1] == baseline.id
    assert "recent-00" not in identifiers
    assert "recent-54" in identifiers


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("port", [None, 8443])
def test_vault_api_uri_preserves_explicit_port(db, values, scheme, port):
    uri = f"{scheme}://vcf.example.test" + (f":{port}" if port else "")
    db.get(VaultEntry, 1).uris_json = json.dumps([uri])
    target = lab.target_from_values(db, values)
    assert target.host == "vcf.example.test"
    assert target.api_port == (port or 443)


def test_terminal_outcome_and_audit_share_commit(db, values, state, monkeypatch):
    from sqlalchemy import event

    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    monkeypatch.setattr(
        lab,
        "remote",
        lambda *args: {
            "ok": False,
            "changed": True,
            "values": {"esa": "true", "nic": "false"},
            "service_active": False,
        },
    )
    terminal_commits = []

    def verify_commit(session):
        if job.status in {"succeeded", "failed"}:
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.resource_id == job.id)
            )
            assert audit is not None
            terminal_commits.append(audit.id)

    event.listen(db, "before_commit", verify_commit)
    try:
        lab.run_job(job.id)
    finally:
        event.remove(db, "before_commit", verify_commit)
    assert len(terminal_commits) == 1


def test_recovery_accepts_replacement_credentials_for_same_endpoint(db, values, state):
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "succeeded"
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key),
                value=job.id,
            )
        )
    api, ssh = db.get(VaultEntry, 1), db.get(VaultEntry, 2)
    api.id, ssh.id = 11, 12
    api.uris_json = '["https://other.test", "https://vcf.example.test"]'
    ssh.uris_json = '["ssh://other.test", "ssh://vcf.example.test"]'
    db.commit()
    replacement = {
        **values,
        "api_entry_id": 11,
        "ssh_entry_id": 12,
        "api_uri_index": 2,
        "ssh_uri_index": 2,
        "source_job_id": job.id,
    }
    state["values"] = {"esa": "true", "nic": "false"}
    target = lab.target_from_values(db, replacement)
    reviewed = lab.review(db, "admin", target, replacement)
    plan = lab._signer().loads(reviewed["token"])
    assert plan["target"]["ssh_entry_id"] == 12
    assert plan["target"]["api_uri_index"] == 2
    ssh.uris_json = '["ssh://other.test", "ssh://vcf.example.test:2222"]'
    db.commit()
    with pytest.raises(lab.LabOverrideError, match="identity differs"):
        lab.review(db, "admin", lab.target_from_values(db, replacement), replacement)
