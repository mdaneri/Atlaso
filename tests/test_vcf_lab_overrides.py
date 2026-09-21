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
    """Exercise property edits are idempotent and preserve unrelated bytes.

    Args:
        desired: Allowlisted property values to apply, with None meaning removal.
        ending: Line-ending variant used by the preservation test.
    """
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
    """Exercise ambiguous properties fail closed without disclosing content.

    Args:
        text: Ambiguous property fixture that must be refused.
    """
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
    """Exercise db.

    Args:
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
            (2, "vcf", "ssh://vcf.example.test"),
            (3, "root", "ssh://vcf.example.test"),
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
        "root_entry_id": 3,
        "root_uri_index": 1,
        "tls_fingerprint": "confirmed-tls",
        "ssh_fingerprint": "confirmed-ssh",
        "confirmed": True,
        "selections": ["esa", "nic"],
    }


@pytest.fixture
def state(monkeypatch):
    """Exercise state.

    Args:
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
    """Exercise matching vault endpoints required.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
    """
    assert lab.target_from_values(db, values).host == "vcf.example.test"
    db.get(VaultEntry, 2).uris_json = '["ssh://other.example.test"]'
    with pytest.raises(lab.LabOverrideError, match="same (hostname|SSH endpoint)"):
        lab.target_from_values(db, values)


@pytest.mark.parametrize("role", ["VcfInstaller", "SddcManager"])
@pytest.mark.parametrize(
    "version", ["9.0.0.0", "9.0.1.0.24962180", "9.0.2", "9.1.0", "9.1.1"]
)
def test_supported_families_and_roles(db, values, monkeypatch, role, version):
    """Exercise supported families and roles.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        role: Detected VCF appliance role.
        version: Detected VCF release string.
    """

    class Api:
        def __init__(self, *args, **kwargs):
            """Exercise   init  .

            Args:
                *args: Positional arguments supplied by the replaced boundary.
                **kwargs: Keyword arguments supplied by the replaced boundary.
            """
            assert kwargs["expected_fingerprint"] == "confirmed-tls"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Exercise   exit  .

            Args:
                *args: Positional arguments supplied by the replaced boundary.
            """
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
    """Exercise unsupported versions.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        version: Detected VCF release string.
    """

    class Api:
        def __init__(self, *args, **kwargs):
            """Exercise   init  .

            Args:
                *args: Positional arguments supplied by the replaced boundary.
                **kwargs: Keyword arguments supplied by the replaced boundary.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Exercise   exit  .

            Args:
                *args: Positional arguments supplied by the replaced boundary.
            """
            pass

        def appliance_info(self):
            return {"role": "VcfInstaller", "version": version}

    monkeypatch.setattr(lab, "VcfDepotApiClient", Api)
    monkeypatch.setattr(lab, "decrypt_secret", lambda value: "test-only-secret")
    with pytest.raises(lab.LabOverrideError, match="Only detected"):
        lab.appliance_info(db, lab.target_from_values(db, values), "confirmed-tls")


def test_review_binds_actor_and_is_single_use(db, values, state):
    """Exercise review binds actor and is single use.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
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
    """Exercise tampered expired and unconfirmed reviews.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
    """Exercise job outcomes preserve recovery state.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        failure: Worker outcome variant under test.
    """
    reviewed = lab.review(db, "admin", lab.target_from_values(db, values), values)
    job = lab.enqueue(db, "admin", reviewed["token"])
    calls = []

    def remote(*args, before_dispatch):
        """Exercise remote.

        Args:
            *args: Positional arguments supplied by the replaced boundary.
            before_dispatch: Callback recording ownership at dispatch.
        """
        before_dispatch()
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
                Setting.key
                == lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                )
            )
        )
        assert (owner.value if owner else None) == (job.id if calls else None)
    if failure == "restart":
        assert json.loads(job.result)["property_verified"] is True
        assert json.loads(job.result)["service_active"] is False


def test_revert_preserves_original_default_and_refuses_drift(db, values, state):
    """Exercise revert preserves original default and refuses drift.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
    target = lab.target_from_values(db, values)
    reviewed = lab.review(db, "admin", target, values)
    job = lab.enqueue(db, "admin", reviewed["token"])
    job.status = "failed"  # Restart failure can still need a revert.
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                ),
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
    """Exercise review requires nonempty allowlisted selection.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
    target = lab.target_from_values(db, values)
    for selected in [[], ["arbitrary"], ["esa", "esa"]]:
        with pytest.raises(lab.LabOverrideError):
            lab.review(db, "admin", target, {**values, "selections": selected})


def test_unverified_write_is_not_claimed_as_revertible(db, values, state):
    """Exercise unverified write is not claimed as revertible.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
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
    """Exercise restart recovery never replays remote changes.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        dispatched: Whether the interrupted task already started running.
        revert: Whether the interrupted task is a revert operation.
    """
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
    """Exercise worker rechecks administrator before remote credentials.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
        "restart_oserror",
        "readiness_oserror",
        "readback_failure",
        "drift",
        "noop",
        "stopped_apply",
        "stopped_revert",
    ],
)
def test_remote_transaction_permissions_restart_and_readback(
    tmp_path, monkeypatch, mode
):
    """Run the actual transaction with only Linux OS/service boundaries substituted.

    Args:
        tmp_path: Isolated temporary directory for transaction fixtures.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        mode: Transaction scenario or permission bits under test.
    """
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
    monkeypatch.setattr(
        sys.modules[remote.__name__], "active", lambda: not mode.startswith("stopped")
    )
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
        """Exercise record fchmod.

        Args:
            fd: Open file descriptor whose mode is recorded and preserved.
            mode: Transaction scenario or permission bits under test.
        """
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
        """Exercise mapped open.

        Args:
            name: Filesystem path passed to the mocked open boundary.
            flags: File-open flags forwarded to the real implementation.
            *args: Positional arguments supplied by the replaced boundary.
            **kwargs: Keyword arguments supplied by the replaced boundary.
        """
        if str(name) == "/run/lock/atlaso-vcf-lab.lock":
            name = tmp_path / "lock"
        if name == path.parent:
            name = tmp_path / "directory-fsync-surrogate"
            flags = os.O_CREAT | os.O_RDWR
        return real_open(name, flags, *args, **kwargs)

    def replace(source, destination):
        """Exercise replace.

        Args:
            source: Temporary replacement-file path.
            destination: Final configuration path.
        """
        real_replace(source, destination)
        if mode == "readback_failure":
            path.write_bytes(b"vendor.setting=concurrently-modified\n")

    monkeypatch.setattr(os, "open", mapped_open)
    monkeypatch.setattr(os, "replace", replace)
    calls = []

    def run(command, **kwargs):
        """Exercise run.

        Args:
            command: Fixed service command submitted by the remote editor.
            **kwargs: Keyword arguments supplied by the replaced boundary.
        """
        calls.append(command)
        if mode == "restart_oserror":
            raise OSError("sensitive-process-error")
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
    if mode == "readiness_oserror":
        observed = []

        def readiness():
            if observed:
                raise OSError("sensitive-readiness-error")
            observed.append(True)
            return True

        monkeypatch.setattr(remote, "active", readiness)
    if mode == "stopped_revert":
        request["recovery"] = True
        # Initial in-lock observation is inactive; readiness subsequently recovers.
        states = iter([False, True])
        monkeypatch.setattr(remote, "active", lambda: next(states, True))
    if mode == "stopped_apply":
        with pytest.raises(PropertyError, match="inactive"):
            remote.operate(request)
        assert path.read_bytes() == b"vendor.setting=untouched\n"
        assert calls == []
        return
    if mode in {"drift", "readback_failure"}:
        with pytest.raises(PropertyError):
            remote.operate(request)
        assert calls == []
        return
    outcome = remote.operate(request)
    assert outcome["ok"] == (mode in {"success", "noop", "stopped_revert"})
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
    """Exercise remote fingerprint mismatch never authenticates.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
    calls = []

    class Transport:
        def __init__(self, sock):
            """Exercise   init  .

            Args:
                sock: Connected socket supplied to the mocked SSH transport.
            """
            pass

        def start_client(self, **kwargs):
            """Exercise start client.

            Args:
                **kwargs: Keyword arguments supplied by the replaced boundary.
            """
            pass

        def get_remote_server_key(self):
            return object()

        def auth_password(self, *args):
            """Exercise auth password.

            Args:
                *args: Positional arguments supplied by the replaced boundary.
            """
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
    """Exercise ui requires admin csrf and explicit acknowledgement.

    Args:
        client: Authenticated application test client.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
    """Exercise long escaped unrelated keys are preserved.

    Args:
        suffix: Separator/value variant appended to an escaped key fixture.
    """
    original = b"\\:" * 100000 + suffix + b"\n"
    assert edit_properties(original, {"esa": "true"}).endswith(original)


def test_probe_keeps_ssh_recovery_available_without_tls(db, values, monkeypatch):
    """Exercise probe keeps ssh recovery available without tls.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
    monkeypatch.setattr(lab, "probe_remote_ssh_host", lambda *args: "confirmed-ssh")

    def unavailable(*args):
        """Exercise unavailable.

        Args:
            *args: Positional arguments supplied by the replaced boundary.
        """
        raise OSError("offline")

    monkeypatch.setattr(lab, "tls_sha256_fingerprint", unavailable)
    assert lab.probe(lab.target_from_values(db, values))["tls_fingerprint"] == ""


@pytest.mark.parametrize("role", ["VcfInstaller", "SddcManager"])
def test_revert_reviews_and_executes_without_api(db, values, state, monkeypatch, role):
    """Exercise revert reviews and executes without api.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        role: Detected VCF appliance role.
    """
    state["role"] = role
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "failed"
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                ),
                value=job.id,
            )
        )
    for lock in db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))):
        db.delete(lock)
    db.commit()
    state["values"] = {"esa": "true", "nic": "false"}
    state["service_active"] = False

    def unavailable(*args):
        """Exercise unavailable.

        Args:
            *args: Positional arguments supplied by the replaced boundary.
        """
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

    def restore(*args, before_dispatch):
        """Exercise restore.

        Args:
            *args: Positional arguments supplied by the replaced boundary.
            before_dispatch: Callback recording ownership at dispatch.
        """
        before_dispatch()
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
    """Exercise apply rechecks service before writing.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
    """Exercise revert rejects superseded property with matching values.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        superseded_key: Property whose later mutation invalidates the baseline.
    """
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "succeeded"
    job.result = json.dumps({"changed": True, "property_verified": True})
    state["values"] = {"esa": "true", "nic": "false"}
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                ),
                value=job.id,
            )
        )
    db.commit()
    reviewed = lab.review(db, "admin", target, {**values, "source_job_id": job.id})
    db.scalar(
        select(Setting).where(
            Setting.key
            == lab._property_owner_key(
                values["ssh_fingerprint"], superseded_key, target
            )
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
    """Exercise history retains old property owners beyond recent limit.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
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
                key=lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                ),
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
    """Exercise vault api uri preserves explicit port.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        scheme: Saved URI scheme under test; API transport remains HTTPS.
        port: Selected remote TCP port.
    """
    uri = f"{scheme}://vcf.example.test" + (f":{port}" if port else "")
    db.get(VaultEntry, 1).uris_json = json.dumps([uri])
    target = lab.target_from_values(db, values)
    assert target.host == "vcf.example.test"
    assert target.api_port == (port or 443)


def test_terminal_outcome_and_audit_share_commit(db, values, state, monkeypatch):
    """Exercise terminal outcome and audit share commit.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
    """
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
        """Exercise verify commit.

        Args:
            session: Database session at the transaction boundary.
        """
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
    """Exercise recovery accepts replacement credentials for same endpoint.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "succeeded"
    job.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(
                    values["ssh_fingerprint"], key, lab.target_from_values(db, values)
                ),
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
    db.get(VaultEntry, 3).uris_json = '["ssh://vcf.example.test:2222"]'
    ssh.uris_json = '["ssh://other.test", "ssh://vcf.example.test:2222"]'
    db.commit()
    with pytest.raises(lab.LabOverrideError, match="identity differs"):
        lab.review(db, "admin", lab.target_from_values(db, replacement), replacement)


def test_settings_restore_preserves_local_lab_runtime_state_without_export(db):
    """Exercise settings restore preserves local lab runtime state without export.

    Args:
        db: Database session for credential metadata and durable task state.
    """
    from atlaso.app.services.settings_archive import (
        SAFE_SETTING_KEYS,
        _clear_desired_state,
        _settings_rows,
    )

    keys = ["vcf_lab_owner:target:esa", "vcf_lab_lock:target", "vcf_lab_used:review"]
    for key in keys + ["ordinary-desired-state"]:
        db.add(Setting(key=key, value="local-state"))
    db.commit()
    assert not any(row["key"] in keys for row in _settings_rows(db))
    assert not set(keys) & SAFE_SETTING_KEYS
    _clear_desired_state(db)
    db.commit()
    retained = set(db.scalars(select(Setting.key)))
    assert set(keys) <= retained
    assert "ordinary-desired-state" not in retained


def test_cloned_ssh_keys_do_not_share_property_ownership(db, values):
    """Exercise cloned ssh keys do not share property ownership.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
    """
    from dataclasses import replace

    first = lab.target_from_values(db, values)
    second = replace(first, host="clone.example.test")
    third = replace(first, ssh_port=2222)
    for index, target in enumerate((first, second, third)):
        db.add(
            Setting(
                key=lab._property_owner_key("same-host-key", "esa", target),
                value=f"job-{index}",
            )
        )
    db.commit()
    for index, target in enumerate((first, second, third)):
        lab._require_property_owner(
            db, "same-host-key", ["esa"], f"job-{index}", target
        )


@pytest.mark.parametrize("changed_key", ["esa", "nic"])
def test_revert_ignores_later_edits_to_original_noop_selection(
    db, values, state, changed_key
):
    """Exercise revert ignores later edits to original noop selection.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        changed_key: Selected property that actually changes in the source task.
    """
    target = lab.target_from_values(db, values)
    desired = {"esa": "true", "nic": "false"}
    state["values"] = {**desired, changed_key: None}
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    job.status = "succeeded"
    job.result = json.dumps({"changed": True, "property_verified": True})
    db.add(
        Setting(
            key=lab._property_owner_key(values["ssh_fingerprint"], changed_key, target),
            value=job.id,
        )
    )
    db.commit()
    noop_key = "nic" if changed_key == "esa" else "esa"
    state["values"] = {**desired, noop_key: None}
    reviewed = lab.review(db, "admin", target, {**values, "source_job_id": job.id})
    assert [(change["id"], change["value"]) for change in reviewed["changes"]] == [
        (changed_key, None)
    ]
    state["values"][changed_key] = "false" if changed_key == "esa" else "true"
    with pytest.raises(lab.LabOverrideError, match="overwrite another edit"):
        lab.review(db, "admin", target, {**values, "source_job_id": job.id})


@pytest.mark.parametrize(
    "clone_uri", ["ssh://clone.example.test", "ssh://vcf.example.test:2222"]
)
def test_reservations_isolate_cloned_ssh_keys(db, values, state, clone_uri):
    """Exercise reservations isolate cloned ssh keys.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        clone_uri: Second SSH endpoint sharing the first target host key.
    """
    from urllib.parse import urlsplit

    first = lab.enqueue(
        db,
        "admin",
        lab.review(db, "admin", lab.target_from_values(db, values), values)["token"],
    )
    first.status = "running"
    db.get(VaultEntry, 1).uris_json = json.dumps(
        [f"https://{urlsplit(clone_uri).hostname}"]
    )
    db.get(VaultEntry, 2).uris_json = json.dumps([clone_uri])
    db.get(VaultEntry, 3).uris_json = json.dumps([clone_uri])
    db.commit()
    second = lab.enqueue(
        db,
        "admin",
        lab.review(db, "admin", lab.target_from_values(db, values), values)["token"],
    )
    assert (
        len(list(db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%")))))
        == 2
    )
    assert lab.recover_interrupted_jobs(db) == 2
    locks = list(db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))))
    assert [lock.value for lock in locks] == [first.id]
    third = lab.enqueue(
        db,
        "admin",
        lab.review(db, "admin", lab.target_from_values(db, values), values)["token"],
    )
    assert third.id != second.id


@pytest.mark.parametrize(
    "failure", ["connection", "host_key", "authentication", "session", "dispatch"]
)
def test_revert_preserves_owner_until_authenticated_dispatch(
    db, values, state, monkeypatch, failure
):
    """Keep recovery retryable for failures known to precede remote dispatch.

    Args:
        db: Database session for retained recovery state.
        values: Confirmed target and credential references.
        state: Inspected target state fixture.
        monkeypatch: External boundary replacement fixture.
        failure: SSH setup or dispatch failure stage.
    """
    target = lab.target_from_values(db, values)
    source = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    source.status = "succeeded"
    source.result = json.dumps({"changed": True, "property_verified": True})
    for key in ("esa", "nic"):
        db.add(
            Setting(
                key=lab._property_owner_key(values["ssh_fingerprint"], key, target),
                value=source.id,
            )
        )
    for lock in db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))):
        db.delete(lock)
    db.commit()
    state["values"] = {"esa": "true", "nic": "false"}
    recovery_values = {**values, "source_job_id": source.id}
    recovery = lab.enqueue(
        db, "admin", lab.review(db, "admin", target, recovery_values)["token"]
    )

    def fail_at(stage):
        """Raise at the selected transport boundary.

        Args:
            stage: Transport stage reached by the test.
        """
        if failure == stage:
            raise OSError("private transport detail")

    class Transport:
        def __init__(self, sock):
            """Accept the synthetic socket.

            Args:
                sock: Test socket placeholder.
            """

        def start_client(self, **kwargs):
            """Simulate an SSH handshake.

            Args:
                **kwargs: Bounded transport options.
            """

        def get_remote_server_key(self):
            return object()

        def auth_password(self, *args):
            """Simulate authentication failure.

            Args:
                *args: Vault authentication inputs.
            """
            fail_at("authentication")

        def open_session(self, **kwargs):
            """Create the command channel.

            Args:
                **kwargs: Bounded channel options.
            """
            fail_at("session")
            return self

        def settimeout(self, timeout):
            """Accept the channel deadline.

            Args:
                timeout: Bounded channel timeout.
            """

        def exec_command(self, command):
            """Check that ownership is durable before uncertain dispatch.

            Args:
                command: Fixed remote editor command.
            """
            for key in ("esa", "nic"):
                owner = db.scalar(
                    select(Setting).where(
                        Setting.key
                        == lab._property_owner_key(
                            values["ssh_fingerprint"], key, target
                        )
                    )
                )
                assert owner.value == source.id
            fail_at("dispatch")

        def close(self):
            pass

    monkeypatch.setattr(
        lab.socket, "create_connection", lambda *args, **kwargs: fail_at("connection")
    )
    monkeypatch.setattr(lab.paramiko, "Transport", Transport)
    monkeypatch.setattr(
        lab,
        "ssh_fingerprint",
        lambda key: "wrong" if failure == "host_key" else values["ssh_fingerprint"],
    )
    monkeypatch.setattr(lab, "decrypt_secret", lambda value: "synthetic-password")
    lab.run_job(recovery.id)
    db.expire_all()
    assert recovery.status == "failed"
    assert "private transport detail" not in recovery.error
    for key in ("esa", "nic"):
        owner = db.scalar(
            select(Setting).where(
                Setting.key
                == lab._property_owner_key(values["ssh_fingerprint"], key, target)
            )
        )
        assert owner.value == source.id
    if failure in {"connection", "host_key", "authentication", "session", "dispatch"}:
        retry = lab.enqueue(
            db, "admin", lab.review(db, "admin", target, recovery_values)["token"]
        )
        assert retry.id != recovery.id
    else:
        with pytest.raises(lab.LabOverrideError, match="superseded"):
            lab.review(db, "admin", target, recovery_values)


@pytest.mark.parametrize("username", ["root", "admin", "sudo-user"])
def test_ssh_requires_vcf_not_root_or_sudo(db, values, username):
    """Reject accounts that bypass the supported vcf privilege boundary.

    Args:
        db: Credential fixture session.
        values: Selected credential references.
        username: Unsupported SSH identity.
    """
    db.get(VaultEntry, 2).username = username
    with pytest.raises(lab.LabOverrideError, match="separate vcf"):
        lab.target_from_values(db, values)


def test_root_credential_is_required_and_bound_to_review(db, values, state):
    """Bind the separate elevation reference without persisting its value.

    Args:
        db: Credential fixture session.
        values: Selected credential references.
        state: Nonmutating inspected-state fixture.
    """
    missing = {key: value for key, value in values.items() if key != "root_entry_id"}
    with pytest.raises(lab.LabOverrideError, match="separate root"):
        lab.target_from_values(db, missing)
    plan = lab.review(db, "admin", lab.target_from_values(db, values), values)
    job = lab.enqueue(db, "admin", plan["token"])
    assert json.loads(job.task_config_json)["target"]["root_entry_id"] == 3
    assert "never-decrypt-this" not in job.task_config_json


def test_readable_inspection_never_elevates(monkeypatch):
    """Readable properties stay at vcf privilege and never consume root input.

    Args:
        monkeypatch: External boundary replacement fixture.
    """
    from atlaso.app.services import vcf_lab_remote as remote

    monkeypatch.setattr(remote, "operate", lambda request: {"ok": True})
    assert remote.dispatch({"request": {"action": "inspect"}}) == {"ok": True}


def test_su_command_excludes_secret_and_runs_only_fixed_editor(monkeypatch):
    """The root secret is separate from every generated command and source.

    Args:
        monkeypatch: External boundary replacement fixture.
    """
    import base64
    import shlex
    from pathlib import Path

    from atlaso.app.services import vcf_lab_remote as remote

    captured = []
    monkeypatch.setattr(
        remote,
        "elevated",
        lambda command, password, **kwargs: (
            captured.append((command, password)) or {"ok": True}
        ),
    )
    source = Path(remote.__file__).read_bytes()
    request = {"action": "write", "desired": {"nic": "false"}, "revision": "a" * 64}
    assert remote.dispatch(
        {
            "request": request,
            "editor": base64.b64encode(source).decode(),
            "root_password": "root-sentinel-only",
        }
    ) == {"ok": True}
    command, password = captured[0]
    assert password == "root-sentinel-only"
    assert password not in command
    assert "sudo -n" not in command
    args = shlex.split(command)
    assert args[:2] == ["python3", "-c"]
    compile(args[2], "<generated-root-program>", "exec")


@pytest.mark.parametrize(
    "mode",
    ["success", "wrong_password", "echo", "timeout", "disconnect", "unavailable"],
)
def test_su_terminal_exchange_is_bounded_and_non_echoing(monkeypatch, mode):
    """Only a non-echoing password prompt accepts the secret; output stays private.

    Args:
        monkeypatch: External boundary replacement fixture.
        mode: Native-terminal outcome being simulated.
    """
    import sys
    from types import SimpleNamespace

    from atlaso.app.services import vcf_lab_remote as remote

    chunks = [b"Password:"]
    if mode == "success":
        chunks += [b"ATLASO_ROOT_READY\r\n", b'ATLASO_RESULT:{"ok": true}\r\n']
    elif mode == "wrong_password":
        chunks += [b"su: Authentication failure root-sentinel-only\r\n"]
    elif mode == "disconnect":
        chunks += [b"ATLASO_ROOT_READY\r\n"]
    writes = []
    monkeypatch.setitem(sys.modules, "pty", SimpleNamespace(fork=lambda: (123, 9)))
    monkeypatch.setitem(
        sys.modules,
        "termios",
        SimpleNamespace(
            tcgetattr=lambda fd: [0, 0, 0, 8 if mode == "echo" else 0],
            ECHO=8,
            ECHONL=64,
        ),
    )
    monkeypatch.setattr(remote.Path, "is_file", lambda path: mode != "unavailable")
    import select

    monkeypatch.setattr(select, "select", lambda *args: ([9], [], []))
    monkeypatch.setattr(
        remote.os, "read", lambda *args: chunks.pop(0) if chunks else b""
    )
    monkeypatch.setattr(
        remote.os, "write", lambda fd, value: writes.append(value) or len(value)
    )
    monkeypatch.setattr(remote.os, "close", lambda fd: None)
    monkeypatch.setattr(remote.os, "waitpid", lambda *args: (0, 0), raising=False)
    monkeypatch.setattr(remote.os, "WNOHANG", 1, raising=False)
    monkeypatch.setattr(remote.os, "kill", lambda *args: None)
    import signal

    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    clock = iter([0, 21] if mode == "timeout" else range(100))
    monkeypatch.setattr(remote.time, "monotonic", lambda: next(clock))
    result = remote.elevated("fixed-nonsecret-command", "root-sentinel-only")
    expected = {
        "success": None,
        "wrong_password": "authentication",
        "echo": "echo",
        "timeout": "timeout",
        "disconnect": "execution",
        "unavailable": "unavailable",
    }[mode]
    assert result.get("elevation_error") == expected
    assert "root-sentinel-only" not in json.dumps(result)
    assert writes == (
        [] if mode in {"echo", "timeout", "unavailable"} else [b"root-sentinel-only\n"]
    )


@pytest.mark.parametrize("mode", ["inspect", "write", "su_failure"])
def test_remote_uses_vcf_and_sends_root_secret_only_over_stdin(
    db, values, monkeypatch, mode
):
    """Keep the distinct root secret out of commands, authentication and results.

    Args:
        db: Credential fixture session.
        values: Selected credential references.
        monkeypatch: External boundary replacement fixture.
        mode: Inspection, authenticated write or failed root authentication.
    """
    captured = {"handoff": False}
    chunks = (
        [b'{"ready":true}\n', b'{"ok":true}\n']
        if mode == "write"
        else [b'{"elevation_error":"authentication"}\n']
        if mode == "su_failure"
        else [b'{"ok":true}\n']
    )
    db.get(VaultEntry, 2).encrypted_value = "ssh-cipher"
    db.get(VaultEntry, 3).encrypted_value = "root-cipher"

    class Channel:
        """Bounded non-PTY SSH channel fixture."""

        available = True

        def settimeout(self, timeout):
            """Accept the channel bound.

            Args:
                timeout: Configured deadline.
            """
            assert timeout == 10

        def exec_command(self, command):
            """Capture only the non-secret command.

            Args:
                command: Fixed remote adapter command.
            """
            captured["command"] = command

        def sendall(self, payload):
            """Capture encrypted channel input privately in this test.

            Args:
                payload: Serialized operation envelope.
            """
            if payload == b"ATLASO_APPLY\n":
                assert captured["handoff"]
                captured["authorized"] = True
            else:
                captured["input"] = json.loads(payload)

        def shutdown_write(self):
            """Finish the request stream."""

        def recv_ready(self):
            """Report the one bounded result chunk."""
            return bool(chunks)

        def recv(self, size):
            """Return sanitized editor output.

            Args:
                size: Maximum read size.
            """
            return chunks.pop(0)

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return not chunks

        def recv_exit_status(self):
            return 0

    class Transport:
        """SSH transport recording the login identity."""

        def __init__(self, sock):
            """Accept the connected fixture socket.

            Args:
                sock: In-memory socket stand-in.
            """

        def start_client(self, timeout):
            """Accept the handshake bound.

            Args:
                timeout: Handshake deadline.
            """

        def get_remote_server_key(self):
            return object()

        def auth_password(self, username, password):
            """Record vcf authentication separately from root elevation.

            Args:
                username: SSH login identity.
                password: SSH-only secret.
            """
            captured["auth"] = (username, password)

        def open_session(self, timeout):
            """Create a non-PTY command channel.

            Args:
                timeout: Channel setup deadline.
            """
            return Channel()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(
        lab.socket, "create_connection", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(lab.paramiko, "Transport", Transport)
    monkeypatch.setattr(lab, "ssh_fingerprint", lambda key: values["ssh_fingerprint"])
    monkeypatch.setattr(
        lab,
        "decrypt_secret",
        lambda value: {"ssh-cipher": "ssh-sentinel", "root-cipher": "root-sentinel"}[
            value
        ],
    )

    def run():
        """Exercise the real adapter with a synthetic SSH channel."""
        return lab.remote(
            db,
            lab.target_from_values(db, values),
            values["ssh_fingerprint"],
            {"action": "inspect" if mode == "inspect" else "write"},
            before_dispatch=lambda: captured.update(handoff=True),
        )

    if mode == "su_failure":
        with pytest.raises(lab.LabOverrideError, match="su authentication failed"):
            run()
        assert not captured["handoff"]
    else:
        assert run() == {"ok": True}
        assert captured["handoff"] == (mode == "write")
    assert captured["auth"] == ("vcf", "ssh-sentinel")
    assert captured["input"]["root_password"] == "root-sentinel"
    assert "root-sentinel" not in captured["command"]
    assert "ssh-sentinel" not in captured["command"]
    assert "sudo" not in captured["command"]
    assert captured["closed"]


@pytest.mark.parametrize("acknowledgement", ["ATLASO_APPLY\n", "wrong\n"])
def test_generated_privileged_program_waits_for_write_authorization(
    monkeypatch, capsys, acknowledgement
):
    """Authenticate first and require Atlaso's durable handoff before mutation.

    Args:
        monkeypatch: External boundary replacement fixture.
        capsys: Captured safe protocol output.
        acknowledgement: Valid or invalid durable write authorization.
    """
    import base64
    import io
    import shlex
    import signal
    import sys

    from atlaso.app.services import vcf_lab_remote as remote

    source = b'import json\ndef safe_operate(request):\n print("EDITOR_RAN",flush=True)\n return {"ok":True}\n'
    monkeypatch.setattr(remote.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(signal, "alarm", lambda timeout: None, raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(acknowledgement))

    def execute(command, password, **kwargs):
        """Execute the generated program against a harmless editor fixture.

        Args:
            command: Fixed privileged Python program.
            password: Separate synthetic root password.
            **kwargs: Write-handshake selection.
        """
        assert kwargs["authorize_write"] is True
        exec(shlex.split(command)[2], {})
        return {"ok": True}

    monkeypatch.setattr(remote, "elevated", execute)
    envelope = {
        "request": {"action": "write"},
        "editor": base64.b64encode(source).decode(),
        "root_password": "synthetic-root",
    }
    if acknowledgement == "wrong\n":
        with pytest.raises(AssertionError):
            remote.dispatch(envelope)
        assert "EDITOR_RAN" not in capsys.readouterr().out
    else:
        assert remote.dispatch(envelope) == {"ok": True}
        assert "EDITOR_RAN" in capsys.readouterr().out
