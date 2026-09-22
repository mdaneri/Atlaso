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
        "ssh_entry_id": 2,
        "ssh_uri_index": 1,
        "root_entry_id": 3,
        "root_uri_index": 1,
        "ssh_fingerprint": "confirmed-ssh",
        "confirmed": True,
        "desired": {"esa": "true", "nic": "false"},
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


@pytest.mark.parametrize(
    "version", ["9.0.0.0", "9.0.1.0.24962180", "9.1.0.0400.25570101", "9.1.1"]
)
def test_supported_versions_over_ssh(db, values, monkeypatch, version):
    """Detect supported versions without resolving API credentials.

    Args:
        db: Test session.
        values: SSH selection.
        monkeypatch: Remote transport replacement.
        version: Native sos release.
    """

    def remote(_db, target, fingerprint, request):
        """Return the fixed version operation result.

        Args:
            _db: Session.
            target: SSH target.
            fingerprint: Confirmed host key.
            request: Fixed operation.
        """
        assert fingerprint == values["ssh_fingerprint"]
        assert request == {"action": "version"}
        return {"ok": True, "version": version}

    monkeypatch.setattr(lab, "remote", remote)
    assert (
        lab.appliance_info(
            db, lab.target_from_values(db, values), values["ssh_fingerprint"]
        )["version"]
        == version
    )


@pytest.mark.parametrize(
    "version", ["9.2.0", "9.10.0", "8.0.0", "9.1", "unknown", "9.1.1 malicious"]
)
def test_unsupported_versions(version):
    """Reject versions outside the explicit supported families.

    Args:
        version: Unsupported release string.
    """
    with pytest.raises(lab.LabOverrideError, match="Only detected"):
        lab.supported_catalog("VCF", version)


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
    with pytest.raises(lab.LabOverrideError, match="Confirm the SSH"):
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
    if failure == "restart":
        assert json.loads(job.result)["property_verified"] is True
        assert json.loads(job.result)["service_active"] is False


def test_review_requires_nonempty_allowlisted_selection(db, values, state):
    """Exercise review requires nonempty allowlisted selection.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
    """
    target = lab.target_from_values(db, values)
    for selected in [{}, {"arbitrary": "true"}, {"esa": "invalid"}, {"nic": []}]:
        with pytest.raises(lab.LabOverrideError):
            lab.review(db, "admin", target, {**values, "desired": selected})


@pytest.mark.parametrize("dispatched", [False, True])
def test_restart_recovery_never_replays_remote_changes(db, values, state, dispatched):
    """Exercise restart recovery never replays remote changes.

    Args:
        db: Database session for credential metadata and durable task state.
        values: Selected credential references and confirmed review inputs.
        state: Mutable inspected-state fixture used to simulate remote changes.
        dispatched: Whether the interrupted task already started running.
    """
    target = lab.target_from_values(db, values)
    job = lab.enqueue(db, "admin", lab.review(db, "admin", target, values)["token"])
    if dispatched:
        job.status = "running"
    job.result = '{"error":"sensitive-remote-output"}'
    db.commit()
    assert lab.recover_interrupted_jobs(db) == 1
    assert job.status == "failed"
    held = list(db.scalars(select(Setting).where(Setting.key.like("vcf_lab_lock:%"))))
    assert bool(held) is dispatched
    assert "Interrupted" in job.error
    event = db.scalar(select(AuditEvent).where(AuditEvent.resource_id == job.id))
    assert event.actor == "admin" and event.success is False
    assert event.action == "apply_vcf_lab_overrides"
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
@pytest.mark.parametrize("layout", ["regular", "vcf_alias"])
def test_remote_transaction_permissions_restart_and_readback(
    tmp_path, monkeypatch, mode, layout
):
    """Run the actual transaction with only Linux OS/service boundaries substituted.

    Args:
        tmp_path: Isolated temporary directory for transaction fixtures.
        monkeypatch: Pytest fixture replacing external boundaries for this test.
        mode: Transaction scenario or permission bits under test.
        layout: Direct file or the supported VCF sibling alias.
    """
    import os
    import stat
    import subprocess
    import sys
    from types import SimpleNamespace

    from atlaso.app.services import vcf_lab_remote as remote

    configured = tmp_path / "application-prod.properties"
    path = configured if layout == "regular" else tmp_path / "application.properties"
    if layout == "vcf_alias":
        configured.symlink_to("application.properties")
    path.write_bytes(b"vendor.setting=untouched\n")
    alias_info = configured.lstat()
    if mode == "noop":
        path.write_bytes(edit_properties(path.read_bytes(), {"esa": "true"}))
    monkeypatch.setattr(remote, "CONFIG_PATH", str(configured))
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
    if layout == "vcf_alias":
        assert configured.is_symlink()
        assert configured.lstat().st_ino == alias_info.st_ino
        assert os.readlink(configured) == "application.properties"
    if mode == "success":
        restored = remote.operate(
            {
                "action": "write",
                "revision": outcome["revision"],
                "desired": {"esa": None},
                "recovery": True,
            }
        )
        assert restored["ok"] and restored["changed"]
        assert path.read_bytes() == b"vendor.setting=untouched\n"
        assert configured.is_symlink() == (layout == "vcf_alias")


@pytest.mark.parametrize(
    "layout", ["other", "absolute", "chain", "hardlink", "ancestor"]
)
def test_remote_configuration_rejects_other_link_layouts(tmp_path, layout):
    """Reject aliases outside the single supported VCF layout.

    Args:
        tmp_path: Isolated filesystem fixture.
        layout: Unsupported link layout to reject.
    """
    import os

    from atlaso.app.services import vcf_lab_remote as remote

    target = tmp_path / "application.properties"
    target.write_bytes(b"vendor.setting=untouched\n")
    configured = tmp_path / "application-prod.properties"
    if layout == "other":
        configured.symlink_to("other.properties")
    elif layout == "absolute":
        configured.symlink_to(target)
    elif layout == "chain":
        target.unlink()
        target.symlink_to("other.properties")
        configured.symlink_to("application.properties")
    elif layout == "hardlink":
        os.link(target, tmp_path / "duplicate")
        configured.symlink_to("application.properties")
    else:
        (tmp_path / "alias").symlink_to(tmp_path, target_is_directory=True)
        configured = tmp_path / "alias/application.properties"
    with pytest.raises(PropertyError):
        remote.read_state(configured)


def test_remote_revision_binds_alias_identity(tmp_path, monkeypatch):
    """Replacing the allowed alias invalidates review even with unchanged bytes.

    Args:
        tmp_path: Isolated filesystem fixture.
        monkeypatch: Fixture replacing the service-status query.
    """
    from atlaso.app.services import vcf_lab_remote as remote

    target = tmp_path / "application.properties"
    target.write_bytes(b"vendor.setting=untouched\n")
    configured = tmp_path / "application-prod.properties"
    configured.symlink_to("application.properties")
    monkeypatch.setattr(remote, "CONFIG_PATH", str(configured))
    monkeypatch.setattr(remote, "active", lambda: True)
    # read_state is platform-neutral; operate's Linux flock import is unnecessary here.
    content, info, _, binding = remote.read_state(configured)
    before = remote.snapshot(content, info, binding)
    configured.rename(tmp_path / "old-alias")
    configured.symlink_to("application.properties")
    content, info, _, binding = remote.read_state(configured)
    assert remote.snapshot(content, info, binding) != before


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
        client.post(
            "/ui/management/vcf-helper/lab-overrides/inspect",
            json={},
            headers={"X-CSRF-Token": csrf},
        ).status_code
        == 403
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


def test_probe_uses_only_ssh_without_credentials(db, values, monkeypatch):
    """Probe the SSH identity without resolving any password.

    Args:
        db: Database session containing saved credential metadata.
        values: Selected credential references.
        monkeypatch: External boundary replacement fixture.
    """
    monkeypatch.setattr(lab, "probe_remote_ssh_host", lambda *args: "confirmed-ssh")
    monkeypatch.setattr(
        lab, "_credential", lambda *args: pytest.fail("credential access")
    )
    assert lab.probe(lab.target_from_values(db, values)) == {
        "target": "vcf.example.test",
        "ssh_fingerprint": "confirmed-ssh",
    }


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


def test_permission_refusal_requests_separate_elevation(monkeypatch):
    """An unreadable file requests a retry without accessing a root secret.

    Args:
        monkeypatch: Fixture replacing the unprivileged file read.
    """
    from atlaso.app.services import vcf_lab_remote as remote

    def denied(request):
        """Simulate the unprivileged read refusal.

        Args:
            request: Fixed inspection request.
        """
        raise PermissionError

    monkeypatch.setattr(remote, "operate", denied)
    assert remote.dispatch({"request": {"action": "inspect"}}) == {
        "elevation_required": True
    }


@pytest.mark.parametrize("retain_credentials", [True, False])
def test_manual_credentials_are_bound_but_never_persisted(
    db, values, state, monkeypatch, retain_credentials
):
    """Manual passwords remain request-local and changed inputs invalidate review.

    Args:
        db: Test database session.
        values: Confirmed review inputs.
        state: Nonmutating remote inspection fixture.
        monkeypatch: Worker boundary replacements.
        retain_credentials: Whether process-local credentials remain available.
    """
    credentials = {
        "ssh": "manual-vcf-sentinel",
        "root": "manual-root-sentinel",
    }
    supplied = {
        **values,
        "credential_mode": "manual",
        "host": "vcf.example.test",
        "credentials": credentials,
    }
    target = lab.target_from_values(db, supplied)
    assert not any(
        secret in repr(target) + json.dumps(target.fields())
        for secret in credentials.values()
    )
    reviewed = lab.review(db, "admin", target, supplied)
    plan = lab._signer().loads(reviewed["token"])
    assert "credentials" not in plan["target"]
    assert not any(secret in json.dumps(plan) for secret in credentials.values())
    with pytest.raises(lab.LabOverrideError, match="changed"):
        lab.enqueue(
            db, "admin", reviewed["token"], {**credentials, "root": "changed-root"}
        )
    with pytest.raises(lab.LabOverrideError, match="changed"):
        lab.enqueue(db, "admin", reviewed["token"])
    job = lab.enqueue(db, "admin", reviewed["token"], credentials)
    assert "credential_revision" not in json.loads(job.task_config_json)["target"]
    assert target.credential_revision not in job.task_config_json
    assert not any(
        secret in job.task_config_json + job.result for secret in credentials.values()
    )

    def remote(_db, received, _fingerprint, request, *, before_dispatch):
        """Verify credentials reach only the in-memory worker boundary.

        Args:
            _db: Worker database session.
            received: Request-local target.
            _fingerprint: Confirmed identity.
            request: Fixed write request.
            before_dispatch: Durable ownership callback.
        """
        assert retain_credentials
        assert received.credentials == credentials
        before_dispatch()
        return {
            "ok": True,
            "changed": True,
            "service_active": True,
            "values": request["desired"],
        }

    monkeypatch.setattr(lab, "remote", remote)
    monkeypatch.setattr(
        lab,
        "appliance_info",
        lambda *args: {"role": state["role"], "version": state["version"]},
    )
    lab.run_job(job.id, credentials if retain_credentials else None)
    db.refresh(job)
    assert job.status == ("succeeded" if retain_credentials else "failed")
    if not retain_credentials:
        assert "Manual credentials are unavailable" in job.error
    persisted = job.task_config_json + job.result + (job.error or "")
    persisted += "".join(event.detail or "" for event in db.scalars(select(AuditEvent)))
    assert not any(secret in persisted for secret in credentials.values())
    assert target.credential_revision not in persisted


def test_manual_probe_has_no_password_requirement(db):
    """Endpoint selection and fingerprint probing do not require login secrets.

    Args:
        db: Test database session.
    """
    target = lab.target_from_values(
        db, {"credential_mode": "manual", "host": "192.0.2.1"}
    )
    assert target.credentials == {}
    assert target.ssh_port == 22
    with pytest.raises(lab.LabOverrideError, match="manual credentials"):
        lab._credential(db, target, "root")


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
    assert args[:8] == ["cd", "/", "&&", "exec", "/usr/bin/python3", "-I", "-S", "-c"]
    compile(args[8], "<generated-root-program>", "exec")


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


@pytest.mark.parametrize("mode", ["inspect", "elevated_inspect", "write", "su_failure"])
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
    captured = {"handoff": False, "decryptions": [], "envelopes": []}
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
                captured["envelopes"].append(captured["input"])

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
            if mode == "elevated_inspect" and not captured["envelopes"]:
                chunks[:] = [b'{"elevation_required":true}\n']
            elif mode == "elevated_inspect":
                chunks[:] = [b'{"ok":true}\n']
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
        lambda value: (
            captured["decryptions"].append(value)
            or {"ssh-cipher": "ssh-sentinel", "root-cipher": "root-sentinel"}[value]
        ),
    )

    def run():
        """Exercise the real adapter with a synthetic SSH channel."""
        return lab.remote(
            db,
            lab.target_from_values(db, values),
            values["ssh_fingerprint"],
            {
                "action": "inspect"
                if mode in {"inspect", "elevated_inspect"}
                else "write"
            },
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
    if mode == "inspect":
        assert "root_password" not in captured["input"]
        assert captured["decryptions"] == ["ssh-cipher"]
    else:
        assert captured["input"]["root_password"] == "root-sentinel"
    if mode == "elevated_inspect":
        assert len(captured["envelopes"]) == 2
        assert "root_password" not in captured["envelopes"][0]
        assert captured["decryptions"] == ["ssh-cipher", "ssh-cipher", "root-cipher"]
    assert "root-sentinel" not in captured["command"]
    assert "ssh-sentinel" not in captured["command"]
    assert "sudo" not in captured["command"]
    assert captured["command"].startswith("cd / && exec /usr/bin/python3 -I -S -c ")
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
        exec(shlex.split(command)[8], {})
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


@pytest.mark.parametrize("module_name", ["base64", "signal"])
def test_remote_python_ignores_caller_modules_and_pythonpath(tmp_path, module_name):
    """Exercise isolated imports with a hostile cwd and environment path.

    Args:
        tmp_path: Owned temporary fixture directory.
        module_name: Standard-library module shadowed by an untrusted file.
    """
    import os
    import shlex
    import subprocess
    import sys

    from atlaso.app.services import vcf_lab_remote as remote

    (tmp_path / f"{module_name}.py").write_text(
        "raise RuntimeError('caller-module-loaded')\n", encoding="utf-8"
    )
    environment = {
        **os.environ,
        "PYTHONPATH": str(tmp_path),
        "PYTHONUSERBASE": str(tmp_path),
    }
    program = f"import {module_name}; print('trusted-import')"
    unsafe = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert unsafe.returncode != 0 and "caller-module-loaded" in unsafe.stderr
    command = shlex.split(remote.PYTHON_COMMAND)
    assert command[:5] == ["cd", "/", "&&", "exec", "/usr/bin/python3"]
    # Run the actual selected interpreter flags on this host; no root privileges
    # or VCF mutation are needed to verify Python's import isolation boundary.
    safe = subprocess.run(
        [sys.executable, *command[5:], program],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert safe.returncode == 0
    assert safe.stdout.strip() == "trusted-import"
    assert "caller-module-loaded" not in safe.stderr


@pytest.mark.parametrize(
    "output,code,valid",
    [
        (b"9.1.0.0400.25570101\n", 0, True),
        (b"diagnostics", 0, False),
        (b"9.1.0", 1, False),
        (b"9." + b"1" * 300, 0, False),
    ],
)
def test_sos_version_command_is_fixed_and_validated(monkeypatch, output, code, valid):
    """Accept only a successful bounded version response from the fixed command.

    Args:
        monkeypatch: Replaces the subprocess boundary.
        output: Synthetic sos output.
        code: Synthetic exit code.
        valid: Whether the response is an acceptable release.
    """
    from types import SimpleNamespace

    from atlaso.app.services import vcf_lab_remote as remote

    def run(command, **kwargs):
        """Capture the fixed command and supply synthetic output.

        Args:
            command: Fixed argv for sos.
            **kwargs: Bounded process options.
        """
        assert command == ["/opt/vmware/sddc-support/sos", "-v"]
        assert kwargs["timeout"] == 30
        kwargs["stdout"].write(output)
        return SimpleNamespace(returncode=code)

    monkeypatch.setattr(remote.subprocess, "run", run)
    if valid:
        assert remote.version() == {"ok": True, "version": output.decode().strip()}
    else:
        with pytest.raises(remote.PropertyError):
            remote.version()
