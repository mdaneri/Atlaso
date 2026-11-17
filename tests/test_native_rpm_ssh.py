"""SSH trust admission and bounded public-input/output transport regression tests."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from scripts import native_rpm_ssh as ssh
from scripts.installation.refresh_plan import validate_native_ssh, validate_plan

PIN = "SHA256:" + base64.b64encode(b"\0" * 32).decode().rstrip("=")


def selection(**changes):
    """Return public native-SSH selectors with one independently altered field.

    Args:
        **changes: Field substitutions under test.
    """
    return {"host": "192.168.1.152", "user": "root", "host_key_sha256": PIN,
            "password_variable": "lab_internal_PASSWORD", **changes}


@pytest.mark.parametrize("changes", [
    {"host": "8.8.8.8"}, {"host": "127.0.0.1"}, {"host": "169.254.1.1"},
    {"host": "192.168.001.152"}, {"host": "vm.example.test"}, {"host": "::1"},
    {"user": "root;touch marker"}, {"host_key_sha256": "accept-new"},
    {"host_key_sha256": PIN + "="}, {"password_variable": "password\nINJECTED"},
    {"password_variable": "secret://path"}, {"password": "must-not-be-a-plan-field"},
])
def test_ssh_selection_rejects_ambiguous_hosts_unpinned_keys_and_values(changes):
    """Reject unsafe selectors and plaintext credential fields before connecting.

    Args:
        changes: One independent malformed selector.
    """
    with pytest.raises(ValueError):
        validate_native_ssh(selection(**changes))


def test_console_fingerprint_is_preserved_exactly():
    assert validate_native_ssh(selection()) == selection()


@pytest.mark.parametrize("path", [
    r"C:\outside\package.rpm", r"\\server\share\package.rpm", r"C:package.rpm",
    r"C:\task\..\outside\package.rpm", r"C:\task\.atlaso-local\token.dpapi",
    r"C:\task\.git\config", r"C:\task\package.rpm:secret", r"C:\task\.env",
])
def test_mirror_refuses_paths_outside_plan_or_into_private_configuration(path):
    """Refuse path escapes and credential/configuration inputs before any SFTP operation.

    Args:
        path: An unsafe absolute or drive-relative input.
    """
    with pytest.raises(ValueError):
        ssh.mapped_path(path, [r"C:\task"])


def test_drive_path_mapping_preserves_spaces_without_shell_syntax():
    assert ssh.mapped_path(r"C:\task\input with spaces\a.rpm", [r"C:\task"]) == "files/c/task/input with spaces/a.rpm"


def test_changed_host_key_prevents_sdk_retrieval_and_password_auth(monkeypatch):
    """An endpoint cannot receive credentials before matching the independent console pin.

    Args:
        monkeypatch: Isolate the socket, SSH negotiation and SDK access.
    """
    import paramiko

    transport = SimpleNamespace(
        get_security_options=lambda: SimpleNamespace(key_types=[]),
        start_client=lambda **_kwargs: None,
        get_remote_server_key=lambda: SimpleNamespace(asbytes=lambda: b"different public key"),
        close=lambda: None,
    )
    retrieve = AsyncMock()
    monkeypatch.setattr(ssh.socket, "create_connection", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(paramiko, "Transport", lambda _connection: transport)
    monkeypatch.setattr(ssh, "authenticate", retrieve)
    with pytest.raises(ValueError, match="host_key_mismatch"):
        ssh.serve({"ssh": selection()}, "synthetic-token", "synthetic-environment")
    retrieve.assert_not_called()


class OrdinaryFiles:
    """Isolate transfer behavior; platform no-follow handles have separate native tests."""

    def ancestors(self, _path):
        """Provide a synthetic retained ancestor scope.

        Args:
            _path: Local fixture path.
        """
        return nullcontext()

    def opened(self, _path, **_kwargs):
        """Provide a synthetic ordinary-object pin.

        Args:
            _path: Local fixture path.
            **_kwargs: Native handle options, separately tested on Windows.
        """
        return nullcontext()


class Sftp:
    """Keep transport bytes in memory and expose unexpected writes to assertions."""

    def __init__(self):
        self.files = {}
        self.puts = 0

    def mkdir(self, _path, **_kwargs):
        """Accept a new synthetic private directory.

        Args:
            _path: Remote directory selector.
            **_kwargs: Requested creation mode.
        """

    def lstat(self, path):
        """Report only entries explicitly transferred in this fixture.

        Args:
            path: Remote path to inspect.
        """
        if path not in self.files:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=0o100600, st_uid=0)

    def putfo(self, stream, path, **_kwargs):
        """Record one public input upload.

        Args:
            stream: Fixture input bytes.
            path: Destination beneath the private mirror.
            **_kwargs: Transfer bounds and callbacks.
        """
        self.puts += 1
        self.files[path] = stream.read()

    def chmod(self, _path, _mode):
        """Accept the fixed private file mode.

        Args:
            _path: Public input destination.
            _mode: Requested private mode.
        """


@pytest.fixture
def mirror(monkeypatch):
    """Bind an in-memory SSH mirror without credentials or a real guest.

    Args:
        monkeypatch: Substitute platform pins and isolate native path translation.
    """
    from scripts import completed_task_files

    monkeypatch.setattr(completed_task_files, "WindowsFiles", OrdinaryFiles)
    monkeypatch.setattr(ssh, "mapped_path", lambda value, _roots: "files/" + Path(value).name)
    ftp = Sftp()
    session = ssh.Session({"deadline_epoch": time.time() + 120, "remote_id": "a" * 32 + "-admit",
                           "allowed_roots": []}, None, ftp)
    session.original = {"uid": 0}

    def control(_operation, **fields):
        """Report the digest actually present in the simulated remote mirror.

        Args:
            _operation: Public workspace inventory operation.
            **fields: Relative paths selected for digest verification.
        """
        relative = fields["paths"][0]
        data = ftp.files[session.root + "/" + relative]
        return {relative: [{"sha256": hashlib.sha256(data).hexdigest()}]}

    monkeypatch.setattr(session, "control", control)
    return session, ftp


def test_public_input_cache_rechecks_remote_digest_and_refuses_mutation(mirror, tmp_path):
    """Caching must not trust a changed remote file or silently replace changed local bytes.

    Args:
        mirror: In-memory transfer fixture.
        tmp_path: Ordinary local public package fixture.
    """
    session, ftp = mirror
    package = tmp_path / "package.rpm"
    package.write_bytes(b"authenticated package")
    remote = session.transfer(package)
    assert session.transfer(package) == remote
    assert ftp.puts == 1
    ftp.files[remote] = b"changed remote package"
    with pytest.raises(ValueError, match="transferred_digest_changed"):
        session.transfer(package)
    package.write_bytes(b"different local package")
    with pytest.raises(ValueError, match="input_digest_changed"):
        session.transfer(package)
    assert ftp.puts == 1


def test_output_directory_replacement_refuses_publication(mirror, tmp_path, monkeypatch):
    """A same-path replacement is not the original empty output directory.

    Args:
        mirror: In-memory transfer fixture.
        tmp_path: Parent for separately identifiable directories.
        monkeypatch: Supply an empty native output inventory.
    """
    session, _ftp = mirror
    root = tmp_path / "output"
    root.mkdir()
    value = root.stat()
    root.rename(tmp_path / "original")
    root.mkdir()
    monkeypatch.setattr(session, "control", lambda *_args, **_kwargs: {"files/output": []})
    with pytest.raises(ValueError, match="output_identity_changed"):
        session.receive_output(root, (value.st_dev, value.st_ino))
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("path", ["../outside.xml", "repodata/../../outside", "C:stream", ""])
def test_remote_output_names_cannot_escape_or_name_an_alternate_stream(mirror, tmp_path, monkeypatch, path):
    """Reject unsafe returned names before opening a local output.

    Args:
        mirror: In-memory transfer fixture.
        tmp_path: Original empty output root.
        monkeypatch: Supply adversarial native inventory names.
        path: Independent path escape to reject.
    """
    session, _ftp = mirror
    monkeypatch.setattr(session, "control", lambda *_args, **_kwargs: {
        "files/" + tmp_path.name: [{"path": path, "kind": "file"}]})
    value = tmp_path.stat()
    with pytest.raises(ValueError, match="output_path_invalid"):
        session.receive_output(tmp_path, (value.st_dev, value.st_ino))
    assert list(tmp_path.iterdir()) == []


def test_output_byte_bound_is_independent_of_server_size_claim(mirror):
    """A responsive server still cannot exceed the original inventory's byte budget.

    Args:
        mirror: In-memory transfer fixture.
    """
    session, _ftp = mirror
    with pytest.raises(ValueError, match="transfer_size_changed"):
        session.progress(11, 10)


def test_plan_hash_keeps_legacy_shape_and_binds_ssh_selectors():
    """SSH selectors are explicit additions; retained WSL plans keep their canonical representation."""
    from tests.test_installation_refresh_plan import plan as make_plan

    original = make_plan()
    legacy = validate_plan(original)
    assert "native_ssh" not in legacy
    selected = validate_plan({**original, "native_ssh": selection()})
    assert selected["native_ssh"] == selection()
    with pytest.raises(ValueError, match="either"):
        validate_plan({**original, "native_ssh": selection(), "native_distribution": "FixtureLinux"})


@pytest.mark.parametrize("pending", [False, True])
def test_ssh_parent_preserves_the_native_receipt_barrier(tmp_path, monkeypatch, pending):
    """SSH forwarding must not release a child before its Linux identity is durable.

    Args:
        tmp_path: Isolated protocol evidence root.
        monkeypatch: Substitute a two-sided native guest without a real SSH connection.
        pending: Whether the guest refuses terminal quiescence.
    """
    from scripts import native_rpm_tools as native
    from tests.test_native_rpm_tools import GuestProtocol

    directory = tmp_path / "native"
    directory.mkdir()
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"task_id": "actual-task", "source_commit": "a" * 40,
                                  "directory": str(directory), "ssh": selection(),
                                  "deadline_epoch": time.time() + 90}))
    monkeypatch.setenv(native.CONTEXT, str(context))
    monkeypatch.setenv("CODEX_THREAD_ID", "actual-task")
    process = GuestProtocol(directory, pending=pending)
    monkeypatch.setattr(native, "_ssh_proxy", lambda _context: process)
    if pending:
        with pytest.raises(RuntimeError, match="quiescence_unproven"):
            native.run(["rpm", "--version"])
        assert not list(directory.glob("*-result.json"))
    else:
        assert native.run(["rpm", "--version"]) == "rpm version fixture\n"
        assert native.quiescent(directory)
    assert list(directory.glob("*-original.json"))


def test_remote_root_completion_must_match_its_original_session(tmp_path):
    """A terminal result from another task or scope cannot close an SSH session.

    Args:
        tmp_path: Isolated session evidence directory.
    """
    from scripts import native_rpm_tools as native

    original = {"scope": "original-scope", "task_id": "task", "source_commit": "a" * 40}
    (tmp_path / "fixture-ssh-original.json").write_text(json.dumps(original))
    assert not native.quiescent(tmp_path)
    result = {**original, "whole_group_quiescent": True, "remote_root_absent": True}
    path = tmp_path / "fixture-ssh-result.json"
    path.write_text(json.dumps({**result, "scope": "another-scope"}))
    assert not native.quiescent(tmp_path)
    path.write_text(json.dumps(result))
    assert native.quiescent(tmp_path)
