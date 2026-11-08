"""Exercise original-ISO wheel transport guards without a VM or real network."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.installation import content_inspection

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_iso_transport as transport  # noqa: E402 - Local interop module import.

_ISO = "a" * 64
_COMMIT = "b" * 40
_HOST_KEY = "SHA256:" + base64.b64encode(hashlib.sha256(b"k" * 32).digest()).decode().rstrip("=")
_PASSWORD = "synthetic-child-only-password"


def _asset_reports() -> tuple[dict[str, object], dict[str, object]]:
    """Return a media-bound asset expectation and matching public measurement.

    Returns:
        The expected assets and matching report objects.
    """
    expected: dict[str, object] = {
        "schema": 1, "kind": "assets", "iso_sha256": _ISO,
        "environment_verifier_sha256": "c" * 64, "source_digest": "d" * 64,
        "source_file_count": 3, "trust_names": ["atlaso-release-test.pem"],
        "trust_digest": "e" * 64, "omitted_sources": sorted(content_inspection._VMWARE_SOURCES),
        "deployed_file_count": 4,
    }
    report: dict[str, object] = {
        "schema": 1, "kind": "assets", "iso_sha256": _ISO,
        "source_digest": "d" * 64, "source_file_count": 3, "deployed_files": 4,
        "trust_digest": "e" * 64, "trust_keys": 1,
    }
    return expected, report


def _valid_transport_request(tmp_path: Path) -> tuple[dict[str, object], SimpleNamespace, Path, str]:
    """Create real pinned request and wheel files accepted by request admission.

    Args:
        tmp_path: Pytest-owned directory for all ordinary input and output files.

    Returns:
        Request, matching deployer arguments, request path, and request digest.
    """
    wheel = tmp_path / "atlaso-1.2.4-py3-none-any.whl"
    wheel.write_bytes(b"synthetic wheel bytes")
    source_root = tmp_path / "source"
    source_root.mkdir()
    output_root = tmp_path / "test-results"
    output_root.mkdir()
    expected: dict[str, object] = {
        "schema": 1, "iso_sha256": _ISO, "version": "1.2.3", "source_commit": _COMMIT,
        "release_manifest_sha256": "1" * 64, "software_verifier_sha256": "2" * 64,
        "payload_inspector_sha256": "3" * 64, "wheel_sha256": "4" * 64,
    }
    original = {
        "schema": 1, "machine_id_sha256": "5" * 64, "host_key_sha256": _HOST_KEY,
        "version": "1.2.3", "source_commit": _COMMIT, "wheel_sha256": "4" * 64,
        "wheel_payload_sha256": "6" * 64, "installed_payload_sha256": "6" * 64,
        "verified_payload_files": 25,
    }
    assets_expected, _ = _asset_reports()
    remote_directory = "/var/tmp/atlaso-certificate-deploy-" + "7" * 32
    request: dict[str, object] = {
        "schema": 1, "kind": "certificate-iso-wheel-deployment-request",
        "repository": "mdaneri/Atlaso", "task_id": "task-transport-test",
        "host_address": "192.168.77.30", "host_key_sha256": _HOST_KEY,
        "wheel_path": str(wheel), "source_root": str(source_root),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_size": wheel.stat().st_size, "wheel_filename": wheel.name,
        "remote_directory": remote_directory, "remote_wheel": remote_directory + "/" + wheel.name,
        "output_root": str(output_root), "inspection_output": str(output_root / "inspection.json"),
        "original_expected": expected, "original_inspection": original,
        "preflight_command": "original-inspection-command", "assets_command": "original-assets-command",
        "assets_expected": assets_expected, "payload_command": "active-payload-command",
        "wheel_sha256_active": "7" * 64, "helper_sha256": "8" * 64,
        "mac": "00:50:56:aa:bb:cc", "version": "1.2.4",
    }
    path = tmp_path / "request.json"
    raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    args = SimpleNamespace(
        host=request["host_address"], user="admin", local_wheel=str(wheel),
        fixture_source_root=str(source_root), remote_dir=remote_directory,
        remote_wheel=request["remote_wheel"], trusted_host_key="", reset_vault_entries=False,
        local_helper="", local_console_manager="", local_boot_installer="",
    )
    return request, args, path, hashlib.sha256(raw).hexdigest()


def test_admit_request_accepts_exact_digest_bound_original_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admit the exact wheel, host key, and fresh output destination.

    Args:
        tmp_path: Pytest-owned directory for request and wheel inputs.
        monkeypatch: Provide the admitted child task ID without external reads.
    """
    request, args, path, digest = _valid_transport_request(tmp_path)
    monkeypatch.setenv("CODEX_THREAD_ID", str(request["task_id"]))

    assert transport.admit_request(path, digest, args) == request
    assert not Path(str(request["inspection_output"])).exists()


def test_phase_receipts_disclose_only_fixed_progress_and_refuse_replacement(tmp_path: Path) -> None:
    """Keep private fields out of progress and preserve the first phase observation.

    Args:
        tmp_path: Owned ordinary fixture directory for public phase records.
    """
    request = {"inspection_output": str(tmp_path / "live.json"), "output_root": str(tmp_path),
               "password": _PASSWORD, "command": "private diagnostic command"}
    transport.record_phase(request, "engine-exited", exit_code=2)
    path = tmp_path / "deployer-phase-engine-exited.json"
    raw = path.read_text()
    assert json.loads(raw) == {"schema": 1, "kind": "certificate-iso-deployment-phase",
                               "phase": "engine-exited", "exit_code": 2}
    assert _PASSWORD not in raw and "private diagnostic" not in raw
    with pytest.raises(FileExistsError):
        transport.record_phase(request, "engine-exited", exit_code=0)
    assert path.read_text() == raw


@pytest.mark.parametrize(("phase", "code"), [(_PASSWORD, None), ("credentials-ready", 0),
                                             ("engine-exited", True), ("engine-exited", -1),
                                             ("engine-exited", 256)])
def test_phase_receipts_reject_unbounded_diagnostics(tmp_path: Path, phase: str, code: object) -> None:
    """Refuse arbitrary diagnostic names and malformed statuses before publishing.

    Args:
        tmp_path: Owned ordinary fixture directory.
        phase: Fixed or deliberately invalid proposed phase name.
        code: Proposed engine exit status.
    """
    request = {"inspection_output": str(tmp_path / "live.json"), "output_root": str(tmp_path)}
    with pytest.raises(transport.Refusal, match="iso_transport_phase_invalid"):
        transport.record_phase(request, phase, exit_code=code)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("defect", "category"),
    [
        ("request_digest", "iso_transport_request_digest_mismatch"),
        ("wheel", "iso_transport_wheel_identity_mismatch"),
        ("host_key", "iso_transport_original_ssh_mismatch"),
        ("output_exists", "iso_transport_output_not_fresh"),
        ("output_parent", "iso_transport_output_not_fresh"),
        ("host", "iso_transport_request_binding_mismatch"),
        ("ephemeral_upload", "iso_transport_request_binding_mismatch"),
    ],
)
def test_admit_request_refuses_changed_pins_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, category: str,
) -> None:
    """Refuse changed request, wheel, original identity, and output selectors.

    Args:
        tmp_path: Pytest-owned directory for real request and wheel files.
        monkeypatch: Provide task identity and modify only the selected defect.
        defect: Independent admission mismatch to introduce.
        category: Expected public refusal category.
    """
    request, args, path, digest = _valid_transport_request(tmp_path)
    monkeypatch.setenv("CODEX_THREAD_ID", str(request["task_id"]))
    if defect == "request_digest":
        digest = "0" * 64
    elif defect == "wheel":
        Path(args.local_wheel).write_bytes(b"changed wheel bytes")
    elif defect == "host_key":
        request["original_inspection"]["host_key_sha256"] = "SHA256:" + base64.b64encode(b"x" * 32).decode().rstrip("=")
    elif defect == "output_exists":
        Path(str(request["inspection_output"])).write_bytes(b"already exists")
    elif defect == "output_parent":
        request["inspection_output"] = str(Path(str(request["output_root"])).parent / "outside.json")
    elif defect == "host":
        args.host = "192.168.77.31"
    elif defect == "ephemeral_upload":
        request["remote_directory"] = args.remote_dir = args.remote_dir.replace("/var/tmp/", "/tmp/", 1)
        request["remote_wheel"] = args.remote_wheel = args.remote_wheel.replace("/var/tmp/", "/tmp/", 1)
    if defect in {"host_key", "output_parent", "ephemeral_upload"}:
        raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(transport.Refusal, match=category):
        transport.admit_request(path, digest, args)


def test_verify_host_key_checks_ed25519_digest_and_type() -> None:
    """Accept the exact console-pinned host key and refuse mismatches."""

    class Key:
        """Minimal fake negotiated SSH key."""

        def __init__(self, raw: bytes, name: str = "ssh-ed25519") -> None:
            """Set the synthetic public key bytes and algorithm.

            Args:
                raw: Public test key bytes.
                name: Negotiated key algorithm.
            """
            self.raw = raw
            self.name = name

        def asbytes(self) -> bytes:
            """Return the public test key blob."""
            return self.raw

        def get_name(self) -> str:
            """Return the negotiated algorithm name."""
            return self.name

    request = {"host_key_sha256": _HOST_KEY}
    transport.verify_host_key(request, Key(b"k" * 32))
    with pytest.raises(transport.Refusal, match="iso_transport_ssh_identity_mismatch"):
        transport.verify_host_key(request, Key(b"x" * 32))
    with pytest.raises(transport.Refusal, match="iso_transport_ssh_identity_mismatch"):
        transport.verify_host_key(request, Key(b"k" * 32, "ssh-rsa"))


def test_deployer_verifies_original_key_before_password_authentication() -> None:
    """Keep password and keyboard-interactive auth after pinned original-key check."""
    source_path = Path(__file__).resolve().parents[1] / "scripts" / "windows" / "vmware" / "deploy-wheel.ps1"
    source = source_path.read_text(encoding="utf-8")
    verification = source.index("fixture_transport.verify_host_key(fixture_request, server_key)")
    password_auth = source.index("transport.auth_password(username, password, fallback=False)")
    interactive_auth = source.index("transport.auth_interactive(username, keyboard_interactive_handler)")
    assert verification < password_auth < interactive_auth


class _Channel:
    """Supply fixed stdout/stderr through the bounded Paramiko channel contract."""

    def __init__(self, output: bytes, stderr: bytes = b"", exit_code: int = 0) -> None:
        """Set synthetic command bytes and status.

        Args:
            output: Bounded stdout bytes.
            stderr: Bounded stderr bytes.
            exit_code: Synthetic process status.
        """
        self.output, self.stderr, self.exit_code = output, stderr, exit_code
        self.closed = False

    def recv_ready(self) -> bool:
        """Report unread fake stdout."""
        return bool(self.output)

    def recv(self, _size: int) -> bytes:
        """Consume fake stdout.

        Args:
            _size: Requested bounded read size.
        """
        result, self.output = self.output, b""
        return result

    def recv_stderr_ready(self) -> bool:
        """Report unread fake stderr."""
        return bool(self.stderr)

    def recv_stderr(self, _size: int) -> bytes:
        """Consume fake stderr.

        Args:
            _size: Requested bounded read size.
        """
        result, self.stderr = self.stderr, b""
        return result

    def exit_status_ready(self) -> bool:
        """Mark the synthetic command complete."""
        return True

    def recv_exit_status(self) -> int:
        """Return the selected synthetic process status."""
        return self.exit_code

    def close(self) -> None:
        """Record fake channel closure."""
        self.closed = True


def test_engine_output_is_discarded_and_byte_bounded(capsys: pytest.CaptureFixture[str]) -> None:
    """Keep remote logs private and refuse a flooding engine before retaining output.

    Args:
        capsys: Capture public host output to prove raw guest logs never escape.
    """
    channel = _Channel(b"synthetic private guest log", b"synthetic guest diagnostic", exit_code=3)
    assert transport.drain_engine(channel, 1) == 3
    assert capsys.readouterr() == ("", "")
    flood = _Channel(b"x" * (4 * 1024**2 + 1))
    with pytest.raises(transport.Refusal, match="iso_transport_engine_output_bound"):
        transport.drain_engine(flood, 1)
    assert flood.closed


def test_engine_deadline_closes_a_stalled_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop a stalled remote engine at the fixed invocation deadline.

    Args:
        monkeypatch: Substitute only the local monotonic test timer.
    """
    observations = iter((0.0, 2.0))
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(observations))
    channel = _Channel(b"")
    with pytest.raises(transport.Refusal, match="iso_transport_engine_timeout"):
        transport.drain_engine(channel, 1)
    assert channel.closed


def test_run_read_keeps_sudo_input_on_stdin_and_returns_public_stdout() -> None:
    """Send the synthetic password only through stdin and discard stderr contents."""
    channel = _Channel(b'{"status":"ok"}', b"synthetic private diagnostic")

    class Input:
        """Capture the bounded private input without printing or persisting it."""

        def __init__(self) -> None:
            """Create the in-memory stdin recorder."""
            self.value = ""
            self.channel = SimpleNamespace(shutdown_write=lambda: None)

        def write(self, value: str) -> None:
            """Capture a test-only sudo password line.

            Args:
                value: In-memory stdin bytes decoded as text by the fake client.
            """
            self.value += value

        def flush(self) -> None:
            """Accept the fake flush call."""

    stdin = Input()

    class Client:
        """Return only the fake non-PTY SSH channel."""

        def exec_command(self, command: str, *, get_pty: bool, timeout: int):
            """Check the sudo invocation and return fake streams.

            Args:
                command: Exact public report command.
                get_pty: PTY selection made by the transport.
                timeout: Per-command deadline.
            """
            assert command == "sudo -S -p '' public-report"
            assert get_pty is False and timeout == 3
            return stdin, SimpleNamespace(channel=channel), object()

    output = transport.run_read(Client(), "public-report", _PASSWORD, 3)
    assert output == b'{"status":"ok"}'
    assert stdin.value == _PASSWORD + "\n"
    assert b"synthetic private diagnostic" not in output


def _original_report() -> tuple[dict[str, object], dict[str, object]]:
    """Return an exact schema-valid installed ISO expectation and inspection."""
    expected: dict[str, object] = {
        "schema": 1, "iso_sha256": _ISO, "version": "1.2.3", "source_commit": _COMMIT,
        "release_manifest_sha256": "1" * 64, "software_verifier_sha256": "2" * 64,
        "payload_inspector_sha256": "3" * 64, "wheel_sha256": "4" * 64,
    }
    report: dict[str, object] = {
        "schema": 1, "machine_id_sha256": "5" * 64, "host_key_sha256": _HOST_KEY,
        "version": "1.2.3", "source_commit": _COMMIT, "wheel_sha256": "4" * 64,
        "wheel_payload_sha256": "6" * 64, "installed_payload_sha256": "6" * 64,
        "verified_payload_files": 25,
    }
    return expected, report


def _marker(value: dict[str, object]) -> bytes:
    """Encode the established console marker around a public report object.

    Args:
        value: Public report serialized as JSON.
    """
    encoded = base64.b64encode(json.dumps(value, separators=(",", ":")).encode())
    return b"ATLASO-INSPECTION:" + encoded + b":END"


def test_preflight_admits_original_report_and_asset_marker_before_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate original ISO and asset markers through existing real validators.

    Args:
        monkeypatch: Provide fixed fake channel output for public report commands.
    """
    expected, original = _original_report()
    assets_expected, assets_report = _asset_reports()
    request = {
        "preflight_command": "original-inspection", "original_expected": expected,
        "original_inspection": original, "assets_command": "assets-inspection",
        "assets_expected": assets_expected,
    }
    replies = iter([_marker(original), _marker(assets_report)])
    calls: list[str] = []

    def read(_client: object, command: str, _password: str, _timeout: int) -> bytes:
        """Return the next marker and track command order.

        Args:
            _client: Fake authenticated channel owner.
            command: Read-only original ISO inspection selector.
            _password: Synthetic in-memory sudo value.
            _timeout: Bounded test deadline.
        """
        calls.append(command)
        return next(replies)

    monkeypatch.setattr(transport, "run_read", read)
    transport.preflight(object(), request, _PASSWORD, 5)
    assert calls == ["original-inspection", "assets-inspection"]

    replies = iter([_marker({**original, "machine_id_sha256": "9" * 64})])
    with pytest.raises(transport.Refusal, match="iso_transport_original_identity_changed"):
        transport.preflight(object(), request, _PASSWORD, 5)

    invalid_assets = {**assets_report, "source_digest": "f" * 64}
    replies = iter([_marker(original), _marker(invalid_assets)])
    with pytest.raises(ValueError, match="installed source or trust differs"):
        transport.preflight(object(), request, _PASSWORD, 5)


def test_verify_uploads_binds_exact_hashes_destinations_and_duplicate_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Build remote verification from exact local files and reject unsafe paths.

    Args:
        tmp_path: Pytest-owned directory containing synthetic upload inputs.
        monkeypatch: Capture the generated read-only verifier command.
    """
    wheel, script = tmp_path / "wheel.whl", tmp_path / "deploy.sh"
    wheel.write_bytes(b"wheel contents")
    script.write_bytes(b"script contents")
    remote = "/var/tmp/atlaso-certificate-deploy-" + "a" * 32
    request = {"remote_directory": remote}
    commands: list[str] = []

    def read(_client: object, command: str, _password: str, _timeout: int) -> bytes:
        """Capture generated verification code and return successful public JSON.

        Args:
            _client: Fake connected client.
            command: Encoded remote file verifier.
            _password: In-memory test credential.
            _timeout: Bounded command duration.
        """
        commands.append(command)
        return b'{"verified_uploads":2}'

    monkeypatch.setattr(transport, "run_read", read)
    transport.verify_uploads(object(), [(wheel, remote + "/wheel.whl"), (script, remote + "/deploy.sh")],
                             request, _PASSWORD, 5)
    encoded = commands[0].split("b64decode('", 1)[1].split("')", 1)[0]
    verifier = base64.b64decode(encoded).decode()
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() in verifier
    assert hashlib.sha256(script.read_bytes()).hexdigest() in verifier
    assert remote + "/wheel.whl" in verifier and remote + "/deploy.sh" in verifier
    with pytest.raises(transport.Refusal, match="iso_transport_upload_destination_invalid"):
        transport.verify_uploads(object(), [(wheel, "/tmp/unrelated/wheel.whl")], request, _PASSWORD, 5)
    with pytest.raises(transport.Refusal, match="iso_transport_duplicate_upload_destination"):
        transport.verify_uploads(object(), [(wheel, remote + "/same"), (script, remote + "/same")],
                                 request, _PASSWORD, 5)
    monkeypatch.setattr(transport, "run_read", lambda *_args: b'{"verified_uploads":0}')
    with pytest.raises(transport.Refusal, match="iso_transport_upload_verification_failed"):
        transport.verify_uploads(object(), [(wheel, remote + "/wheel.whl")], request, _PASSWORD, 5)


def test_finish_writes_validated_immutable_output_and_leaves_none_on_payload_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publish only measured payload and original assets, once, after validation.

    Args:
        tmp_path: Pytest-owned directory for the immutable inspection output.
        monkeypatch: Replace remote reads and active measurement comparison only.
    """
    import scripts.interop.certificate_iso_deployment as deployment

    output = tmp_path / "inspection.json"
    assets_expected, assets_report = _asset_reports()
    original = {"machine_id_sha256": "4" * 64}
    measurement: dict[str, object] = {
        "schema": 1, "wheel_payload_sha256": "1" * 64, "installed_payload_sha256": "1" * 64,
        "verified_payload_files": 12, "wheel_sha256": "2" * 64, "helper_sha256": "3" * 64,
        "interface": "eth0", "mac": "00:50:56:aa:bb:cc", "address": "192.168.77.30",
        "version": "1.2.4", "machine_id_sha256": "4" * 64,
    }
    request = {
        "inspection_output": str(output), "payload_command": "payload", "assets_command": "assets",
        "assets_expected": assets_expected, "original_inspection": original,
        "wheel_sha256": "2" * 64, "helper_sha256": "3" * 64,
        "host_address": "192.168.77.30", "mac": "00:50:56:aa:bb:cc", "version": "1.2.4",
    }
    monkeypatch.setattr(transport, "run_read", lambda _client, command, *_args:
                        json.dumps(measurement).encode() if command == "payload" else _marker(assets_report))
    monkeypatch.setattr(deployment, "validate_measurement", lambda value, **_kwargs: value)
    transport.finish(object(), request, _PASSWORD, 5)
    assert json.loads(output.read_text())["assets_report"] == assets_report
    with pytest.raises(FileExistsError):
        transport.finish(object(), request, _PASSWORD, 5)

    output.unlink()

    def reject_measurement(*_args: object, **_kwargs: object) -> None:
        """Reject active payload identity before report publication.

        Args:
            *_args: Measurement and independent public identity selectors.
            **_kwargs: Expected payload and original machine bindings.
        """
        raise transport.Refusal("iso_deployment_active_payload_mismatch")

    monkeypatch.setattr(deployment, "validate_measurement", reject_measurement)
    with pytest.raises(transport.Refusal, match="iso_deployment_active_payload_mismatch"):
        transport.finish(object(), request, _PASSWORD, 5)
    assert not output.exists()
