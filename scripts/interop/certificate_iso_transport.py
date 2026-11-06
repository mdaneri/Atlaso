"""Constrain the existing password deployer's optional original-ISO transport."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import stat
import time
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.installation.content_inspection import validate_content_report
from scripts.installation.inspection import validate_report


class Refusal(ValueError):
    """Return a fixed public category without guest output or secret values."""


def ordinary_bytes(path: Path, limit: int) -> bytes:
    """Read one bounded ordinary single-link input while the owner retains its pins.

    Args:
        path: Originally admitted local file.
        limit: Maximum accepted byte count.
    """
    with path.open("rb") as stream:
        metadata = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or len(data) > limit:
        raise Refusal("iso_transport_input_invalid")
    return data


def admit_request(path: Path, checksum: str, args: Any) -> dict[str, Any]:
    """Bind the parent's pinned request before the child reads any credentials.

    Args:
        path: Immutable public owner request.
        checksum: Independent digest passed by its retaining parent.
        args: Existing deployer arguments with explicit source, wheel and destination.
    """
    raw = ordinary_bytes(path, 131072)
    if not re.fullmatch(r"[0-9a-f]{64}", checksum) or hashlib.sha256(raw).hexdigest() != checksum:
        raise Refusal("iso_transport_request_digest_mismatch")
    value = json.loads(raw)
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("kind") != "certificate-iso-wheel-deployment-request"
            or value.get("repository") != "mdaneri/Atlaso"
            or value.get("task_id") != os.environ.get("CODEX_THREAD_ID")
            or value.get("host_address") != args.host or args.user != "admin"
            or value.get("remote_directory") != args.remote_dir
            or value.get("remote_wheel") != args.remote_wheel
            or not re.fullmatch(r"/tmp/atlaso-certificate-deploy-[0-9a-f]{32}", args.remote_dir)
            or PurePosixPath(args.remote_wheel).parent != PurePosixPath(args.remote_dir)
            or Path(value.get("wheel_path", "")).resolve() != Path(args.local_wheel).resolve()
            or Path(value.get("source_root", "")).resolve() != Path(args.fixture_source_root).resolve()
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", str(value.get("host_key_sha256", "")))
            or args.trusted_host_key or args.reset_vault_entries
            or any((args.local_helper, args.local_console_manager, args.local_boot_installer))):
        raise Refusal("iso_transport_request_binding_mismatch")
    wheel = ordinary_bytes(Path(args.local_wheel), 268435456)
    if (hashlib.sha256(wheel).hexdigest() != value.get("wheel_sha256")
            or len(wheel) != value.get("wheel_size")
            or Path(args.local_wheel).name != value.get("wheel_filename")):
        raise Refusal("iso_transport_wheel_identity_mismatch")
    output = Path(value["inspection_output"])
    if output.exists() or output.parent.resolve() != Path(value["output_root"]).resolve():
        raise Refusal("iso_transport_output_not_fresh")
    expected = value["original_expected"]
    original = validate_report(json.dumps(value["original_inspection"]).encode(), expected)
    if original["host_key_sha256"] != value["host_key_sha256"]:
        raise Refusal("iso_transport_original_ssh_mismatch")
    return value


def verify_host_key(request: dict[str, Any], key: Any) -> None:
    """Check the console-observed Ed25519 key before password authentication.

    Args:
        request: Admitted original-ISO request.
        key: Server key negotiated by the existing Paramiko connection.
    """
    digest = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    if key.get_name() != "ssh-ed25519" or digest != request["host_key_sha256"]:
        raise Refusal("iso_transport_ssh_identity_mismatch")


def run_read(client: Any, command: str, password: str, timeout: int) -> bytes:
    """Read one bounded public JSON report without exposing command output.

    Args:
        client: Already authenticated original-ISO SSH client.
        command: Fixed inspector command generated from original admitted media.
        password: Ephemeral credential retained only in this child.
        timeout: Remaining bounded invocation time in seconds.
    """
    stdin, stdout, _stderr = client.exec_command("sudo -S -p '' " + command, get_pty=False, timeout=timeout)
    stdin.write(password + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    channel = stdout.channel
    result = bytearray()
    errors = 0
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() >= deadline:
            channel.close()
            raise Refusal("iso_transport_inspection_timeout")
        if channel.recv_ready():
            result.extend(channel.recv(16384))
        if channel.recv_stderr_ready():
            errors += len(channel.recv_stderr(16384))
        if len(result) > 131072 or errors > 131072:
            channel.close()
            raise Refusal("iso_transport_inspection_output_bound")
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        time.sleep(0.01)
    if channel.recv_exit_status():
        raise Refusal("iso_transport_inspection_failed")
    return bytes(result)


def drain_engine(channel: Any, timeout: int) -> int:
    """Discard existing-engine output within a fixed byte and time budget.

    Args:
        channel: Existing deployer's already opened non-PTY execution channel.
        timeout: Bounded engine execution duration in seconds.
    """
    total = 0
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() >= deadline:
            channel.close()
            raise Refusal("iso_transport_engine_timeout")
        if channel.recv_ready():
            total += len(channel.recv(65536))
        if channel.recv_stderr_ready():
            total += len(channel.recv_stderr(65536))
        if total > 4 * 1024**2:
            channel.close()
            raise Refusal("iso_transport_engine_output_bound")
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            return int(channel.recv_exit_status())
        time.sleep(0.01)


def preflight(client: Any, request: dict[str, Any], password: str, timeout: int) -> None:
    """Verify original software, public identities and media assets before uploading.

    Args:
        client: Client bound to the original console SSH identity.
        request: Public original-media inspection commands and expectations.
        password: Child-only sudo credential.
        timeout: Bounded readback duration.
    """
    raw = run_read(client, request["preflight_command"], password, timeout).strip()
    match = re.fullmatch(rb"ATLASO-INSPECTION:([A-Za-z0-9+/=]+):END", raw)
    if not match:
        raise Refusal("iso_transport_preflight_report_invalid")
    report = validate_report(base64.b64decode(match[1], validate=True), request["original_expected"])
    if report != request["original_inspection"]:
        raise Refusal("iso_transport_original_identity_changed")
    validate_content_report(decode_report(run_read(client, request["assets_command"], password, timeout)), request["assets_expected"])


def decode_report(raw: bytes) -> bytes:
    """Decode only the existing strict public console-inspection marker.

    Args:
        raw: Bounded output of an original-media inspector over pinned SSH.
    """
    match = re.fullmatch(rb"ATLASO-INSPECTION:([A-Za-z0-9+/=]+):END", raw.strip())
    if not match:
        raise Refusal("iso_transport_inspection_marker_invalid")
    return base64.b64decode(match[1], validate=True)


def verify_uploads(client: Any, uploads: list[tuple[Path, str]], request: dict[str, Any],
                   password: str, timeout: int) -> None:
    """Verify every private staging file before running the existing deployment engine.

    Args:
        client: Client whose original SSH identity was already checked.
        uploads: Exact existing deployer upload set, with original local inputs pinned.
        request: Admission selecting the unique remote staging directory.
        password: Child-only sudo credential.
        timeout: Bounded verification duration.
    """
    records = []
    for local, remote in uploads:
        if PurePosixPath(remote).parent != PurePosixPath(request["remote_directory"]):
            raise Refusal("iso_transport_upload_destination_invalid")
        raw = ordinary_bytes(local, 268435456)
        records.append((remote, len(raw), hashlib.sha256(raw).hexdigest()))
    if len({record[0] for record in records}) != len(records):
        raise Refusal("iso_transport_duplicate_upload_destination")
    body = f'''import hashlib,json,os,stat
r={records!r}
for p,n,h in r:
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());d=hashlib.file_digest(f,'sha256').hexdigest()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=n or d!=h: raise ValueError()
print(json.dumps({{"verified_uploads":len(r)}}))
'''
    encoded = base64.b64encode(body.encode()).decode()
    command = "/opt/atlaso/.venv/bin/python -I -B -c " + shlex.quote("import base64;exec(base64.b64decode('" + encoded + "'))")
    if json.loads(run_read(client, command, password, timeout)) != {"verified_uploads": len(records)}:
        raise Refusal("iso_transport_upload_verification_failed")


def finish(client: Any, request: dict[str, Any], password: str, timeout: int) -> None:
    """Publish only validated public payload and original-media evidence after success.

    Args:
        client: Original SSH client retained through the existing deployment engine.
        request: Pinned wheel, machine, network and asset expectations.
        password: Ephemeral child-only sudo credential.
        timeout: Bounded post-deployment readback duration.
    """
    from scripts.interop.certificate_iso_deployment import validate_measurement

    measurement = json.loads(run_read(client, request["payload_command"], password, timeout))
    validate_measurement(measurement, wheel_sha256=request["wheel_sha256"], helper_sha256=request["helper_sha256"],
                         installed=request["original_inspection"], address=request["host_address"],
                         mac=request["mac"], version=request["version"])
    assets_raw = decode_report(run_read(client, request["assets_command"], password, timeout))
    validate_content_report(assets_raw, request["assets_expected"])
    value = {"schema": 1, "kind": "certificate-iso-wheel-live-inspection", "measurement": measurement,
             "assets_report": json.loads(assets_raw)}
    with Path(request["inspection_output"]).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
