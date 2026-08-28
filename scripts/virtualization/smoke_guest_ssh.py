"""Validate VMware or Hyper-V guest state using the artifact-bound SSH host key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any


class SmokeError(RuntimeError):
    """Report a sanitized virtualization smoke-test failure."""


@dataclass(frozen=True)
class SecretInput:
    """Hold credentials consumed only from standard input."""

    username: str
    password: str


def load_secret_input() -> SecretInput:
    """Read the exact credential envelope from standard input."""

    try:
        payload: Any = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise SmokeError("Smoke-test credential input is not valid JSON.") from exc
    if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
        raise SmokeError("Smoke-test credential input has an unexpected schema.")
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise SmokeError("Smoke-test credential input contains an invalid required value.")
    return SecretInput(username=username, password=password)


def parse_host_public_key(value: str) -> tuple[str, bytes]:
    """Return one canonical Ed25519 SSH host public key tuple.

    Args:
        value: OpenSSH public-key text.
    """

    fields = value.split()
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        raise SmokeError("The artifact SSH host public key is malformed.")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise SmokeError("The artifact SSH host public key is not canonical base64.") from exc
    if (
        len(blob) != 51
        or struct.unpack(">I", blob[:4])[0] != 11
        or blob[4:15] != b"ssh-ed25519"
        or struct.unpack(">I", blob[15:19])[0] != 32
    ):
        raise SmokeError("The artifact SSH host public key has an invalid wire format.")
    return fields[0], blob


def _connect(host: str, secret: SecretInput, *, expected_key: tuple[str, bytes]) -> Any:
    """Open a bounded SSH connection after installing the artifact-bound host key.

    Args:
        host: Guest address.
        secret: Standard-input credential envelope.
        expected_key: Parsed provenance-bound host key.
    """

    import paramiko  # type: ignore[import-untyped]  # Paramiko does not publish complete type metadata.

    deadline = time.monotonic() + 900
    last_error: Exception | None = None
    key_type, key_blob = expected_key
    trusted_key = paramiko.PKey.from_type_string(key_type, key_blob)
    while time.monotonic() < deadline:
        client = paramiko.SSHClient()
        client.get_host_keys().add(host, key_type, trusted_key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                host,
                username=secret.username,
                password=secret.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=15,
                auth_timeout=15,
                banner_timeout=15,
            )
            return client
        except (OSError, paramiko.SSHException) as exc:
            client.close()
            last_error = exc
            time.sleep(5)
    raise SmokeError(f"The guest did not become SSH-ready within 15 minutes: {type(last_error).__name__}")


def _run_root(client: Any, secret: SecretInput, script: str) -> None:
    """Run one fixed root validation script without placing credentials in arguments.

    Args:
        client: Connected SSH client.
        secret: Credential used only through standard input.
        script: Root validation script body.
    """

    command = "sudo -S -p '' sh -s"
    _stdin, stdout, stderr = client.exec_command(command, timeout=180)
    _stdin.write(secret.password + "\n")
    _stdin.write(script)
    _stdin.channel.shutdown_write()
    status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8", "replace").strip()
    error = stderr.read().decode("utf-8", "replace").strip()
    if status != 0 or output != "atlaso-guest-smoke-ok":
        tail = error.splitlines()[-10:]
        raise SmokeError("Guest validation failed: " + " | ".join(tail))


def _validation_script(platform: str) -> str:
    """Return the fixed non-secret guest validation script for one platform.

    Args:
        platform: Expected virtualization provider.
    """

    common = r"""
set -eu
test "$(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | wc -l)" -eq 2
test "$(lsblk -dn -o TYPE | awk '$1 == "disk" { count++ } END { print count + 0 }')" -eq 4
test ! -e /var/lib/atlaso/first-boot-packages
findmnt -rn --target /var/lib/atlaso-system >/dev/null
findmnt -rn --target /mnt/atlaso-vcf-offline-depot >/dev/null
findmnt -rn --target /mnt/atlaso-vcf-backups >/dev/null
systemctl is-active --quiet atlaso-data-disks.service
systemctl is-active --quiet atlaso.service
systemctl is-active --quiet atlaso-worker.service
systemctl is-active --quiet nginx.service
curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null
"""
    provider = {
        "vmware": r"""
grep -qx 'platform=vmware' /var/lib/atlaso-privileged/guest-agent/guest-agent.applied
rpm -q open-vm-tools >/dev/null
! rpm -q hyper-v >/dev/null 2>&1
! rpm -q qemu-guest-agent atlaso-qemu-guest-agent >/dev/null 2>&1
systemctl is-active --quiet vmtoolsd.service
! systemctl is-active --quiet qemu-guest-agent.service
""",
        "hyperv": r"""
grep -qx 'platform=hyperv' /var/lib/atlaso-privileged/guest-agent/guest-agent.applied
rpm -q hyper-v >/dev/null
! rpm -q open-vm-tools >/dev/null 2>&1
! rpm -q qemu-guest-agent atlaso-qemu-guest-agent >/dev/null 2>&1
for service in hv_kvp_daemon.service hv_fcopy_daemon.service hv_vss_daemon.service; do
  systemctl is-active --quiet "$service"
done
! systemctl is-active --quiet vmtoolsd.service
! systemctl is-active --quiet qemu-guest-agent.service
""",
    }[platform]
    return common + provider + "printf 'atlaso-guest-smoke-ok\\n'\n"


def _front_door_fingerprint(host: str) -> str:
    """Require host-facing OpenAPI readiness and return the observed TLS certificate hash.

    Args:
        host: Guest address exposing the front door.
    """

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(host, 443, timeout=30, context=context)
    try:
        connection.request("GET", "/openapi.json")
        response = connection.getresponse()
        response.read()
        certificate = connection.sock.getpeercert(binary_form=True) if connection.sock else None
        if response.status != 200 or not certificate:
            raise SmokeError("The host-facing OpenAPI endpoint is not ready.")
        return hashlib.sha256(certificate).hexdigest()
    finally:
        connection.close()


def _wait_for_reboot(host: str) -> None:
    """Require the guest SSH port to disappear before accepting reboot recovery.

    Args:
        host: Guest address expected to reboot.
    """

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, 22), timeout=3):
                pass
        except OSError:
            return
        time.sleep(3)
    raise SmokeError("The guest did not leave SSH readiness during the reboot check.")


def main(argv: list[str] | None = None) -> int:
    """Run one reboot phase of guest validation with pinned identities.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--host-key", required=True)
    parser.add_argument("--platform", choices=("vmware", "hyperv"), required=True)
    parser.add_argument("--phase", choices=("initial", "post-reboot"), required=True)
    parser.add_argument("--expected-tls-fingerprint")
    args = parser.parse_args(argv)
    if args.phase == "initial" and args.expected_tls_fingerprint is not None:
        parser.error("The initial phase cannot accept a prior TLS fingerprint.")
    if args.phase == "post-reboot" and (
        args.expected_tls_fingerprint is None
        or not re.fullmatch(r"[0-9a-f]{64}", args.expected_tls_fingerprint)
    ):
        parser.error("The post-reboot phase requires one canonical TLS fingerprint.")
    secret = load_secret_input()
    expected_host_key = parse_host_public_key(args.host_key)
    try:
        client = _connect(args.host, secret, expected_key=expected_host_key)
        try:
            script = _validation_script(args.platform)
            _run_root(client, secret, script)
            certificate = _front_door_fingerprint(args.host)
            if args.phase == "initial":
                _stdin, stdout, _stderr = client.exec_command(
                    "sudo -S -p '' systemctl reboot", timeout=30
                )
                _stdin.write(secret.password + "\n")
                _stdin.channel.shutdown_write()
                stdout.channel.recv_exit_status()
        finally:
            client.close()
        if args.phase == "initial":
            _wait_for_reboot(args.host)
            print(certificate)
            return 0
        if certificate != args.expected_tls_fingerprint:
            raise SmokeError("The host-facing TLS identity changed across the appliance reboot.")
    except SmokeError as exc:
        parser.error(str(exc))
    print(f"Atlaso {args.platform} guest smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
