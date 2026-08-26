"""Validate VMware or Hyper-V guest state over one bounded SSH trust-on-first-use session."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import ssl
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


def _connect(host: str, secret: SecretInput, *, expected_key: bytes | None = None) -> tuple[Any, bytes]:
    """Open a bounded SSH connection and optionally pin its first observed host key."""

    import paramiko  # type: ignore[import-untyped]  # Paramiko does not publish complete type metadata.

    deadline = time.monotonic() + 900
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
            transport = client.get_transport()
            key = transport.get_remote_server_key().asbytes() if transport else b""
            if not key or (expected_key is not None and key != expected_key):
                client.close()
                raise SmokeError("The guest SSH host key changed during the smoke test.")
            return client, key
        except (OSError, paramiko.SSHException) as exc:
            client.close()
            last_error = exc
            time.sleep(5)
    raise SmokeError(f"The guest did not become SSH-ready within 15 minutes: {type(last_error).__name__}")


def _run_root(client: Any, secret: SecretInput, script: str) -> None:
    """Run one fixed root validation script without placing credentials in arguments."""

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
    """Return the fixed non-secret guest validation script for one platform."""

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
grep -qx 'platform=vmware' /var/lib/atlaso/guest-agent.applied
rpm -q open-vm-tools >/dev/null
! rpm -q hyper-v >/dev/null 2>&1
! rpm -q qemu-guest-agent atlaso-qemu-guest-agent >/dev/null 2>&1
systemctl is-active --quiet vmtoolsd.service
! systemctl is-active --quiet qemu-guest-agent.service
""",
        "hyperv": r"""
grep -qx 'platform=hyperv' /var/lib/atlaso/guest-agent.applied
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
    """Require host-facing OpenAPI readiness and return the observed TLS certificate hash."""

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
    """Require the guest SSH port to disappear before accepting reboot recovery."""

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
    """Run guest validation, reboot, and repeat validation with pinned identities."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--platform", choices=("vmware", "hyperv"), required=True)
    args = parser.parse_args(argv)
    secret = load_secret_input()
    try:
        client, host_key = _connect(args.host, secret)
        try:
            script = _validation_script(args.platform)
            _run_root(client, secret, script)
            certificate = _front_door_fingerprint(args.host)
            _stdin, stdout, _stderr = client.exec_command("sudo -S -p '' systemctl reboot", timeout=30)
            _stdin.write(secret.password + "\n")
            _stdin.channel.shutdown_write()
            stdout.channel.recv_exit_status()
        finally:
            client.close()
        _wait_for_reboot(args.host)
        client, _ = _connect(args.host, secret, expected_key=host_key)
        try:
            _run_root(client, secret, script)
        finally:
            client.close()
        if _front_door_fingerprint(args.host) != certificate:
            raise SmokeError("The host-facing TLS identity changed across the appliance reboot.")
    except SmokeError as exc:
        parser.error(str(exc))
    print(f"Atlaso {args.platform} guest smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
