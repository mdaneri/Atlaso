#!/usr/bin/env python3
"""Create unique machine identity and credentials before appliance networking."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

ENV_PATH = Path("/etc/atlaso/atlaso.env")
ACCESS_PATH = Path("/run/atlaso/first-boot-access.json")
SSH_DIRECTORY = Path("/etc/ssh")
KVP_POOL_PATH = Path("/var/lib/hyperv/.kvp_pool_1")
KVP_KEY_BYTES = 512
KVP_VALUE_BYTES = 2048
KVP_RECORD_BYTES = KVP_KEY_BYTES + KVP_VALUE_BYTES


def _password() -> str:
    """Return one high-entropy password satisfying the appliance policy."""

    return f"A!a1{secrets.token_urlsafe(32)}"


def _replace_environment(values: dict[str, str]) -> str:
    """Replace security-sensitive appliance environment values atomically.

    Args:
        values: Exact environment values to replace.
    """

    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        key = line.partition("=")[0]
        if key in values:
            output.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            output.append(line)
    if seen != set(values):
        raise RuntimeError(f"appliance environment is missing identity fields: {sorted(set(values) - seen)}")
    temporary = ENV_PATH.with_name(f".{ENV_PATH.name}.{secrets.token_hex(8)}.tmp")
    temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o640)
    shutil.chown(temporary, user="root", group="atlaso")
    os.replace(temporary, ENV_PATH)
    return next(line.split("=", 1)[1] for line in output if line.startswith("ATLASO_BOOTSTRAP_ADMIN_USERNAME="))


def _regenerate_host_identity() -> str:
    """Regenerate machine ID and OpenSSH host keys, returning the public Ed25519 key."""

    Path("/etc/machine-id").unlink(missing_ok=True)
    Path("/var/lib/dbus/machine-id").unlink(missing_ok=True)
    subprocess.run(["systemd-machine-id-setup"], check=True)
    for path in SSH_DIRECTORY.glob("ssh_host_*"):
        if path.is_symlink() or path.is_file():
            path.unlink()
    subprocess.run(["ssh-keygen", "-A"], check=True)
    fields = (SSH_DIRECTORY / "ssh_host_ed25519_key.pub").read_text(encoding="ascii").split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise RuntimeError("generated Ed25519 SSH host public key is invalid")
    return f"ssh-ed25519 {fields[1]}"


def _publish_hyperv_access(payload: str) -> None:
    """Publish the unique first-boot envelope through Hyper-V guest KVP.

    Args:
        payload: Compact JSON credential and host-key envelope.
    """

    key = b"atlaso.first_boot_access"
    value = payload.encode("utf-8")
    if len(key) >= KVP_KEY_BYTES or len(value) >= KVP_VALUE_BYTES:
        raise RuntimeError("Hyper-V first-boot KVP payload exceeds the protocol record")
    KVP_POOL_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = KVP_POOL_PATH.read_bytes() if KVP_POOL_PATH.is_file() else b""
    if len(existing) % KVP_RECORD_BYTES:
        raise RuntimeError("Hyper-V guest KVP pool has a malformed record boundary")
    records = [existing[index : index + KVP_RECORD_BYTES] for index in range(0, len(existing), KVP_RECORD_BYTES)]
    record = key.ljust(KVP_KEY_BYTES, b"\0") + value.ljust(KVP_VALUE_BYTES, b"\0")
    own_indices = [index for index, item in enumerate(records) if item[:KVP_KEY_BYTES].rstrip(b"\0") == key]
    if len(own_indices) > 1:
        raise RuntimeError("Hyper-V guest KVP pool contains duplicate Atlaso access records")
    if own_indices:
        records[own_indices[0]] = record
    else:
        records.append(record)
    temporary = KVP_POOL_PATH.with_name(f".{KVP_POOL_PATH.name}.{secrets.token_hex(8)}.tmp")
    # This is the Hyper-V guest-to-host KVP transport, not appliance storage.
    # The selector removes Atlaso's record on the first reboot.
    # codeql[py/clear-text-storage-sensitive-data]
    temporary.write_bytes(b"".join(records))
    os.chmod(temporary, 0o600)
    os.replace(temporary, KVP_POOL_PATH)


def _clear_hyperv_access() -> None:
    """Remove only Atlaso's record from the Hyper-V guest KVP transport."""

    if not KVP_POOL_PATH.is_file():
        return
    existing = KVP_POOL_PATH.read_bytes()
    if len(existing) % KVP_RECORD_BYTES:
        raise RuntimeError("Hyper-V guest KVP pool has a malformed record boundary")
    key = b"atlaso.first_boot_access"
    records = [existing[index : index + KVP_RECORD_BYTES] for index in range(0, len(existing), KVP_RECORD_BYTES)]
    retained = [item for item in records if item[:KVP_KEY_BYTES].rstrip(b"\0") != key]
    if len(retained) == len(records):
        return
    temporary = KVP_POOL_PATH.with_name(f".{KVP_POOL_PATH.name}.{secrets.token_hex(8)}.tmp")
    temporary.write_bytes(b"".join(retained))
    os.chmod(temporary, 0o600)
    os.replace(temporary, KVP_POOL_PATH)


def clear_access(platform: str) -> None:
    """Erase the one-time access transport after the first reboot.

    Args:
        platform: Verified guest-agent platform identifier.
    """

    ACCESS_PATH.unlink(missing_ok=True)
    if platform == "hyperv":
        _clear_hyperv_access()


def _publish_console_access(payload: str) -> None:
    """Write the one-time envelope directly to the transient tty1 device.

    Args:
        payload: Compact JSON credential and host-key envelope.
    """

    no_controlling_terminal = getattr(os, "O_NOCTTY", 0)
    descriptor = os.open("/dev/tty1", os.O_WRONLY | os.O_APPEND | no_controlling_terminal)
    try:
        # tty1 is a character-device transport rather than persistent storage.
        # codeql[py/clear-text-storage-sensitive-data]
        os.write(descriptor, f"Atlaso one-time first-boot access: {payload}\n".encode())
    finally:
        os.close(descriptor)


def initialize(platform: str) -> None:
    """Initialize one cloned appliance before any network service starts.

    Args:
        platform: Verified guest-agent platform identifier.
    """

    admin_password = _password()
    root_password = _password()
    username = _replace_environment(
        {
            "ATLASO_SECRET_KEY": secrets.token_urlsafe(48),
            "ATLASO_SECRETS_KEY": secrets.token_urlsafe(48),
            "ATLASO_BOOTSTRAP_ADMIN_PASSWORD": admin_password,
        }
    )
    host_key = _regenerate_host_identity()
    subprocess.run(
        ["chpasswd"],
        input=f"{username}:{admin_password}\nroot:{root_password}\n",
        text=True,
        check=True,
    )
    if platform != "vmware":
        access = json.dumps(
            {"username": username, "password": admin_password, "root_password": root_password, "ssh_host_key": host_key},
            sort_keys=True,
            separators=(",", ":"),
        )
        ACCESS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # /run is tmpfs and this root-only envelope is erased on first reboot.
        # codeql[py/clear-text-storage-sensitive-data]
        ACCESS_PATH.write_text(access + "\n", encoding="utf-8")
        os.chmod(ACCESS_PATH, 0o600)
        if platform == "hyperv":
            _publish_hyperv_access(access)
        try:
            _publish_console_access(access)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    """Run the machine-identity initializer.

    Args:
        argv: Optional command-line argument sequence.
    """

    # Every file created below can contain a one-time password. Keep creation
    # private even before the explicit final ownership and mode checks run.
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("vmware", "qemu", "hyperv", "baremetal"), required=True)
    parser.add_argument("--clear-access", action="store_true", help="Erase the one-time access transport.")
    args = parser.parse_args(argv)
    if args.clear_access:
        clear_access(args.platform)
    else:
        initialize(args.platform)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
