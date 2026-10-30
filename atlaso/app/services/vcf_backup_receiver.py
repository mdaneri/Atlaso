"""Admit the applied Atlaso SFTP receiver and verify native backup artifacts."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

import paramiko  # type: ignore[import-untyped]  # Paramiko has no bundled typing stubs.
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import User, VcfBackupSettings
from atlaso.app.services.applied_service_dns import load_appliance_apply_baselines
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces
from atlaso.app.services.local_users import has_pending_os_password
from atlaso.app.services.log_sanitization import redact_operational_text
from atlaso.app.services.vcf_backups import (
    VCF_BACKUP_DEFAULT_VOLUME_MOUNT,
    VCF_BACKUP_EFFECTIVE_CONFIG_PATH,
    render_vcf_backup_config,
    validate_vcf_backup_state,
)

ECDSA_PUBLIC_KEY = Path("/etc/ssh/ssh_host_ecdsa_key.pub")
RSA_PUBLIC_KEY = Path("/etc/ssh/ssh_host_rsa_key.pub")
MAX_ARTIFACTS = 10000


class ReceiverError(ValueError):
    """Public refusal without passwords, remote response bodies, or backup contents."""


def _public_key() -> tuple[str, str]:
    """Read the public ECDSA host key without accessing any private key."""
    parts = ECDSA_PUBLIC_KEY.read_text(encoding="ascii").split()
    if len(parts) < 2 or not parts[0].startswith("ecdsa-sha2-"):
        raise ReceiverError("VCF 9.1 requires an available ECDSA SFTP host key.")
    blob = base64.b64decode(parts[1], validate=True)
    key = paramiko.PKey.from_type_string(parts[0], blob)
    if key.get_name() != parts[0]:
        raise ReceiverError("The SFTP public host key is invalid.")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"{parts[0]} {parts[1]}", "SHA256:" + fingerprint


def _rsa_public_key() -> str:
    """Read the public key needed to verify modern RSA-SHA2 advertisement."""
    parts = RSA_PUBLIC_KEY.read_text(encoding="ascii").split()
    if len(parts) < 2 or parts[0] != "ssh-rsa":
        raise ReceiverError("VCF 9.1 also requires modern RSA-SHA2 SSH advertisement.")
    paramiko.PKey.from_type_string(parts[0], base64.b64decode(parts[1], validate=True))
    return f"{parts[0]} {parts[1]}"


def _transport(receiver: dict[str, Any]) -> paramiko.Transport:
    """Verify the selected listener against the appliance's own public host key.

    Args:
        receiver: Applied receiver identity, including its public ECDSA key.
    """
    transport: paramiko.Transport | None = None
    try:
        parts = str(receiver["host_key"]).split()
        expected = base64.b64decode(parts[1], validate=True)
        sock = socket.create_connection((receiver["host"], receiver["port"]), timeout=5)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = 5
        transport.auth_timeout = 10
        transport.get_security_options().key_types = tuple(receiver.get("negotiation_types", [parts[0]]))
        transport.start_client(timeout=5)
        if transport.get_remote_server_key().asbytes() != expected:
            raise ReceiverError("The live SFTP host key differs from the appliance key.")
        return transport
    except (OSError, ValueError, paramiko.SSHException):
        if transport is not None:
            transport.close()
        raise ReceiverError("The applied SFTP listener is not ready or its identity changed.") from None


def _runtime(receiver: dict[str, Any], expected_config: str) -> None:
    """Prove mount, effective configuration, daemon, and live listener identity.

    Args:
        receiver: Applied receiver identity without a password.
        expected_config: Exact public configuration admitted by Appliance Apply.
    """
    if os.name != "posix" or not os.path.ismount(VCF_BACKUP_DEFAULT_VOLUME_MOUNT):
        raise ReceiverError("The dedicated VCF backup volume must be mounted.")
    path = Path(VCF_BACKUP_EFFECTIVE_CONFIG_PATH)
    if path.is_symlink() or path.read_text(encoding="utf-8") != expected_config:
        raise ReceiverError("Apply the current VCF Backup SFTP configuration first.")
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "sshd.service"],
        capture_output=True, timeout=5, check=False,
    )
    if result.returncode:
        raise ReceiverError("The SFTP backing SSH service is not active.")
    transport = _transport(receiver)
    transport.close()
    transport = _transport({**receiver, "host_key": receiver["rsa_host_key"],
                            "negotiation_types": ["rsa-sha2-512", "rsa-sha2-256"]})
    transport.close()


def receiver_state(db: Session) -> dict[str, Any]:
    """Return a fail-closed launcher prerequisite without resolving credentials.

    Args:
        db: Session containing current desired state and applied baselines.
    """
    result: dict[str, Any] = {"ready": False, "reason": "Enable and apply VCF Backup SFTP first."}
    settings = db.scalar(select(VcfBackupSettings).where(VcfBackupSettings.id == 1).execution_options(populate_existing=True))
    if settings is None or not settings.enabled:
        return result
    user = db.get(User, settings.sftp_user_id, populate_existing=True) if settings.sftp_user_id else None
    try:
        if user is None or not user.enabled:
            raise ReceiverError("Enable the selected SFTP user and apply Local Users first.")
        if user.os_sync_status != "applied" or has_pending_os_password(user):
            raise ReceiverError("Apply the selected user's current Local Users settings first.")
        if not settings.chroot_enabled or not settings.allow_password_auth:
            raise ReceiverError("Enable chroot and password authentication for native VCF backups.")
        if settings.storage_path != VCF_BACKUP_DEFAULT_VOLUME_MOUNT:
            raise ReceiverError("Use the dedicated Atlaso VCF backup volume.")
        errors = validate_vcf_backup_state(settings, [user])
        if errors:
            raise ReceiverError("Correct the VCF Backup SFTP validation errors before continuing.")
        preview = render_vcf_backup_config(settings)
        baseline = load_appliance_apply_baselines(db, refresh=True).get("vcf_backups", {})
        if baseline.get("config_preview") != redact_operational_text(preview):
            raise ReceiverError("Apply pending VCF Backup SFTP changes before continuing.")
        addresses = split_addresses(settings.listen_address)
        host_key, fingerprint = _public_key()
        receiver = {
            "host": addresses[0], "addresses": addresses, "port": settings.port,
            "username": user.username, "directory": "/backups", "host_key": host_key,
            "ecdsa_fingerprint": fingerprint, "interfaces": split_interfaces(settings.listen_interface),
            "volume": settings.storage_path, "rsa_host_key": _rsa_public_key(),
        }
        _runtime(receiver, preview)
        result.update(receiver, ready=True, reason="VCF Backup SFTP is applied and its listener is ready.")
    except ReceiverError as exc:
        result["reason"] = str(exc)
    except (OSError, ValueError, IndexError, subprocess.SubprocessError, paramiko.SSHException):
        result["reason"] = "The backup mount, applied configuration, or SFTP host key is unavailable."
    return result


def require_receiver(db: Session) -> dict[str, Any]:
    """Refuse every workflow action when the current receiver is not ready.

    Args:
        db: Session containing receiver prerequisites.
    """
    result = receiver_state(db)
    if result["ready"] is not True:
        raise ReceiverError(str(result["reason"]))
    return result


def receiver_revision(receiver: dict[str, Any]) -> dict[str, Any]:
    """Return the public receiver fields bound into an immutable remote review.

    Args:
        receiver: Ready receiver state from the current request.
    """
    return {key: receiver[key] for key in
            ("host", "port", "username", "directory", "host_key", "rsa_host_key", "ecdsa_fingerprint", "interfaces", "volume")}


class ReceiverSession:
    """Use the applied receiver's ordinary SFTP identity, never privileged file access."""

    def __init__(self, receiver: dict[str, Any], password: str):
        """Bind an applied public endpoint and a request-local password.

        Args:
            receiver: Receiver fields already admitted by current readiness checks.
            password: Vault-resolved password retained only for this task.
        """
        self.receiver = receiver
        self.password = password
        self.transport: paramiko.Transport | None = None
        self.sftp: paramiko.SFTPClient | None = None

    def __enter__(self) -> ReceiverSession:
        """Authenticate only after checking the live ECDSA host key."""
        try:
            self.transport = _transport(self.receiver)
            self.transport.auth_password(self.receiver["username"], self.password, fallback=False)
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.sftp.get_channel().settimeout(15)
            return self
        except (OSError, paramiko.SSHException):
            self.__exit__(None, None, None)
            raise ReceiverError("SFTP authentication or chroot access failed; check the selected Vault key.") from None

    def __exit__(self, *_args: Any) -> None:
        """Close channels and discard the request-local receiver password.

        Args:
            *_args: Context-manager exception metadata, never logged.
        """
        if self.sftp:
            self.sftp.close()
        if self.transport:
            self.transport.close()
        self.password = ""

    def _client(self) -> paramiko.SFTPClient:
        """Require an authenticated SFTP channel."""
        if self.sftp is None:
            raise ReceiverError("The receiver session is not authenticated.")
        return self.sftp

    def _path(self, value: str) -> str:
        """Accept only ordinary descendants of the reviewed chroot backup directory.

        Args:
            value: Native-reported artifact or planned destination path.
        """
        path = PurePosixPath(value)
        if (
            not value.startswith("/backups/") or any(part in {".", ".."} for part in value.split("/"))
            or any(ord(char) < 32 for char in value) or "\\" in value or "://" in value
        ):
            raise ReceiverError("Native artifact paths must remain beneath /backups.")
        return str(path)

    def prepare(self, directory: str) -> None:
        """Create only the reviewed destination after final task authorization.

        Args:
            directory: Reviewed group-specific backup directory.
        """
        client = self._client()
        path = self._path(directory)
        cursor = ""
        try:
            for part in PurePosixPath(path).parts[1:]:
                cursor += "/" + part
                try:
                    attributes = client.lstat(cursor)
                except FileNotFoundError:
                    client.mkdir(cursor, mode=0o700)
                    attributes = client.lstat(cursor)
                if not stat.S_ISDIR(attributes.st_mode or 0):
                    raise ReceiverError("The reviewed backup directory contains a symlink or non-directory.")
        except (OSError, paramiko.SSHException):
            raise ReceiverError("The reviewed SFTP backup directory could not be prepared.") from None

    def manifest(self, directory: str) -> dict[str, tuple[int, int]]:
        """Read a bounded public file manifest without downloading backup contents.

        Args:
            directory: Reviewed backup directory to inspect recursively.
        """
        client = self._client()
        root = self._path(directory)
        result: dict[str, tuple[int, int]] = {}
        pending = [(root, 0)]
        visited = 0
        deadline = time.monotonic() + 45
        try:
            while pending:
                path, depth = pending.pop()
                visited += 1
                if depth > 12 or visited > MAX_ARTIFACTS or time.monotonic() > deadline:
                    raise ReceiverError("Backup artifact traversal exceeds its depth, file, or time limit.")
                attributes = client.lstat(path)
                mode = attributes.st_mode or 0
                if stat.S_ISDIR(mode):
                    for child in client.listdir_attr(path):
                        if child.filename in {".", ".."} or "/" in child.filename or "\\" in child.filename:
                            raise ReceiverError("The SFTP artifact listing contains an invalid name.")
                        pending.append((path + "/" + child.filename, depth + 1))
                    if len(pending) + len(result) > MAX_ARTIFACTS:
                        raise ReceiverError("Backup artifact traversal exceeds the supported file limit.")
                elif stat.S_ISREG(mode):
                    result[path] = (int(attributes.st_size or 0), int(attributes.st_mtime or 0))
                else:
                    raise ReceiverError("Backup verification refuses symlinks and special files.")
            return result
        except FileNotFoundError:
            return {}
        except (OSError, paramiko.SSHException):
            raise ReceiverError("SFTP artifact metadata could not be verified.") from None
