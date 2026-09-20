"""Shared Vault SSH endpoint parsing and pre-authentication host-key checks."""

import base64
import hashlib
import socket
from urllib.parse import urlparse

import paramiko  # type: ignore[import-untyped]  # Paramiko has no bundled typing stubs.

from atlaso.app.models import VaultEntry
from atlaso.app.services.vaults import vault_entry_uris


def ssh_fingerprint(key: paramiko.PKey) -> str:
    """Format the OpenSSH SHA-256 fingerprint used by remote terminal trust.

    Args:
        key: SSH public key presented by the remote server.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def remote_entry_target(entry: VaultEntry, uri_index: int) -> tuple[str, int, str]:
    """Resolve one explicit SSH URI without resolving a Vault password.

    Args:
        entry: Encrypted Vault entry with endpoint metadata.
        uri_index: One-based selected URI index in the Vault entry.
    """
    uris = vault_entry_uris(entry)
    if uri_index < 1 or uri_index > len(uris):
        raise ValueError("The selected vault URI does not exist.")
    parsed = urlparse(uris[uri_index - 1])
    if parsed.scheme not in {"ssh", "sftp"} or not parsed.hostname:
        raise ValueError("The selected vault URI is not an SSH or SFTP target.")
    if not entry.username:
        raise ValueError("The selected SSH credential needs a username.")
    return parsed.hostname, parsed.port or 22, entry.username


def probe_remote_ssh_host(hostname: str, port: int) -> str:
    """Probe an SSH host key without authentication.

    Args:
        hostname: Remote hostname to probe without authentication.
        port: Selected remote TCP port.
    """
    sock = socket.create_connection((hostname, port), timeout=10)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)
        return ssh_fingerprint(transport.get_remote_server_key())
    finally:
        transport.close()
