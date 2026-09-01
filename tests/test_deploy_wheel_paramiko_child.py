"""Focused tests for the generated password-backed Paramiko child."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SOURCE = (ROOT / "scripts/windows/vmware/deploy-wheel.ps1").read_text(
    encoding="utf-8"
)


def _generated_function(name: str):
    """Compile one named function from the generated Paramiko child.

    Args:
        name: Generated function name to extract.
    """
    marker = "$pythonDeploySource = @'\n"
    start = DEPLOY_SOURCE.index(marker) + len(marker)
    end = DEPLOY_SOURCE.index("\n'@", start)
    module = ast.parse(DEPLOY_SOURCE[start:end])
    function = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace: dict[str, object] = {"base64": base64}
    exec(
        compile(
            ast.Module(body=[function], type_ignores=[]), "generated-child", "exec"
        ),
        namespace,
    )
    return namespace[name]


class FakeKey:
    def __init__(self, name: str, value: str) -> None:
        """Create a comparable fake SSH public key.

        Args:
            name: SSH key algorithm name.
            value: Stable fake key material.
        """
        self.name = name
        self.value = value

    def get_name(self) -> str:
        return self.name

    def __eq__(self, other: object) -> bool:
        """Compare fake key algorithm and material.

        Args:
            other: Candidate object to compare.
        """
        return isinstance(other, FakeKey) and (self.name, self.value) == (
            other.name,
            other.value,
        )


class FakeHostKeys:
    def __init__(self, entries: dict[str, dict[str, FakeKey]] | None = None) -> None:
        """Create an in-memory Paramiko host-key mapping.

        Args:
            entries: Optional initial host and key-type mapping.
        """
        self.entries = entries or {}

    def lookup(self, host: str):
        """Return recorded keys for a host.

        Args:
            host: Host address to look up.
        """
        return self.entries.get(host)

    def add(self, host: str, key_type: str, key: FakeKey) -> None:
        """Record one in-memory host key.

        Args:
            host: Host address that owns the key.
            key_type: SSH key algorithm name.
            key: Fake key to record.
        """
        self.entries.setdefault(host, {})[key_type] = key


class FakeTransport:
    def __init__(self, server_key: FakeKey) -> None:
        """Create a fake Paramiko transport for one server key.

        Args:
            server_key: Key returned by the simulated SSH server.
        """
        self.server_key = server_key
        self.security = SimpleNamespace(key_types=["ssh-ed25519", "rsa-sha2-512"])
        self.authenticated = False
        self.closed = False
        self.auth_attempted = False

    def get_security_options(self):
        return self.security

    def start_client(self, timeout: int) -> None:
        """Validate the generated child's bounded handshake timeout.

        Args:
            timeout: Requested SSH handshake timeout in seconds.
        """
        assert timeout == 15

    def get_remote_server_key(self) -> FakeKey:
        return self.server_key

    def auth_password(self, username: str, password: str, fallback: bool) -> None:
        """Record the generated child's password authentication attempt.

        Args:
            username: SSH account name.
            password: SSH account password.
            fallback: Whether keyboard-interactive fallback is allowed.
        """
        assert (username, password, fallback) == ("admin", "example-password", False)
        self.auth_attempted = True
        self.authenticated = True

    def is_authenticated(self) -> bool:
        return self.authenticated

    def close(self) -> None:
        self.closed = True


class FakeBadHostKey(Exception):
    def __init__(self, host: str, actual: FakeKey, expected: FakeKey) -> None:
        """Create a fake Paramiko host-key mismatch error.

        Args:
            host: Host whose key mismatched.
            actual: Key presented by the server.
            expected: Key recorded for the host.
        """
        super().__init__(host, actual, expected)


def _run_connection(expected_key: FakeKey | None, server_key: FakeKey):
    """Build the generated connection function and isolated fakes.

    Args:
        expected_key: Optional key already recorded for the host.
        server_key: Key presented by the simulated SSH server.
    """
    connect = _generated_function("connect_password_or_keyboard_interactive")
    transport = FakeTransport(server_key)
    system_entries = (
        {"192.0.2.10": {expected_key.name: expected_key}} if expected_key else {}
    )
    client = SimpleNamespace(
        _system_host_keys=FakeHostKeys(system_entries),
        _host_keys=FakeHostKeys(),
        _transport=None,
    )
    fake_paramiko = SimpleNamespace(
        Transport=lambda sock: transport,
        SSHException=type("SSHException", (Exception,), {}),
        BadHostKeyException=FakeBadHostKey,
        AuthenticationException=type("AuthenticationException", (Exception,), {}),
        BadAuthenticationType=type("BadAuthenticationType", (Exception,), {}),
    )
    connect.__globals__["paramiko"] = fake_paramiko
    connect.__globals__["socket"] = SimpleNamespace(
        create_connection=lambda address, timeout: object()
    )
    return connect, client, transport, fake_paramiko


def test_unknown_host_key_is_controlled_and_pre_authentication() -> None:
    connect, client, transport, paramiko = _run_connection(
        None, FakeKey("ssh-ed25519", "server")
    )

    with pytest.raises(paramiko.SSHException, match="Unknown SSH host key"):
        connect(client, "192.0.2.10", "admin", "example-password")

    assert transport.closed
    assert not transport.auth_attempted
    assert client._transport is None


def test_matching_host_key_authenticates_and_attaches_transport() -> None:
    recorded = FakeKey("ssh-ed25519", "same")
    connect, client, transport, _ = _run_connection(
        recorded, FakeKey("ssh-ed25519", "same")
    )

    connect(client, "192.0.2.10", "admin", "example-password")

    assert transport.authenticated
    assert not transport.closed
    assert client._transport is transport
    assert transport.security.key_types[0] == "ssh-ed25519"


def test_mismatched_host_key_fails_before_authentication() -> None:
    connect, client, transport, _ = _run_connection(
        FakeKey("ssh-ed25519", "recorded"),
        FakeKey("ssh-ed25519", "different"),
    )

    with pytest.raises(FakeBadHostKey):
        connect(client, "192.0.2.10", "admin", "example-password")

    assert transport.closed
    assert not transport.auth_attempted
    assert client._transport is None


def test_verified_guest_key_is_added_only_to_in_memory_host_keys() -> None:
    add_trusted_host_key = _generated_function("add_trusted_host_key")
    host_keys = FakeHostKeys()
    client = SimpleNamespace(get_host_keys=lambda: host_keys)
    trusted_key = FakeKey("ssh-ed25519", "guest-info")
    key_blob = b"\x00\x00\x00\x0bssh-ed25519" + (b"\x01" * 32)

    class FakePKey:
        @staticmethod
        def from_type_string(key_type: str, decoded_blob: bytes) -> FakeKey:
            """Parse the expected in-memory Ed25519 public key.

            Args:
                key_type: SSH key algorithm name.
                decoded_blob: Decoded SSH public-key blob.
            """
            assert key_type == "ssh-ed25519"
            assert decoded_blob == key_blob
            return trusted_key

    add_trusted_host_key.__globals__["paramiko"] = SimpleNamespace(
        PKey=FakePKey,
        SSHException=type("SSHException", (Exception,), {}),
    )
    public_key = f"ssh-ed25519 {base64.b64encode(key_blob).decode('ascii')}"

    add_trusted_host_key(client, "192.0.2.10", public_key)

    assert host_keys.lookup("192.0.2.10") == {"ssh-ed25519": trusted_key}
