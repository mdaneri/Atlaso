"""Focused synthetic checks for console-only test primitives; never native proof."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.interop import certificate_dual_stack_guest as guest  # noqa: E402 - Local interop module.


def read_sequence(raw: bytes) -> Any:
    """Return one synthetic terminal byte per call.

    Args:
        raw: Public test input; never a real credential.
    """
    iterator = iter(raw)
    return lambda _remaining: bytes([next(iterator)])


def test_sdk_clearing_sequence_is_not_part_of_the_concealed_value() -> None:
    """Consume the existing consumer's 255 Backspaces without an echoing fallback."""
    result = guest.concealed_bytes(
        read_sequence(b"\x08" * 255 + b"public-test-sentinel\n"), deadline=10, clock=lambda: 1
    )
    assert result == "public-test-sentinel"


def test_terminal_adapter_refuses_until_sdk_stop_containment_exists() -> None:
    """A timeout must never expose late credential keystrokes to a restored shell."""
    with pytest.raises(guest.GuestRefusal, match="^credential_controller_stop_proof_required$"):
        guest.concealed_admin_value()


def test_concealed_editing_erases_both_supported_backspace_forms() -> None:
    """Do not retain a corrected public sentinel's erased bytes."""
    assert guest.concealed_bytes(
        read_sequence(b"ab\x08\x7fc\n"), deadline=10, clock=lambda: 1
    ) == "c"


@pytest.mark.parametrize("raw", [b"\n", b" leading\n", b"trailing \n", b"a\x01b\n", b"\xff\n"])
def test_bad_concealed_input_has_only_a_fixed_diagnostic(raw: bytes) -> None:
    """Refuse controls, malformed UTF-8 and ambiguous whitespace without values.

    Args:
        raw: Synthetic invalid byte sequence.
    """
    with pytest.raises(guest.GuestRefusal, match="^concealed_input_invalid$"):
        guest.concealed_bytes(read_sequence(raw), deadline=10, clock=lambda: 1)


def test_concealed_input_uses_one_original_monotonic_deadline() -> None:
    """Refuse before reading after the bounded input deadline."""
    with pytest.raises(guest.GuestRefusal, match="^concealed_input_timeout$"):
        guest.concealed_bytes(lambda _remaining: pytest.fail("Unexpected read"), deadline=1, clock=lambda: 2)


def test_incomplete_input_does_not_return_a_partial_value() -> None:
    """A closed input stream cannot authenticate with a partial line."""
    with pytest.raises(guest.GuestRefusal, match="^concealed_input_incomplete$"):
        guest.concealed_bytes(lambda _remaining: b"", deadline=10, clock=lambda: 1)


def test_public_observation_limit_never_truncates_to_a_valid_result() -> None:
    """An oversized inventory is a refusal, not incomplete absence evidence."""
    with pytest.raises(guest.GuestRefusal, match="^public_observation_too_large$"):
        guest.public_bytes({"data": "x" * guest.MAX_PUBLIC_BYTES})


@pytest.mark.parametrize("raw", ['{"key":1,"key":2}', '[NaN]', '[Infinity]', '[-Infinity]'])
def test_duplicate_or_non_json_observations_are_not_silently_normalized(raw: str) -> None:
    """Preserve uncertainty instead of accepting non-standard or overwritten facts.

    Args:
        raw: Synthetic malformed observation.
    """
    with pytest.raises(guest.GuestRefusal):
        guest.json_loads_unique(raw)


def test_nonfinite_public_number_never_becomes_a_valid_json_checkpoint() -> None:
    """Reject non-JSON numeric values before public evidence publication."""
    with pytest.raises(guest.GuestRefusal, match="^public_observation_not_json$"):
        guest.public_bytes({"elapsed_seconds": float("nan")})


def native_result(command: tuple[str, ...], **_options: Any) -> SimpleNamespace:
    """Provide all seven complete synthetic public command results.

    Args:
        command: Fixed native command vector being tested.
        **_options: Captured bounded subprocess arguments.
    """
    return SimpleNamespace(returncode=0, stderr=b"", stdout=b"" if command[0] == "ss" else b"[]")


def test_inventory_preserves_complete_both_family_and_all_table_producers(monkeypatch: Any) -> None:
    """Keep empty complete inventories distinct from producer failure.

    Args:
        monkeypatch: Scoped fixture replacement helper.
    """
    calls = []

    def run(command: tuple[str, ...], **options: Any) -> SimpleNamespace:
        """Record one synthetic bounded native read.

        Args:
            command: Fixed argument vector.
            **options: Bounded subprocess invocation settings.
        """
        calls.append((command, options))
        return native_result(command, **options)

    monkeypatch.setattr(guest.subprocess, "run", run)
    monkeypatch.setattr(guest.Path, "read_text", lambda *_args, **_kwargs: "01234567-89ab-cdef-0123-456789abcdef\n")
    value = guest.native_inventory()
    assert set(value["observations"]) == {"links", "addresses", "routes4", "routes6", "rules4", "rules6", "listeners"}
    assert value["formal_acceptance"] is False and value["test_only"] is True
    assert len(calls) == 7
    assert ("ip", "-j", "-4", "route", "show", "table", "all") in [call[0] for call in calls]
    assert ("ip", "-j", "-6", "route", "show", "table", "all") in [call[0] for call in calls]
    assert all(options == {"capture_output": True, "timeout": 8, "check": False} for _, options in calls)


@pytest.mark.parametrize(
    ("stdout", "stderr", "returncode", "reason"),
    [(b"[]", b"warning", 0, "native_inventory_incomplete"),
     (b"[]", b"", 1, "native_inventory_incomplete"),
     (b"{}", b"", 0, "native_inventory_invalid"),
     (b"[", b"", 0, "native_inventory_invalid"),
     (b"\xff", b"", 0, "native_inventory_invalid")],
)
def test_inventory_producer_uncertainty_refuses(
    monkeypatch: Any, stdout: bytes, stderr: bytes, returncode: int, reason: str
) -> None:
    """Never turn a failed or malformed complete producer into empty inventory.

    Args:
        monkeypatch: Scoped fixture replacement helper.
        stdout: Synthetic raw producer bytes.
        stderr: Synthetic producer diagnostic bytes.
        returncode: Actual-style producer completion status.
        reason: Expected fixed refusal category.
    """
    monkeypatch.setattr(guest.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        stdout=stdout, stderr=stderr, returncode=returncode
    ))
    with pytest.raises(guest.GuestRefusal, match="^" + reason + "$"):
        guest.native_inventory()


class FakeContext:
    """Assert the TLS caller keeps certificate and numeric hostname verification."""

    def __init__(self, protocol: int) -> None:
        """Record the client-only SSL context selection.

        Args:
            protocol: Standard library TLS protocol selector.
        """
        assert protocol == guest.ssl.PROTOCOL_TLS_CLIENT
        self.loaded = ""
        self.closed = False
        self.hostname = ""

    def load_verify_locations(self, *, cadata: str) -> None:
        """Capture only a public synthetic CA.

        Args:
            cadata: Public synthetic bundle text.
        """
        self.loaded = cadata

    def wrap_socket(self, raw: Any, *, server_hostname: str) -> Any:
        """Record the unbracketed numeric IP-SAN verification name.

        Args:
            raw: Synthetic numeric socket.
            server_hostname: Exact numeric peer identity.
        """
        self.hostname = server_hostname
        return SimpleNamespace(getpeercert=lambda **_kwargs: b"public-leaf", close=self.close)

    def close(self) -> None:
        """Record closure of a refused synthetic TLS connection."""
        self.closed = True


@pytest.mark.parametrize(("address", "family"), [("192.0.2.10", guest.socket.AF_INET), ("fd00:1084:1077::10", guest.socket.AF_INET6)])
def test_numeric_tls_never_uses_dns_or_a_bracketed_san_name(
    monkeypatch: Any, tmp_path: Path, address: str, family: int
) -> None:
    """Bind direct family-specific transport and the independently observed leaf.

    Args:
        monkeypatch: Scoped fixture replacement helper.
        tmp_path: Originally owned focused pytest child.
        address: Synthetic usable numeric peer.
        family: Expected explicit socket family.
    """
    ca = tmp_path / "public-ca.pem"
    ca.write_bytes(b"PUBLIC SYNTHETIC CA")
    context = FakeContext(guest.ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(guest.ssl, "SSLContext", lambda protocol: context)
    sockets = []

    def socket(selected_family: int, kind: int) -> Any:
        """Record the exact numeric connect without opening a host socket.

        Args:
            selected_family: Explicit IP family.
            kind: TCP socket type.
        """
        assert selected_family == family and kind == guest.socket.SOCK_STREAM
        raw = SimpleNamespace(settimeout=lambda timeout: None, connect=lambda endpoint: sockets.append(endpoint), close=lambda: None)
        return raw

    monkeypatch.setattr(guest.socket, "socket", socket)
    connection = guest.NumericHTTPSConnection(
        address, 443, ca_path=ca, ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(),
        leaf_sha256=hashlib.sha256(b"public-leaf").hexdigest(),
    )
    connection.connect()
    assert sockets == [(address, 443)]
    assert context.hostname == address
    assert context.loaded == "PUBLIC SYNTHETIC CA"
    assert connection.verified_leaf_sha256 == hashlib.sha256(b"public-leaf").hexdigest()


def test_changed_public_ca_refuses_before_any_socket(monkeypatch: Any, tmp_path: Path) -> None:
    """A reachable candidate cannot supply its own replacement trust pin.

    Args:
        monkeypatch: Scoped fixture replacement helper.
        tmp_path: Originally owned focused pytest child.
    """
    ca = tmp_path / "public-ca.pem"
    ca.write_bytes(b"PUBLIC SYNTHETIC CA")
    monkeypatch.setattr(guest.socket, "socket", lambda *_args: pytest.fail("Unexpected socket"))
    with pytest.raises(guest.GuestRefusal, match="^public_ca_original_mismatch$"):
        guest.NumericHTTPSConnection("192.0.2.10", 443, ca_path=ca, ca_sha256="0" * 64, leaf_sha256="1" * 64)


@pytest.mark.parametrize("address", ["::ffff:192.0.2.10", "::ffff:127.0.0.1", "0.0.0.0", "127.0.0.1", "fe80::1", "ff02::1"])
def test_ambiguous_or_unusable_tls_endpoints_refuse_before_ca_read(address: str) -> None:
    """Reject hidden mapped family changes, loopback, multicast and scoped-only endpoints.

    Args:
        address: Synthetic unusable numeric endpoint.
    """
    with pytest.raises(guest.GuestRefusal, match="^numeric_endpoint_invalid$"):
        guest.NumericHTTPSConnection(address, 443, ca_path=Path("not-read"), ca_sha256="0" * 64, leaf_sha256="1" * 64)


@pytest.mark.parametrize(("code", "outcome"), [(111, "explicit_connect_failed"), (113, "explicit_connect_failed"), (101, "unknown"), (110, "unknown")])
def test_retirement_retains_explicit_kernel_outcome_and_both_active_checks(
    monkeypatch: Any, code: int, outcome: str
) -> None:
    """A peer TCP observation alone never becomes a retirement acceptance record.

    Args:
        monkeypatch: Scoped fixture replacement helper.
        code: Synthetic native connect outcome.
        outcome: Expected normalized fact.
    """
    observations = []

    class RetiredSocket:
        """A synthetic socket that never opens a host connection."""

        def __enter__(self) -> Any:
            """Expose the synthetic context-managed socket."""
            return self

        def __exit__(self, *_args: Any) -> None:
            """Close the synthetic context without state changes.

            Args:
                *_args: Synthetic context exit arguments.
            """

        def settimeout(self, seconds: int) -> None:
            """Assert the selected bounded timeout.

            Args:
                seconds: Timeout selected by the observer.
            """
            assert seconds == 8

        def connect_ex(self, endpoint: tuple[str, int]) -> int:
            """Record the retired numeric endpoint and return its kernel-style code.

            Args:
                endpoint: Declared retired address and management port.
            """
            assert endpoint == ("fd00:1084:1077::10", 443)
            observations.append("retired")
            return code

    def active() -> dict[str, str]:
        """Record one strict-active-path callback without creating a connection."""
        observations.append("active")
        return {"leaf": "a" * 64}

    monkeypatch.setattr(guest.errno, "ECONNREFUSED", 111)
    monkeypatch.setattr(guest.errno, "EHOSTUNREACH", 113)
    monkeypatch.setattr(guest.socket, "socket", lambda *_args: RetiredSocket())
    result = guest.retired_tcp_observation("fd00:1084:1077::10", 443, active_check=active)
    assert observations == ["active", "retired", "active"]
    assert result["errno"] == code and result["outcome"] == outcome
    assert result["formal_acceptance"] is False
    assert result["requires_complete_native_absence_and_path_admission"] is True
