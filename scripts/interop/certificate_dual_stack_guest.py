"""Console-only primitives for separately admitted dual-stack functional tests.

These helpers do not admit resources or provide formal certificate/address-control
acceptance. The controller must bind their committed bytes, original VM receipts,
boot/runtime identity and observed console before any invocation. Credentials are
accepted only through the existing bounded concealed-field SDK consumer.
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_PUBLIC_BYTES = 393_216
NATIVE_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("links", ("ip", "-j", "-details", "link", "show")),
    ("addresses", ("ip", "-j", "-details", "address", "show")),
    ("routes4", ("ip", "-j", "-4", "route", "show", "table", "all")),
    ("routes6", ("ip", "-j", "-6", "route", "show", "table", "all")),
    ("rules4", ("ip", "-j", "-4", "rule", "show")),
    ("rules6", ("ip", "-j", "-6", "rule", "show")),
    ("listeners", ("ss", "-H", "-ltn")),
)


class GuestRefusal(ValueError):
    """A fixed diagnostic that never includes private input or response bodies."""



def json_loads_unique(raw: str | bytes) -> Any:
    """Decode opaque JSON without silently replacing any observed object member.

    This performs no logging or public projection; callers retain responsibility
    for privacy, producer admission and a complete action-specific schema.

    Args:
        raw: Bounded original JSON bytes or text.
    """
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Reject duplicate members while retaining all original values.

        Args:
            pairs: Original ordered JSON object members.
        """
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GuestRefusal("json_duplicate_key")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        """Refuse non-JSON numeric constants without echoing the input.

        Args:
            _value: Rejected parser constant.
        """
        raise GuestRefusal("json_nonfinite_number")

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)

def public_bytes(value: object) -> bytes:
    """Encode bounded public observations deterministically, without truncation.

    Args:
        value: Already allowlisted non-secret native or UI observations.
    """
    try:
        raw = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError):
        raise GuestRefusal("public_observation_not_json") from None
    if len(raw) > MAX_PUBLIC_BYTES:
        raise GuestRefusal("public_observation_too_large")
    return raw


def concealed_bytes(
    read_byte: Callable[[float], bytes], *, deadline: float, clock: Callable[[], float] = time.monotonic
) -> str:
    """Read an echo-disabled field and tolerate the SDK's initial Backspaces.

    This function never configures a terminal or proves that echo is disabled.
    The terminal adapter must do so before calling it. There is no echoing fallback.

    Args:
        read_byte: Terminal adapter returning exactly one byte within the remaining budget.
        deadline: Absolute monotonic deadline, including all clearing and input bytes.
        clock: Monotonic time source for the fixed input budget.
    """
    value = bytearray()
    count = 0
    while clock() < deadline:
        part = read_byte(deadline - clock())
        if len(part) != 1:
            raise GuestRefusal("concealed_input_incomplete")
        count += 1
        if count > 4_608:
            raise GuestRefusal("concealed_input_limit")
        if part in (b"\r", b"\n"):
            try:
                result = value.decode("utf-8", "strict")
            except UnicodeError:
                raise GuestRefusal("concealed_input_invalid") from None
            finally:
                value[:] = b"\x00" * len(value)
            if not result or result != result.strip() or any(ord(char) < 32 for char in result):
                raise GuestRefusal("concealed_input_invalid")
            return result
        if part in (b"\x08", b"\x7f"):
            if value:
                value.pop()
        elif part[0] < 32:
            raise GuestRefusal("concealed_input_invalid")
        else:
            value.extend(part)
    raise GuestRefusal("concealed_input_timeout")


def concealed_admin_value() -> str:
    """Refuse credential input until controller-stop containment is implemented.

    A terminal-input deadline alone cannot safely restore echo: a bounded SDK
    child may still be sending its already-admitted keystrokes. No terminal is
    opened or changed here. The future controller must prove that child stopped
    before a concealed input adapter may restore a terminal or return to a shell.
    """
    raise GuestRefusal("credential_controller_stop_proof_required")


class NumericHTTPSConnection(http.client.HTTPSConnection):
    """Direct numeric TLS with a pinned public CA and independently observed leaf."""

    def __init__(
        self, address: str, port: int, *, ca_path: Path, ca_sha256: str, leaf_sha256: str
    ) -> None:
        """Prepare one exact peer origin without a proxy, DNS or insecure fallback.

        Args:
            address: Bare usable unscoped IPv4 or IPv6 address.
            port: Explicit numeric TCP port.
            ca_path: Originally observed public CA bundle, never a private key.
            ca_sha256: Original SHA-256 of that public bundle.
            leaf_sha256: SHA-256 of the leaf actually viewed on the admitted console.
        """
        if (type(port) is not int or not 1 <= port <= 65_535
                or not isinstance(address, str) or "%" in address):
            raise GuestRefusal("numeric_endpoint_invalid")
        try:
            numeric = ipaddress.ip_address(address)
        except ValueError:
            raise GuestRefusal("numeric_endpoint_invalid") from None
        if (numeric.is_unspecified or numeric.is_multicast or numeric.is_loopback
                or numeric.is_link_local or numeric.is_reserved
                or isinstance(numeric, ipaddress.IPv6Address) and numeric.ipv4_mapped is not None):
            raise GuestRefusal("numeric_endpoint_invalid")
        if any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in (ca_sha256, leaf_sha256)):
            raise GuestRefusal("tls_original_pin_invalid")
        ca = ca_path.read_bytes()
        if len(ca) > 262_144 or b"PRIVATE KEY" in ca or hashlib.sha256(ca).hexdigest() != ca_sha256:
            raise GuestRefusal("public_ca_original_mismatch")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=ca.decode("ascii", "strict"))
        self.tls_context = context
        super().__init__(str(numeric), port, timeout=8, context=context)
        self.numeric_address = numeric
        self.expected_leaf_sha256 = leaf_sha256
        self.verified_leaf_sha256 = ""

    def connect(self) -> None:
        """Connect only to the declared numeric socket and verify its CA/IP SAN/leaf."""
        family = socket.AF_INET if self.numeric_address.version == 4 else socket.AF_INET6
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.connect((str(self.numeric_address), self.port))
            verified = self.tls_context.wrap_socket(raw, server_hostname=str(self.numeric_address))
            try:
                leaf = verified.getpeercert(binary_form=True)
                digest = hashlib.sha256(leaf or b"").hexdigest()
                if not leaf or digest != self.expected_leaf_sha256:
                    raise GuestRefusal("observed_console_leaf_mismatch")
                self.verified_leaf_sha256 = digest
                self.sock = verified
            except BaseException:
                verified.close()
                raise
        except BaseException:
            raw.close()
            raise


def native_inventory() -> dict[str, Any]:
    """Collect complete bounded public inventories through the admitted guest console.

    This collects raw facts only. It neither authenticates the console/controller
    nor infers static assignment, retirement, address exclusivity or acceptance.
    A nonzero command, malformed JSON, incomplete producer or size overflow refuses.
    """
    observations: dict[str, Any] = {}
    total = 0
    for name, command in NATIVE_COMMANDS:
        result = subprocess.run(command, capture_output=True, timeout=8, check=False)
        total += len(result.stdout) + len(result.stderr)
        if result.returncode != 0 or result.stderr or total > MAX_PUBLIC_BYTES:
            raise GuestRefusal("native_inventory_incomplete")
        try:
            text = result.stdout.decode("utf-8", "strict")
            value = json_loads_unique(text) if name != "listeners" else text.splitlines()
        except (UnicodeError, ValueError):
            raise GuestRefusal("native_inventory_invalid") from None
        if not isinstance(value, list):
            raise GuestRefusal("native_inventory_invalid")
        observations[name] = {"argv": list(command), "exit_code": 0, "raw": value}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is None:
        raise GuestRefusal("guest_boot_identity_invalid")
    payload = {
        "schema": 1,
        "kind": "dual-stack-native-raw-observation",
        "test_only": True,
        "formal_acceptance": False,
        "boot_id": boot,
        "monotonic_ns": time.monotonic_ns(),
        "observations": observations,
    }
    public_bytes(payload)
    return payload


def retired_tcp_observation(
    address: str, port: int, *, active_check: Callable[[], dict[str, str]]
) -> dict[str, Any]:
    """Record one explicit numeric peer TCP outcome with active TLS before/after.

    The caller still needs authenticated complete native address/listener/route/
    rule absence and unchanged peer topology. Timeout and routing uncertainty do
    not establish retirement. This function neither retries nor submits Apply.

    Args:
        address: Admitted bare retired IPv4 or IPv6 endpoint.
        port: Exact management HTTPS port.
        active_check: Same-family strict CA/IP-SAN/console-leaf positive-path probe.
    """
    if (not isinstance(address, str) or "%" in address or type(port) is not int
            or not 1 <= port <= 65_535):
        raise GuestRefusal("retired_endpoint_invalid")
    try:
        numeric = ipaddress.ip_address(address)
    except ValueError:
        raise GuestRefusal("retired_endpoint_invalid") from None
    if (numeric.is_unspecified or numeric.is_multicast or numeric.is_loopback
            or numeric.is_link_local or numeric.is_reserved
            or isinstance(numeric, ipaddress.IPv6Address) and numeric.ipv4_mapped is not None):
        raise GuestRefusal("retired_endpoint_invalid")
    before = active_check()
    started = time.monotonic()
    family = socket.AF_INET if numeric.version == 4 else socket.AF_INET6
    outcome = "unknown"
    code: int | None = None
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        try:
            code = connection.connect_ex((str(numeric), port))
            if code == 0:
                raise GuestRefusal("retired_tcp_connection_accepted")
            if code in (errno.ECONNREFUSED, errno.EHOSTUNREACH):
                outcome = "explicit_connect_failed"
        except TimeoutError:
            outcome = "unknown"
    after = active_check()
    return {
        "schema": 1, "kind": "test-only-retired-tcp-observation",
        "family": numeric.version, "address": str(numeric), "port": port,
        "outcome": outcome, "errno": code, "elapsed_seconds": time.monotonic() - started,
        "active_before": before, "active_after": after,
        "requires_complete_native_absence_and_path_admission": True,
        "automatic_retry_or_restore": False, "test_only": True, "formal_acceptance": False,
    }
