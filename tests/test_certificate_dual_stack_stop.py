"""Synthetic signature fixtures only; no production signing or VMware calls."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.interop import certificate_dual_stack_stop as stop  # noqa: E402 - Local interop module.
from scripts.interop.certificate_dual_stack_guest import GuestRefusal  # noqa: E402 - Local module.

# Public deterministic synthetic fixture, never a usable production identity.
FIXTURE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = FIXTURE_KEY.public_key().public_bytes_raw().hex()
FINGERPRINT = hashlib.sha256(bytes.fromhex(PUBLIC_KEY)).hexdigest()
FIXTURE_DOMAIN = b"Atlaso-PR1084-SDK-stop-ACK-v2\x00"


def binding() -> dict[str, Any]:
    """Return independent public synthetic admission bindings."""
    return {
        **dict.fromkeys(stop.DIGEST_FIELDS, "a" * 64),
        "task_id": "01234567-89ab-cdef-0123-456789abcdef",
        "source_commit": "b" * 40, "run_id": "c" * 32, "receiver_nonce": "d" * 32,
        "guest_boot_id": "11234567-89ab-cdef-0123-456789abcdef",
        "host_boot_identity": "123456", "deadline_unix_ms": 2_000,
        "root_pid": 123, "root_start_filetime_utc": "123456789",
        "transport_key": f"{stop.PREFIX}.{'c' * 32}.{'d' * 32}",
    }


def canonical(value: object) -> bytes:
    """Encode a fixture using the independently specified canonical syntax.

    Args:
        value: Synthetic public object.
    """
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def envelope() -> dict[str, Any]:
    """Return an unsigned fixture including all success facts."""
    return {
        "schema": 2, "kind": "console-sdk-stop-ack-v2", "algorithm": "Ed25519",
        "signing_key_sha256": FINGERPRINT,
        "payload": {**binding(), "whole_job_empty": True, "outcome": "succeeded",
                    "root_exit_code": 0, "original_binding_rechecked": True},
    }


def sign(value: dict[str, Any], domain: bytes = FIXTURE_DOMAIN) -> bytes:
    """Sign only with the public deterministic test identity.

    Args:
        value: Unsigned synthetic envelope.
        domain: Protocol domain under test.
    """
    return canonical({**value, "signature_hex": FIXTURE_KEY.sign(domain + canonical(value)).hex()})


def verify(raw: bytes, **options: Any) -> str:
    """Verify against separate synthetic admission, never wire-provided keys.

    Args:
        raw: Synthetic original ACK bytes.
        **options: Explicit admission overrides under test.
    """
    return stop.verify_stop_ack(raw, **{
        "public_key_hex": PUBLIC_KEY, "signing_key_sha256": FINGERPRINT,
        "expected_binding": binding(), "now_unix_ms": 1_000, **options,
    })


def test_signed_success_and_failed_statement_remain_distinct() -> None:
    """A signed failure never becomes a success or authorizes release."""
    assert verify(sign(envelope())) == "succeeded"
    failed = envelope()
    failed["payload"].update(outcome="terminated_failure", root_exit_code=-1,
                             original_binding_rechecked=False)
    assert verify(sign(failed)) == "terminated_failure"


@pytest.mark.parametrize("field", sorted(stop.BINDING_FIELDS))
def test_every_binding_is_checked_even_with_a_valid_signature(field: str) -> None:
    """Another run, resource or receipt cannot be replayed into admission.

    Args:
        field: Independently admitted field changed by the fixture signer.
    """
    value = envelope()
    old = value["payload"][field]
    value["payload"][field] = old + 1 if type(old) is int else old + "0"
    with pytest.raises(GuestRefusal, match="stop_ack_binding_mismatch"):
        verify(sign(value))


@pytest.mark.parametrize("field,value", [
    ("whole_job_empty", False), ("whole_job_empty", 1),
    ("outcome", "unknown"), ("outcome", []), ("root_exit_code", True),
    ("root_exit_code", 1), ("root_exit_code", 2**40),
    ("original_binding_rechecked", False), ("original_binding_rechecked", 1),
])
def test_signed_contradictory_or_untyped_facts_refuse(field: str, value: object) -> None:
    """Even a signed success must contain coherent typed quiescence facts.

    Args:
        field: Quiescence fact under test.
        value: Invalid synthetic fact.
    """
    item = envelope()
    item["payload"][field] = value
    with pytest.raises(GuestRefusal, match="stop_ack_quiescence_invalid"):
        verify(sign(item))


@pytest.mark.parametrize("now", [2_000, 2_001, True, -1])
def test_expiry_and_clock_type_refuse(now: int) -> None:
    """Expiry is inclusive and ACK data supplies no trusted clock.

    Args:
        now: Synthetic admitted clock value.
    """
    with pytest.raises(GuestRefusal):
        verify(sign(envelope()), now_unix_ms=now)


def test_forgery_wrong_key_domain_and_post_signature_edit_refuse() -> None:
    """A guest knowing every public binding still lacks the host signer."""
    raw = sign(envelope())
    item = json.loads(raw)
    item["signature_hex"] = "0" * 128
    with pytest.raises(GuestRefusal, match="stop_ack_signature_invalid"):
        verify(canonical(item))
    with pytest.raises(GuestRefusal, match="stop_ack_signature_invalid"):
        verify(sign(envelope(), b"another-protocol"))
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32)))).public_key().public_bytes_raw()
    with pytest.raises(GuestRefusal):
        verify(raw, public_key_hex=other_key.hex(), signing_key_sha256=hashlib.sha256(other_key).hexdigest())
    with pytest.raises(GuestRefusal, match="stop_ack_key_not_admitted"):
        verify(raw, signing_key_sha256="0" * 64)
    item = json.loads(raw)
    item["payload"]["outcome"] = "terminated_failure"
    with pytest.raises(GuestRefusal, match="stop_ack_signature_invalid"):
        verify(canonical(item))


@pytest.mark.parametrize("raw", [
    b"", b"x" * 3_001, b"\xff", b"[]", b"null", b"{", b'{"schema":2,"schema":2}',
    b'{"value":NaN}', b'{"value":Infinity}', b'"\\ud800"',
])
def test_malformed_or_unbounded_input_refuses(raw: bytes) -> None:
    """Malformed public input never leaks its contents into diagnostics.

    Args:
        raw: Invalid synthetic wire bytes.
    """
    with pytest.raises(GuestRefusal):
        verify(raw)


def test_canonical_schema_hex_and_duplicate_nested_keys() -> None:
    """Alternate serialization, algorithm and key encodings cannot be adopted."""
    raw = sign(envelope())
    for changed in (b" " + raw, raw + b"\n", raw.replace(b'"schema":2', b'"schema":2,"schema":2'),
                    raw.replace(b'"root_pid":123', b'"root_pid":123,"root_pid":123')):
        with pytest.raises(GuestRefusal):
            verify(changed)
    for field, value in (("algorithm", "none"), ("schema", True), ("signature_hex", "A" * 128),
                         ("public_key", PUBLIC_KEY), ("kind", "console-credential-stop")):
        item = json.loads(raw)
        item[field] = value
        with pytest.raises(GuestRefusal, match="stop_ack_schema_invalid"):
            verify(canonical(item))


@pytest.mark.parametrize("field,value", [("root_pid", True), ("deadline_unix_ms", True),
                                       ("root_start_filetime_utc", "01"), ("run_id", "e" * 32)])
def test_invalid_independent_admission_refuses(field: str, value: object) -> None:
    """Malformed or internally inconsistent admission is rejected first.

    Args:
        field: Admission field under test.
        value: Invalid admitted value.
    """
    expected = binding()
    expected[field] = value
    with pytest.raises(GuestRefusal, match="stop_ack_binding_invalid"):
        verify(sign(envelope()), expected_binding=expected)
