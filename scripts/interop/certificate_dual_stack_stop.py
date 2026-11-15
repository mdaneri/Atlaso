"""Pure verification of separately admitted public SDK-stop statements.

No signer, transport, receiver admission or terminal release is implemented here.
The independently admitted key authenticates a statement, not its truth. The host
signer must establish the original receipt chain and whole-job quiescence itself.
Existing v1 transaction and receiver receipts are not signed-protocol admission.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.interop.certificate_dual_stack_guest import GuestRefusal, json_loads_unique

DOMAIN = b"Atlaso-PR1084-SDK-stop-ACK-v2\x00"
MAX_ACK_BYTES = 3_000
PREFIX = "guestinfo.atlaso.pr1084.native.stop-ack"
DIGEST_FIELDS = frozenset({
    "bundle_sha256", "original_vm_receipt_sha256", "persistent_vm_identity_sha256",
    "plan_sha256", "receiver_receipt_sha256", "process_receipt_sha256",
    "stop_receipt_sha256", "ack_intent_sha256",
})
BINDING_FIELDS = DIGEST_FIELDS | {
    "task_id", "source_commit", "run_id", "receiver_nonce", "guest_boot_id",
    "host_boot_identity", "transport_key", "deadline_unix_ms", "root_pid",
    "root_start_filetime_utc",
}
FACT_FIELDS = frozenset({
    "whole_job_empty", "outcome", "root_exit_code", "original_binding_rechecked",
})
ENVELOPE_FIELDS = frozenset({
    "schema", "kind", "algorithm", "signing_key_sha256", "payload", "signature_hex",
})


def _matches(value: object, pattern: str) -> bool:
    """Check exact public text without coercion.

    Args:
        value: Untrusted field.
        pattern: Complete allowlisted syntax.
    """
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _canonical(value: object) -> bytes:
    """Encode an already bounded public schema with one wire representation.

    Args:
        value: Exact validated public object.
    """
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _binding(value: Mapping[str, object]) -> None:
    """Require the complete independently admitted binding shape.

    Args:
        value: Public bindings admitted outside the ACK channel.
    """
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    if (set(value) != BINDING_FIELDS
            or any(not _matches(value[key], r"[0-9a-f]{64}") for key in DIGEST_FIELDS)
            or not _matches(value["source_commit"], r"[0-9a-f]{40}")
            or not _matches(value["task_id"], uuid)
            or not _matches(value["guest_boot_id"], uuid)
            or not _matches(value["run_id"], r"[0-9a-f]{32}")
            or not _matches(value["receiver_nonce"], r"[0-9a-f]{32}")
            or not _matches(value["host_boot_identity"], r"[1-9][0-9]{0,18}")
            or not _matches(value["root_start_filetime_utc"], r"[1-9][0-9]{0,18}")
            or type(value["root_pid"]) is not int
            or not 1 <= value["root_pid"] <= 2_147_483_647
            or type(value["deadline_unix_ms"]) is not int
            or not 1 <= value["deadline_unix_ms"] <= 253_402_300_799_999
            or value["transport_key"] != f"{PREFIX}.{value['run_id']}.{value['receiver_nonce']}"):
        raise GuestRefusal("stop_ack_binding_invalid")


def verify_stop_ack(
    raw: bytes, *, public_key_hex: str, signing_key_sha256: str,
    expected_binding: Mapping[str, object], now_unix_ms: int,
) -> Literal["succeeded", "terminated_failure"]:
    """Authenticate one canonical statement against independent admission.

    A successful return never authorizes terminal release on its own. A receiver
    also needs a complete valid consumed line and its separately reviewed guard.
    Failed statements must keep the receiver concealed and outside a shell.

    Args:
        raw: Original bounded ASCII ACK bytes, not an RPC wrapper.
        public_key_hex: Raw Ed25519 public key admitted before credential entry.
        signing_key_sha256: Independently admitted SHA-256 of the raw key bytes.
        expected_binding: Complete original bindings from independent admission.
        now_unix_ms: Admitted current wall time; no ACK-provided clock is trusted.
    """
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_ACK_BYTES
            or not raw.isascii() or type(now_unix_ms) is not int or now_unix_ms < 0
            or not _matches(public_key_hex, r"[0-9a-f]{64}")
            or not _matches(signing_key_sha256, r"[0-9a-f]{64}")):
        raise GuestRefusal("stop_ack_admission_invalid")
    # Snapshot scalar admission values before parsing any channel data.
    admitted = dict(expected_binding)
    _binding(admitted)
    key_bytes = bytes.fromhex(public_key_hex)
    if hashlib.sha256(key_bytes).hexdigest() != signing_key_sha256:
        raise GuestRefusal("stop_ack_key_not_admitted")
    try:
        envelope: Any = json_loads_unique(raw)
    except (ValueError, RecursionError):
        raise GuestRefusal("stop_ack_json_invalid") from None
    if (not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS
            or type(envelope["schema"]) is not int or envelope["schema"] != 2
            or envelope["kind"] != "console-sdk-stop-ack-v2"
            or envelope["algorithm"] != "Ed25519"
            or envelope["signing_key_sha256"] != signing_key_sha256
            or not _matches(envelope["signature_hex"], r"[0-9a-f]{128}")
            or not isinstance(envelope["payload"], dict)):
        raise GuestRefusal("stop_ack_schema_invalid")
    payload = envelope["payload"]
    if set(payload) != BINDING_FIELDS | FACT_FIELDS:
        raise GuestRefusal("stop_ack_schema_invalid")
    if any(type(payload[key]) is not type(value) or payload[key] != value
           for key, value in admitted.items()):
        raise GuestRefusal("stop_ack_binding_mismatch")
    if (payload["whole_job_empty"] is not True
            or type(payload["original_binding_rechecked"]) is not bool
            or payload["outcome"] not in ("succeeded", "terminated_failure")
            or type(payload["root_exit_code"]) is not int
            or not -2_147_483_648 <= payload["root_exit_code"] <= 2_147_483_647
            or (payload["outcome"] == "succeeded" and (
                payload["root_exit_code"] != 0 or payload["original_binding_rechecked"] is not True))):
        raise GuestRefusal("stop_ack_quiescence_invalid")
    deadline = admitted["deadline_unix_ms"]
    if not isinstance(deadline, int) or now_unix_ms >= deadline:
        raise GuestRefusal("stop_ack_expired")
    if _canonical(envelope) != raw:
        raise GuestRefusal("stop_ack_noncanonical")
    unsigned = {key: value for key, value in envelope.items() if key != "signature_hex"}
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            bytes.fromhex(envelope["signature_hex"]), DOMAIN + _canonical(unsigned),
        )
    except InvalidSignature:
        raise GuestRefusal("stop_ack_signature_invalid") from None
    return "succeeded" if payload["outcome"] == "succeeded" else "terminated_failure"
