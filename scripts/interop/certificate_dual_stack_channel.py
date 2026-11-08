"""Framed public guestinfo observations for admitted console-only TEST_ONLY runs.

This is observation transport, not membership or address-control enforcement.
Native runtimeConfig quoting/roundtrip and absent-key behavior must be qualified
with a public canary before credentials or mutation. All fields are public.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from scripts.interop.certificate_dual_stack_contract import (
    ContractRefusal,
    plan_tls_numeric_endpoint,
)
from scripts.interop.certificate_dual_stack_guest import (
    NATIVE_COMMANDS,
    GuestRefusal,
    json_loads_unique,
    public_bytes,
)
from scripts.interop.certificate_dual_stack_ui import (
    FIELDS,
    assert_public_review,
    validate_public_apply_review,
)

PREFIX = "guestinfo.atlaso.pr1084.native"
CHUNK_DATA_BYTES = 1_024
MAX_CHUNKS = 384
MAX_ENVELOPE_BYTES = 3_000
METADATA_KEYS = frozenset({
    "source_commit", "bundle_sha256", "resource_receipt_sha256",
    "persistent_vm_identity_sha256", "boot_id", "run_id", "stage",
})
MANIFEST_KEYS = METADATA_KEYS | {
    "schema", "kind", "test_only", "formal_acceptance", "count", "bytes", "payload_sha256",
}
CHUNK_KEYS = frozenset({
    "schema", "kind", "run_id", "stage", "index", "count", "payload_sha256", "data",
})
PUBLIC_KINDS = frozenset({
    "dual-stack-native-raw-observation", "test-only-protected-apply-intent",
    "test-only-original-apply-job", "test-only-desired-save-intent",
    "desired_save_readback", "test-only-task-status", "test-only-tls-observation",
    "test-only-retired-tcp-observation", "test-only-public-canary",
    "test-only-driver-terminal",
})


def _sha256(value: object) -> bool:
    """Recognize one public content digest without accepting coercions.

    Args:
        value: Candidate digest.
    """
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _job(value: object) -> bool:
    """Recognize a bounded public task identifier.

    Args:
        value: Candidate original job ID.
    """
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None


def _interface_fields(value: object) -> bool:
    """Check the exact public physical-interface field types before serialization.

    Args:
        value: Complete normal-UI desired record.
    """
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        return False
    boolean_fields = {"ipv6_enabled", "check_duplicate_ip_addresses", "access_management_ui_enabled"}
    text_fields = set(FIELDS) - boolean_fields - {"mtu"}
    return (
        all(type(value[key]) is bool for key in boolean_fields)
        and all(isinstance(value[key], str) and len(value[key]) <= 256 for key in text_fields)
        and (type(value["mtu"]) is int and 576 <= value["mtu"] <= 65_535
             or isinstance(value["mtu"], str) and (value["mtu"] == "" or re.fullmatch(r"[0-9]{3,5}", value["mtu"]) is not None
                                                  and 576 <= int(value["mtu"]) <= 65_535))
        and value["role"] in {"management", "access", "route", "unused"}
        and value["mode"] in {"access", "trunk", "unused"}
        and value["ipv4_method"] in {"static", "dhcp"}
        and value["admin_state"] in {"up", "down"}
    )


def _tls_payload(payload: dict[str, Any]) -> None:
    """Validate numeric TLS facts without authenticating the reporter.

    Args:
        payload: Complete exact-schema TLS observation.
    """
    if (not isinstance(payload["address"], str) or type(payload["family"]) is not int
            or type(payload["port"]) is not int or not _sha256(payload["leaf_sha256"])
            or not _sha256(payload["ca_sha256"]) or not isinstance(payload["ip_sans"], list)
            or not payload["ip_sans"] or not all(isinstance(item, str) for item in payload["ip_sans"])):
        raise GuestRefusal("public_tls_facts_invalid")
    try:
        endpoint = plan_tls_numeric_endpoint(payload["address"], family=payload["family"], port=payload["port"])
    except ContractRefusal:
        raise GuestRefusal("public_tls_facts_invalid") from None
    try:
        sans = [str(ipaddress.ip_address(item)) for item in payload["ip_sans"] if "%" not in item]
    except ValueError:
        raise GuestRefusal("public_tls_facts_invalid") from None
    if (payload["address"] != endpoint.address or sans != payload["ip_sans"]
            or len(sans) != len(set(sans)) or endpoint.address not in sans):
        raise GuestRefusal("public_tls_facts_invalid")



def validate_public_payload(payload: dict[str, Any]) -> None:
    """Require one exact public action schema before publication and reconstruction.

    Args:
        payload: Complete already-sanitized action result.
    """
    if not isinstance(payload, dict):
        raise GuestRefusal("public_action_schema_invalid")
    common = {"schema", "kind", "test_only", "formal_acceptance"}
    kind = payload.get("kind")
    additional = {
        "dual-stack-native-raw-observation": {"boot_id", "monotonic_ns", "observations"},
        "test-only-protected-apply-intent": {"review", "review_sha256"},
        "test-only-original-apply-job": {"job_id", "status_url", "intent_sha256", "HTTP_status", "automatic_poll_or_restore"},
        "test-only-desired-save-intent": {"interface", "mac", "row_id", "before", "after"},
        "desired_save_readback": {"interface", "mac", "row_id", "before", "after", "verified"},
        "test-only-task-status": {"job_id", "status_url", "task_type", "status", "original_job_receipt_sha256"},
        "test-only-tls-observation": {"address", "family", "port", "leaf_sha256", "ca_sha256", "ip_sans"},
        "test-only-retired-tcp-observation": {"family", "address", "port", "outcome", "errno", "elapsed_seconds", "active_before", "active_after", "requires_complete_native_absence_and_path_admission", "automatic_retry_or_restore"},
        "test-only-public-canary": {"challenge"},
        "test-only-driver-terminal": {"exit_code", "reason"},
    }
    if (not isinstance(kind, str) or kind not in additional or set(payload) != common | additional[kind]
            or type(payload.get("schema")) is not int or payload["schema"] != 1
            or payload.get("test_only") is not True or payload.get("formal_acceptance") is not False):
        raise GuestRefusal("public_action_schema_invalid")
    if kind == "dual-stack-native-raw-observation":
        if (not isinstance(payload["boot_id"], str)
                or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", payload["boot_id"]) is None
                or type(payload["monotonic_ns"]) is not int or payload["monotonic_ns"] <= 0):
            raise GuestRefusal("complete_native_inventory_required")
        observed = payload["observations"]
        expected = dict(NATIVE_COMMANDS)
        if not isinstance(observed, dict) or set(observed) != set(expected):
            raise GuestRefusal("complete_native_inventory_required")
        for name, command in expected.items():
            row = observed[name]
            if (not isinstance(row, dict) or set(row) != {"argv", "exit_code", "raw"}
                    or row.get("argv") != list(command) or type(row.get("exit_code")) is not int
                    or row["exit_code"] != 0 or not isinstance(row.get("raw"), list)):
                raise GuestRefusal("complete_native_inventory_required")
    if kind == "test-only-protected-apply-intent":
        review = payload["review"]
        if (not isinstance(review, dict)
                or payload["review_sha256"] != hashlib.sha256(public_bytes(review)).hexdigest()):
            raise GuestRefusal("complete_public_review_required")
        validate_public_apply_review(review)
    if kind == "test-only-original-apply-job":
        job = payload["job_id"]
        if (not isinstance(job, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job) is None
                or payload["status_url"] not in (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status")
                or type(payload["HTTP_status"]) is not int or payload["HTTP_status"] != 202
                or not isinstance(payload["intent_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", payload["intent_sha256"]) is None
                or payload["automatic_poll_or_restore"] is not False):
            raise GuestRefusal("original_job_receipt_invalid")
    if kind in {"test-only-desired-save-intent", "desired_save_readback"}:
        if (not isinstance(payload["interface"], str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", payload["interface"]) is None
                or not isinstance(payload["mac"], str)
                or re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", payload["mac"]) is None
                or type(payload["row_id"]) is not int or payload["row_id"] <= 0
                or not _interface_fields(payload["before"]) or not _interface_fields(payload["after"])
                or kind == "desired_save_readback" and payload["verified"] is not True):
            raise GuestRefusal("public_desired_save_invalid")
    if kind == "test-only-task-status":
        job = payload["job_id"]
        if (not _job(job) or payload["status_url"] not in
                (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status")
                or payload["task_type"] != "appliance-apply" or not isinstance(payload["status"], str)
                or payload["status"] not in {"queued", "running", "succeeded", "failed", "cancelled"}
                or not _sha256(payload["original_job_receipt_sha256"])):
            raise GuestRefusal("public_task_status_invalid")
    if kind == "test-only-tls-observation":
        _tls_payload(payload)
    if kind == "test-only-retired-tcp-observation":
        if (type(payload["family"]) is not int or not isinstance(payload["address"], str)
                or type(payload["port"]) is not int or not isinstance(payload["outcome"], str)
                or payload["outcome"] not in {"explicit_connect_failed", "unknown"}
                or payload["errno"] is not None and (type(payload["errno"]) is not int or not 1 <= payload["errno"] <= 65_535)
                or payload["outcome"] == "explicit_connect_failed" and payload["errno"] not in (111, 113)
                or type(payload["elapsed_seconds"]) not in (int, float)
                or not math.isfinite(payload["elapsed_seconds"]) or not 0 <= payload["elapsed_seconds"] <= 60
                or payload["requires_complete_native_absence_and_path_admission"] is not True
                or payload["automatic_retry_or_restore"] is not False):
            raise GuestRefusal("public_retirement_facts_invalid")
        try:
            plan_tls_numeric_endpoint(payload["address"], family=payload["family"], port=payload["port"])
        except ContractRefusal:
            raise GuestRefusal("public_retirement_facts_invalid") from None
        for key in ("active_before", "active_after"):
            active = payload[key]
            if not isinstance(active, dict) or active.get("kind") != "test-only-tls-observation":
                raise GuestRefusal("public_retirement_positive_path_required")
            validate_public_payload(active)
            if (active["family"] != payload["family"] or active["port"] != payload["port"]
                    or active["address"] == payload["address"]):
                raise GuestRefusal("public_retirement_positive_path_required")
        if payload["active_before"] != payload["active_after"]:
            raise GuestRefusal("public_retirement_positive_path_changed")
    if kind == "test-only-public-canary":
        challenge = payload["challenge"]
        if (not isinstance(challenge, str) or not challenge or not challenge.isascii()
                or any(ord(char) < 32 or ord(char) == 127 for char in challenge)):
            raise GuestRefusal("public_canary_invalid")
    if kind == "test-only-driver-terminal":
        if (type(payload["exit_code"]) is not int or not isinstance(payload["reason"], str)
                or (payload["exit_code"], payload["reason"]) not in {
                    (0, "completed"), (1, "refused"), (1, "outcome_unknown")}):
            raise GuestRefusal("public_terminal_reason_invalid")

def validate_metadata(metadata: Mapping[str, str]) -> None:
    """Require original public source/resource/boot and fresh stage bindings.

    Args:
        metadata: Exact controller-admitted public binding fields.
    """
    if set(metadata) != METADATA_KEYS or not all(isinstance(value, str) for value in metadata.values()):
        raise GuestRefusal("public_channel_metadata_invalid")
    patterns = {
        "source_commit": r"[0-9a-f]{40}",
        "bundle_sha256": r"[0-9a-f]{64}",
        "resource_receipt_sha256": r"[0-9a-f]{64}",
        "persistent_vm_identity_sha256": r"[0-9a-f]{64}",
        "boot_id": r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        "run_id": r"[0-9a-f]{32}",
        "stage": r"[a-z][a-z0-9-]{0,47}",
    }
    if any(re.fullmatch(pattern, metadata[key]) is None for key, pattern in patterns.items()):
        raise GuestRefusal("public_channel_metadata_invalid")


def variable_names(metadata: Mapping[str, str], count: int) -> tuple[list[str], str]:
    """Construct exact new immutable-stage keys; never accept arbitrary key names.

    Args:
        metadata: Validated fresh run and stage bindings.
        count: Bounded nonempty chunk count.
    """
    validate_metadata(metadata)
    if type(count) is not int or not 1 <= count <= MAX_CHUNKS:
        raise GuestRefusal("public_channel_chunk_count_invalid")
    stem = f"{PREFIX}.{metadata['run_id']}.{metadata['stage']}"
    return [f"{stem}.part-{index:03d}" for index in range(count)], stem + ".manifest"


def frame_public(
    payload: dict[str, Any], metadata: Mapping[str, str], private_markers: set[str]
) -> tuple[list[str], str]:
    """Frame already schema-allowlisted public data without whitespace loss or base64.

    The calling driver must validate the complete action-specific payload schema.
    Known session values, private keys and credential URLs refuse before any write.

    Args:
        payload: Complete public observation, never an arbitrary HTTP response.
        metadata: Original controller-admitted source/resource/boot/stage bindings.
        private_markers: In-memory session material that must never be exported.
    """
    validate_metadata(metadata)
    validate_public_payload(payload)
    if payload["kind"] == "dual-stack-native-raw-observation" and payload["boot_id"] != metadata["boot_id"]:
        raise GuestRefusal("public_inventory_boot_changed")
    if (payload.get("kind") not in PUBLIC_KINDS or payload.get("test_only") is not True
            or payload.get("formal_acceptance") is not False):
        raise GuestRefusal("public_payload_kind_unadmitted")
    assert_public_review(payload, private_markers)
    raw = public_bytes(payload)
    text = raw.decode("ascii")
    count = max(1, (len(text) + CHUNK_DATA_BYTES - 1) // CHUNK_DATA_BYTES)
    variable_names(metadata, count)
    digest = hashlib.sha256(raw).hexdigest()
    chunks = []
    for index in range(count):
        envelope = {
            "schema": 1, "kind": "atlaso-test-only-public-chunk",
            "run_id": metadata["run_id"], "stage": metadata["stage"],
            "index": index, "count": count, "payload_sha256": digest,
            "data": text[index * CHUNK_DATA_BYTES:(index + 1) * CHUNK_DATA_BYTES],
        }
        encoded = public_bytes(envelope).decode("ascii")
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise GuestRefusal("public_chunk_envelope_too_large")
        chunks.append(encoded)
    manifest = {
        **metadata, "schema": 1, "kind": "atlaso-test-only-public-manifest",
        "test_only": True, "formal_acceptance": False,
        "count": count, "bytes": len(raw), "payload_sha256": digest,
    }
    return chunks, public_bytes(manifest).decode("ascii")


def decode_envelope(raw: str, mode: Literal["raw-object", "json-string"]) -> dict[str, Any]:
    """Decode only the explicitly canary-qualified native representation.

    Never auto-adopt a different runtime scope or strip arbitrary quote pairs.

    Args:
        raw: Exact trimmed public value from typed runtimeConfig readVariable.
        mode: Native representation independently qualified with the public canary.
    """
    if not isinstance(raw, str) or not raw.isascii() or len(raw) > MAX_ENVELOPE_BYTES * 2 + 2:
        raise GuestRefusal("public_native_representation_invalid")
    if mode not in ("raw-object", "json-string"):
        raise GuestRefusal("public_native_representation_unqualified")
    try:
        value = json_loads_unique(raw)
        if mode == "json-string":
            if not isinstance(value, str):
                raise GuestRefusal("public_native_representation_changed")
            value = json_loads_unique(value)
    except GuestRefusal:
        raise
    except (ValueError, TypeError):
        raise GuestRefusal("public_native_representation_invalid") from None
    if not isinstance(value, dict) or len(public_bytes(value)) > MAX_ENVELOPE_BYTES:
        raise GuestRefusal("public_native_representation_invalid")
    return value


def reconstruct_public(
    manifest_before: str, chunks: Sequence[str], manifest_after: str,
    metadata: Mapping[str, str], *, mode: Literal["raw-object", "json-string"],
) -> dict[str, Any]:
    """Verify a complete immutable-stage read before publishing a host original.

    The host controller must validate the action-specific public payload schema,
    fsync the original complete result, and only then type its observed ACK.

    Args:
        manifest_before: First exact typed native manifest read.
        chunks: All ordered typed native chunk reads.
        manifest_after: Second exact typed native manifest read.
        metadata: Original expected source/resource/boot/run/stage bindings.
        mode: Public-canary-qualified runtimeConfig representation.
    """
    validate_metadata(metadata)
    if manifest_before != manifest_after:
        raise GuestRefusal("public_manifest_changed")
    manifest = decode_envelope(manifest_before, mode)
    if (set(manifest) != MANIFEST_KEYS or type(manifest.get("schema")) is not int or manifest.get("schema") != 1
            or manifest.get("kind") != "atlaso-test-only-public-manifest"
            or manifest.get("test_only") is not True or manifest.get("formal_acceptance") is not False
            or any(manifest.get(key) != value for key, value in metadata.items())):
        raise GuestRefusal("public_manifest_binding_changed")
    count = manifest.get("count")
    if type(count) is not int:
        raise GuestRefusal("public_channel_chunk_count_invalid")
    variable_names(metadata, count)
    if type(manifest.get("bytes")) is not int or not 1 <= manifest["bytes"] <= 393_216:
        raise GuestRefusal("public_manifest_size_invalid")
    digest = manifest.get("payload_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None or len(chunks) != count:
        raise GuestRefusal("public_chunks_incomplete")
    parts = []
    for index, raw in enumerate(chunks):
        envelope = decode_envelope(raw, mode)
        if (set(envelope) != CHUNK_KEYS or type(envelope.get("schema")) is not int or envelope.get("schema") != 1
                or envelope.get("kind") != "atlaso-test-only-public-chunk"
                or envelope.get("run_id") != metadata["run_id"] or envelope.get("stage") != metadata["stage"]
                or type(envelope.get("index")) is not int or envelope["index"] != index
                or type(envelope.get("count")) is not int or envelope["count"] != count
                or envelope.get("payload_sha256") != digest or not isinstance(envelope.get("data"), str)
                or not envelope["data"].isascii() or not 1 <= len(envelope["data"]) <= CHUNK_DATA_BYTES):
            raise GuestRefusal("public_chunk_binding_changed")
        parts.append(envelope["data"])
    raw_payload = "".join(parts).encode("ascii")
    if len(raw_payload) != manifest["bytes"] or hashlib.sha256(raw_payload).hexdigest() != digest:
        raise GuestRefusal("public_payload_digest_changed")
    payload = json_loads_unique(raw_payload)
    if (not isinstance(payload, dict) or payload.get("kind") not in PUBLIC_KINDS
            or payload.get("test_only") is not True or payload.get("formal_acceptance") is not False):
        raise GuestRefusal("public_payload_kind_unadmitted")
    validate_public_payload(payload)
    if payload["kind"] == "dual-stack-native-raw-observation" and payload["boot_id"] != metadata["boot_id"]:
        raise GuestRefusal("public_inventory_boot_changed")
    return payload


def _rpc(action: str, name: str, value: str | None, remaining: float) -> None:
    """Use the installed guest's standard public VMware RPC with no shell.

    Args:
        action: Fixed get-absence or set-public operation.
        name: Exact new namespace key constructed by this module.
        value: Framed public ASCII envelope for a set, otherwise None.
        remaining: Remaining whole-publication monotonic budget.
    """
    pattern = re.escape(PREFIX) + r"\.[0-9a-f]{32}\.[a-z][a-z0-9-]{0,47}\.(?:part-[0-9]{3}|manifest)"
    if (action not in {"absent", "set"} or re.fullmatch(pattern, name) is None
            or action == "absent" and value is not None
            or action == "set" and (not isinstance(value, str) or not value.isascii()
                                    or len(value) > MAX_ENVELOPE_BYTES or any(ord(char) < 32 for char in value))):
        raise GuestRefusal("public_rpc_arguments_invalid")
    if remaining <= 0:
        raise GuestRefusal("public_publication_timeout")
    command = f"info-get {name}" if action == "absent" else f"info-set {name} {value}"
    result = subprocess.run(
        ["/usr/bin/vmtoolsd", "--cmd", command], capture_output=True,
        timeout=min(8, remaining), check=False,
    )
    if len(result.stdout) + len(result.stderr) > 6_144:
        raise GuestRefusal("public_rpc_output_invalid")
    if action == "absent":
        # This exact absence diagnostic must be qualified by the native canary.
        diagnostic = (result.stdout + result.stderr).decode("utf-8", "strict").strip()
        if result.returncode != 1 or diagnostic != "No value found":
            raise GuestRefusal("public_stage_key_not_proven_absent")
    elif action != "set" or result.returncode != 0 or result.stdout or result.stderr:
        raise GuestRefusal("public_rpc_set_failed")


def publish_public(
    payload: dict[str, Any], metadata: Mapping[str, str], marker_root: Path,
    private_markers: set[str], *, root_identity: tuple[int, int],
    rpc: Callable[[str, str, str | None, float], None] = _rpc,
) -> str:
    """Publish one complete public stage once, preserving every partial outcome.

    An original exclusive marker is retained before runtimeConfig writes; all keys
    must be absent. The manifest is published LAST. Neither marker nor variables
    are removed or overwritten on success/failure. No credentials enter this path.

    Args:
        payload: Complete caller-allowlisted public result.
        metadata: Original source/resource/boot and fresh run/stage binding.
        marker_root: Previously admitted ordinary guest artifact directory.
        private_markers: Private in-memory material excluded from the payload.
        root_identity: Original admitted guest artifact directory device/inode.
        rpc: Bounded installed VMware RPC adapter, injectable only for synthetic tests.
    """
    if sys.platform != "linux":
        raise GuestRefusal("admitted_linux_guest_required")
    chunks, manifest = frame_public(payload, metadata, private_markers)
    names, manifest_name = variable_names(metadata, len(chunks))
    root_descriptor = os.open(marker_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    started = time.monotonic()
    try:
        actual_root = os.fstat(root_descriptor)
        if (actual_root.st_dev, actual_root.st_ino) != root_identity:
            raise GuestRefusal("original_guest_artifact_root_required")
        marker = f"{metadata['run_id']}.{metadata['stage']}.publication.json"
        descriptor = os.open(
            marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            dir_fd=root_descriptor,
        )
        identity = os.fstat(descriptor)
        original = {
            "schema": 1, "kind": "test-only-original-publication-marker",
            "metadata": dict(metadata), "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
            "guest_original_identity": [str(identity.st_dev), str(identity.st_ino)],
            "before_public_variable_write": True,
        }
        marker_bytes = public_bytes(original)
        if os.write(descriptor, marker_bytes) != len(marker_bytes):
            raise GuestRefusal("public_original_marker_incomplete")
        os.fsync(descriptor)
        os.fsync(root_descriptor)
        for name in [*names, manifest_name]:
            rpc("absent", name, None, 40 - (time.monotonic() - started))
        for name, chunk in zip(names, chunks, strict=True):
            rpc("set", name, chunk, 40 - (time.monotonic() - started))
        rpc("set", manifest_name, manifest, 40 - (time.monotonic() - started))
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root_descriptor)
    return hashlib.sha256(public_bytes(payload)).hexdigest()
