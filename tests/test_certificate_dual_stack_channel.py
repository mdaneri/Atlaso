"""Synthetic public-channel checks; these never contact a guest or VMware."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.interop import certificate_dual_stack_channel as channel  # noqa: E402 - Local interop module.
from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes  # noqa: E402 - Local module.


def metadata() -> dict[str, str]:
    """Return a complete synthetic source and immutable-stage binding."""
    return {
        "source_commit": "a" * 40,
        "bundle_sha256": "b" * 64,
        "resource_receipt_sha256": "c" * 64,
        "persistent_vm_identity_sha256": "d" * 64,
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "run_id": "e" * 32,
        "stage": "synthetic-stage",
    }


def payload(challenge: str = "public synthetic canary") -> dict[str, Any]:
    """Return one exact allowed action schema without private or native data.

    Args:
        challenge: Public synthetic canary text.
    """
    return {
        "schema": 1,
        "kind": "test-only-public-canary",
        "test_only": True,
        "formal_acceptance": False,
        "challenge": challenge,
    }


def action_payload(kind: str, **fields: Any) -> dict[str, Any]:
    """Build an action envelope from explicit public synthetic fields.

    Args:
        kind: Exact allowlisted action kind under test.
        **fields: Action-specific public fields.
    """
    return {
        "schema": 1, "kind": kind, "test_only": True,
        "formal_acceptance": False, **fields,
    }


def tls_facts(family: int) -> dict[str, Any]:
    """Return one complete positive numeric TLS observation for a test family.

    Args:
        family: Numeric IPv4 or IPv6 family selector.
    """
    address = "192.0.2.10" if family == 4 else "fd00:1084:1077::10"
    return action_payload(
        "test-only-tls-observation", address=address, family=family, port=443,
        leaf_sha256="1" * 64, ca_sha256="2" * 64, ip_sans=[address],
    )


def interface_record() -> dict[str, Any]:
    """Return a complete physical-interface record with exact scalar types."""
    return {
        "role": "management", "mode": "access", "ipv4_method": "static",
        "ip_cidr": "192.0.2.10/24", "gateway": "", "ipv6_enabled": True,
        "ipv6_cidr": "fd00:1084:1077::10/64", "ipv6_gateway": "", "mtu": 1500,
        "admin_state": "up", "check_duplicate_ip_addresses": True,
        "access_management_ui_enabled": True,
    }


def protected_review() -> dict[str, Any]:
    """Build a complete synthetic selected five-unit protected public review."""
    from scripts.interop import certificate_dual_stack_ui as ui

    units = []
    for name in sorted(ui.PROTECTED):
        unit = dict.fromkeys(ui.UNIT_KEYS)
        unit.update(
            id=name, label=name, page_url=f"/ui/management/{name}", summary=[],
            valid=True, validation_errors=[], validation_warnings=[], connection_warnings=[],
            config_path=f"/etc/atlaso/{name}.conf", config_preview="public preview",
            config_diff="public diff", snapshot_hash="a" * 64,
            network_candidate_preview=None, network_candidate_diff=None,
            network_candidate_valid=None, network_candidate_validation_errors=[],
            forces_network_selection=False, forces_wan_selection=False,
            has_baseline=True, changed=True, selected=True,
            required_dependency=False, dependency_reason="", requires_dns_selection=False,
            requires_network_selection=False, format_volumes=[],
        )
        units.append(unit)
    return {
        "units": units, "pending_count": len(units), "execution_count": len(units),
        "requested_units": sorted(ui.PROTECTED), "plan_error": "",
        "initial_apply_required": False, "active_task": None,
    }


def round_trip(value: dict[str, Any], binding: dict[str, str] | None = None) -> dict[str, Any]:
    """Frame and reconstruct one synthetic action using its exact public binding.

    Args:
        value: Complete public action payload.
        binding: Optional source and stage metadata; default metadata is used otherwise.
    """
    original_binding = metadata() if binding is None else binding
    chunks, manifest = channel.frame_public(value, original_binding, set())
    return channel.reconstruct_public(manifest, chunks, manifest, original_binding, mode="raw-object")


def manual_wire_frame(
    value: dict[str, Any], binding: dict[str, str],
) -> tuple[list[str], str]:
    """Encode tampered payload bytes with internally consistent synthetic envelopes.

    This bypasses the producer validator only to reach the independent consumer check.

    Args:
        value: Public payload bytes to test at reconstruction.
        binding: Expected source, boot, run, and stage metadata.
    """
    raw = public_bytes(value)
    text = raw.decode("ascii")
    count = max(1, (len(text) + channel.CHUNK_DATA_BYTES - 1) // channel.CHUNK_DATA_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    chunks = []
    for index in range(count):
        envelope = {
            "schema": 1, "kind": "atlaso-test-only-public-chunk",
            "run_id": binding["run_id"], "stage": binding["stage"],
            "index": index, "count": count, "payload_sha256": digest,
            "data": text[index * channel.CHUNK_DATA_BYTES:(index + 1) * channel.CHUNK_DATA_BYTES],
        }
        chunks.append(public_bytes(envelope).decode("ascii"))
    manifest = {
        **binding, "schema": 1, "kind": "atlaso-test-only-public-manifest",
        "test_only": True, "formal_acceptance": False,
        "count": count, "bytes": len(raw), "payload_sha256": digest,
    }
    return chunks, public_bytes(manifest).decode("ascii")


def encoded(value: dict[str, Any], mode: str) -> str:
    """Serialize one synthetic object in an explicitly selected native mode.

    Args:
        value: Public synthetic envelope.
        mode: Explicit raw-object or JSON-string representation.
    """
    raw = public_bytes(value).decode("ascii")
    return raw if mode == "raw-object" else json.dumps(raw)


def framed(value: dict[str, Any] | None = None) -> tuple[dict[str, str], list[str], str]:
    """Build a synthetic public frame using the real deterministic encoder.

    Args:
        value: Optional exact-schema synthetic public action.
    """
    binding = metadata()
    chunks, manifest = channel.frame_public(value or payload(), binding, set())
    return binding, chunks, manifest


@pytest.mark.parametrize("mode", ["raw-object", "json-string"])
def test_reconstruct_round_trips_explicit_native_representations(mode: str) -> None:
    """Reconstruct the same complete public action in both qualified modes.

    Args:
        mode: Explicit native representation under test.
    """
    binding, chunks, manifest = framed(payload("retain spaces and punctuation: a / b"))
    result = channel.reconstruct_public(
        encoded(json.loads(manifest), mode), [encoded(json.loads(chunk), mode) for chunk in chunks],
        encoded(json.loads(manifest), mode), binding, mode=mode,
    )
    assert result == payload("retain spaces and punctuation: a / b")


def test_chunking_preserves_ordered_multichunk_payload() -> None:
    """Reassemble a payload spanning multiple bounded chunks without whitespace loss."""
    value = payload("word with spaces / punctuation " * 120)
    binding, chunks, manifest = framed(value)
    assert len(chunks) > 1
    assert channel.reconstruct_public(manifest, chunks, manifest, binding, mode="raw-object") == value


@pytest.mark.parametrize("field", sorted(channel.METADATA_KEYS))
def test_changed_expected_metadata_refuses(field: str) -> None:
    """A manifest for another source, resource, VM, boot, run, or stage cannot bind.

    Args:
        field: Public binding field to change.
    """
    binding, chunks, manifest = framed()
    changed = dict(binding)
    changed[field] = "f" * len(changed[field]) if field != "stage" else "other-stage"
    with pytest.raises(GuestRefusal):
        channel.reconstruct_public(manifest, chunks, manifest, changed, mode="raw-object")


@pytest.mark.parametrize(
    "mutation",
    [
        "manifest_binding", "manifest_drift", "manifest_count", "missing_chunk",
        "reordered_chunks", "chunk_index", "chunk_count", "chunk_digest",
        "chunk_type", "chunk_size", "payload_digest", "payload_size",
    ],
)
def test_changed_or_incomplete_frame_refuses(mutation: str) -> None:
    """Reject manifest drift and malformed count, order, type, size, and digest fields.

    Args:
        mutation: Single synthetic manifest or chunk mutation to reject.
    """
    binding, chunks, manifest = framed(payload("large enough for two parts " * 100))
    edited_chunks = list(chunks)
    edited_manifest = json.loads(manifest)
    if mutation == "manifest_binding":
        edited_manifest["source_commit"] = "f" * 40
    elif mutation == "manifest_drift":
        with pytest.raises(GuestRefusal, match="^public_manifest_changed$"):
            channel.reconstruct_public(manifest, chunks, manifest + " ", binding, mode="raw-object")
        return
    elif mutation == "manifest_count":
        edited_manifest["count"] += 1
    elif mutation == "missing_chunk":
        edited_chunks.pop()
    elif mutation == "reordered_chunks":
        edited_chunks.reverse()
    elif mutation in {"chunk_index", "chunk_count", "chunk_digest", "chunk_type", "chunk_size"}:
        first = json.loads(edited_chunks[0])
        if mutation == "chunk_index":
            first["index"] = 1
        elif mutation == "chunk_count":
            first["count"] += 1
        elif mutation == "chunk_digest":
            first["payload_sha256"] = "0" * 64
        elif mutation == "chunk_type":
            first["kind"] = "unknown"
        else:
            first["data"] = "x" * (channel.CHUNK_DATA_BYTES + 1)
        edited_chunks[0] = public_bytes(first).decode("ascii")
    elif mutation == "payload_digest":
        edited_chunks[0] = edited_chunks[0].replace("large enough", "changed payload", 1)
    else:
        edited_manifest["bytes"] += 1
    changed_manifest = public_bytes(edited_manifest).decode("ascii")
    with pytest.raises(GuestRefusal):
        channel.reconstruct_public(changed_manifest, edited_chunks, changed_manifest, binding, mode="raw-object")


@pytest.mark.parametrize("raw", ["{", '{"schema":1,"schema":1}', '"not an object"'])
def test_malformed_or_duplicate_native_json_refuses(raw: str) -> None:
    """Reject malformed objects, duplicate JSON members, and wrong native types.

    Args:
        raw: Malformed, duplicate-key, or wrong-type native representation.
    """
    with pytest.raises(GuestRefusal):
        channel.decode_envelope(raw, "raw-object")


def test_unknown_representation_mode_is_never_guessed() -> None:
    """Do not auto-adopt a runtimeConfig representation that was not qualified."""
    with pytest.raises(GuestRefusal, match="^public_native_representation_unqualified$"):
        channel.decode_envelope("{}", "guess")  # type: ignore[arg-type]  # Deliberately exercise an unqualified mode.


@pytest.mark.parametrize("change", ["unknown_kind", "unknown_schema", "extra_field", "missing_field"])
def test_unadmitted_public_action_or_schema_refuses(change: str) -> None:
    """Require the exact known action and complete action-specific payload schema.

    Args:
        change: Unknown action, schema, extra field, or missing field case.
    """
    value = payload()
    if change == "unknown_kind":
        value["kind"] = "unknown-action"
    elif change == "unknown_schema":
        value["schema"] = 2
    elif change == "extra_field":
        value["unexpected"] = "public"
    else:
        del value["challenge"]
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def original_job_payload() -> dict[str, Any]:
    """Return one valid synthetic original apply-job receipt."""
    return action_payload(
        "test-only-original-apply-job", job_id="job_123", status_url="/tasks/job_123/status",
        intent_sha256="a" * 64, HTTP_status=202, automatic_poll_or_restore=False,
    )


def task_status_payload() -> dict[str, Any]:
    """Return one valid synthetic appliance-apply task status."""
    return action_payload(
        "test-only-task-status", job_id="job-123", status_url="/ui/management/tasks/job-123/status",
        task_type="appliance-apply", status="succeeded",
        original_job_receipt_sha256="b" * 64,
    )


def test_original_apply_job_receipt_schema_roundtrips() -> None:
    """Accept a complete original 202 receipt with a matching safe task URL."""
    assert round_trip(original_job_payload()) == original_job_payload()


@pytest.mark.parametrize("field", ["job_id", "status_url", "intent_sha256", "HTTP_status", "automatic_poll_or_restore"])
def test_original_apply_job_receipt_rejects_changed_semantics(field: str) -> None:
    """Reject invalid original task identity, path, digest, or submission semantics.

    Args:
        field: Receipt member to change to an invalid value.
    """
    value = original_job_payload()
    bad_values = {
        "job_id": "bad/job", "status_url": "/tasks/other/status",
        "intent_sha256": "not-a-digest", "HTTP_status": True,
        "automatic_poll_or_restore": True,
    }
    value[field] = bad_values[field]
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def test_task_status_schema_roundtrips() -> None:
    """Accept an allowlisted status bound to its original job receipt digest."""
    value = task_status_payload()
    assert round_trip(value) == value


@pytest.mark.parametrize("field", ["job_id", "status_url", "task_type", "status", "original_job_receipt_sha256"])
def test_task_status_rejects_invalid_identity_path_type_status_or_digest(field: str) -> None:
    """Reject task status if any job, path, type, status, or receipt fact drifts.

    Args:
        field: Task status member to replace with an invalid value.
    """
    value = task_status_payload()
    bad_values = {
        "job_id": "job/with/slash", "status_url": "/tasks/other/status",
        "task_type": "dnsmasq", "status": True,
        "original_job_receipt_sha256": "b" * 63,
    }
    value[field] = bad_values[field]
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def test_numeric_tls_observations_roundtrip_for_both_families() -> None:
    """Round-trip complete canonical IPv4 and IPv6 address, pin, and SAN facts."""
    for family in (4, 6):
        value = tls_facts(family)
        assert round_trip(value) == value


@pytest.mark.parametrize("mutation", ["family", "address", "port", "leaf_pin", "ca_pin", "missing_san", "noncanonical_san", "duplicate_san", "scoped_san"])
def test_numeric_tls_observation_rejects_invalid_numeric_facts(mutation: str) -> None:
    """Refuse mismatched endpoint family, invalid pins, or noncanonical IP SANs.

    Args:
        mutation: TLS fact to change to a malformed or inconsistent value.
    """
    value = tls_facts(4)
    if mutation == "family":
        value["family"] = 6
    elif mutation == "address":
        value["address"] = "management.example.test"
    elif mutation == "port":
        value["port"] = True
    elif mutation == "leaf_pin":
        value["leaf_sha256"] = "z" * 64
    elif mutation == "ca_pin":
        value["ca_sha256"] = "2" * 63
    elif mutation == "missing_san":
        value["ip_sans"] = []
    elif mutation == "noncanonical_san":
        value["ip_sans"] = ["192.0.2.010"]
    elif mutation == "duplicate_san":
        value["ip_sans"] = ["192.0.2.10", "192.0.2.10"]
    else:
        value["ip_sans"] = ["192.0.2.10%eth0"]
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def test_driver_terminal_accepts_only_fixed_reason_exit_code_pairs() -> None:
    """Round-trip each explicitly allowed synthetic terminal result."""
    for exit_code, reason in ((0, "completed"), (1, "refused"), (1, "outcome_unknown")):
        value = action_payload("test-only-driver-terminal", exit_code=exit_code, reason=reason)
        assert round_trip(value) == value


@pytest.mark.parametrize("exit_code,reason", [(0, "refused"), (1, "completed"), (1, "other"), (True, "completed")])
def test_driver_terminal_rejects_unpaired_or_wrongly_typed_outcomes(
    exit_code: Any, reason: str,
) -> None:
    """Reject arbitrary reason strings and exit-code aliases or mismatches.

    Args:
        exit_code: Synthetic terminal process result.
        reason: Synthetic fixed terminal result label.
    """
    value = action_payload("test-only-driver-terminal", exit_code=exit_code, reason=reason)
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


@pytest.mark.parametrize("kind", ["test-only-desired-save-intent", "desired_save_readback"])
def test_complete_desired_save_intent_and_readback_roundtrip(kind: str) -> None:
    """Accept full scalar before/after field records and the verified readback shape.

    Args:
        kind: Intent or verified readback action to frame.
    """
    fields = {
        "interface": "eth0", "mac": "02:00:00:00:00:10", "row_id": 7,
        "before": interface_record(), "after": interface_record(),
    }
    if kind == "desired_save_readback":
        fields["verified"] = True
    value = action_payload(kind, **fields)
    assert round_trip(value) == value


@pytest.mark.parametrize("mutation", ["boolean_type", "nested_value", "extra_field", "mac", "row_id", "unverified"])
def test_desired_save_rejects_invalid_field_types_or_nested_objects(mutation: str) -> None:
    """Refuse incomplete or nested arbitrary desired-state values from a Save.

    Args:
        mutation: Desired-state value to replace with an invalid representation.
    """
    value = action_payload(
        "desired_save_readback", interface="eth0", mac="02:00:00:00:00:10", row_id=7,
        before=interface_record(), after=interface_record(), verified=True,
    )
    if mutation == "boolean_type":
        value["before"]["ipv6_enabled"] = 1
    elif mutation == "nested_value":
        value["after"]["gateway"] = {"unexpected": "nested"}
    elif mutation == "extra_field":
        value["after"]["new_field"] = "unexpected"
    elif mutation == "mac":
        value["mac"] = {"address": "02:00:00:00:00:10"}
    elif mutation == "row_id":
        value["row_id"] = True
    else:
        value["verified"] = False
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def test_protected_apply_intent_roundtrips_complete_public_review() -> None:
    """Accept a correctly hashed, complete selected protected-apply review."""
    review = protected_review()
    value = action_payload(
        "test-only-protected-apply-intent", review=review,
        review_sha256=hashlib.sha256(public_bytes(review)).hexdigest(),
    )
    assert round_trip(value) == value


def test_actual_protected_apply_ui_checkpoint_and_receipt_roundtrip() -> None:
    """Pass actual one-shot UI callback outputs through the public channel schemas."""
    from scripts.interop import certificate_dual_stack_ui as ui

    class ApplyClient:
        """Keep synthetic private plan and CSRF values inside the fake UI client."""

        def __init__(self) -> None:
            """Prepare an exact expanded review with private in-memory form values."""
            self.review = protected_review()
            self.review["plan_token"] = "private-plan-token-sentinel"
            self.private_markers = {"private-csrf-sentinel"}

        def read_json(self, path: str) -> dict[str, Any]:
            """Return the synthetic reviewed plan without any network access.

            Args:
                path: Selection-bound normal UI review endpoint.
            """
            assert path.startswith("/ui/management/appliance-apply/review?")
            return self.review

        def interfaces(self) -> Any:
            """Provide one private synthetic CSRF value for the submission."""
            return SimpleNamespace(csrf="private-csrf-sentinel")

        def request(self, path: str, form: Any = None) -> tuple[int, str, bytes]:
            """Return a matching one-shot accepted job receipt without network I/O.

            Args:
                path: Normal UI submission endpoint.
                form: Synthetic private CSRF and approved plan fields.
            """
            assert path == "/ui/management/appliance-apply"
            assert ("csrf", "private-csrf-sentinel") in form
            return 202, "", b'{"job_id":"job-123","status_url":"/tasks/job-123/status"}'

    checkpoints: list[dict[str, Any]] = []

    def checkpoint(stage: str, value: dict[str, Any]) -> None:
        """Capture the actual public Apply intent before the synthetic POST.

        Args:
            stage: UI checkpoint stage emitted before submission.
            value: Sanitized complete public Apply intent.
        """
        assert stage == "apply_intent"
        checkpoints.append(value)

    result = ui.submit_once(ApplyClient(), sorted(ui.PROTECTED), checkpoint)
    assert len(checkpoints) == 1
    assert round_trip(checkpoints[0]) == checkpoints[0]
    assert round_trip(result) == result
    assert "private-plan-token-sentinel" not in json.dumps(checkpoints[0])
    assert "private-csrf-sentinel" not in json.dumps([*checkpoints, result])


@pytest.mark.parametrize("mutation", ["selected_type", "nested_value"])
def test_protected_apply_rejects_invalid_typed_or_nested_review(mutation: str) -> None:
    """Reject an invalid selected boolean or nested arbitrary review value.

    Args:
        mutation: Review field to replace with an invalid representation.
    """
    review = protected_review()
    if mutation == "selected_type":
        review["units"][0]["selected"] = 1
    else:
        review["units"][0]["config_preview"] = {"unexpected": "nested"}
    value = action_payload(
        "test-only-protected-apply-intent", review=review,
        review_sha256=hashlib.sha256(public_bytes(review)).hexdigest(),
    )
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


@pytest.mark.parametrize("challenge", ["ascii canary / spaces", "0123456789abcdef"])
def test_public_canary_accepts_ascii_text_and_punctuation(challenge: str) -> None:
    """Round-trip nonempty printable ASCII canary strings without normalization.

    Args:
        challenge: Printable ASCII value used by the synthetic canary action.
    """
    value = payload(challenge)
    assert round_trip(value) == value


@pytest.mark.parametrize("challenge", ["", "café", "line\nbreak", "del\x7f"])
def test_public_canary_rejects_empty_non_ascii_or_control_text(challenge: str) -> None:
    """Reject empty, non-ASCII, or control-bearing public canary strings.

    Args:
        challenge: Invalid synthetic canary value.
    """
    with pytest.raises(GuestRefusal):
        channel.frame_public(payload(challenge), metadata(), set())


def retirement_payload(family: int, outcome: str, errno_value: int | None) -> dict[str, Any]:
    """Return retirement facts bound to one unchanged positive TLS observation.

    Args:
        family: Numeric IP family of the retired endpoint.
        outcome: Explicit connect failure or unknown observation result.
        errno_value: Kernel error code for explicit failure, otherwise ``None``.
    """
    active = tls_facts(family)
    retired_address = "192.0.2.11" if family == 4 else "fd00:1084:1077::11"
    return action_payload(
        "test-only-retired-tcp-observation", family=family, address=retired_address,
        port=443, outcome=outcome, errno=errno_value, elapsed_seconds=8.0,
        active_before=active, active_after=dict(active),
        requires_complete_native_absence_and_path_admission=True,
        automatic_retry_or_restore=False,
    )


@pytest.mark.parametrize(("family", "outcome", "errno_value"), [(4, "explicit_connect_failed", 111), (6, "explicit_connect_failed", 113), (6, "unknown", None)])
def test_retirement_observation_requires_unchanged_positive_tls_path_and_stays_test_only(
    family: int, outcome: str, errno_value: int | None,
) -> None:
    """Round-trip retirement only alongside complete, unchanged positive TLS facts.

    Args:
        family: Numeric IP family under observation.
        outcome: Explicit connect result or unknown result.
        errno_value: Synthetic errno or ``None`` for an unknown result.
    """
    value = retirement_payload(family, outcome, errno_value)
    result = round_trip(value)
    assert result == value
    assert result["formal_acceptance"] is False
    assert result["active_before"] == result["active_after"]
    if outcome == "unknown":
        assert result["elapsed_seconds"] == 8.0
        assert result["errno"] is None


def test_retirement_refuses_changed_positive_tls_facts() -> None:
    """Reject a retirement record whose positive before/after TLS path differs."""
    value = retirement_payload(4, "unknown", None)
    value["active_after"] = tls_facts(4)
    value["active_after"]["leaf_sha256"] = "3" * 64
    with pytest.raises(GuestRefusal):
        channel.frame_public(value, metadata(), set())


def inventory_payload(boot_id: str) -> dict[str, Any]:
    """Return a complete synthetic native observation with a selected boot ID.

    Args:
        boot_id: Public boot identifier to place in the raw inventory payload.
    """
    observed = {
        name: {"argv": list(command), "exit_code": 0, "raw": []}
        for name, command in channel.NATIVE_COMMANDS
    }
    return action_payload(
        "dual-stack-native-raw-observation", boot_id=boot_id, monotonic_ns=123456,
        observations=observed,
    )


def test_raw_inventory_boot_mismatch_refuses_in_framing_and_reconstruction() -> None:
    """Reject payload boot drift both before publication and after valid rehashing."""
    binding = metadata()
    other_boot = "fedcba98-7654-3210-fedc-ba9876543210"
    mismatch = inventory_payload(other_boot)
    with pytest.raises(GuestRefusal, match="^public_inventory_boot_changed$"):
        channel.frame_public(mismatch, binding, set())
    chunks, manifest = manual_wire_frame(mismatch, binding)
    with pytest.raises(GuestRefusal, match="^public_inventory_boot_changed$"):
        channel.reconstruct_public(manifest, chunks, manifest, binding, mode="raw-object")


def test_private_marker_refuses_before_framing() -> None:
    """Known in-memory session values are excluded from every public chunk."""
    secret = "private-synthetic-session-marker"
    with pytest.raises(GuestRefusal, match="^public_review_contains_private_material$"):
        channel.frame_public(payload(secret), metadata(), {secret})


def test_public_publication_is_marker_first_absence_checked_and_manifest_last(
    monkeypatch: Any, tmp_path: Path,
) -> None:
    """Mock filesystem/RPC boundaries and assert immutable publication ordering.

    Args:
        monkeypatch: Scoped replacement helper for all external boundaries.
        tmp_path: Test-owned placeholder path; the mocks prevent filesystem access.
    """
    events: list[tuple[str, Any]] = []
    rpc = install_publication_mocks(monkeypatch, events)
    result = channel.publish_public(
        payload(), metadata(), tmp_path, set(), root_identity=(7, 9), rpc=rpc,
    )
    rpc_events = [event for event in events if event[0] in {"absent", "set"}]
    assert [event[0] for event in events[:5]] == ["open_root", "open_marker", "marker_write", "fsync", "fsync"]
    marker = events[2][1][1]
    assert marker["before_public_variable_write"] is True
    assert marker["guest_original_identity"] == ["7", "11"]
    marker_open = next(event for event in events if event[0] == "open_marker")
    marker_flags = marker_open[1][1]
    assert marker_flags & channel.os.O_CREAT
    assert marker_flags & channel.os.O_EXCL
    assert not marker_flags & getattr(channel.os, "O_TRUNC", 0)
    absent_names = [value[0] for action, value in rpc_events if action == "absent"]
    set_names = [value[0] for action, value in rpc_events if action == "set"]
    assert len(absent_names) == len(set(absent_names))
    assert absent_names == set_names
    assert rpc_events[-1][1][0].endswith(".manifest")
    assert result == hashlib.sha256(public_bytes(payload())).hexdigest()
    assert not any(event[0] == "subprocess" for event in events)


def install_publication_mocks(
    monkeypatch: Any,
    events: list[tuple[str, Any]],
    *,
    actual_root_identity: tuple[int, int] = (7, 9),
    fail_marker_fsync: bool = False,
    fail_first_chunk: bool = False,
) -> Callable[[str, str, str | None, float], None]:
    """Replace every publication filesystem and RPC operation with recorders.

    Args:
        monkeypatch: Scoped replacement helper.
        events: Ordered synthetic operation trace to append to.
        actual_root_identity: Identity returned for the synthetic artifact root.
        fail_marker_fsync: Whether syncing the exclusive marker raises an error.
        fail_first_chunk: Whether the first public chunk write raises an error.
    """
    monkeypatch.setattr(channel.sys, "platform", "linux")
    monkeypatch.setattr(channel.os, "O_DIRECTORY", getattr(channel.os, "O_DIRECTORY", 0), raising=False)
    monkeypatch.setattr(channel.os, "O_NOFOLLOW", getattr(channel.os, "O_NOFOLLOW", 0), raising=False)

    def fake_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        """Return synthetic descriptors and retain exact open flags.

        Args:
            path: Synthetic root or marker name passed by the publisher.
            flags: Open flags, including exclusive creation for the marker.
            *args: Additional positional open options, if any.
            **kwargs: Directory-relative marker open options, if any.
        """
        del args
        fd = 10 if "dir_fd" not in kwargs else 11
        events.append(("open_root" if fd == 10 else "open_marker", (path, flags, kwargs)))
        return fd

    monkeypatch.setattr(channel.os, "open", fake_open)

    def fake_fstat(fd: int) -> SimpleNamespace:
        """Return the pinned root or synthetic exclusive-marker identity.

        Args:
            fd: Synthetic descriptor selected by the publication code.
        """
        identity = actual_root_identity if fd == 10 else (7, 11)
        return SimpleNamespace(st_dev=identity[0], st_ino=identity[1])

    def fake_write(fd: int, value: bytes) -> int:
        """Record the public marker bytes without touching the filesystem.

        Args:
            fd: Synthetic marker descriptor.
            value: Public marker bytes written by the publisher.
        """
        events.append(("marker_write", (fd, json.loads(value))))
        return len(value)

    def fake_fsync(fd: int) -> None:
        """Record sync ordering and optionally fail the first marker sync.

        Args:
            fd: Synthetic marker or directory descriptor.
        """
        events.append(("fsync", fd))
        if fail_marker_fsync and fd == 11:
            raise OSError("synthetic marker fsync failure")

    def fake_close(fd: int) -> None:
        """Record closure of a synthetic descriptor.

        Args:
            fd: Synthetic marker or directory descriptor.
        """
        events.append(("close", fd))

    def fake_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        """Record any attempted deletion of the original marker.

        Args:
            path: Synthetic path passed to the deletion function.
            *args: Additional positional deletion options, if any.
            **kwargs: Additional keyword deletion options, if any.
        """
        events.append(("unlink", (path, args, kwargs)))

    def fake_remove(path: Any, *args: Any, **kwargs: Any) -> None:
        """Record any attempted removal of the original marker.

        Args:
            path: Synthetic path passed to the removal function.
            *args: Additional positional removal options, if any.
            **kwargs: Additional keyword removal options, if any.
        """
        events.append(("remove", (path, args, kwargs)))

    def fake_rpc(action: str, name: str, value: str | None, remaining: float) -> None:
        """Record synthetic guestinfo RPC calls and optionally fail a chunk write.

        Args:
            action: Fixed absence-check or public-value set action.
            name: Publisher-constructed immutable stage key.
            value: Public envelope for a set, otherwise ``None``.
            remaining: Publisher's remaining monotonic time budget.
        """
        del remaining
        events.append((action, (name, value)))
        if fail_first_chunk and action == "set" and ".part-" in name:
            raise OSError("synthetic chunk set failure")

    monkeypatch.setattr(channel.os, "fstat", fake_fstat)
    monkeypatch.setattr(channel.os, "write", fake_write)
    monkeypatch.setattr(channel.os, "fsync", fake_fsync)
    monkeypatch.setattr(channel.os, "close", fake_close)
    monkeypatch.setattr(channel.os, "unlink", fake_unlink)
    monkeypatch.setattr(channel.os, "remove", fake_remove)
    return fake_rpc


def test_root_identity_drift_prevents_marker_creation_and_rpc(
    monkeypatch: Any, tmp_path: Path,
) -> None:
    """Refuse a replaced artifact root before marker creation or guestinfo access.

    Args:
        monkeypatch: Scoped replacement helper for all external boundaries.
        tmp_path: Test-owned placeholder path; the mocks prevent filesystem access.
    """
    events: list[tuple[str, Any]] = []
    rpc = install_publication_mocks(monkeypatch, events, actual_root_identity=(7, 99))
    with pytest.raises(GuestRefusal, match="^original_guest_artifact_root_required$"):
        channel.publish_public(
            payload(), metadata(), tmp_path, set(), root_identity=(7, 9), rpc=rpc,
        )
    assert [event[0] for event in events] == ["open_root", "close"]
    assert not any(event[0] in {"open_marker", "absent", "set", "unlink", "remove"} for event in events)


def test_marker_fsync_failure_prevents_any_rpc(
    monkeypatch: Any, tmp_path: Path,
) -> None:
    """Keep an unsynced original marker and refuse before absence checks or writes.

    Args:
        monkeypatch: Scoped replacement helper for all external boundaries.
        tmp_path: Test-owned placeholder path; the mocks prevent filesystem access.
    """
    events: list[tuple[str, Any]] = []
    rpc = install_publication_mocks(monkeypatch, events, fail_marker_fsync=True)
    with pytest.raises(OSError, match="^synthetic marker fsync failure$"):
        channel.publish_public(
            payload(), metadata(), tmp_path, set(), root_identity=(7, 9), rpc=rpc,
        )
    assert not any(event[0] in {"absent", "set", "unlink", "remove"} for event in events)
    assert any(event[0] == "marker_write" for event in events)


def test_chunk_write_failure_never_publishes_manifest_or_unlinks_marker(
    monkeypatch: Any, tmp_path: Path,
) -> None:
    """Retain the original marker and partial chunk trace without publishing manifest.

    Args:
        monkeypatch: Scoped replacement helper for all external boundaries.
        tmp_path: Test-owned placeholder path; the mocks prevent filesystem access.
    """
    events: list[tuple[str, Any]] = []
    rpc = install_publication_mocks(monkeypatch, events, fail_first_chunk=True)
    value = payload("multiple chunks " * 120)
    with pytest.raises(OSError, match="^synthetic chunk set failure$"):
        channel.publish_public(
            value, metadata(), tmp_path, set(), root_identity=(7, 9), rpc=rpc,
        )
    marker_open = next(event for event in events if event[0] == "open_marker")
    marker_flags = marker_open[1][1]
    assert marker_flags & channel.os.O_CREAT
    assert marker_flags & channel.os.O_EXCL
    assert not marker_flags & getattr(channel.os, "O_TRUNC", 0)
    marker = next(event[1][1] for event in events if event[0] == "marker_write")
    assert marker["before_public_variable_write"] is True
    set_names = [value[0] for action, value in events if action == "set"]
    assert len(set_names) == 1 and ".part-000" in set_names[0]
    assert all(not name.endswith(".manifest") for name in set_names)
    assert not any(event[0] in {"unlink", "remove"} for event in events)
