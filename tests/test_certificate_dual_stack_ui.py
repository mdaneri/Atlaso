"""Synthetic transaction checks; these do not execute or admit a native test."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.interop import certificate_dual_stack_ui as ui  # noqa: E402 - Local interop module.
from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes  # noqa: E402 - Local interop module.


def review_fixture() -> dict[str, Any]:
    """Provide a complete synthetic server-expanded five-unit review."""
    units = []
    for name in sorted(ui.PROTECTED):
        row = dict.fromkeys(ui.UNIT_KEYS)
        row.update(
            id=name, label=name, selected=True, changed=True, valid=True,
            has_baseline=True, format_volumes=[], config_preview="public preview",
            config_diff="public diff", snapshot_hash="a" * 64,
            page_url="/ui/management/physical-interfaces", config_path="/etc/atlaso/public.json",
            summary=["public unit summary"], validation_errors=[], validation_warnings=[],
            connection_warnings=[], network_candidate_validation_errors=[],
            dependency_reason="", required_dependency=False, forces_network_selection=False,
            forces_wan_selection=False, requires_dns_selection=False, requires_network_selection=False,
        )
        units.append(row)
    return {
        "units": units, "pending_count": 5, "execution_count": 5,
        "requested_units": sorted(ui.PROTECTED), "plan_token": "private-plan-token-sentinel",
        "plan_error": "", "initial_apply_required": False, "active_task": None,
    }


class FakeClient:
    """Keep synthetic private values inside the fake normal-UI session."""

    def __init__(self, review: dict[str, Any] | None = None) -> None:
        """Store a synthetic review and request trace.

        Args:
            review: Optional synthetic server review override.
        """
        self.review = review_fixture() if review is None else review
        self.private_markers = {"private-admin-sentinel", "private-csrf-sentinel"}
        self.requests: list[tuple[str, Any]] = []
        self.post_result: tuple[int, str, bytes] | Exception = (
            202, "", b'{"job_id":"job-123","status_url":"/tasks/job-123/status"}'
        )

    def read_json(self, path: str) -> dict[str, Any]:
        """Return only the selected synthetic review, without network access.

        Args:
            path: Exact selection-specific review path.
        """
        self.requests.append((path, None))
        return copy.deepcopy(self.review)

    def interfaces(self) -> Any:
        """Return a synthetic private CSRF token."""
        return SimpleNamespace(csrf="private-csrf-sentinel")

    def request(self, path: str, form: Any = None) -> tuple[int, str, bytes]:
        """Record one synthetic POST and return its explicit outcome.

        Args:
            path: Normal UI endpoint.
            form: Private successful form values held in the fake only.
        """
        self.requests.append((path, form))
        if isinstance(self.post_result, Exception):
            raise self.post_result
        return self.post_result


def test_job_status_is_unavailable_before_original_receipt_acknowledgement() -> None:
    """Never poll when the controller has not durably acknowledged the original job."""
    client = FakeClient()
    receipt = ui.submit_once(client, sorted(ui.PROTECTED), lambda _stage, _value: None)
    requests_before = list(client.requests)
    with pytest.raises(GuestRefusal, match="^original_durable_job_receipt_required$"):
        ui.read_apply_status_once(client, receipt, durable_receipt_sha256="0" * 64)
    assert client.requests == requests_before


@pytest.mark.parametrize("status", ["pending", "running", "succeeded", "failed", "cancelled"])
def test_job_status_projects_only_original_job_identity_without_followup(status: str) -> None:
    """A single status read never exports the full task result or submits restoration.

    Args:
        status: Explicit synthetic task state, including failure and cancellation.
    """
    client = FakeClient()
    receipt = ui.submit_once(client, sorted(ui.PROTECTED), lambda _stage, _value: None)
    digest = hashlib.sha256(public_bytes(receipt)).hexdigest()
    client.review = {"task": {"id": "job-123", "type": "appliance-apply", "status": status,
                              "result": {"arbitrary": "private-synthetic-not-exported"}}}
    before = len(client.requests)
    result = ui.read_apply_status_once(client, receipt, durable_receipt_sha256=digest)
    assert client.requests[before:] == [("/tasks/job-123/status", None)]
    assert result["status"] == status and result["original_job_receipt_sha256"] == digest
    assert result["formal_acceptance"] is False
    assert "private-synthetic-not-exported" not in json.dumps(result)


@pytest.mark.parametrize("change", [{"id": "foreign-job"}, {"type": "foreign-type"},
                                    {"status": "unknown"}, {"status": "queued"}, {"status": []}])
def test_status_drift_does_not_adopt_another_job_or_unknown_outcome(change: dict[str, Any]) -> None:
    """Reject identity and state drift without resubmission or automatic restoration.

    Args:
        change: Synthetic changed job identity or unknown status.
    """
    client = FakeClient()
    receipt = ui.submit_once(client, sorted(ui.PROTECTED), lambda _stage, _value: None)
    client.review = {"task": {"id": "job-123", "type": "appliance-apply", "status": "running", **change}}
    with pytest.raises(GuestRefusal, match="^original_apply_task_identity_changed$"):
        ui.read_apply_status_once(client, receipt,
                                  durable_receipt_sha256=hashlib.sha256(public_bytes(receipt)).hexdigest())
    assert sum(form is not None for _, form in client.requests) == 1


def test_pending_job_matches_application_enum_and_public_channel() -> None:
    """Reconcile a real pending Apply status before the worker has started it."""
    from atlaso.app.models import JobStatus

    client = FakeClient()
    receipt = ui.submit_once(client, sorted(ui.PROTECTED), lambda _stage, _value: None)
    client.review = {"task": {"id": receipt["job_id"], "type": "appliance-apply",
                              "status": JobStatus.PENDING.value}}
    before = len(client.requests)
    result = ui.read_apply_status_once(client, receipt,
                                      durable_receipt_sha256=hashlib.sha256(public_bytes(receipt)).hexdigest())
    assert result["status"] == "pending"
    assert client.requests[before:] == [("/tasks/job-123/status", None)]
    assert_public_channel_roundtrip(result)


def test_checkpoint_precedes_the_single_post_and_no_poll_follows() -> None:
    """Require durable-intent acknowledgement before POST and receipt before polling."""
    client = FakeClient()
    checkpoints = []

    def checkpoint(stage: str, value: dict[str, Any]) -> None:
        """Verify the original public intent boundary before fake submission.

        Args:
            stage: Public checkpoint kind.
            value: Public selected execution plan.
        """
        assert stage == "apply_intent"
        assert not any(path == "/ui/management/appliance-apply" for path, _ in client.requests)
        serialized = json.dumps(value)
        assert "private-plan-token-sentinel" not in serialized
        assert "private-csrf-sentinel" not in serialized
        assert "private-admin-sentinel" not in serialized
        assert len(value["review"]["units"]) == 5
        checkpoints.append(value)

    result = ui.submit_once(client, sorted(ui.PROTECTED), checkpoint)
    posts = [(path, form) for path, form in client.requests if form is not None]
    assert len(posts) == 1
    assert posts[0][0] == "/ui/management/appliance-apply"
    assert ("reviewed_plan", "private-plan-token-sentinel") in posts[0][1]
    assert ("csrf", "private-csrf-sentinel") in posts[0][1]
    assert len(checkpoints) == 1
    assert result["job_id"] == "job-123"
    assert result["automatic_poll_or_restore"] is False
    assert result["formal_acceptance"] is False
    assert not any("/tasks/" in path for path, _ in client.requests)


def test_checkpoint_failure_prohibits_post() -> None:
    """A controller unable to durably retain intent must not submit."""
    client = FakeClient()

    def failed_checkpoint(_stage: str, _value: dict[str, Any]) -> None:
        """Model an original host intent publication failure.

        Args:
            _stage: Public checkpoint stage.
            _value: Public intent not durably preserved.
        """
        raise OSError("synthetic original journal failure")

    with pytest.raises(OSError, match="synthetic original journal failure"):
        ui.submit_once(client, sorted(ui.PROTECTED), failed_checkpoint)
    assert not any(path == "/ui/management/appliance-apply" for path, _ in client.requests)


@pytest.mark.parametrize(
    "outcome",
    [TimeoutError(), (409, "", b'{"detail":"changed"}'),
     (202, "", b"not-json"), (202, "", b'{"job_id":"different","status_url":"/tasks/other/status"}')],
)
def test_unknown_submit_outcome_never_replays_or_restores(outcome: Any) -> None:
    """A lost, invalid or non-202 outcome requires a separate read-only reconciliation.

    Args:
        outcome: Synthetic transport or protocol outcome.
    """
    client = FakeClient()
    client.post_result = outcome
    with pytest.raises(GuestRefusal, match="^apply_outcome_unknown_read_only_reconcile$"):
        ui.submit_once(client, sorted(ui.PROTECTED), lambda _stage, _value: None)
    assert len([path for path, _ in client.requests if path == "/ui/management/appliance-apply"]) == 1
    assert not any("restore" in path or "/tasks/" in path for path, _ in client.requests)


@pytest.mark.parametrize("change", ["missing", "unknown", "duplicate", "initial", "active", "format", "invalid", "unrelated"])
def test_incomplete_or_expanded_scope_refuses_before_checkpoint(change: str) -> None:
    """Refuse incomplete protected handoff, new semantics or unrelated pending work.

    Args:
        change: Synthetic unsafe review variation.
    """
    review = review_fixture()
    roots = sorted(ui.PROTECTED)
    if change == "missing":
        roots.remove("ca")
    elif change == "unknown":
        review["new_semantics"] = True
    elif change == "duplicate":
        review["units"].append(copy.deepcopy(review["units"][0]))
    elif change == "initial":
        review["initial_apply_required"] = True
    elif change == "active":
        review["active_task"] = {"id": "another-job"}
    elif change == "format":
        review["units"][0]["format_volumes"] = [{"id": 1}]
    elif change == "invalid":
        review["units"][0]["valid"] = False
    elif change == "unrelated":
        review["units"][0]["id"] = "ntpd"
    client = FakeClient(review)
    with pytest.raises(GuestRefusal):
        ui.submit_once(client, roots, lambda *_args: pytest.fail("Unexpected checkpoint"))
    assert not any(path == "/ui/management/appliance-apply" for path, _ in client.requests)


def test_server_root_order_is_retained_without_changing_consent() -> None:
    """Accept the same exact root set while preserving the returned server order."""
    review = review_fixture()
    review["requested_units"].reverse()
    client = FakeClient(review)
    public, fields = ui.prepare_review(client, sorted(ui.PROTECTED))
    assert public["requested_units"] == review["requested_units"]
    assert [value for key, value in fields if key == "requested_units"] == review["requested_units"]


@pytest.mark.parametrize("secret", ["private-admin-sentinel", "private-csrf-sentinel", "private-plan-token-sentinel", "-----BEGIN PRIVATE KEY-----", "https://user:password@example.test/"])
def test_selected_preview_cannot_publish_private_material(secret: str) -> None:
    """Never place a private key, credential URL or known session value in a checkpoint.

    Args:
        secret: Public synthetic marker for forbidden material.
    """
    review = review_fixture()
    review["units"][0]["config_preview"] = secret
    client = FakeClient(review)
    with pytest.raises(GuestRefusal, match="^public_review_contains_private_material$"):
        ui.submit_once(client, sorted(ui.PROTECTED), lambda *_args: pytest.fail("Unexpected checkpoint"))
    assert not any(path == "/ui/management/appliance-apply" for path, _ in client.requests)


def test_unselected_configuration_is_not_exported_as_public_evidence() -> None:
    """Retain unselected metadata while excluding unrelated configuration content."""
    review = review_fixture()
    row = copy.deepcopy(review["units"][0])
    row.update(id="ntpd", selected=False, changed=False, config_preview="private-unrelated-sentinel")
    review["units"].append(row)
    client = FakeClient(review)
    public, _ = ui.prepare_review(client, sorted(ui.PROTECTED))
    assert "private-unrelated-sentinel" not in json.dumps(public)
    assert public["units"][-1] == {"id": "ntpd", "label": row["label"], "changed": False, "valid": True, "selected": False}


class SaveClient(FakeClient):
    """Expose one fixed synthetic interface for normal desired-state Save tests."""

    def __init__(self) -> None:
        """Prepare an original synthetic IPv4-only desired record."""
        super().__init__()
        self.row: dict[str, Any] = dict.fromkeys(ui.FIELDS, "")
        self.row.update(
            id=7, name="eth0", mac_address="02:00:00:00:00:10", admin_up=True,
            role="management", mode="access", ipv4_method="static",
            ip_cidr="192.0.2.10/24", ipv6_enabled=False,
            check_duplicate_ip_addresses=True, access_management_ui_enabled=False,
        )
        self.desired = {**ui.interface_fields(self.row), "ipv6_enabled": True, "ipv6_cidr": "fd00:1084:1077::10/64"}
        self.save_error: Exception | None = None

    def interfaces(self) -> Any:
        """Return the original desired row and private synthetic CSRF."""
        return SimpleNamespace(csrf="private-csrf-sentinel", rows=[copy.deepcopy(self.row)])

    def request(self, path: str, form: Any = None) -> tuple[int, str, bytes]:
        """Record one desired-state Save without any Apply or native mutation.

        Args:
            path: Existing normal-UI Save endpoint.
            form: Private CSRF plus public desired values.
        """
        self.requests.append((path, form))
        if self.save_error:
            raise self.save_error
        self.row.update(self.desired)
        return 303, "/ui/management/physical-interfaces", b""


def test_save_keeps_the_other_family_and_never_submits_apply() -> None:
    """Save a complete approved record only after its original public intent."""
    client = SaveClient()
    before = ui.interface_fields(client.row)
    intents = []

    def checkpoint(stage: str, value: dict[str, Any]) -> None:
        """Assert the controller journal boundary before Save.

        Args:
            stage: Public Save intent stage.
            value: Exact public before/after fields.
        """
        assert stage == "save_intent" and not client.requests
        assert value["before"] == before and value["after"] == client.desired
        intents.append(value)

    result = ui.save_interface(client, "eth0", "02:00:00:00:00:10", before, client.desired, checkpoint)
    assert result["verified"] is True and len(intents) == 1
    assert len(client.requests) == 1
    assert client.requests[0][0] == "/ui/management/physical-interfaces/7/edit"
    form = dict(client.requests[0][1])
    assert form["ip_cidr"] == "192.0.2.10/24"
    assert form["ipv6_cidr"] == "fd00:1084:1077::10/64"
    assert form["csrf"] == "private-csrf-sentinel"
    assert "csrf" not in json.dumps(intents)
    assert not any("appliance-apply" in path for path, _ in client.requests)
    for value in [*intents, result]:
        assert_public_channel_roundtrip(value)


def assert_public_channel_roundtrip(value: dict[str, Any]) -> None:
    """Verify the actual callback schema crosses the unchanged public framing boundary.

    Args:
        value: Actual synthetic normal-UI checkpoint or receipt.
    """
    from scripts.interop.certificate_dual_stack_channel import (
        frame_public,
        reconstruct_public,
    )

    metadata = {"source_commit": "a" * 40, "bundle_sha256": "b" * 64,
                "resource_receipt_sha256": "c" * 64, "persistent_vm_identity_sha256": "d" * 64,
                "boot_id": "01234567-89ab-cdef-0123-456789abcdef", "run_id": "e" * 32,
                "stage": "synthetic-ui-checkpoint"}
    chunks, manifest = frame_public(value, metadata, set())
    assert reconstruct_public(manifest, chunks, manifest, metadata, mode="raw-object") == value


def test_unused_baseline_and_exact_restoration_cross_the_public_channel() -> None:
    """Retain the normal UI's unused mode during activation and reviewed restoration."""
    client = SaveClient()
    client.row.update(role="unused", mode="unused")
    original = ui.interface_fields(client.row)
    checkpoints = []
    active = ui.save_interface(client, "eth0", "02:00:00:00:00:10", original, client.desired,
                               lambda _stage, value: checkpoints.append(value))
    client.desired = original
    restored = ui.save_interface(client, "eth0", "02:00:00:00:00:10", active["after"], original,
                                 lambda _stage, value: checkpoints.append(value))
    for value in [*checkpoints, active, restored]:
        assert_public_channel_roundtrip(value)
    assert restored["after"] == original


def test_changed_save_baseline_refuses_before_post() -> None:
    """Never overwrite a concurrent desired-state edit."""
    client = SaveClient()
    before = ui.interface_fields(client.row)
    client.row["mtu"] = 9000
    with pytest.raises(GuestRefusal, match="^desired_interface_baseline_changed$"):
        ui.save_interface(client, "eth0", "02:00:00:00:00:10", before, client.desired, lambda *_args: pytest.fail("Unexpected checkpoint"))
    assert not client.requests


def test_lost_save_response_has_no_retry_or_apply() -> None:
    """Lost Save completion requires read-only reconciliation of desired state."""
    client = SaveClient()
    client.save_error = TimeoutError()
    before = ui.interface_fields(client.row)
    with pytest.raises(GuestRefusal, match="^save_outcome_unknown_read_only_reconcile$"):
        ui.save_interface(client, "eth0", "02:00:00:00:00:10", before, client.desired, lambda *_args: None)
    assert len(client.requests) == 1


def test_job_receipt_cannot_publish_a_private_session_value() -> None:
    """A malformed server result must not turn a known secret into a public job ID."""
    client = FakeClient()
    client.post_result = (202, "", b'{"job_id":"private-admin-sentinel","status_url":"/tasks/private-admin-sentinel/status"}')
    with pytest.raises(GuestRefusal, match="^public_review_contains_private_material$"):
        ui.submit_once(client, sorted(ui.PROTECTED), lambda *_args: None)
    assert len([path for path, _ in client.requests if path == "/ui/management/appliance-apply"]) == 1
