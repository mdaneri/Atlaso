"""Removal reads remain bound to the appliance after native schedule deletion."""

from copy import deepcopy

import pytest

from atlaso.app.services import vcf_backup_removal as removal
from atlaso.app.services.vcf_certificate_remote import Credentials


@pytest.mark.parametrize("case", ["absent", "other-schedule", "overlapping-destination", "ambiguous-destination", "replaced-appliance", "running-backup"])
def test_vcenter_removal_checks_appliance_tasks_and_every_remaining_destination(monkeypatch, case):
    """Permit deleting a named schedule without relaxing file or appliance ownership.

    Args:
        monkeypatch: Fixture replacing credential resolution and native reads.
        case: Removed scheduler, other destination, identity change, or active task.
    """
    instance = "7b32c7b4-127b-4b26-8d53-c9cf4fd50482"
    source = {"source_id": "source", "kind": "vcenter", "inventory": {
        "identity": "vcenter:" + instance, "version": "9.1.1", "service": None,
        "groups": [{"id": "daily", "native_identity": {"instance_uuid": instance}}]}}
    group = {"source_id": "source", "native_group_id": "daily", "checkpoint": "verified",
             "receiver_directory": "/backups/vcf/recorded", "configuration_reference": {},
             "backup_reference": {"reference": {"kind": "vcenter", "group_id": "daily",
                 "component_ids": ["vcenter"], "started_at": "2026-11-02T22:00:00Z", "native_task_id": "backup-1"}}}
    latest = {"identity": "vcenter:" + instance, "version": "9.1.1", "service": None,
              "groups": [{"id": "atlaso-vcf-backup", "native_identity": {"instance_uuid": instance}, "current": {}}]}
    if case in {"other-schedule", "overlapping-destination", "ambiguous-destination"}:
        latest["groups"].append({"id": "replacement", "native_identity": {"instance_uuid": instance},
            "current": {"host": "backup.example.test", "directory": "/backups/vcf/recorded/child" if case == "overlapping-destination" else "/other"}})
        if case == "ambiguous-destination":
            latest["groups"][-1]["current"]["directory"] = "/other/../backups/vcf/recorded"
    if case == "replaced-appliance":
        latest["identity"] = "vcenter:replacement"
    calls = []

    class Native:
        def __init__(self, *_args):
            """Accept only fixture construction inputs.

            Args:
                *_args: Pinned source and request-local test credential.
            """

        def __enter__(self):
            """Expose the read-only fixture adapter."""
            return self

        def __exit__(self, *_args):
            """Finish the context without any external mutation.

            Args:
                *_args: Context-manager completion state.
            """

        def login(self):
            """Simulate authentication to the pinned appliance."""

        def discover(self):
            """Return all current schedules on the same native instance."""
            return deepcopy(latest)

        def vcenter_removal_task_status(self, scheduler, reference):
            """Read the recorded job independently of the deleted scheduler.

            Args:
                scheduler: Original schedule identity.
                reference: Original native backup task binding.
            """
            calls.append((scheduler, reference))
            assert scheduler == "daily" and reference["native_task_id"] == "backup-1"
            return {"state": "running" if case == "running-backup" else "succeeded"}

    monkeypatch.setattr(removal, "NativeBackup", Native)
    monkeypatch.setattr(removal.workflow, "_recovery_source_inputs", lambda *_args: {"source": (source, Credentials("admin", "fixture"))})
    if case in {"overlapping-destination", "ambiguous-destination", "replaced-appliance", "running-backup"}:
        with pytest.raises(removal.workflow.BackupOperationError):
            removal._native_idle(None, {"plan": [group]}, {})
    else:
        removal._native_idle(None, {"plan": [group]}, {})
    assert len(calls) == (0 if case in {"overlapping-destination", "ambiguous-destination", "replaced-appliance"} else 1)
