"""Focused checks for the receipt-bound NTP fixture host topology."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_topology as topology  # noqa: E402 - Local interop entrypoint.


@pytest.fixture
def admitted_topology(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict:
    """Provide two running VMs whose only private membership matches receipts.

    Args:
        monkeypatch: Patcher for topology readers and host-state probes.
        tmp_path: Temporary directory holding synthetic VMX and receipt paths.
    """
    appliance = tmp_path / "appliance.vmx"
    peer = tmp_path / "peer.vmx"
    appliance.touch()
    peer.touch()
    segment_id = "00 11 22 33 44 55 66 77-88 99 aa bb cc dd ee ff"
    host = {
        "host_administrator_trusted": True,
        "vmrun_path": str(tmp_path / "vmrun.exe"),
        "inventory_path": str(tmp_path / "inventory.vmls"),
        "preferences_path": str(tmp_path / "preferences.ini"),
        "segment_name": "ntp-private",
        "segment_id": segment_id,
        "segment_receipt": {"path": str(tmp_path / "segment.json"), "sha256": "a" * 64},
        "appliance_vmx": str(appliance),
        "peer_vmx": str(peer),
        "appliance_management_mac": "00:50:56:aa:00:01",
        "appliance_service_mac": "00:50:56:aa:00:02",
        "peer_private_mac": "00:50:56:aa:00:03",
        "peer_control_mac": "00:50:56:aa:00:04",
        "control_network": "VMnet8",
    }
    plan = {
        "task_id": "task-ntp-fixture",
        "repository": "mdaneri/Atlaso",
        "pr": 1121,
        "source_commit": "1" * 40,
        "resource_source_commit": "1" * 40,
        "trusted_host": host,
    }
    appliance_vmx = [
        {"index": 0, "present": "true", "startconnected": "true", "connectiontype": "pvn",
         "pvnid": segment_id, "address": "00:50:56:aa:00:01"},
        {"index": 1, "present": "true", "startconnected": "true", "connectiontype": "pvn",
         "pvnid": segment_id, "address": "00:50:56:aa:00:02"},
    ]
    peer_vmx = [
        {"index": 0, "present": "true", "startconnected": "true", "connectiontype": "custom",
         "vnet": "VMnet8", "address": "00:50:56:aa:00:04"},
        {"index": 1, "present": "true", "startconnected": "true", "connectiontype": "pvn",
         "pvnid": segment_id, "address": "00:50:56:aa:00:03"},
    ]
    vmx_by_path = {str(appliance): appliance_vmx, str(peer): peer_vmx}
    monkeypatch.setattr(topology, "_ordinary_file", lambda path, reason: (Path(path), b"admitted"))
    monkeypatch.setattr(topology, "bound_json", lambda _reference: {
        "schema": 1, "name": "ntp-private", "pvn_id": segment_id,
        "task_id": plan["task_id"], "repository": plan["repository"], "pr": plan["pr"],
        "source_commit": plan["resource_source_commit"],
    })
    monkeypatch.setattr(topology, "_parse_segments", lambda _payload: {"ntp-private": segment_id})
    monkeypatch.setattr(topology, "_parse_inventory", lambda _payload: ([appliance, peer], 0, 0))
    monkeypatch.setattr(topology, "_run_vmrun", lambda _executable: ([appliance, peer], ""))
    monkeypatch.setattr(topology, "_read_vmx", lambda path: vmx_by_path[str(path)])
    return {"plan": plan, "host": host, "appliance": appliance, "peer": peer,
            "segment_id": segment_id, "vmx": vmx_by_path}


def test_inspect_topology_accepts_exact_two_private_appliance_nics_and_split_peer(
    admitted_topology: dict,
) -> None:
    """Accept the exact dual-subnet appliance LAN and separate peer control leg.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
    """
    result = topology.inspect_topology(admitted_topology["plan"])

    assert result["kind"] == "ntp-cold-start-trusted-host-topology"
    assert result["segment_id"] == admitted_topology["segment_id"]
    assert result["running_vm_count"] == 2
    assert datetime.fromisoformat(result["observed_utc"]).utcoffset() == timedelta(0)
    adapter_rows = list(result["lab_adapters"].values())
    assert sorted(len(rows) for rows in adapter_rows) == [2, 2]
    assert any(rows[0]["network"] == "VMnet8" for rows in adapter_rows)


def test_inspect_topology_rejects_untrusted_host(admitted_topology: dict) -> None:
    """Reject a plan that lacks explicit administrator trust.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
    """
    admitted_topology["host"]["host_administrator_trusted"] = False

    with pytest.raises(topology.Refusal, match="ntp_topology_explicit_trust_required"):
        topology.inspect_topology(admitted_topology["plan"])


def test_inspect_topology_rejects_stopped_vm(admitted_topology: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject topology evidence when one original VM is stopped.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher used to report only one running original VM.
    """
    monkeypatch.setattr(topology, "_run_vmrun", lambda _executable: ([admitted_topology["peer"]], ""))

    with pytest.raises(topology.Refusal, match="ntp_topology_original_vms_not_running"):
        topology.inspect_topology(admitted_topology["plan"])


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        ("third_member", "ntp_topology_private_membership_changed"),
        ("missing_mac", "ntp_topology_adapter_binding_changed"),
        ("wrong_mac", "ntp_topology_adapter_binding_changed"),
        ("extra_connected", "ntp_topology_adapter_binding_changed"),
    ],
    ids=["third-private-member", "missing-mac", "wrong-mac", "extra-connected-adapter"],
)
def test_inspect_topology_rejects_changed_adapter_membership(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch, mutate: str, reason: str,
) -> None:
    """Refuse added fixture members and any unexpected or ambiguous VM adapter.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher for inventory, adapter, and host readers.
        mutate: Adapter or private-membership change to introduce.
        reason: Expected stable refusal category for the introduced change.
    """
    appliance = admitted_topology["appliance"]
    peer = admitted_topology["peer"]
    rows = admitted_topology["vmx"][str(appliance)]
    if mutate == "third_member":
        third = appliance.parent / "third.vmx"
        third.touch()
        monkeypatch.setattr(topology, "_parse_inventory", lambda _payload: ([appliance, peer, third], 0, 0))
        monkeypatch.setattr(topology, "_run_vmrun", lambda _exe: ([appliance, peer, third], ""))
        monkeypatch.setattr(topology, "_read_vmx", lambda path: (
            rows if Path(path) == appliance else admitted_topology["vmx"][str(peer)]
        ) if Path(path) in {appliance, peer} else [
            {"index": 0, "present": "true", "startconnected": "true", "connectiontype": "pvn",
             "pvnid": admitted_topology["segment_id"], "address": "00:50:56:aa:00:05"},
        ])
    elif mutate == "missing_mac":
        rows[0].pop("address")
    elif mutate == "wrong_mac":
        rows[0]["address"] = "00:50:56:aa:ff:ff"
    else:
        rows.append({"index": 2, "present": "true", "startconnected": "true", "connectiontype": "custom",
                     "vnet": "VMnet8", "address": "00:50:56:aa:00:09"})

    with pytest.raises(topology.Refusal, match=reason):
        topology.inspect_topology(admitted_topology["plan"])


@pytest.mark.parametrize("change", ["segment_receipt", "segment_source"], ids=["receipt-binding", "source-binding"])
def test_inspect_topology_rejects_changed_original_lan_binding(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Require the current VMware segment to match the original source-bound receipt.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher for receipt or current segment evidence.
        change: Original LAN binding component to alter.
    """
    if change == "segment_receipt":
        monkeypatch.setattr(topology, "bound_json", lambda _reference: {"schema": 1, "name": "other"})
    else:
        monkeypatch.setattr(topology, "_parse_segments", lambda _payload: {"ntp-private": "changed"})

    with pytest.raises(topology.Refusal, match="ntp_topology_original_lan_changed"):
        topology.inspect_topology(admitted_topology["plan"])


def test_watched_topology_keeps_a_detected_change_sticky(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A detected MAC change remains a failure after the adapter is restored.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher used to control topology readers and the clock.
    """
    with pytest.raises(topology.Refusal, match="ntp_topology_observer_unverified"):
        with topology.watched_topology(admitted_topology["plan"]) as (_original, check):
            row = admitted_topology["vmx"][str(admitted_topology["appliance"])][0]
            original_mac = row["address"]
            row["address"] = "00:50:56:aa:ff:fe"
            with pytest.raises(topology.Refusal, match="ntp_topology_changed"):
                check()
            row["address"] = original_mac
            with pytest.raises(topology.Refusal, match="ntp_topology_changed"):
                check()


def test_watched_topology_records_utc_samples_without_treating_time_as_drift(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stable topology hashes survive changing sample timestamps and retain bounded evidence.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher used to substitute deterministic UTC samples.
    """
    instants = iter(datetime(2026, 11, 6, 12, tzinfo=timezone.utc) + timedelta(seconds=i) for i in range(3))

    class Clock:
        @staticmethod
        def now(_timezone: object) -> datetime:
            """Return the next deterministic sample time.

            Args:
                _timezone: Time zone requested by the topology observer.
            """
            return next(instants)

    monkeypatch.setattr(topology, "datetime", Clock)
    with topology.watched_topology(admitted_topology["plan"]) as (snapshot, check):
        original_hash = snapshot["sha256"]
        check()

    assert snapshot["sha256"] == original_hash
    assert len(snapshot["observations"]) == 3
    assert [row["topology_sha256"] for row in snapshot["observations"]] == [original_hash] * 3
    assert len({row["observed_utc"] for row in snapshot["observations"]}) == 3


def test_watched_topology_accepts_unrelated_vm_power_and_registration_changes(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep private membership checks while unrelated VM counts change.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher for unrelated provider registration and power state.
    """
    appliance = admitted_topology["appliance"]
    peer = admitted_topology["peer"]
    unrelated = appliance.parent / "unrelated.vmx"
    unrelated.touch()
    admitted_topology["vmx"][str(unrelated)] = [
        {"index": 0, "present": "true", "startconnected": "true", "connectiontype": "custom",
         "vnet": "VMnet2", "address": "00:50:56:ff:00:01"},
    ]
    with topology.watched_topology(admitted_topology["plan"]) as (snapshot, check):
        monkeypatch.setattr(topology, "_parse_inventory", lambda _payload: ([appliance, peer, unrelated], 1, 2))
        monkeypatch.setattr(topology, "_run_vmrun", lambda _exe: ([appliance, peer, unrelated], ""))
        check()
        current = topology.inspect_topology(admitted_topology["plan"])
        assert current["running_vm_count"] == 3
        assert current["sha256"] == snapshot["sha256"]
        monkeypatch.setattr(topology, "_run_vmrun", lambda _exe: ([appliance, peer], ""))
        check()


def test_watched_topology_fails_closed_when_observation_bound_is_exceeded(
    admitted_topology: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observation evidence remains bounded and overflow permanently invalidates the watch.

    Args:
        admitted_topology: Synthetic receipt-bound host and VMX state fixture.
        monkeypatch: Patcher used to reduce the permitted observation count.
    """
    monkeypatch.setattr(topology, "_MAX_TOPOLOGY_OBSERVATIONS", 2)
    with pytest.raises(topology.Refusal, match="ntp_topology_observer_unverified"):
        with topology.watched_topology(admitted_topology["plan"]) as (_snapshot, check):
            check()
            with pytest.raises(topology.Refusal, match="ntp_topology_changed"):
                check()
