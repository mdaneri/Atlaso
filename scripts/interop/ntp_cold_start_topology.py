"""Trusted-host inventory for the separately admitted private NTP fixture."""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from certificate_peer_proof import bound_json
from certificate_trusted_host import (
    _normalized_path,
    _ordinary_file,
    _ordinary_vm_path,
    _parse_inventory,
    _parse_segments,
    _read_vmx,
    _run_vmrun,
)


class Refusal(Exception):
    """Fixed public topology refusal."""


_MAX_TOPOLOGY_OBSERVATIONS = 4096


def _stable_projection(topology: dict) -> dict:
    """Remove dynamic observation metadata before topology equality checks.

    Args:
        topology: Public topology snapshot.
    """
    return {key: value for key, value in topology.items() if key not in {"observed_utc", "observations"}}


def inspect_topology(plan: dict) -> dict:
    """Require exactly the admitted appliance and peer on one private LAN.

    The appliance has two private NICs on this LAN: management and an access
    service interface with disjoint subnets. The peer has one private NIC and
    one separate control NIC. It never routes or bridges these networks.

    Args:
        plan: Originally receipt-bound NTP-only plan.
    """
    host = plan["trusted_host"]
    if host.get("host_administrator_trusted") is not True:
        raise Refusal("ntp_topology_explicit_trust_required")
    executable, _ = _ordinary_file(host["vmrun_path"], "ntp_topology_vmrun_invalid")
    _, inventory = _ordinary_file(host["inventory_path"], "ntp_topology_inventory_invalid")
    _, preferences = _ordinary_file(host["preferences_path"], "ntp_topology_preferences_invalid")
    segment = bound_json(host["segment_receipt"])
    if (segment.get("schema") != 1 or segment.get("name") != host["segment_name"]
            or segment.get("pvn_id") != host["segment_id"]
            or any(segment.get(key) != plan[key] for key in ("task_id", "repository", "pr"))
            or segment.get("source_commit") != plan["resource_source_commit"]
            or _parse_segments(preferences).get(host["segment_name"]) != host["segment_id"]):
        raise Refusal("ntp_topology_original_lan_changed")
    registered, stale, vacant = _parse_inventory(inventory)
    running, _ = _run_vmrun(executable)
    observed = {_normalized_path(path): path for path in [*registered, *running]}
    active = {_normalized_path(path) for path in running}
    appliance = _normalized_path(_ordinary_vm_path(host["appliance_vmx"]))
    peer = _normalized_path(_ordinary_vm_path(host["peer_vmx"]))
    if appliance == peer or not {appliance, peer} <= active:
        raise Refusal("ntp_topology_original_vms_not_running")
    expected = {
        appliance: [
            {"index": 0, "network": host["segment_id"], "type": "pvn", "mac": host["appliance_management_mac"]},
            {"index": 1, "network": host["segment_id"], "type": "pvn", "mac": host["appliance_service_mac"]},
        ],
        peer: [
            {"index": 0, "network": host["control_network"], "type": "custom", "mac": host["peer_control_mac"]},
            {"index": 1, "network": host["segment_id"], "type": "pvn", "mac": host["peer_private_mac"]},
        ],
    }
    members = []
    facts = {}
    for key, path in sorted(observed.items()):
        adapters = [row for row in _read_vmx(Path(path)) if row.get("present", "true").lower() == "true"
                    and row.get("startconnected", "true").lower() == "true"]
        private = [row for row in adapters if row.get("connectiontype", "").lower() == "pvn"
                   and row.get("pvnid", "").lower() == host["segment_id"].lower()]
        members.extend([key] * len(private))
        if key not in expected:
            continue
        actual = [{"index": row["index"], "type": row.get("connectiontype", "").lower(),
                   "network": row.get("pvnid") if row.get("connectiontype", "").lower() == "pvn" else row.get("vnet"),
                   "mac": row.get("address", row.get("generatedaddress", "")).replace("-", ":").lower()}
                  for row in adapters]
        wanted = [{**row, "mac": row["mac"].replace("-", ":").lower()} for row in expected[key]]
        if actual != wanted:
            raise Refusal("ntp_topology_adapter_binding_changed")
        facts[key] = actual
    if sorted(members) != sorted([appliance, appliance, peer]) or set(facts) != {appliance, peer}:
        raise Refusal("ntp_topology_private_membership_changed")
    public = {"kind": "ntp-cold-start-trusted-host-topology", "task_id": plan["task_id"],
              "source_commit": plan["source_commit"], "pr": plan["pr"], "segment_id": host["segment_id"],
              "segment_receipt_sha256": host["segment_receipt"]["sha256"], "lab_adapters": facts,
              "registered_vm_count": len(registered), "running_vm_count": len(running),
              "stale_registration_count": stale, "vacant_registration_count": vacant}
    public["sha256"] = hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()
    public["observed_utc"] = datetime.now(UTC).isoformat()
    return public


@contextmanager
def watched_topology(plan: dict):
    """Keep topology drift sticky, with synchronous checks around every request.

    Args:
        plan: Admitted NTP-only plan.
    """
    original = inspect_topology(plan)
    stable_original = _stable_projection(original)
    observations = [{"observed_utc": original["observed_utc"], "topology_sha256": original["sha256"]}]
    original["observations"] = observations
    stop = threading.Event()
    failed = threading.Event()
    observation_lock = threading.Lock()

    def check():
        """Refuse any current or previously observed identity drift."""
        if failed.is_set():
            raise Refusal("ntp_topology_changed")
        try:
            current = inspect_topology(plan)
            if _stable_projection(current) != stable_original:
                raise Refusal("ntp_topology_changed")
            with observation_lock:
                if len(observations) >= _MAX_TOPOLOGY_OBSERVATIONS:
                    failed.set()
                    raise Refusal("ntp_topology_observation_limit")
                observations.append({"observed_utc": current["observed_utc"],
                                     "topology_sha256": current["sha256"]})
        except Exception:  # noqa: BLE001 - Any provider uncertainty invalidates admission.
            failed.set()
            raise Refusal("ntp_topology_changed") from None

    def watch():
        """Sample host topology only while this bounded acceptance run is active."""
        while not stop.wait(1):
            try:
                check()
            except Refusal:
                return

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    try:
        yield original, check
        check()
    finally:
        stop.set()
        thread.join(timeout=20)
        if thread.is_alive() or failed.is_set():
            raise Refusal("ntp_topology_observer_unverified")
