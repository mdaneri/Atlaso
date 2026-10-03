"""Contract tests for the bounded VMware dedicated-host observation."""

from __future__ import annotations

import copy

import pytest

from scripts.interop import dedicated_host_contract as contract

APPLIANCE = r"E:\lab\appliance.vmx"
PEER = r"E:\lab\peer.vmx"
EXECUTABLE = r"C:\Program Files\VMware\VMware Workstation\vmware-vmx.exe"
MAC_APPLIANCE = "00:50:56:aa:bb:01"
MAC_PEER = "00:50:56:aa:bb:02"


def _expected() -> dict[str, list[dict[str, object]]]:
    return {
        APPLIANCE: [{"index": 0, "connection_type": "pvn", "network_id": "segment-id",
                     "mac": MAC_APPLIANCE}],
        PEER: [{"index": 1, "connection_type": "pvn", "network_id": "segment-id",
                "mac": MAC_PEER}],
    }


def _snapshot() -> dict[str, object]:
    expected = _expected()
    processes = [
        {"pid": 101, "creation_time": "2026-10-03T10:00:00.0000000Z",
         "vmx_path": APPLIANCE, "executable": EXECUTABLE},
        {"pid": 102, "creation_time": "2026-10-03T10:00:01.0000000Z",
         "vmx_path": PEER, "executable": EXECUTABLE},
    ]
    adapters: dict[str, list[dict[str, object]]] = {}
    for vmx_path, wanted_rows in expected.items():
        rows: list[dict[str, object]] = [
            {"index": index, "present": False, "connection_type": "", "network_id": "",
             "mac": "", "start_connected": False}
            for index in range(contract.MAX_ADAPTERS)
        ]
        for wanted in wanted_rows:
            index = int(wanted["index"])
            rows[index] = {**wanted, "present": True, "start_connected": True}
        adapters[vmx_path] = rows
    return {"processes": processes, "running_vm_paths": [APPLIANCE, PEER], "adapters": adapters}


def _guest_interface(mac: str, *addresses: tuple[str, int]) -> dict[str, object]:
    return {
        "mac": mac,
        "link_type": "ether",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "master": None,
        "linkinfo": None,
        "addresses": [{"local": address, "prefixlen": prefix} for address, prefix in addresses],
    }


def _guests() -> dict[str, list[dict[str, object]]]:
    return {
        "appliance": [
            _guest_interface(MAC_APPLIANCE, ("192.168.77.40", 24)),
            _guest_interface("00:50:56:aa:bb:03", ("192.168.77.50", 24)),
        ],
        "peer": [_guest_interface(MAC_PEER, ("192.168.77.1", 24))],
    }


def test_validates_complete_dedicated_host_snapshot_without_exclusivity_claim() -> None:
    evidence = contract.validate_snapshot(_expected(), _snapshot())

    assert evidence["contract"] == "dedicated-host-stable-observation-v1"
    assert evidence["claim"] == "validated-observation-only"
    assert evidence["atomic_snapshot"] is False
    assert evidence["exclusive_membership"] is False
    assert len(evidence["processes"]) == 2
    assert len(evidence["adapters"]) == 2 * contract.MAX_ADAPTERS
    assert "exclusive" not in str(evidence["claim"])


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda snap: snap["processes"][0].update(pid=0), "process_identity_invalid"),
        (lambda snap: snap["processes"][0].update(pid=True), "process_identity_invalid"),
        (lambda snap: snap["processes"][1].update(pid=101), "process_duplicate"),
        (lambda snap: snap["processes"][1].update(vmx_path=APPLIANCE), "process_duplicate"),
        (lambda snap: snap["processes"][1].update(vmx_path=r"E:\lab\unknown.vmx"),
         "process_inventory_disagrees"),
        (lambda snap: snap["running_vm_paths"].pop(), "process_inventory_disagrees"),
        (lambda snap: snap["processes"][0].update(executable=r"C:\Windows\not-vmware.exe"),
         "process_executable_invalid"),
        (lambda snap: snap["adapters"][APPLIANCE].pop(), "adapter_inventory_incomplete"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(present=False, connection_type="",
                                                              network_id="", mac="", start_connected=False),
         "adapter_set_mismatch"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(start_connected=False),
         "expected_adapter_not_start_connected"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(connection_type="custom"),
         "expected_adapter_mismatch"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(network_id="other-segment"),
         "expected_adapter_mismatch"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(mac=MAC_PEER),
         "adapter_mac_duplicate"),
        (lambda snap: snap["adapters"][APPLIANCE][0].update(network_id=""),
         "adapter_configuration_invalid"),
        (lambda snap: snap["adapters"][PEER].append({"index": 1, "present": True,
                                                       "connection_type": "pvn", "network_id": "segment-id",
                                                       "mac": "00:50:56:aa:bb:04", "start_connected": True}),
         "adapter_duplicate_index"),
    ],
)
def test_refuses_invalid_or_changed_host_inventory(change: object, reason: str) -> None:
    snapshot = _snapshot()
    change(snapshot)  # type: ignore[operator]  # Each parameter is a test mutation callback.

    with pytest.raises(contract.Refusal, match=reason):
        contract.validate_snapshot(_expected(), snapshot)


def test_rejects_unc_or_relative_enrollment_paths() -> None:
    for path in (r"\\server\share\appliance.vmx", r"E:lab\appliance.vmx", r"E:\lab\..\appliance.vmx"):
        with pytest.raises(contract.Refusal, match="expected_path_invalid"):
            contract.validate_snapshot({path: _expected()[APPLIANCE]}, _snapshot())


def test_rejects_extra_adapter_vm_even_when_expected_vm_inventory_matches() -> None:
    snapshot = _snapshot()
    extra_rows = copy.deepcopy(snapshot["adapters"][PEER])
    extra_rows[1]["mac"] = "00:50:56:aa:bb:04"
    snapshot["adapters"][r"E:\lab\other.vmx"] = extra_rows

    with pytest.raises(contract.Refusal, match="adapter_inventory_disagrees"):
        contract.validate_snapshot(_expected(), snapshot)


def test_unchanged_bracket_ignores_order_but_refuses_identity_or_topology_drift() -> None:
    before = _snapshot()
    after = copy.deepcopy(before)
    after["processes"].reverse()
    after["running_vm_paths"].reverse()
    after["adapters"][APPLIANCE].reverse()
    contract.assert_unchanged(before, after)

    after["processes"][0]["creation_time"] = "different"
    with pytest.raises(contract.Refusal, match="host_snapshot_changed"):
        contract.assert_unchanged(before, after)

    after = copy.deepcopy(before)
    after["adapters"][APPLIANCE][9].update(present=True, connection_type="custom",
                                           network_id="VMnet8", mac="00:50:56:aa:bb:04",
                                           start_connected=True)
    with pytest.raises(contract.Refusal, match="host_snapshot_changed"):
        contract.assert_unchanged(before, after)


def test_unchanged_bracket_accepts_canonical_evidence_and_tracks_absent_slots() -> None:
    before = contract.validate_snapshot(_expected(), _snapshot())
    after = copy.deepcopy(before)
    contract.assert_unchanged(before, after)

    after["adapters"][9]["start_connected"] = True
    with pytest.raises(contract.Refusal, match="adapter_absence_ambiguous"):
        contract.assert_unchanged(before, after)


def test_canonical_evidence_rejects_weakened_claim_flags() -> None:
    evidence = contract.validate_snapshot(_expected(), _snapshot())
    evidence["exclusive_membership"] = True

    with pytest.raises(contract.Refusal, match="evidence_invalid"):
        contract.assert_unchanged(evidence, evidence)


def test_validates_candidate_claims_only_on_appliance_management_mac() -> None:
    result = contract.validate_guest_addresses(
        {"appliance": [MAC_APPLIANCE, "00:50:56:aa:bb:03"], "peer": [MAC_PEER]},
        _guests(), ["192.168.77.40", "192.168.77.10", "2001:db8::10"],
    )

    assert result["claim"] == "candidate-claims-checked-on-enrolled-guest-interfaces"
    assert result["candidate_claims"] == {
        "192.168.77.40": {"role": "appliance", "mac": MAC_APPLIANCE},
    }


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda guests: guests["peer"][0]["addresses"].append(
            {"local": "192.168.77.10", "prefixlen": 24}), "candidate_address_conflict"),
        (lambda guests: guests["appliance"][1]["addresses"].append(
            {"local": "192.168.77.10", "prefixlen": 24}), "candidate_address_conflict"),
        (lambda guests: guests["peer"][0].update(mac=MAC_APPLIANCE), "guest_interface_mac_duplicate"),
        (lambda guests: guests["peer"][0].update(flags=["UP"]), "guest_interface_not_up"),
        (lambda guests: guests["peer"][0].update(link_type="loopback"), "guest_interface_not_ethernet"),
        (lambda guests: guests["peer"][0].update(master="br0"), "guest_interface_master_present"),
        (lambda guests: guests["peer"][0].update(linkinfo={"info_kind": "bridge"}),
         "guest_virtual_interface_present"),
        (lambda guests: guests["peer"][0]["addresses"].append(
            {"local": "not-an-ip", "prefixlen": 24}), "guest_address_record_invalid"),
    ],
)
def test_refuses_guest_address_or_topology_conflict(change: object, reason: str) -> None:
    guests = _guests()
    change(guests)  # type: ignore[operator]  # Each parameter is a test mutation callback.

    with pytest.raises(contract.Refusal, match=reason):
        contract.validate_guest_addresses(
            {"appliance": [MAC_APPLIANCE, "00:50:56:aa:bb:03"], "peer": [MAC_PEER]},
            guests, ["192.168.77.40", "192.168.77.10"],
        )


def test_guest_interface_allowlist_and_candidate_list_are_exact() -> None:
    with pytest.raises(contract.Refusal, match="guest_interface_set_mismatch"):
        contract.validate_guest_addresses(
            {"appliance": [MAC_APPLIANCE], "peer": [MAC_PEER]}, _guests(), ["192.168.77.40"]
        )
    with pytest.raises(contract.Refusal, match="candidate_address_invalid"):
        contract.validate_guest_addresses(
            {"appliance": [MAC_APPLIANCE, "00:50:56:aa:bb:03"], "peer": [MAC_PEER]},
            _guests(), ["192.0.2.1/24"],
        )


def test_unused_appliance_interface_may_be_admin_down_but_is_still_checked() -> None:
    guests = _guests()
    guests["appliance"][1]["flags"] = ["BROADCAST", "MULTICAST"]
    contract.validate_guest_addresses(
        {"appliance": [MAC_APPLIANCE, "00:50:56:aa:bb:03"], "peer": [MAC_PEER]},
        guests, ["192.168.77.10"],
    )

    guests["appliance"][1]["addresses"].append({"local": "192.168.77.10", "prefixlen": 24})
    with pytest.raises(contract.Refusal, match="candidate_address_conflict"):
        contract.validate_guest_addresses(
            {"appliance": [MAC_APPLIANCE, "00:50:56:aa:bb:03"], "peer": [MAC_PEER]},
            guests, ["192.168.77.10"],
        )
