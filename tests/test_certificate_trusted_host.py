"""Focused admission tests for the trusted VMware certificate lab."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_trusted_host as trusted  # noqa: E402 - Local interop module import.

SEGMENT_ID = "52 00 00 00 00 00 00 01-00 00 00 00 00 00 00 01"
SOURCE = "a" * 40


def _write(path: Path, text: str) -> Path:
    """Write a UTF-8 fixture file, creating its parent directory as needed.

    Args:
        path: Destination path for the fixture.
        text: Text content to write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _vmx(path: Path, adapters: list[tuple[int, str]]) -> Path:
    """Write a VMX fixture with the requested virtual network adapters.

    Args:
        path: Destination path for the VMX file.
        adapters: Adapter index and connection-type pairs to include.
    """
    lines = [".encoding = \"UTF-8\""]
    for index, kind in adapters:
        lines.extend(
            [
                f'ethernet{index}.present = "TRUE"',
                f'ethernet{index}.startConnected = "TRUE"',
                f'ethernet{index}.connectionType = "{kind}"',
                f'ethernet{index}.address = "00:50:56:aa:bb:{index:02x}"',
            ]
        )
        if kind == "pvn":
            lines.append(f'ethernet{index}.pvnID = "{SEGMENT_ID}"')
        else:
            lines.append(f'ethernet{index}.vnet = "vmnet1"')
    return _write(path, "\n".join(lines) + "\n")


def _identity(task_id: str, kind: str, **fields: object) -> dict[str, object]:
    """Build a task-bound receipt body with additional public fields.

    Args:
        task_id: Task identifier bound into the receipt.
        kind: Receipt kind marker.
        **fields: Additional receipt values to include.
    """
    return {"schema": 1, "task_id": task_id, "repository": "mdaneri/Atlaso", "pr": 1074,
            "source_commit": SOURCE, "kind": kind, **fields}


def _lab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    third_member: bool = False,
    third_running_only: str | None = None,
    appliance_unregistered: bool = False,
    peer_running: bool = True,
) -> dict[str, object]:
    """Create a controlled-lab plan and mock the host VM inventory.

    Args:
        tmp_path: Isolated fixture root for VMX and VMware configuration files.
        monkeypatch: Replacements for host subprocess inspection.
        third_member: Whether to register a third VM on the private segment.
        third_running_only: Optional connection type for an unregistered running VM.
        appliance_unregistered: Whether to omit the appliance from the registered inventory.
        peer_running: Whether the designated peer appears in the running inventory.
    """
    task_id = "trusted-host-unit"
    appliance = _vmx(tmp_path / "appliance" / "appliance.vmx", [(0, "pvn")])
    peer = _vmx(tmp_path / "peer" / "peer.vmx", [(0, "custom"), (1, "pvn")])
    registered_paths = [appliance, peer]
    running_paths = [appliance]
    if peer_running:
        running_paths.append(peer)
    if appliance_unregistered:
        registered_paths.remove(appliance)
    if third_member or third_running_only is not None:
        kind = "pvn" if third_member else third_running_only
        third = _vmx(tmp_path / "third" / "third.vmx", [(0, kind)])
        running_paths.append(third)
        if third_member:
            registered_paths.append(third)
    inventory_lines = [
        f'vmlist{index * 3}.config = "{path}"' for index, path in enumerate(registered_paths)
    ]
    inventory = _write(
        tmp_path / "VMware" / "inventory.vmls",
        '.encoding = "windows-1252"\n' + "\n".join(inventory_lines) + "\n",
    )
    preferences = _write(
        tmp_path / "VMware" / "preferences.ini",
        f'pref.namedPVNs0.name = "certificate-trusted-host"\npref.namedPVNs0.pvnID = "{SEGMENT_ID}"\npref.namedPVNs.count = "1"\n',
    )
    segment_path = _write(
        tmp_path / "evidence" / "segment.json",
        json.dumps(_identity(
            task_id, "lan-segment", name="certificate-trusted-host", pvn_id=SEGMENT_ID,
        )),
    )
    segment_bytes = segment_path.read_bytes()
    segment_sha = hashlib.sha256(segment_bytes).hexdigest()
    vmrun = _write(tmp_path / "bin" / "vmrun.exe", "test executable placeholder")
    output = (f"Total running VMs: {len(running_paths)}\n"
              + "\n".join(map(str, running_paths)) + "\n").encode()
    monkeypatch.setattr(trusted.subprocess, "run", lambda *args, **kwargs: type(
        "Completed", (), {"returncode": 0, "stdout": output, "stderr": b""},
    )())
    return {
        "schema": 1,
        "task_id": task_id,
        "repository": "mdaneri/Atlaso",
        "pr": 1074,
        "source_commit": SOURCE,
        "trusted_host": {
            "host_administrator_trusted": True,
            "vmrun_path": str(vmrun),
            "inventory_path": str(inventory),
            "preferences_path": str(preferences),
            "segment_name": "certificate-trusted-host",
            "segment_id": SEGMENT_ID,
            "segment_receipt": {"path": str(segment_path), "sha256": segment_sha},
            "appliance_vmx": str(appliance),
            "peer_vmx": str(peer),
            "appliance_private_adapter": {"index": 0, "mac": "00:50:56:aa:bb:00"},
            "peer_private_adapter": {"index": 1, "mac": "00:50:56:aa:bb:01"},
            "peer_control_adapter": {
                "index": 0,
                "connection_type": "custom",
                "vnet": "vmnet1",
                "mac": "00:50:56:aa:bb:00",
            },
        },
    }


def test_trusted_host_snapshot_names_exact_lab_members_without_claiming_address_exclusivity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Name the two lab VMs while leaving address exclusivity unclaimed.

    Args:
        tmp_path: Isolated root for VMX, inventory, and receipt fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)

    evidence = trusted.inspect_trusted_host(plan)

    assert evidence["trust_model"] == "trusted-host"
    assert evidence["private_members"] == sorted(
        trusted._normalized_path(plan["trusted_host"][role]) for role in ("appliance_vmx", "peer_vmx")
    )
    assert evidence["address_exclusivity_claim"] == "not-established"
    assert evidence["host_administrator_exclusion_claim"] == "not-established"
    assert len(evidence["topology_sha256"]) == 64
    assert "registered_vms" not in evidence
    assert "running_vms" not in evidence


def test_trusted_host_model_requires_explicit_host_administrator_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require the plan to record host-administrator trust explicitly.

    Args:
        tmp_path: Isolated root for VMX, inventory, and receipt fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    plan["trusted_host"]["host_administrator_trusted"] = False

    with pytest.raises(trusted.Refusal, match="trusted_host_explicit_trust_required"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_refuses_third_registered_vm_on_segment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a third registered VM attached to the private segment.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch, third_member=True)

    with pytest.raises(trusted.Refusal, match="trusted_host_private_membership_changed"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_allows_unregistered_running_appliance_and_unrelated_peer_vm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permit the two expected lab members among unrelated running VMs.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(
        tmp_path,
        monkeypatch,
        third_running_only="custom",
        appliance_unregistered=True,
    )

    evidence = trusted.inspect_trusted_host(plan)

    assert evidence["registered_vm_count"] == 1
    assert evidence["running_vm_count"] == 3
    assert evidence["observed_vm_count"] == 3
    assert len(evidence["private_members"]) == 2


def test_trusted_host_refuses_unregistered_running_third_segment_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse an unregistered running VM attached to the private segment.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch, third_running_only="pvn")

    with pytest.raises(trusted.Refusal, match="trusted_host_private_membership_changed"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_requires_both_lab_vms_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require both designated lab VMs to appear in the running inventory.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch, peer_running=False)

    with pytest.raises(trusted.Refusal, match="trusted_host_vm_not_running"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_refuses_missing_vmx_reported_by_vmrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a running VM path reported by vmrun when its VMX is missing.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    missing = tmp_path / "removed" / "still-reported.vmx"
    output = b"Total running VMs: 3\n"
    output += (str(Path(plan["trusted_host"]["appliance_vmx"])) + "\n").encode()
    output += (str(Path(plan["trusted_host"]["peer_vmx"])) + "\n").encode()
    output += (str(missing) + "\n").encode()
    monkeypatch.setattr(trusted.subprocess, "run", lambda *_args, **_kwargs: type(
        "Completed", (), {"returncode": 0, "stdout": output, "stderr": b""},
    )())

    with pytest.raises(trusted.Refusal, match="trusted_host_vm_path_invalid"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_ignores_only_missing_stale_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ignore a missing VMX only when it is a stale registered entry.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    inventory = Path(plan["trusted_host"]["inventory_path"])
    with inventory.open("a", encoding="utf-8") as stream:
        stream.write(f'vmlist77.config = "{tmp_path / "removed" / "old.vmx"}"\n')

    evidence = trusted.inspect_trusted_host(plan)

    assert evidence["stale_registration_count"] == 1
    assert evidence["registered_vm_count"] == 2


def test_vacant_inventory_slots_are_not_vm_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept native cleared slots without excluding any real registration.

    Args:
        tmp_path: Isolated lab and inventory files.
        monkeypatch: Replaces only host process readback.
    """
    plan = _lab(tmp_path, monkeypatch)
    inventory = Path(plan["trusted_host"]["inventory_path"])
    with inventory.open("a", encoding="utf-8") as stream:
        stream.write('vmlist53.config = ""\nvmlist54.config = ""\n')
    evidence = trusted.inspect_trusted_host(plan)
    assert evidence["vacant_registration_count"] == 2
    assert evidence["stale_registration_count"] == 0
    assert evidence["registered_vm_count"] == 2
    assert len(evidence["private_members"]) == 2


@pytest.mark.parametrize("third_member", [False, True])
def test_native_nested_nic_metadata_preserves_membership_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, third_member: bool,
) -> None:
    """Parse ordinary VMware metadata without hiding a real private LAN member.

    Args:
        tmp_path: Isolated lab and VMX files.
        monkeypatch: Replaces only host process readback.
        third_member: Whether another VM really references the private LAN.
    """
    plan = _lab(tmp_path, monkeypatch, third_member=third_member)
    appliance = Path(plan["trusted_host"]["appliance_vmx"])
    with appliance.open("a", encoding="utf-8") as stream:
        stream.write('ethernet0.linkstatepropagation.enable = "TRUE"\n')
    if third_member:
        with pytest.raises(trusted.Refusal, match="trusted_host_private_membership_changed"):
            trusted.inspect_trusted_host(plan)
    else:
        assert len(trusted.inspect_trusted_host(plan)["private_members"]) == 2


@pytest.mark.parametrize("extra", [
    'vmlist0.config = ""\n',
    'vmlist53.config = ""\nvmlist53.config = ""\n',
    'vmlist53.config = " "\n',
    'vmlist53.config = "\n',
])
def test_vacant_slot_handling_keeps_malformed_and_duplicate_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str,
) -> None:
    """Reject ambiguous duplicate slots and nonempty invalid values.

    Args:
        tmp_path: Isolated lab and inventory files.
        monkeypatch: Replaces only host process readback.
        extra: Native-shaped invalid or duplicate slot added to the inventory.
    """
    plan = _lab(tmp_path, monkeypatch)
    inventory = Path(plan["trusted_host"]["inventory_path"])
    with inventory.open("a", encoding="utf-8") as stream:
        stream.write(extra)
    with pytest.raises(trusted.Refusal, match="trusted_host_inventory_invalid"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_scrubs_vmrun_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run vmrun with a scrubbed environment and bounded timeout.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host command and environment.
    """
    plan = _lab(tmp_path, monkeypatch)
    observed: dict[str, object] = {}
    output = b"Total running VMs: 2\n"
    output += (str(Path(plan["trusted_host"]["appliance_vmx"])) + "\n").encode()
    output += (str(Path(plan["trusted_host"]["peer_vmx"])) + "\n").encode()

    def fake_run(*args: object, **kwargs: object) -> object:
        """Capture subprocess options and return the expected running VMs.

        Args:
            *args: Positional vmrun command arguments.
            **kwargs: Subprocess options to inspect in the test.
        """
        observed.update(kwargs)
        return type("Completed", (), {"returncode": 0, "stdout": output, "stderr": b""})()

    monkeypatch.setattr(trusted.subprocess, "run", fake_run)
    monkeypatch.setenv("ATLASO_NATIVE_TEST_SECRET", "not-forwarded")
    for name in ("ATLASO_NATIVE_ADMIN", "ATLASO_NATIVE_PEER_KEY", "OP_SERVICE_ACCOUNT_TOKEN", "VMWARE_REST_PASSWORD"):
        monkeypatch.setenv(name, "synthetic-not-forwarded")
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "program-data"))
    monkeypatch.setenv("TEMP", str(tmp_path / "owned-temp"))

    trusted.inspect_trusted_host(plan)

    environment = observed["env"]
    assert isinstance(environment, dict)
    assert "ATLASO_NATIVE_TEST_SECRET" not in environment
    assert "VMWARE_REST_PASSWORD" not in environment
    assert "ATLASO_NATIVE_ADMIN" not in environment
    assert "ATLASO_NATIVE_PEER_KEY" not in environment
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in environment
    assert environment["APPDATA"] == str(tmp_path / "roaming")
    assert environment["PROGRAMDATA"] == str(tmp_path / "program-data")
    assert environment["TEMP"] == str(tmp_path / "owned-temp")
    assert observed["timeout"] == 15


@pytest.mark.parametrize(
    ("adapter_field", "adapter_value", "reason"),
    [
        ("connectionType", "bridged", "trusted_host_private_membership_changed"),
        ("pvnID", "52 00 00 00 00 00 00 02-00 00 00 00 00 00 00 02", "trusted_host_private_membership_changed"),
        ("address", "00:50:56:aa:bb:fe", "trusted_host_private_adapter_changed"),
    ],
)
def test_trusted_host_refuses_private_adapter_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adapter_field: str, adapter_value: str, reason: str,
) -> None:
    """Refuse changes to the appliance private adapter's type, segment, or MAC.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
        adapter_field: VMX property to alter in the appliance fixture.
        adapter_value: Replacement value for that VMX property.
        reason: Expected refusal marker for the changed property.
    """
    plan = _lab(tmp_path, monkeypatch)
    vmx_path = Path(plan["trusted_host"]["appliance_vmx"])
    original = vmx_path.read_text(encoding="utf-8")
    old_value = SEGMENT_ID if adapter_field == "pvnID" else (
        "pvn" if adapter_field == "connectionType" else "00:50:56:aa:bb:00"
    )
    vmx_path.write_text(original.replace(f'ethernet0.{adapter_field} = "{old_value}"',
                                          f'ethernet0.{adapter_field} = "{adapter_value}"'), encoding="utf-8")

    with pytest.raises(trusted.Refusal, match=reason):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_refuses_ambiguous_duplicate_adapter_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a VMX with duplicated values for a private adapter property.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    appliance = Path(plan["trusted_host"]["appliance_vmx"])
    appliance.write_text(appliance.read_text(encoding="utf-8") +
                         f'ethernet0.pvnID = "{SEGMENT_ID}"\n', encoding="utf-8")

    with pytest.raises(trusted.Refusal, match="trusted_host_vmx_adapter_duplicate_field"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_refuses_invalid_inventory_without_echoing_its_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse malformed inventory without exposing its contents in the error.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    inventory = Path(plan["trusted_host"]["inventory_path"])
    inventory.write_text("private-system-name", encoding="utf-8")

    with pytest.raises(trusted.Refusal, match="trusted_host_inventory_invalid") as error:
        trusted.inspect_trusted_host(plan)

    assert str(error.value) == "trusted_host_inventory_invalid"


def test_trusted_host_refuses_nat_peer_control_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a peer control adapter changed from custom networking to NAT.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    peer = Path(plan["trusted_host"]["peer_vmx"])
    contents = peer.read_text(encoding="utf-8").replace('ethernet0.connectionType = "custom"',
                                                         'ethernet0.connectionType = "nat"')
    peer.write_text(contents, encoding="utf-8")

    with pytest.raises(trusted.Refusal, match="trusted_host_peer_control_adapter_changed"):
        trusted.inspect_trusted_host(plan)


def test_trusted_host_compares_pre_and_post_topology_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detect a changed running inventory between topology snapshots.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    before = trusted.inspect_trusted_host(plan)
    after = dict(before)
    after["running_inventory_sha256"] = "0" * 64
    unsigned = {key: value for key, value in after.items() if key not in {"topology_sha256", "receipt_path"}}
    after["topology_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        trusted.assert_same_topology(before, after)


def test_trusted_host_refuses_snapshot_tampering() -> None:
    before = {"trust_model": "trusted-host", "kind": "certificate-trusted-host-topology", "topology_sha256": "0" * 64}

    with pytest.raises(trusted.Refusal, match="trusted_host_snapshot_invalid"):
        trusted.assert_same_topology(before, before)


def test_trusted_host_refuses_segment_receipt_from_another_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a private-segment receipt bound to another source revision.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for the host VM inventory command.
    """
    plan = _lab(tmp_path, monkeypatch)
    reference = plan["trusted_host"]["segment_receipt"]
    path = Path(reference["path"])
    old = json.loads(path.read_text(encoding="utf-8"))
    old["source_commit"] = "b" * 40
    path.write_text(json.dumps(old), encoding="utf-8")
    reference["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(trusted.Refusal, match="trusted_host_segment_receipt_binding_mismatch"):
        trusted.inspect_trusted_host(plan)


def _resign_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    """Recompute the topology digest after changing a snapshot fixture.

    Args:
        snapshot: Topology mapping to copy and sign.
    """
    signed = dict(snapshot)
    unsigned = {key: value for key, value in signed.items() if key not in {"topology_sha256", "receipt_path"}}
    signed["topology_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return signed


def test_trusted_host_monitor_keeps_drift_failed_after_topology_is_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the monitor failed after detecting drift even if topology is restored.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacement for host topology inspection.
    """
    plan = _lab(tmp_path, monkeypatch)
    original = trusted.inspect_trusted_host(plan)
    drifted = dict(original)
    drifted["running_inventory_sha256"] = "0" * 64
    drifted = _resign_snapshot(drifted)
    observations = iter((drifted, original))
    calls = 0

    def inspect(_plan: dict[str, object]) -> dict[str, object]:
        """Return the next configured topology observation.

        Args:
            _plan: Trusted-host plan passed to the inspector.
        """
        nonlocal calls
        calls += 1
        return next(observations)

    monkeypatch.setattr(trusted, "inspect_trusted_host", inspect)
    monitor = trusted.TrustedHostMonitor(plan, original)

    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        monitor.check()
    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        monitor.check()

    assert monitor.failed.is_set()
    assert calls == 1


def test_trusted_host_monitor_refuses_malformed_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail the monitor closed when its topology observation is malformed.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacement for host topology inspection.
    """
    plan = _lab(tmp_path, monkeypatch)
    original = trusted.inspect_trusted_host(plan)
    malformed = {
        "kind": "certificate-trusted-host-topology",
        "trust_model": "trusted-host",
        "topology_sha256": "not-a-digest",
    }
    monkeypatch.setattr(trusted, "inspect_trusted_host", lambda _plan: malformed)
    monitor = trusted.TrustedHostMonitor(plan, original)

    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        monitor.check()

    assert monitor.failed.is_set()
    assert monitor.observations == []


def test_trusted_host_monitor_refuses_before_starting_when_initial_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the monitor thread stopped when its initial host check fails.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacement for host topology inspection.
    """
    plan = _lab(tmp_path, monkeypatch)
    original = trusted.inspect_trusted_host(plan)

    def unavailable(_plan: dict[str, object]) -> dict[str, object]:
        """Simulate unavailable initial topology readback.

        Args:
            _plan: Trusted-host plan passed to the inspector.
        """
        raise trusted.Refusal("host_readback_unavailable")

    monkeypatch.setattr(trusted, "inspect_trusted_host", unavailable)
    monitor = trusted.TrustedHostMonitor(plan, original)

    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        monitor.start()

    assert monitor.failed.is_set()
    assert monitor.thread.ident is None


def test_trusted_host_monitor_caps_observation_count_and_sticks_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cap successful topology observations and make the monitor failure sticky.

    Args:
        tmp_path: Isolated root for VMX and VMware inventory fixtures.
        monkeypatch: Replacements for topology inspection and snapshot comparison.
    """
    plan = _lab(tmp_path, monkeypatch)
    original = trusted.inspect_trusted_host(plan)
    monkeypatch.setattr(trusted, "inspect_trusted_host", lambda _plan: original)
    monkeypatch.setattr(trusted, "assert_same_topology", lambda _before, _after: None)
    monitor = trusted.TrustedHostMonitor(plan, original)

    for _ in range(4096):
        monitor.check()

    with pytest.raises(trusted.Refusal, match="trusted_host_observation_limit"):
        monitor.check()
    with pytest.raises(trusted.Refusal, match="trusted_host_topology_changed"):
        monitor.check()

    assert monitor.failed.is_set()
    assert len(monitor.observations) == 4096
