"""Verify the byte-preserving part of an original OVA private-LAN move."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import BinaryIO

import pytest

from scripts.completed_task_files import WindowsFiles
from scripts.interop import certificate_ova_identity, certificate_trusted_host
from scripts.interop.certificate_ova_identity import (
    _bound_original_transition,
    _OvaImportProof,
    _run_owned_ova_transition,
    _verify_private_lan_receipts,
    assert_ova_stopped,
    open_ova_vmx_writer,
    ova_private_lan_receipt_paths,
    pin_stopped_ova_backings,
    prepare_ova_private_lan_completion,
    prepare_ova_private_lan_edit,
    render_ova_private_lan,
    write_ova_private_lan,
)
from scripts.interop.certificate_peer_factory import Refusal
from scripts.interop.certificate_trusted_host import Refusal as TrustedHostRefusal
from scripts.interop.certificate_trusted_host import verify_registered_segment

_MAC = "00:0c:29:f9:ff:49"
_SEGMENT = "52 80 fb 33 b6 c3 92 21-41 cf 79 be 11 2b f4 15"
_VMX = b"""# VMX comments and spacing are retained.
ethernet0.present = "TRUE"
ethernet0.startConnected = "TRUE"
ethernet0.connectionType = "custom"
ethernet0.allowGuestConnectionControl = "FALSE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType = "generated"
ethernet0.generatedAddress = "00:0c:29:f9:ff:49"
ethernet0.vnet = "vmnet2"
ethernet1.present = "TRUE"
ethernet1.startConnected = "FALSE"
ethernet1.connectionType = "custom"
ethernet1.vnet = "vmnet2"
ethernet1.allowGuestConnectionControl = "FALSE"
ethernet1.virtualDev = "vmxnet3"
scsi0:0.fileName = "disk.vmdk"
guestinfo.ovfenv = "|22|22"
"""


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_ova_private_lan_preserves_unrelated_vmx_bytes(newline: bytes) -> None:
    """Require exact service NIC, original disk, comment and line-ending bytes.

    Args:
        newline: Original newline format used by the VMX.
    """
    data = b"\xef\xbb\xbf" + _VMX.replace(b"\n", newline)
    expected = data.replace(b'ethernet0.connectionType = "custom"', b'ethernet0.connectionType = "pvn"').replace(
        b'ethernet0.vnet = "vmnet2"', f'ethernet0.pvnID = "{_SEGMENT}"'.encode(),
    )
    assert render_ova_private_lan(data, mac=_MAC, vmnet="vmnet2", segment_id=_SEGMENT) == expected
    with pytest.raises(Refusal, match="ova_original_network_changed"):
        render_ova_private_lan(expected, mac=_MAC, vmnet="vmnet2", segment_id=_SEGMENT)


@pytest.mark.parametrize(
    ("data", "mac", "segment", "reason"),
    [
        (_VMX, "00:0c:29:f9:ff:48", _SEGMENT, "ova_original_network_changed"),
        (_VMX, _MAC, "bogus", "ova_private_lan_segment_invalid"),
        (_VMX.replace(b'ethernet1.startConnected = "FALSE"', b'ethernet1.startConnected = "TRUE"'),
         _MAC, _SEGMENT, "ova_original_network_changed"),
        (_VMX.replace(b'guestinfo.ovfenv = "|22|22"', b'guestinfo.ovfenv = "unexpected"'),
         _MAC, _SEGMENT, "ova_original_network_changed"),
        (_VMX.replace(b"\n", b"\r\n", 1), _MAC, _SEGMENT, "ova_private_lan_line_endings_invalid"),
        (_VMX + b'ethernet0.VNET = "vmnet2"\n', _MAC, _SEGMENT, "imported_ova_vmx_assignment_invalid"),
    ],
)
def test_ova_private_lan_refuses_drift(data: bytes, mac: str, segment: str, reason: str) -> None:
    """Reject changed or ambiguous source bytes and invalid selectors.

    Args:
        data: VMX bytes to transform.
        mac: Original management MAC selector.
        segment: Registered LAN identifier selector.
        reason: Expected fixed refusal category.
    """
    with pytest.raises(Refusal, match=reason):
        render_ova_private_lan(data, mac=mac, vmnet="vmnet2", segment_id=segment)


@pytest.mark.parametrize(("changed", "reason"), [
    ({"vmx_identity": "replacement"}, "intent_mismatch"),
    ({"segment_receipt_sha256": "c" * 64}, "binding_mismatch"),
    ({"before_sha256": "c" * 64}, "digest_mismatch"),
    ({"readback_sha256": "c" * 64}, "readback_mismatch"),
    ({"intent_path": "other.json"}, "intent_mismatch"),
])
def test_ova_private_lan_completion_requires_original_edit_readback(changed: dict, reason: str) -> None:
    """Reject replacement, unrelated LAN authority, and mismatched write receipts.

    Args:
        changed: Completion override.
        reason: Expected fixed refusal suffix.
    """
    binding = {"before_vmx_identity": "original", "segment_receipt_sha256": "d" * 64}
    intent = {**binding, "schema": 1, "phase": "ova-private-lan-pending", "source_commit": "e" * 40,
              "before_sha256": "a" * 64, "after_sha256": "b" * 64}
    completion = {**intent, "phase": "ova-private-lan-complete", "vmx_identity": "original",
                  "intent_path": "original.json", "intent_sha256": "f" * 64, "readback_sha256": "b" * 64}
    selectors = {"intent_path": "original.json", "intent_sha256": "f" * 64}
    _verify_private_lan_receipts(intent, completion, binding, **selectors)
    with pytest.raises(Refusal, match=reason):
        _verify_private_lan_receipts(intent, {**completion, **changed}, binding, **selectors)


def test_ova_private_lan_producer_binds_original_payloads() -> None:
    """Feed the source-generated payloads through the receipt verifier."""
    binding = {"mac": _MAC, "segment_id": _SEGMENT, "before_vmx_identity": "original"}
    path = "original-intent.json"
    after, intent = prepare_ova_private_lan_edit(_VMX, binding, source_commit="e" * 40, vmnet="vmnet2")
    completion = prepare_ova_private_lan_completion(
        intent, after, binding, intent_path=path, vmx_identity="original",
    )
    _verify_private_lan_receipts(
        json.loads(intent), completion, binding, intent_path=path, intent_sha256=hashlib.sha256(intent).hexdigest(),
    )
    with pytest.raises(Refusal, match="ova_private_lan_readback_mismatch"):
        prepare_ova_private_lan_completion(intent, _VMX, binding, intent_path=path, vmx_identity="original")


def test_ova_lan_catalog_pairs_fields_by_original_index() -> None:
    """Admit the intended registration with independently ordered catalog fields."""
    other = _SEGMENT[:-2] + "16"
    prefs = (f'pref.namedPVNs.count = "2"\n'
             f'pref.namedPVNs0.name = "Fixture"\n'
             f'pref.namedPVNs1.name = "Other"\n'
             f'pref.namedPVNs1.pvnID = "{other}"\n'
             f'pref.namedPVNs0.pvnID = "{_SEGMENT}"\n').encode()
    selectors = {"task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1084,
                 "source_commit": "e" * 40, "name": "Fixture"}
    original = json.dumps({"schema": 1, **selectors, "pvn_id": _SEGMENT}).encode()
    digest = hashlib.sha256(original).hexdigest()
    verify_registered_segment(prefs, original, expected_sha256=digest, segment_id=_SEGMENT, **selectors)
    with pytest.raises(TrustedHostRefusal, match="trusted_host_preferences_ambiguous"):
        verify_registered_segment(
            prefs.replace(b'"Other"', b'"fixture"'), original,
            expected_sha256=digest, segment_id=_SEGMENT, **selectors,
        )
    with pytest.raises(TrustedHostRefusal, match="trusted_host_segment_receipt_digest_mismatch"):
        verify_registered_segment(prefs, original + b" ", expected_sha256=digest, segment_id=_SEGMENT, **selectors)


def test_ova_private_lan_rejects_receipt_from_another_import() -> None:
    """A matching digest selector must still point to this import's original claim."""
    ownership = Path.cwd() / ".task-ownership"
    first, second = "1" * 32, "2" * 32
    first_import = ownership / f"atlaso-test-vm-ova-import-original-{first}.json"
    second_import = ownership / f"atlaso-test-vm-ova-import-original-{second}.json"
    first_intent, first_complete = ova_private_lan_receipt_paths(first_import, first)
    second_intent, _ = ova_private_lan_receipt_paths(second_import, second)
    assert first_intent.parent == first_complete.parent == ownership
    assert first_intent != first_complete
    with pytest.raises(Refusal, match="ova_private_lan_import_reference_invalid"):
        ova_private_lan_receipt_paths(first_import, second)
    with pytest.raises(Refusal, match="ova_private_lan_original_reference_invalid"):
        _bound_original_transition({"path": str(second_intent), "sha256": "a" * 64}, first_intent)


@pytest.mark.skipif(os.name != "nt", reason="Workstation receipt publication requires Windows")
@pytest.mark.parametrize("refuse_write", [False, True])
def test_ova_transition_consumes_original_intent_before_write(tmp_path: Path, refuse_write: bool) -> None:
    """Verify durable intent, original-byte retention on refusal, and replay prevention.

    Args:
        tmp_path: Owned synthetic receipt and VMX fixture root.
        refuse_write: Whether the owner observes a changed VMX identity after the claim.
    """
    ownership = tmp_path / ".task-ownership"
    ownership.mkdir()
    invocation = "1" * 32
    original = ownership / f"atlaso-test-vm-ova-import-original-{invocation}.json"
    vmx = tmp_path / "synthetic.vmx"
    vmx.write_bytes(_VMX)
    intent, complete = ova_private_lan_receipt_paths(original, invocation)
    identity = WindowsFiles().mutable_file_identity(vmx)
    binding = {"mac": _MAC, "segment_id": _SEGMENT, "before_vmx_identity": identity}

    def admit() -> str:
        """Observe publication before authorizing the original writer."""
        assert intent.is_file() and not complete.exists()
        with pytest.raises(Refusal, match="ova_private_lan_writer_unavailable"):
            with open_ova_vmx_writer(vmx, identity):
                pytest.fail("Competing VMX writer unexpectedly opened")
        return "changed" if refuse_write else identity

    open_attempts = []

    def open_writer() -> AbstractContextManager[BinaryIO]:
        """Check that the durable claim precedes access to the writer."""
        assert intent.is_file() and not complete.exists()
        open_attempts.append(vmx)
        return open_ova_vmx_writer(vmx, identity)

    def run() -> None:
        """Use the synthetic stream with the transition's normal receipt publication."""
        write_ova_private_lan(
            open_writer, _VMX, binding, source_commit="e" * 40, vmnet="vmnet2",
            original_import=original, invocation=invocation, admit_write=admit,
        )

    with pytest.raises(Refusal, match="ova_private_lan_writer_identity_changed"):
        with open_ova_vmx_writer(vmx, "00000000:0000000000000000"):
            pytest.fail("An unbound VMX writer unexpectedly opened")
    assert not intent.exists()

    if refuse_write:
        with pytest.raises(Refusal, match="ova_private_lan_writer_identity_changed"):
            run()
        assert vmx.read_bytes() == _VMX
        assert not complete.exists()
    else:
        run()
        after = render_ova_private_lan(_VMX, mac=_MAC, vmnet="vmnet2", segment_id=_SEGMENT)
        assert vmx.read_bytes() == after
        assert json.loads(complete.read_bytes())["readback_sha256"] == hashlib.sha256(after).hexdigest()

    original_intent = intent.read_bytes()
    with pytest.raises(Refusal, match="ova_private_lan_attempt_already_claimed"):
        run()
    assert open_attempts == [vmx]
    assert intent.read_bytes() == original_intent


@pytest.mark.skipif(os.name != "nt", reason="Workstation disk identity checks require Windows")
def test_ova_stopped_transition_pins_all_original_disks(tmp_path: Path) -> None:
    """Refuse a competing disk writer and reject a byte-identical replacement.

    Args:
        tmp_path: Owned synthetic appliance directory and four disk backings.
    """
    vmx = tmp_path / "synthetic.vmx"
    vmx_bytes = b'scsi0.present = "TRUE"\nscsi0.virtualDev = "pvscsi"\n'
    files = WindowsFiles()
    with files.opened(tmp_path, directory=True) as (_, directory_id, _):
        directory = "{:08X}:{:08X}{:08X}".format(*directory_id)
    disks = []
    for slot, (role, gib) in enumerate(
        (("photon_os", 40), ("atlaso_system", 20), ("atlaso-depot", 500), ("atlaso-backups", 500)),
    ):
        backing = tmp_path / f"disk-{slot}.vmdk"
        backing.write_bytes(b"synthetic backing")
        with files.opened(backing) as (_, identity, _):
            disks.append({"slot": slot, "role": role, "virtual_size_bytes": gib << 30,
                          "file": backing.name, "identity": list(identity)})
        vmx_bytes += (f'scsi0:{slot}.present = "TRUE"\nscsi0:{slot}.fileName = "{backing.name}"\n').encode()
    original = {"directory_identity": directory, "disk_inspection": {"disks": disks}}
    with pin_stopped_ova_backings(vmx, vmx_bytes, original):
        for disk in disks:
            with pytest.raises(PermissionError):
                with (tmp_path / disk["file"]).open("r+b"):
                    pytest.fail("Competing VMDK writer unexpectedly opened")
    target = tmp_path / disks[-1]["file"]
    target.rename(tmp_path / "retained.vmdk")
    target.write_bytes(b"synthetic backing")
    with pytest.raises(Refusal, match="ova_original_disk_changed"):
        with pin_stopped_ova_backings(vmx, vmx_bytes, original):
            pytest.fail("Replacement VMDK unexpectedly admitted")


@pytest.mark.skipif(os.name != "nt", reason="Workstation receipt pins require Windows")
@pytest.mark.parametrize("state", ["stopped", "starts_running", "other_catalog", "changed_plan"])
def test_stopped_ova_transition_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    """Hold the original inputs during both stopped checks and refuse a late power change.

    Args:
        tmp_path: Owned synthetic VM, catalog and receipt root.
        monkeypatch: Supplies synthetic import provenance and VMware inventory.
        state: Whether the appliance stays stopped, starts, or the catalog or plan differs.
    """
    vmx = tmp_path / "synthetic.vmx"
    before = _VMX.replace(b'scsi0:0.fileName = "disk.vmdk"\n', b'')
    before += b'scsi0.present = "TRUE"\nscsi0.virtualDev = "pvscsi"\n'
    disks = []
    files = WindowsFiles()
    for slot, (role, size) in enumerate((("photon_os", 40), ("atlaso_system", 20),
                                        ("atlaso-depot", 500), ("atlaso-backups", 500))):
        disk = tmp_path / f"disk-{slot}.vmdk"
        disk.write_bytes(b"original disk")
        with files.opened(disk) as (_, identity, _):
            disks.append({"slot": slot, "role": role, "virtual_size_bytes": size << 30,
                          "file": disk.name, "identity": list(identity)})
        before += f'scsi0:{slot}.present = "TRUE"\nscsi0:{slot}.fileName = "{disk.name}"\n'.encode()
    vmx.write_bytes(before)
    vmrun = tmp_path / "vmrun.exe"
    vmrun.write_bytes(b"synthetic provider")
    catalog = tmp_path / "preferences.ini"
    catalog.write_text(f'pref.namedPVNs.count = "1"\npref.namedPVNs0.name = "test"\n'
                       f'pref.namedPVNs0.pvnID = "{_SEGMENT}"\n', encoding="utf-8")
    scope = {"schema": 1, "task_id": "test-task", "repository": "mdaneri/Atlaso", "pr": 1084,
             "source_commit": "e" * 40}

    def original_reference(path: Path, payload: dict) -> dict:
        """Write the synthetic original and compute its exact digest."""
        data = json.dumps(payload).encode()
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}

    registered_catalog = catalog
    if state == "other_catalog":
        registered_catalog = catalog.with_name("original-preferences.ini")
        registered_catalog.write_bytes(catalog.read_bytes())
    segment = original_reference(tmp_path / "segment.json", {
        **scope, "name": "test", "pvn_id": _SEGMENT, "preferences_path": str(registered_catalog),
    })
    ownership = tmp_path / ".task-ownership"
    ownership.mkdir()
    invocation = "1" * 32
    imported = ownership / f"atlaso-test-vm-ova-import-original-{invocation}.json"
    import_ref = original_reference(imported, {"import": True})
    boot_ref = original_reference(tmp_path / "boot.json", {"boot": True})
    peer = str(tmp_path / "peer.vmx")
    fixture = original_reference(ownership / "peer.json", {
        **scope, "kind": "certificate-dhcp-peer-fixture", "appliance_vmx": str(vmx), "peer_vmx": peer,
        "private_network": "lan:test", "lan_segment_id": _SEGMENT, "lan_segment_receipt": segment["path"],
        "lan_segment_receipt_sha256": segment["sha256"],
    })
    plan = {**scope, "peer_fixture": fixture, "appliance_ownership": import_ref, "appliance_ova_boot": boot_ref,
            "trusted_host": {"host_administrator_trusted": True, "vmrun_path": str(vmrun), "appliance_vmx": str(vmx),
                             "peer_vmx": peer, "appliance_private_adapter": {"index": 0, "mac": _MAC},
                             "preferences_path": str(catalog), "segment_name": "test", "segment_id": _SEGMENT,
                             "segment_receipt": segment}}
    intent, complete = ova_private_lan_receipt_paths(imported, invocation)
    with files.opened(tmp_path, directory=True) as (_, directory, _):
        original = {"directory_identity": "{:08X}:{:08X}{:08X}".format(*directory),
                    "disk_inspection": {"disks": disks}}
    identity = files.mutable_file_identity(vmx)

    def admit_import(_plan: dict, _vmx: Path, _repository: Path, *,
                     mac: str, read_receipt: Callable[[dict], dict]) -> _OvaImportProof:
        """Supply synthetic provenance while retaining the real receipt read pins."""
        assert mac == _MAC
        assert read_receipt(import_ref) == {"import": True}
        assert read_receipt(boot_ref) == {"boot": True}
        return _OvaImportProof(original, imported, invocation, "vmnet2", identity)

    observed = []

    def inventory(executable: Path) -> tuple[list[Path], str]:
        """Observe held pins and the claim state at each provider call."""
        assert executable == vmrun
        observed.append(intent.is_file())
        with pytest.raises(PermissionError):
            ownership.rename(ownership.with_name("different-ownership"))
        for path in (imported, Path(boot_ref["path"]), catalog, vmrun, tmp_path / "disk-0.vmdk"):
            with pytest.raises(PermissionError):
                with path.open("r+b"):
                    pytest.fail("An admitted input unexpectedly allowed a writer")
        return ([vmx] if state == "starts_running" and observed[-1] else []), ""

    monkeypatch.setattr(certificate_ova_identity, "_admit_ova_import", admit_import)
    monkeypatch.setattr(certificate_ova_identity, "require_ancestor", lambda *_: None)
    monkeypatch.setattr(certificate_trusted_host, "_run_vmrun", inventory)
    provider_digest = hashlib.sha256(vmrun.read_bytes()).hexdigest()
    plan_directory = tmp_path / "test-results"
    plan_directory.mkdir()
    plan_ref = original_reference(plan_directory / "plan.json", plan)
    with files.opened(ownership, directory=True) as (_, native, _):
        ownership_id = "{:08X}:{:08X}{:08X}".format(*native)

    def run() -> None:
        """Exercise the plan and ownership boundary used by the command."""
        _run_owned_ova_transition(
            Path(plan_ref["path"]), "0" * 64 if state == "changed_plan" else plan_ref["sha256"],
            tmp_path, vmx, "test-task", 1084, "e" * 40, ownership, ownership_id, provider_digest,
        )

    if state == "changed_plan":
        with pytest.raises(Refusal, match="original_receipt_changed"):
            run()
        assert not intent.exists()
        assert observed == []
        return
    if state == "other_catalog":
        with pytest.raises(Refusal, match="ova_private_lan_catalog_reference_mismatch"):
            run()
        assert not intent.exists() and not complete.exists()
        assert vmx.read_bytes() == before
        assert observed == []
        return
    if state == "starts_running":
        with pytest.raises(Refusal, match="ova_private_lan_appliance_running"):
            run()
        assert vmx.read_bytes() == before
        assert not complete.exists()
    else:
        run()
        expected = render_ova_private_lan(before, mac=_MAC, vmnet="vmnet2", segment_id=_SEGMENT)
        assert vmx.read_bytes() == expected
        assert json.loads(complete.read_bytes())["import_sha256"] == import_ref["sha256"]
    assert observed == [False, True]


@pytest.mark.parametrize("state", ["stopped", "running", "locked", "suspended", "checkpoint"])
def test_ova_stopped_admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    """Refuse ambiguous power state before a transition can touch the original.

    Args:
        tmp_path: Owned synthetic appliance directory.
        monkeypatch: Replaces the provider's running inventory with synthetic data.
        state: Running inventory and local VMware state to check.
    """
    vmx = tmp_path / "synthetic.vmx"
    before = _VMX
    monkeypatch.setattr(certificate_trusted_host, "_run_vmrun", lambda _: ([vmx] if state == "running" else [], ""))
    if state == "locked":
        (tmp_path / "synthetic.vmx.LCK").mkdir()
    if state == "suspended":
        (tmp_path / "synthetic.vmss").write_bytes(b"")
    if state == "checkpoint":
        before += b'checkpoint.vmState = "synthetic.vmss"\n'
    provider = tmp_path / "vmrun.exe"
    if state == "stopped":
        assert_ova_stopped(vmx, before, provider)
    else:
        reason = {"running": "running", "locked": "locked", "suspended": "locked", "checkpoint": "suspended"}
        with pytest.raises(Refusal, match=f"ova_private_lan_appliance_{reason[state]}"):
            assert_ova_stopped(vmx, before, provider)
