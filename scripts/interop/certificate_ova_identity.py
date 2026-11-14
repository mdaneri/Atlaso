"""Verify original OVA import, first-boot and runtime evidence for certificate fixtures."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from scripts.completed_task_files import WindowsFiles, publish_durable_file
from scripts.interop.certificate_peer_factory import (
    Refusal,
    bound_json,
    public_file,
    require_ancestor,
)


def _sibling(reference: dict, name: str, digest: str, *, read_receipt: Callable[[dict], dict] = bound_json) -> dict:
    """Resolve a digest-bound basename relative to the original evidence file.

    Args:
        reference: Absolute path of the referencing receipt.
        name: Original evidence filename.
        digest: Independently recorded SHA-256.
        read_receipt: Reader for the original digest-bound receipt.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", name):
        raise Refusal("ova_evidence_name_invalid")
    return read_receipt({"path": str(Path(reference["path"]).with_name(name)), "sha256": digest})


def _linked(reference: dict, link: dict, *, read_receipt: Callable[[dict], dict] = bound_json) -> dict:
    """Read one sibling receipt by its original name and digest.

    Args:
        reference: Absolute path of the referencing receipt.
        link: Original relative receipt reference.
        read_receipt: Reader for the original digest-bound receipt.
    """
    return _sibling(reference, link["receipt"], link["sha256"], read_receipt=read_receipt)


def _native_id(identity: list[int]) -> str:
    """Format a three-part Windows file identity.

    Args:
        identity: Volume and file index from an original inspection.
    """
    if len(identity) != 3 or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in identity):
        raise Refusal("ova_file_identity_invalid")
    return "{:08X}:{:08X}{:08X}".format(*identity)


def admit_ova(
    plan: dict, vmx: Path, repository: Path, *, mac: str, private_lan: str | None = None,
) -> dict:
    """Read original OVA evidence and verify the exact VM and backing identities.

    Args:
        plan: Trusted-host selectors with original import and boot references.
        vmx: Original imported appliance path.
        repository: Admitted checkout for Git ancestry checks.
        mac: Original management MAC.
        private_lan: Exact private LAN ID for baseline admission, if applicable.
    """
    proof = _admit_ova_import(plan, vmx, repository, mac=mac, read_receipt=bound_json)
    expected_vmx_id = proof.vmx_identity
    if private_lan is not None:
        expected_vmx_id = _admit_private_lan(plan, repository, vmx, mac, private_lan, proof)
    _verify_backings(vmx, proof.original, expected_vmx_id, mac, proof.vmnet, private_lan)
    return proof.original


@dataclass(frozen=True)
class _OvaImportProof:
    """Original OVA identity and network inputs shared by the reader and transition."""

    original: dict
    original_path: Path
    invocation: str
    vmnet: str
    vmx_identity: str


def _admit_ova_import(
    plan: dict, vmx: Path, repository: Path, *, mac: str, read_receipt: Callable[[dict], dict],
) -> _OvaImportProof:
    """Verify the original import, isolation and boot receipt chain.

    Args:
        plan: Trusted-host selectors with original import and boot references.
        vmx: Original imported appliance path.
        repository: Admitted checkout for Git ancestry checks.
        mac: Original management MAC.
        read_receipt: Digest-bound reader supplied by the owning operation.
    """
    if (plan.get("trust_model") != "trusted-host" or plan.get("repository", "mdaneri/Atlaso") != "mdaneri/Atlaso"
            or not repository.is_absolute() or not vmx.is_relative_to(repository / "test-results") or ".." in vmx.parts):
        raise Refusal("ova_requires_trusted_host")
    original_ref = plan["appliance_ownership"]
    original = read_receipt(original_ref)
    commit = original["source_commit"]
    require_ancestor(repository, commit, plan["source_commit"])
    head = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), "rev-parse", "--show-toplevel", "HEAD"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    lines = head.stdout.splitlines()
    if head.returncode or len(lines) != 2 or Path(lines[0]) != repository or lines[1] != plan["source_commit"]:
        raise Refusal("ova_reviewed_checkout_mismatch")
    if plan.get("resource_source_commit", commit) != commit:
        raise Refusal("ova_creation_source_mismatch")
    intent_ref = plan["appliance_intent"]
    previous = {"intent": {"Path": intent_ref.get("original_path", intent_ref["path"]), "Sha256": intent_ref["sha256"]}}
    if read_receipt(intent_ref) != read_receipt({"path": previous["intent"]["Path"], "sha256": intent_ref["sha256"]}):
        raise Refusal("ova_import_intent_reference_invalid")
    records = {"original": original}
    phases = ("intent", "process", "directory", "terminal", "original")
    invocation = original["invocation_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", invocation) or Path(original["worktree"]) != repository:
        raise Refusal("ova_import_scope_invalid")
    original_path = Path(original_ref.get("original_path", original_ref["path"]))
    if (original_path.parent.name != ".task-ownership" or not repository.is_relative_to(original_path.parent.parent)
            or original_path.name != f"atlaso-test-vm-ova-import-original-{invocation}.json"
            or read_receipt({"path": str(original_path), "sha256": original_ref["sha256"]}) != original):
        raise Refusal("ova_import_original_reference_invalid")
    for index, phase in enumerate(phases):
        ref = previous["intent"] if phase == "intent" else original[phase] if phase != "original" else None
        if ref is not None:
            ref_path = Path(ref["Path"])
            if (ref_path.parent != original_path.parent
                    or ref_path.name != f"atlaso-test-vm-ova-import-{phase}-{invocation}.json"):
                raise Refusal("ova_import_phase_reference_invalid")
            records[phase] = read_receipt({"path": ref["Path"], "sha256": ref["Sha256"]})
        record = records[phase]
        if (type(record["schema"]) is not int or record["schema"] != 1 or record["phase"] != f"ova-import-{phase}"
                or record["task_id"] != plan["task_id"] or record["repository"] != "mdaneri/Atlaso"
                or record["pull_request_number"] != plan["pr"] or record["vmx_path"] != str(vmx)
                or record["output_directory"] != str(vmx.parent) or record["worktree"] != original["worktree"]
                or record["source_commit"] != commit or record["invocation_id"] != invocation
                or any(record[parent] != previous[parent] for parent in phases[:index])):
            raise Refusal("ova_import_phase_binding_mismatch")
        if ref is not None:
            previous[phase] = ref

    terminal = records["terminal"]["terminal"]
    process = records["process"]
    intent = records["intent"]
    require_ancestor(repository, intent["archive_source_commit"], commit)
    if (not re.fullmatch(r"[0-9a-f]{64}", intent["archive_sha256"])
            or type(intent["archive_bytes"]) is not int or intent["archive_bytes"] <= 0
            or Path(intent["working_directory"]) != repository):
        raise Refusal("ova_import_archive_binding_invalid")
    if (original["powered_off"] is not True or records["directory"]["directory_identity"] != original["directory_identity"]
            or terminal["Outcome"] != "succeeded" or terminal["WholeJobEmpty"] is not True
            or type(terminal["RootExitCode"]) is not int or terminal["RootExitCode"] != 0
            or type(process["root_pid"]) is not int or process["root_pid"] <= 0
            or terminal["RootProcessId"] != process["root_pid"] or terminal["RootStartTimeUtc"] != process["root_start_utc"]
            or terminal["ProcessJobName"] != process["job_name"] or process["job_name"] != intent["job_name"]
            or terminal["DeadlineUtc"] != intent["deadline_utc"]):
        raise Refusal("ova_import_not_completed")

    boot_ref = plan["appliance_ova_boot"]
    boot_closeout = read_receipt(boot_ref)
    boot = _linked(boot_ref, boot_closeout["independent_boot"], read_receipt=read_receipt)
    isolation_ref = plan["appliance_ova_isolation"]
    isolation = read_receipt(isolation_ref)
    result = _sibling(isolation_ref, isolation["result"], isolation["result_sha256"], read_receipt=read_receipt)
    acl = _linked(boot_ref, boot_closeout["credential_acl"], read_receipt=read_receipt)
    readback_ref = plan["appliance_ova_import_readback"]
    readback = read_receipt(readback_ref)
    if (any(row["head"] != commit for row in (boot_closeout, boot, isolation, result, readback, acl))
            or any(row["vmx"] != str(vmx) for row in (boot, isolation, result, readback, acl))
            or readback["original_receipt"] != str(original_path)
            or readback["terminal"] != terminal or readback["disk_inspection"] != original["disk_inspection"]
            or any(row["directory_identity"] != original["directory_identity"] for row in (boot, result, readback, acl))
            or result["task_id"] != plan["task_id"] or result["pr"] != plan["pr"]
            or result["original_import"] != Path(readback_ref["path"]).name
            or isolation["before_sha256"] != original["disk_inspection"]["vmx_sha256"]
            or isolation["disk_inspection"]["disks"] != original["disk_inspection"]["disks"]
            or isolation["vmx_sha256"] != result["after_sha256"] or isolation["powered_off"] is not True
            or isolation["management_connected"] is not True or isolation["services_connected"] is not False
            or acl["isolation_sha256"] != isolation_ref["sha256"] or acl["restricted_acl_verified"] is not True
            or type(boot["actual_exit"]) is not int or boot["actual_exit"] != 0 or boot["native_customization"] != "vmware-customization-complete"
            or boot["runtime_and_persisted_ovf_empty"] is not True
            or boot["readiness"]["VmxPath"] != str(vmx) or boot["readiness"]["MacAddress"].replace("-", ":").lower() != mac):
        raise Refusal("ova_original_boot_binding_mismatch")

    vmnet = isolation["vmnet"]
    if not re.fullmatch(r"vmnet[1-9][0-9]*", vmnet) or plan.get("management_vmnet", vmnet) != vmnet:
        raise Refusal("ova_original_network_invalid")
    return _OvaImportProof(original, original_path, invocation, vmnet, boot["vmx_identity"])


def _admit_private_lan(plan: dict, repository: Path, vmx: Path, mac: str, private_lan: str,
                       proof: _OvaImportProof) -> str:
    """Verify the completed private-LAN transition and return its VMX identity.

    Args:
        plan: Trusted-host selectors including the original transition receipts.
        repository: Admitted checkout for ancestry checks.
        vmx: Original imported appliance path.
        mac: Original management MAC.
        private_lan: Exact registered private LAN ID.
        proof: Verified original import and boot identity.
    """
    rewire_ref = plan["appliance_ova_private_lan"]
    rewire_intent_ref = plan["appliance_ova_private_lan_intent"]
    transition_paths = ova_private_lan_receipt_paths(proof.original_path, proof.invocation)
    rewire_intent, rewire = (
        _bound_original_transition(ref, expected)
        for ref, expected in zip((rewire_intent_ref, rewire_ref), transition_paths, strict=True)
    )
    for record in (rewire_intent, rewire):
        require_ancestor(repository, record["source_commit"], plan["source_commit"])
    _verify_private_lan_receipts(
        rewire_intent, rewire, _private_lan_binding(plan, vmx, mac, private_lan, proof),
        intent_path=rewire_intent_ref.get("original_path", rewire_intent_ref["path"]),
        intent_sha256=rewire_intent_ref["sha256"],
    )
    return rewire["vmx_identity"]


def _private_lan_binding(plan: dict, vmx: Path, mac: str, segment_id: str, proof: _OvaImportProof) -> dict:
    """Bind both producer and verifier to the same original appliance and segment.

    Args:
        plan: Trusted-host selectors including the original segment receipt.
        vmx: Original imported appliance path.
        mac: Original management MAC.
        segment_id: Exact registered private LAN ID.
        proof: Verified original import and boot identity.
    """
    segment_ref = plan["trusted_host"]["segment_receipt"]
    return {
        "task_id": plan["task_id"], "repository": plan["repository"], "pr": plan["pr"],
        "vmx_path": str(vmx), "directory_identity": proof.original["directory_identity"],
        "import_sha256": plan["appliance_ownership"]["sha256"], "boot_sha256": plan["appliance_ova_boot"]["sha256"],
        "segment_id": segment_id, "mac": mac, "segment_receipt_sha256": segment_ref["sha256"],
        "segment_receipt_path": segment_ref["path"], "before_vmx_identity": proof.vmx_identity,
    }


def ova_private_lan_receipt_paths(original_import: Path, invocation: str) -> tuple[Path, Path]:
    """Derive the one transition claim and completion from the original import.

    Args:
        original_import: Original import completion in the task ownership directory.
        invocation: Original import invocation identifier.
    """
    if (not re.fullmatch(r"[0-9a-f]{32}", invocation) or not original_import.is_absolute()
            or ".." in original_import.parts or original_import.parent.name != ".task-ownership"
            or original_import.name != f"atlaso-test-vm-ova-import-original-{invocation}.json"):
        raise Refusal("ova_private_lan_import_reference_invalid")
    return (
        original_import.with_name(f"atlaso-test-vm-ova-private-lan-intent-{invocation}.json"),
        original_import.with_name(f"atlaso-test-vm-ova-private-lan-complete-{invocation}.json"),
    )


def _bound_original_transition(reference: dict, expected_path: Path) -> dict:
    """Bind a transition receipt to the import's unique original claim paths.

    Args:
        reference: Digest-bound receipt selector, possibly with a retained copy.
        expected_path: Canonical original receipt path for this import.
    """
    original = reference.get("original_path", reference["path"])
    if original != str(expected_path):
        raise Refusal("ova_private_lan_original_reference_invalid")
    value = bound_json({"path": original, "sha256": reference["sha256"]})
    if reference["path"] != original and bound_json(reference) != value:
        raise Refusal("ova_private_lan_original_reference_invalid")
    return value


def _verify_private_lan_receipts(
    intent: dict, completion: dict, binding: dict, *, intent_path: str, intent_sha256: str,
) -> None:
    """Verify that one stopped VMX edit completed under its original intent.

    Args:
        intent: Original durable receipt published before the edit.
        completion: Original durable receipt published after exclusive readback.
        binding: Independently admitted resource, boot and segment identity.
        intent_path: Original path of the pre-write receipt.
        intent_sha256: Independent digest of the pre-write receipt.
    """
    for record, phase in ((intent, "ova-private-lan-pending"), (completion, "ova-private-lan-complete")):
        if (type(record.get("schema")) is not int or record["schema"] != 1
                or record.get("phase") != phase or any(record.get(key) != value for key, value in binding.items())):
            raise Refusal("ova_private_lan_binding_mismatch")
    if (completion.get("intent_sha256") != intent_sha256 or completion.get("intent_path") != intent_path
            or completion.get("source_commit") != intent.get("source_commit")
            or completion.get("vmx_identity") != binding["before_vmx_identity"]):
        raise Refusal("ova_private_lan_intent_mismatch")
    for key in ("before_sha256", "after_sha256"):
        value = intent.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) or completion.get(key) != value:
            raise Refusal("ova_private_lan_digest_mismatch")
    if (intent["before_sha256"] == intent["after_sha256"]
            or completion.get("readback_sha256") != intent["after_sha256"]):
        raise Refusal("ova_private_lan_readback_mismatch")


def _verify_backings(vmx: Path, original: dict, vmx_identity: str, mac: str, vmnet: str, private_lan: str | None) -> None:
    """Verify the live appliance against the admitted original backing identities.

    Args:
        vmx: Exact original VMX path.
        original: Original import record with directory and disk identities.
        vmx_identity: Admitted post-boot or private-LAN VMX identity.
        mac: Original management MAC.
        vmnet: Original host-only network.
        private_lan: Admitted private LAN when the appliance has moved to it.
    """
    from scripts.virtualization.inspect_workstation_ova_disks import _read_assignments

    files = WindowsFiles()
    with public_file(vmx), files.opened(vmx.parent, directory=True) as (_, directory, _):
        if (_native_id(list(directory)) != original["directory_identity"]
                or files.mutable_file_identity(vmx) != vmx_identity):
            raise Refusal("ova_original_identity_changed")
        with vmx.open("rb") as stream:
            values = _read_assignments(stream.read(1048577))
        for name, identity in _expected_backings(values, original).items():
            if files.mutable_file_identity(vmx.parent / name) != identity:
                raise Refusal("ova_original_disk_changed")
        _verify_network(values, mac, vmnet, private_lan)


def _expected_backings(values: dict[str, str], original: dict) -> dict[str, str]:
    """Match every VMX disk slot to its original ordinary backing.

    Args:
        values: Assignments parsed from the original VMX.
        original: Original OVA import receipt.
    """
    disks = original["disk_inspection"]["disks"]
    if [(disk["slot"], disk["role"], disk["virtual_size_bytes"]) for disk in disks] != [
        (0, "photon_os", 40 << 30), (1, "atlaso_system", 20 << 30),
        (2, "atlaso-depot", 500 << 30), (3, "atlaso-backups", 500 << 30),
    ] or len({_native_id(disk["identity"]) for disk in disks}) != 4:
        raise Refusal("ova_original_disk_layout_invalid")
    expected_devices = {f"scsi0:{disk['slot']}" for disk in disks}
    present_devices = {key.removesuffix(".present") for key, value in values.items()
                       if re.fullmatch(r"(?:scsi|sata|ide|nvme)\d+:\d+\.present", key) and value.lower() == "true"}
    if (present_devices != expected_devices or values.get("scsi0.present", "").lower() != "true"
            or values.get("scsi0.virtualdev", "").lower() != "pvscsi"):
        raise Refusal("ova_original_disk_layout_changed")
    backings = {}
    for disk in disks:
        name = disk["file"]
        prefix = f"scsi0:{disk['slot']}."
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]*\.vmdk", name, re.I)
                or values.get(prefix + "filename") != name
                or values.get(prefix + "devicetype", "scsi-harddisk").lower() not in {"disk", "scsi-harddisk"}):
            raise Refusal("ova_original_disk_changed")
        backings[name] = _native_id(disk["identity"])
    if len(backings) != len(disks):
        raise Refusal("ova_original_disk_layout_invalid")
    return backings


@contextmanager
def pin_stopped_ova_backings(vmx: Path, before: bytes, original: dict) -> Iterator[None]:
    """Retain the original directory and all disk handles while a stopped VM is edited.

    Args:
        vmx: Admitted original VMX path under its retained directory.
        before: Exact admitted VMX bytes before the private LAN transition.
        original: Original import receipt containing directory and disk identities.
    """
    from scripts.virtualization.inspect_workstation_ova_disks import _read_assignments

    if not vmx.is_absolute() or ".." in vmx.parts:
        raise Refusal("ova_private_lan_writer_selector_invalid")
    backings = _expected_backings(_read_assignments(before), original)
    files = WindowsFiles()
    with ExitStack() as pins:
        for parent in reversed(vmx.parents):
            _, directory, _ = pins.enter_context(files.opened(parent, directory=True))
            if parent == vmx.parent and _native_id(list(directory)) != original["directory_identity"]:
                raise Refusal("ova_original_identity_changed")
        for name, expected in backings.items():
            _, identity, _ = pins.enter_context(files.opened(vmx.parent / name))
            if _native_id(list(identity)) != expected:
                raise Refusal("ova_original_disk_changed")
        yield


def _verify_network(values: dict[str, str], mac: str, vmnet: str, private_lan: str | None) -> None:
    """Require the original adapter layout before or after the private-LAN move.

    Args:
        values: Parsed VMX assignments.
        mac: Original management MAC.
        vmnet: Original host-only network retained on the disconnected services NIC.
        private_lan: Exact registered private LAN ID, when attached.
    """
    expected = {
        "ethernet0.present": "true", "ethernet0.startconnected": "true",
        "ethernet0.connectiontype": "pvn" if private_lan else "custom",
        "ethernet0.allowguestconnectioncontrol": "false", "ethernet0.virtualdev": "vmxnet3",
        "ethernet0.addresstype": "generated", "ethernet0.generatedaddress": mac,
        "ethernet1.present": "true", "ethernet1.startconnected": "false",
        "ethernet1.connectiontype": "custom", "ethernet1.vnet": vmnet,
        "ethernet1.allowguestconnectioncontrol": "false", "ethernet1.virtualdev": "vmxnet3",
    }
    expected["ethernet0.pvnid" if private_lan else "ethernet0.vnet"] = private_lan or vmnet
    incompatible = {"ethernet0.address", "ethernet1.pvnid", "ethernet0.vnet" if private_lan else "ethernet0.pvnid"}
    if (any(values.get(key, "").lower() != value.lower() for key, value in expected.items())
            or incompatible.intersection(values)
            or any(re.fullmatch(r"ethernet(?![01]\.)\d+\.present", key) and val.lower() == "true"
                   for key, val in values.items())
            or values.get("guestinfo.ovfenv", "") not in {"", "|22|22"}):
        raise Refusal("ova_original_network_changed")


def render_ova_private_lan(data: bytes, *, mac: str, vmnet: str, segment_id: str) -> bytes:
    """Render only the management NIC move in an admitted stopped VMX.

    Args:
        data: Original VMX bytes retained by the owning transition.
        mac: Original generated management MAC.
        vmnet: Original host-only network of both adapters.
        segment_id: Exact registered private LAN ID.
    """
    from scripts.virtualization.inspect_workstation_ova_disks import _read_assignments

    if not re.fullmatch(r"52(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}", segment_id):
        raise Refusal("ova_private_lan_segment_invalid")
    original = _read_assignments(data)
    _verify_network(original, mac, vmnet, None)
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    normalized = data.replace(newline, b"") if newline == b"\r\n" else data
    if b"\r" in normalized or (newline == b"\r\n" and b"\n" in normalized):
        raise Refusal("ova_private_lan_line_endings_invalid")
    changes = (
        (b"connectionType", b"custom", b"connectionType", b"pvn"),
        (b"vnet", vmnet.encode("ascii"), b"pvnID", segment_id.encode("ascii")),
    )
    updated = data
    for key, old_value, new_key, new_value in changes:
        pattern = rb'(?im)^([ \t]*ethernet0\.)' + key + rb'([ \t]*=[ \t]*")' + re.escape(old_value) + rb'("[ \t]*\r?$)'
        replacement = rb"\g<1>" + new_key + rb"\g<2>" + new_value + rb"\g<3>"
        updated, count = re.subn(pattern, replacement, updated)
        if count != 1:
            raise Refusal("ova_private_lan_assignment_changed")
    parsed = _read_assignments(updated)
    _verify_network(parsed, mac, vmnet, segment_id)
    expected = {**original, "ethernet0.connectiontype": "pvn", "ethernet0.pvnid": segment_id}
    del expected["ethernet0.vnet"]
    if parsed != expected:
        raise Refusal("ova_private_lan_unrelated_assignment_changed")
    return updated


def prepare_ova_private_lan_edit(
    before: bytes, binding: dict, *, source_commit: str, vmnet: str,
) -> tuple[bytes, bytes]:
    """Prepare replacement bytes and an intent payload for the owning controller.

    Args:
        before: Original VMX bytes from the admitted appliance.
        binding: Independently verified import, boot and LAN selectors.
        source_commit: Current source of the transition.
        vmnet: Original host-only adapter network.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise Refusal("ova_private_lan_source_invalid")
    after = render_ova_private_lan(before, mac=binding["mac"], vmnet=vmnet, segment_id=binding["segment_id"])
    intent = {
        **binding, "schema": 1, "phase": "ova-private-lan-pending", "source_commit": source_commit,
        "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest(),
    }
    return after, (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def prepare_ova_private_lan_completion(
    intent_bytes: bytes, readback: bytes, binding: dict, *, intent_path: str, vmx_identity: str,
) -> dict:
    """Prepare a completion payload from original intent bytes and exact readback.

    Args:
        intent_bytes: Exact durable intent bytes read from their original pin.
        readback: Exact replacement bytes read through the original VMX handle.
        binding: Independently verified import, boot and LAN selectors.
        intent_path: Original intent path.
        vmx_identity: Live original VMX identity from the writer handle.
    """
    intent = json.loads(intent_bytes)
    completion = {
        **intent, "phase": "ova-private-lan-complete", "intent_path": intent_path,
        "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(), "vmx_identity": vmx_identity,
        "readback_sha256": hashlib.sha256(readback).hexdigest(),
    }
    _verify_private_lan_receipts(
        intent, completion, binding, intent_path=intent_path, intent_sha256=completion["intent_sha256"],
    )
    return completion


@contextmanager
def open_ova_vmx_writer(path: Path, expected_identity: str) -> Iterator[BinaryIO]:
    """Hold an exclusive writer on the exact original ordinary VMX.

    Args:
        path: Absolute admitted VMX path under the pinned original appliance.
        expected_identity: Original Windows volume and file index.
    """
    if os.name != "nt":
        raise Refusal("ova_private_lan_requires_windows")
    if not path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{16}", expected_identity):
        raise Refusal("ova_private_lan_writer_selector_invalid")

    import msvcrt

    files = WindowsFiles()
    with ExitStack() as pins:
        for parent in reversed(path.parents):
            pins.enter_context(files.opened(parent, directory=True))
        # OPEN_EXISTING and OPEN_REPARSE_POINT preserve the leaf identity. Deny
        # write and delete sharing, including competing VMware config writers.
        handle = files.kernel.CreateFileW(str(path), 0xC0000000, 1, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise Refusal("ova_private_lan_writer_unavailable")
        descriptor = None
        try:
            information = (ctypes.c_uint32 * 13)()
            if (not files.kernel.GetFileInformationByHandle(handle, information)
                    or information[0] & (0x10 | 0x400) or information[10] != 1
                    or _native_id([information[7], information[11], information[12]]) != expected_identity):
                raise Refusal("ova_private_lan_writer_identity_changed")
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        finally:
            if descriptor is None:
                files.kernel.CloseHandle(handle)
        with os.fdopen(descriptor, "r+b", buffering=0) as stream:
            yield stream


def assert_ova_stopped(vmx: Path, before: bytes, vmrun: Path) -> None:
    """Require a stopped OVA while the caller retains its VMX and disk pins.

    Args:
        vmx: Exact original owned appliance path.
        before: Exact original VMX bytes retained by the caller.
        vmrun: Already admitted and pinned VMware executable.
    """
    from scripts.interop.certificate_trusted_host import _normalized_path, _run_vmrun
    from scripts.virtualization.inspect_workstation_ova_disks import _read_assignments

    if _read_assignments(before).get("checkpoint.vmstate", ""):
        raise Refusal("ova_private_lan_appliance_suspended")
    running, _ = _run_vmrun(vmrun)
    if any(_normalized_path(path) == _normalized_path(vmx) for path in running):
        raise Refusal("ova_private_lan_appliance_running")
    if any(path.suffix.lower() in {".lck", ".vmss"} for path in vmx.parent.iterdir()):
        raise Refusal("ova_private_lan_appliance_locked")


def _publish_ova_transition(path: Path, payload: bytes) -> os.stat_result:
    """Publish an original without replacing a claim or an interrupted stage.

    Args:
        path: Deterministic original path in a retained ownership directory.
        payload: Exact public receipt bytes to write.
    """
    stage = path.with_name(f".{path.name}.pending")
    with stage.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
        staged = os.fstat(stream.fileno())
    publish_durable_file(stage, path)
    with public_file(path), path.open("rb") as stream:
        original = os.fstat(stream.fileno())
        if (not staged.st_ino or (original.st_dev, original.st_ino) != (staged.st_dev, staged.st_ino)
                or stream.read(len(payload) + 1) != payload):
            raise Refusal("ova_private_lan_receipt_publication_changed")
        return original


def write_ova_private_lan(
    open_writer: Callable[[], AbstractContextManager[BinaryIO]], before: bytes, binding: dict,
    *, source_commit: str, vmnet: str,
    original_import: Path, invocation: str, admit_write: Callable[[], str],
) -> None:
    """Publish an intent, write through the retained VMX handle and verify readback.

    Args:
        open_writer: Open the original VMX without write or delete sharing after the claim.
        before: Admitted original VMX bytes read before the exclusive writer was opened.
        binding: Independently admitted original import, boot and segment selectors.
        source_commit: Current source of the transition.
        vmnet: Original host-only adapter network.
        original_import: Original import completion in the retained ownership directory.
        invocation: Original import invocation identifier.
        admit_write: Owner check of current stopped state and original writer identity.
    """
    if os.name != "nt":
        raise Refusal("ova_private_lan_requires_windows")
    intent_path, completion_path = ova_private_lan_receipt_paths(original_import, invocation)
    for path in (intent_path, completion_path):
        if os.path.lexists(path) or os.path.lexists(path.with_name(f".{path.name}.pending")):
            raise Refusal("ova_private_lan_attempt_already_claimed")
    after, intent = prepare_ova_private_lan_edit(before, binding, source_commit=source_commit, vmnet=vmnet)
    published = _publish_ova_transition(intent_path, intent)
    with WindowsFiles().opened(intent_path), intent_path.open("rb") as claim:
        retained = os.fstat(claim.fileno())
        if ((retained.st_dev, retained.st_ino) != (published.st_dev, published.st_ino)
                or claim.read(len(intent) + 1) != intent):
            raise Refusal("ova_private_lan_receipt_publication_changed")
        with open_writer() as writer:
            writer.seek(0)
            if writer.read(len(before) + 1) != before:
                raise Refusal("ova_private_lan_original_bytes_changed")
            identity = admit_write()
            if identity != binding["before_vmx_identity"]:
                raise Refusal("ova_private_lan_writer_identity_changed")
            writer.seek(0)
            if writer.write(after) != len(after):
                raise Refusal("ova_private_lan_short_write")
            writer.truncate(len(after))
            writer.flush()
            os.fsync(writer.fileno())
            writer.seek(0)
            readback = writer.read(len(after) + 1)
            if readback != after:
                raise Refusal("ova_private_lan_readback_mismatch")
            completion = prepare_ova_private_lan_completion(
                intent, readback, binding, intent_path=str(intent_path), vmx_identity=identity,
            )
            _publish_ova_transition(completion_path, (json.dumps(completion, sort_keys=True) + "\n").encode("utf-8"))


def _transition_stopped_ova(plan: dict, repository: Path, *, vmrun_sha256: str) -> None:
    """Move the management NIC of the original stopped appliance under held pins.

    The owning controller must first admit its current source, host scope and
    task resources. The peer fixture must already have created the private LAN.

    Args:
        plan: Digest-admitted trusted-host plan and original receipt selectors.
        repository: Exact admitted checkout.
        vmrun_sha256: Independently admitted digest of the local VMware executable.
    """
    from scripts.interop.certificate_trusted_host import (
        _ordinary_file,
        _segment_creation_source,
        _validate_plan,
        verify_registered_segment,
    )
    from scripts.virtualization.inspect_workstation_ova_disks import _read_assignments

    host = _validate_plan(plan)
    if not isinstance(plan.get("peer_fixture"), dict):
        raise Refusal("ova_private_lan_peer_fixture_required")
    adapter = host.get("appliance_private_adapter")
    if (not isinstance(adapter, dict) or type(adapter.get("index")) is not int or adapter["index"] != 0
            or not isinstance(adapter.get("mac"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", adapter["mac"])):
        raise Refusal("ova_private_lan_adapter_invalid")
    vmx = Path(host["appliance_vmx"])
    mac = adapter["mac"]
    segment = host["segment_id"]
    segment_ref = host["segment_receipt"]
    preferences_path = Path(host["preferences_path"])
    vmrun = Path(host["vmrun_path"])
    original_ref = plan["appliance_ownership"]
    ownership = Path(original_ref.get("original_path", original_ref["path"])).parent
    files = WindowsFiles()
    with ExitStack() as pins:
        def pin_input(path: Path) -> None:
            """Protect original inputs while allowing sibling receipt publication.

            Args:
                path: Absolute path to the file whose original handle remains pinned.
            """
            if not path.is_absolute() or ".." in path.parts:
                raise Refusal("public_input_path_invalid")
            for parent in reversed(path.parents):
                pins.enter_context(files.opened(parent, directory=True, allow_child_publication=parent == ownership))
            pins.enter_context(files.opened(path))

        def pinned_receipt(reference: dict) -> dict:
            """Keep every validated original receipt pinned through completion.

            Args:
                reference: Original receipt path and independently retained digest.
            """
            pin_input(Path(reference["path"]))
            return bound_json(reference)

        proof = _admit_ova_import(plan, vmx, repository, mac=mac, read_receipt=pinned_receipt)
        for path in (
            Path(plan["peer_fixture"]["path"]), Path(segment_ref["path"]), preferences_path, vmrun,
        ):
            pin_input(path)
        segment_source = _segment_creation_source(plan, host)
        require_ancestor(repository, segment_source, plan["source_commit"])
        catalog, preferences = _ordinary_file(host["preferences_path"], "trusted_host_preferences_invalid")
        _, segment_bytes = _ordinary_file(segment_ref["path"], "trusted_host_segment_receipt_invalid", limit=262144)
        verify_registered_segment(
            preferences, segment_bytes, expected_sha256=segment_ref["sha256"], task_id=plan["task_id"],
            repository=plan["repository"], pr=plan["pr"], source_commit=segment_source,
            name=host["segment_name"], segment_id=segment,
        )
        original_catalog = json.loads(segment_bytes).get("preferences_path")
        if (not isinstance(original_catalog, str) or not Path(original_catalog).is_absolute()
                or ".." in Path(original_catalog).parts or Path(original_catalog) != catalog):
            raise Refusal("ova_private_lan_catalog_reference_mismatch")
        with vmrun.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != vmrun_sha256:
                raise Refusal("ova_private_lan_vmrun_digest_mismatch")

        with public_file(vmx):
            if files.mutable_file_identity(vmx) != proof.vmx_identity:
                raise Refusal("ova_original_identity_changed")
            with vmx.open("rb") as stream:
                before = stream.read(1048577)
            _verify_network(_read_assignments(before), mac, proof.vmnet, None)
            pins.enter_context(pin_stopped_ova_backings(vmx, before, proof.original))
            assert_ova_stopped(vmx, before, vmrun)

        def admit_write() -> str:
            """Recheck the stopped state after opening the identity-bound writer."""
            assert_ova_stopped(vmx, before, vmrun)
            return proof.vmx_identity

        write_ova_private_lan(
            lambda: open_ova_vmx_writer(vmx, proof.vmx_identity), before,
            _private_lan_binding(plan, vmx, mac, segment, proof),
            source_commit=plan["source_commit"], vmnet=proof.vmnet,
            original_import=proof.original_path, invocation=proof.invocation, admit_write=admit_write,
        )


def _run_owned_ova_transition(
    plan_path: Path, plan_sha256: str, repository: Path, vmx: Path, task_id: str, pr: int,
    source_commit: str, evidence_directory: Path, evidence_identity: str, vmrun_sha256: str,
) -> None:
    """Check the owning wrapper's selectors before entering the stopped transition.

    Args:
        plan_path: Original public plan beneath the task checkout's test-results.
        plan_sha256: Independently recorded digest of the plan.
        repository: Source-pinned task checkout.
        vmx: Canonical appliance path admitted by the ownership context.
        task_id: Task ID from the active ownership context.
        pr: PR number from the active ownership context.
        source_commit: Commit retained by the wrapper's checkout source pin.
        evidence_directory: Original ownership evidence directory.
        evidence_identity: Windows identity from the ownership context.
        vmrun_sha256: Independently verified digest of the VMware executable.
    """
    if not plan_path.is_relative_to(repository / "test-results"):
        raise Refusal("ova_private_lan_plan_outside_worktree")
    with public_file(plan_path):
        plan = bound_json({"path": str(plan_path), "sha256": plan_sha256})
        expected = {"task_id": task_id, "pr": pr, "source_commit": source_commit, "repository": "mdaneri/Atlaso"}
        if any(plan.get(key) != value for key, value in expected.items()) or type(plan.get("pr")) is not int:
            raise Refusal("ova_private_lan_plan_scope_mismatch")
        if plan["trusted_host"]["appliance_vmx"] != str(vmx):
            raise Refusal("ova_private_lan_plan_scope_mismatch")
        original_ref = plan["appliance_ownership"]
        if Path(original_ref.get("original_path", original_ref["path"])).parent != evidence_directory:
            raise Refusal("ova_private_lan_ownership_directory_mismatch")
        with WindowsFiles().opened(evidence_directory, directory=True, allow_child_publication=True) as (_, native, _):
            if _native_id(list(native)) != evidence_identity:
                raise Refusal("ova_private_lan_ownership_directory_mismatch")
            _transition_stopped_ova(plan, repository, vmrun_sha256=vmrun_sha256)


def admit_ova_runtime(plan: dict) -> dict:
    """Bind the exact wheel and helper to the original OVA boot and runtime evidence.

    Args:
        plan: OVA baseline plan with original runtime and first-boot selectors.
    """
    if (plan.get("trust_model") != "trusted-host" or plan.get("ordinary_ca_baseline_mode") != "dhcp"
            or plan.get("scenario") != "ordinary-ca-rotation" or "iso_wheel_deployment" in plan
            or "installed_inspection" in plan):
        raise Refusal("ova_requires_original_dhcp_baseline")
    reference = plan["appliance_ova_runtime"]
    runtime = bound_json(reference)
    deployment = _linked(reference, runtime["canonical_deployment"])
    installed = _linked(reference, runtime["installed_readback"])
    expected = _linked(reference, runtime["expected"])
    boot_ref = plan["appliance_ova_boot"]
    boot = _linked(boot_ref, bound_json(boot_ref)["independent_boot"])
    admission = bound_json(plan["appliance_ova_deploy_admission"])
    facts = runtime["measured"]
    commit = plan["deployed_commit"]
    if (not re.fullmatch(r"[0-9a-f]{40}", commit) or runtime["head"] != commit or runtime["deployed_commit"] != commit
            or runtime["appliance"]["sha256"] != boot_ref["sha256"] or runtime["appliance"]["vmx"] != plan["vmx_path"]
            or runtime["appliance"]["receipt"] != Path(boot_ref["path"]).name
            or expected["head"] != commit or deployment["head"] != commit or deployment["actual_exit"] != 0
            or installed["actual_exit"] != 0 or installed["report"] != facts
            or boot["appliance_ssh_host_key_fingerprint"] != plan["appliance_ssh_host_key"]
            or type(facts["schema"]) is not int or facts["schema"] != 1
            or facts["mac"] != plan["mac"].replace("-", ":").lower() or facts["interface"] != "eth0"
            or facts["address"] != boot["readiness"]["IPAddress"] or facts["default_routes"] is not False
            or type(facts["verified_payload_files"]) is not int or facts["verified_payload_files"] <= 0
            or facts["installed_payload_sha256"] != facts["wheel_payload_sha256"]
            or any(not re.fullmatch(r"[0-9a-f]{64}", facts[key]) or facts[key] != expected[key]
                   for key in ("wheel_sha256", "helper_sha256", "wheel_payload_sha256"))
            or facts["verified_payload_files"] != expected["verified_payload_files"]
            or admission["head"] != commit or admission["vmx"] != plan["vmx_path"]
            or admission["first_boot"] != Path(boot_ref["path"]).name
            or admission["address"] != facts["address"] or admission["wheel_sha256"] != facts["wheel_sha256"]
            or admission["helper_sha256"] != facts["helper_sha256"]):
        raise Refusal("ova_original_runtime_mismatch")
    remote = plan["appliance_ova_remote_wheel"]
    if (not re.fullmatch(r"/var/tmp/atlaso-ova-deploy-[0-9a-f]{32}/atlaso-[0-9]+\.[0-9]+\.[0-9]+-py3-none-any\.whl", remote)
            or remote.rsplit("/", 1)[0] != admission["remote"]
            or Path(remote).name != f'atlaso-{runtime["https"]["version"]}-py3-none-any.whl'):
        raise Refusal("ova_runtime_wheel_path_invalid")
    return facts
