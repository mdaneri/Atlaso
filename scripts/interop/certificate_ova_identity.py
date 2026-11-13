"""Verify original OVA import, first-boot and runtime evidence for certificate fixtures."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from scripts.completed_task_files import WindowsFiles
from scripts.interop.certificate_peer_factory import (
    Refusal,
    bound_json,
    public_file,
    require_ancestor,
)


def _sibling(reference: dict, name: str, digest: str) -> dict:
    """Resolve a digest-bound basename relative to the original evidence file.

    Args:
        reference: Absolute path of the referencing receipt.
        name: Original evidence filename.
        digest: Independently recorded SHA-256.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", name):
        raise Refusal("ova_evidence_name_invalid")
    return bound_json({"path": str(Path(reference["path"]).with_name(name)), "sha256": digest})


def _linked(reference: dict, link: dict) -> dict:
    """Read one sibling receipt by its original name and digest.

    Args:
        reference: Absolute path of the referencing receipt.
        link: Original relative receipt reference.
    """
    return _sibling(reference, link["receipt"], link["sha256"])


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
    if (plan.get("trust_model") != "trusted-host" or plan.get("repository", "mdaneri/Atlaso") != "mdaneri/Atlaso"
            or not repository.is_absolute() or not vmx.is_relative_to(repository / "test-results") or ".." in vmx.parts):
        raise Refusal("ova_requires_trusted_host")
    original_ref = plan["appliance_ownership"]
    original = bound_json(original_ref)
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
    if bound_json(intent_ref) != bound_json({"path": previous["intent"]["Path"], "sha256": intent_ref["sha256"]}):
        raise Refusal("ova_import_intent_reference_invalid")
    records = {"original": original}
    phases = ("intent", "process", "directory", "terminal", "original")
    invocation = original["invocation_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", invocation) or Path(original["worktree"]) != repository:
        raise Refusal("ova_import_scope_invalid")
    original_path = Path(original_ref.get("original_path", original_ref["path"]))
    if (original_path.parent.name != ".task-ownership" or not repository.is_relative_to(original_path.parent.parent)
            or original_path.name != f"atlaso-test-vm-ova-import-original-{invocation}.json"
            or bound_json({"path": str(original_path), "sha256": original_ref["sha256"]}) != original):
        raise Refusal("ova_import_original_reference_invalid")
    for index, phase in enumerate(phases):
        ref = previous["intent"] if phase == "intent" else original[phase] if phase != "original" else None
        if ref is not None:
            ref_path = Path(ref["Path"])
            if (ref_path.parent != original_path.parent
                    or ref_path.name != f"atlaso-test-vm-ova-import-{phase}-{invocation}.json"):
                raise Refusal("ova_import_phase_reference_invalid")
            records[phase] = bound_json({"path": ref["Path"], "sha256": ref["Sha256"]})
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
    boot_closeout = bound_json(boot_ref)
    boot = _linked(boot_ref, boot_closeout["independent_boot"])
    isolation_ref = plan["appliance_ova_isolation"]
    isolation = bound_json(isolation_ref)
    result = _sibling(isolation_ref, isolation["result"], isolation["result_sha256"])
    acl = _linked(boot_ref, boot_closeout["credential_acl"])
    readback_ref = plan["appliance_ova_import_readback"]
    readback = bound_json(readback_ref)
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
    expected_vmx_id = boot["vmx_identity"]
    if private_lan is not None:
        rewire_ref = plan["appliance_ova_private_lan"]
        rewire_intent_ref = plan["appliance_ova_private_lan_intent"]
        rewire = bound_json(rewire_ref)
        rewire_intent = bound_json(rewire_intent_ref)
        segment_ref = plan["trusted_host"]["segment_receipt"]
        for record, phase in ((rewire_intent, "ova-private-lan-pending"), (rewire, "ova-private-lan-complete")):
            require_ancestor(repository, record["source_commit"], plan["source_commit"])
            if (record["schema"] != 1 or record["phase"] != phase or record["task_id"] != plan["task_id"]
                    or record["repository"] != "mdaneri/Atlaso" or record["pr"] != plan["pr"]
                    or record["vmx_path"] != str(vmx) or record["directory_identity"] != original["directory_identity"]
                    or record["import_sha256"] != original_ref["sha256"] or record["boot_sha256"] != boot_ref["sha256"]
                    or record["segment_id"] != private_lan or record["mac"] != mac
                    or record["segment_receipt_sha256"] != segment_ref["sha256"]
                    or record["segment_receipt_path"] != segment_ref["path"]
                    or record["before_vmx_identity"] != boot["vmx_identity"]):
                raise Refusal("ova_private_lan_binding_mismatch")
        if (rewire["intent_sha256"] != rewire_intent_ref["sha256"]
                or rewire["intent_path"] != rewire_intent_ref.get("original_path", rewire_intent_ref["path"])
                or rewire["source_commit"] != rewire_intent["source_commit"]):
            raise Refusal("ova_private_lan_intent_mismatch")
        expected_vmx_id = rewire["vmx_identity"]

    _verify_backings(vmx, original, expected_vmx_id, mac, vmnet, private_lan)
    return original


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
        for disk in disks:
            name = disk["file"]
            prefix = f"scsi0:{disk['slot']}."
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]*\.vmdk", name, re.I)
                    or values.get(prefix + "filename") != name
                    or values.get(prefix + "devicetype", "scsi-harddisk").lower() not in {"disk", "scsi-harddisk"}
                    or files.mutable_file_identity(vmx.parent / name) != _native_id(disk["identity"])):
                raise Refusal("ova_original_disk_changed")
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
