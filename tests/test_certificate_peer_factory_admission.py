"""Windows-only admission tests for original ISO and peer source inputs."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.interop import certificate_peer_factory as factory
from scripts.virtualization.inspect_workstation_ova_disks import inspect_disks

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Factory admission pins native Windows file identities")

_TASK = "test-task-1094"
_PR = 1118
_RESOURCE_SOURCE = "a" * 40
_FACTORY_SOURCE = "b" * 40
_CLEANUP_ID = "d" * 32
_APPLIANCE_MAC = "00:50:56:2a:11:22"
_PEER_MACS = ("00:50:56:2a:11:33", "00:50:56:2a:11:44")
_CAPACITY_2_GIB = 4_194_304
_VMDK_NAME = "peer.vmdk"


def _write_json(path: Path, value: dict) -> dict[str, str]:
    """Write one fixture receipt and return its path and content digest.

    Args:
        path: Destination for the compact JSON receipt.
        value: Receipt fields serialized into the fixture file.
    """
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    path.write_bytes(payload)
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}


def _sparse_vmdk(
    *,
    name: str = _VMDK_NAME,
    capacity: int = _CAPACITY_2_GIB,
    offset: int = 1,
    sectors: int = 1,
    magic: bytes = b"KDMV",
    descriptor: str | None = None,
) -> bytes:
    """Build a minimal sparse VMDK header for disk-admission tests.

    Args:
        name: Filename used by the embedded extent declaration.
        capacity: Declared virtual disk capacity in sectors.
        offset: Grain-table offset encoded in the sparse header.
        sectors: Grain-table extent length in sectors.
        magic: Sparse-header signature bytes.
        descriptor: Optional descriptor text embedded in the header.
    """
    text = descriptor or (
        '# Disk DescriptorFile\n'
        'version=1\n'
        'CID=fffffffe\n'
        'parentCID=ffffffff\n'
        'createType="monolithicSparse"\n'
        '\n'
        '# Extent description\n'
        f'RW {capacity} SPARSE "{name}"\n'
    )
    encoded = text.encode("ascii")
    header = bytearray(512)
    header[:4] = magic
    struct.pack_into("<Q", header, 12, capacity)
    struct.pack_into("<Q", header, 28, offset)
    struct.pack_into("<Q", header, 36, sectors)
    descriptor_bytes = encoded[: max(0, sectors * 512)]
    return bytes(header) + descriptor_bytes.ljust(sectors * 512, b"\0")


@pytest.mark.parametrize(
    "damage", [None, "extra_slot", "wrong_capacity", "same_disk", "parent", "duplicate", "ambiguous_parent"],
)
def test_inspect_imported_ova_disks(tmp_path: Path, damage: str | None) -> None:
    """Inspect all materialized OVA backings and refuse ambiguous attachments.

    Args:
        tmp_path: Owned directory for the synthetic VMX and VMDK files.
        damage: Mutation applied to a conforming disk layout.
    """
    vmx = tmp_path / "imported.vmx"
    lines = ['scsi0.present = "TRUE"', 'scsi0.virtualDev = "pvscsi"']
    for slot, gib in enumerate((40, 20, 500, 500)):
        name = f"imported-disk{slot}.vmdk"
        sectors = (gib - (slot == 3 and damage == "wrong_capacity")) * 1024**3 // 512
        vmdk = _sparse_vmdk(name=name, capacity=sectors)
        if slot == 3 and damage == "parent":
            vmdk = vmdk.replace(b"parentCID=ffffffff", b"parentCID=00000000")
        if slot == 3 and damage == "ambiguous_parent":
            vmdk = vmdk.rstrip(b"\0") + b" ParentCID = 00000000\n"
            vmdk = vmdk.ljust(1024, b"\0")
        (tmp_path / name).write_bytes(vmdk)
        if slot == 3 and damage == "same_disk":
            name = "imported-disk2.vmdk"
        lines.extend([f'scsi0:{slot}.present = "TRUE"', f'scsi0:{slot}.fileName = "{name}"'])
    if damage == "extra_slot":
        lines.append('sata0:0.present = "TRUE"')
    if damage == "duplicate":
        lines.append('SCSI0:0.FILENAME = "unexpected.vmdk"')
    vmx.write_text("\n".join(lines), encoding="utf-8")

    if damage:
        with pytest.raises(factory.Refusal):
            inspect_disks(vmx)
    else:
        result = inspect_disks(vmx)
        assert result["vmx_sha256"] == hashlib.sha256(vmx.read_bytes()).hexdigest()
        assert [disk["role"] for disk in result["disks"]] == [
            "photon_os", "atlaso_system", "atlaso-depot", "atlaso-backups",
        ]


@pytest.fixture
def admitted_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Create immutable-shaped receipts and checksum-bound local source fixtures.

    Args:
        tmp_path: Pytest-owned root for source, repository, and receipt fixtures.
        monkeypatch: Pytest patch manager for capturing ancestry checks.
    """
    repo = tmp_path / "repository"
    prep_script = repo / "scripts" / "windows" / "vmware" / "prepare-tiny-linux-client.ps1"
    prep_script.parent.mkdir(parents=True)
    qcow = tmp_path / "peer-source" / "alpine.qcow2"
    disk = tmp_path / "peer-source" / _VMDK_NAME
    qcow.parent.mkdir()
    qcow.write_bytes(b"synthetic pinned qcow source\n")
    disk.write_bytes(_sparse_vmdk())
    qcow_sha512 = hashlib.sha512(qcow.read_bytes()).hexdigest()
    disk_sha256 = hashlib.sha256(disk.read_bytes()).hexdigest()
    prep_script.write_text(f"[string]$ExpectedSha512 = '{qcow_sha512}'\n", encoding="utf-8")

    appliance_root = tmp_path / "original-appliance"
    appliance_root.mkdir()
    vmx = appliance_root / f"Atlaso-PR-{_PR}-Appliance.vmx"
    cleanup_identity = _CLEANUP_ID
    with WindowsFiles().opened(appliance_root, directory=True) as (_, identity, _):
        original_directory_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"

    receipts = tmp_path / "original-receipts"
    receipts.mkdir()
    intent_path = receipts / "intent.json"
    ownership_path = receipts / "ownership.json"
    boot_path = receipts / "installed-boot.json"
    intent = {
        "schema": 1,
        "phase": "installation-pending",
        "task_id": _TASK,
        "repository": "mdaneri/Atlaso",
        "pull_request_number": _PR,
        "source_commit": _RESOURCE_SOURCE,
        "vmx_path": str(vmx),
        "output_directory": str(appliance_root),
    }
    intent_ref = _write_json(intent_path, intent)

    vmx.write_text(
        "\n".join(
            (
                f'guestinfo.atlaso.test_vm_cleanup_identity = "{cleanup_identity}"',
                'ethernet0.present = "TRUE"',
                'ethernet0.addressType = "static"',
                f'ethernet0.address = "{_APPLIANCE_MAC}"',
                'ethernet1.present = "FALSE"',
                "",
            )
        ),
        encoding="utf-8",
    )
    ownership = {
        "schema": 1,
        "phase": "original-installation-vm-created",
        "task_id": _TASK,
        "repository": "mdaneri/Atlaso",
        "pull_request_number": _PR,
        "source_commit": _RESOURCE_SOURCE,
        "vmx_path": str(vmx),
        "output_directory": str(appliance_root),
        "intent_sha256": intent_ref["sha256"],
        "original_identities": {"directory": original_directory_identity},
        "persistent_vm_identity_sha256": hashlib.sha256(cleanup_identity.encode()).hexdigest(),
        "installation_iso": {"sha256": "e" * 64},
    }
    ownership_ref = _write_json(ownership_path, ownership)
    boot = {
        "schema": 1,
        "phase": "installation-boot-without-media",
        "task_id": _TASK,
        "repository": "mdaneri/Atlaso",
        "pull_request_number": _PR,
        "source_commit": _RESOURCE_SOURCE,
        "vmx_path": str(vmx),
        "output_directory": str(appliance_root),
        "original_receipt_sha256": ownership_ref["sha256"],
        "original_receipt_path": ownership_ref["path"],
        "original_directory_identity": original_directory_identity,
    }
    boot_ref = _write_json(boot_path, boot)

    peer_preparation_path = receipts / "peer-source.json"
    peer_preparation_ref = _write_json(
        peer_preparation_path,
        {"vmdk": str(disk), "qcow2": str(qcow), "sha512": qcow_sha512},
    )
    spec = {
        "schema": 1,
        "trust_model": "trusted-host",
        "repository": "mdaneri/Atlaso",
        "pr": _PR,
        "task_id": _TASK,
        "source_commit": _FACTORY_SOURCE,
        "server_cidr": "192.168.77.1/24",
        "lease_address": "192.168.77.10",
        "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"],
        "management_vmnet": "vmnet9",
        "peer_user": "alpine",
        "peer_hostname": "certificate-peer",
        "appliance_intent": intent_ref,
        "appliance_ownership": ownership_ref,
        "appliance_installed_boot": boot_ref,
        "peer_source_preparation": peer_preparation_ref,
        "appliance_vmx": str(vmx),
        "peer_public_key_path": str(receipts / "peer.pub"),
        "peer_vmdk_sha256": disk_sha256,
        "peer_public_key_sha256": "c" * 64,
        "appliance_mac": _APPLIANCE_MAC,
    }
    ancestor_calls: list[tuple[Path, str, str]] = []
    monkeypatch.setattr(
        factory,
        "require_ancestor",
        lambda repository, source, head: ancestor_calls.append((repository, source, head)),
    )
    return SimpleNamespace(
        repo=repo,
        prep_script=prep_script,
        spec=spec,
        vmx=vmx,
        disk=disk,
        qcow=qcow,
        cleanup_identity=cleanup_identity,
        intent=intent,
        intent_path=intent_path,
        ownership=ownership,
        ownership_path=ownership_path,
        boot=boot,
        boot_path=boot_path,
        ancestor_calls=ancestor_calls,
    )


def _rewrite_reference(inputs: SimpleNamespace, record_name: str, reference_name: str) -> None:
    """Rewrite one fixture receipt and refresh its spec reference.

    Args:
        inputs: Admitted fixture state containing receipt paths and the spec.
        record_name: Receipt object and path prefix to serialize again.
        reference_name: Specification key bound to the rewritten receipt.
    """
    record = getattr(inputs, record_name)
    path = getattr(inputs, f"{record_name}_path")
    inputs.spec[reference_name] = _write_json(path, record)


def test_inspect_inputs_admits_original_iso_and_checksum_bound_standalone_peer(
    admitted_inputs: SimpleNamespace,
) -> None:
    """Admit the original ISO and checksum-bound standalone peer source.

    Args:
        admitted_inputs: Receipt-bound source fixture from the admission factory.
    """
    result = factory.inspect_inputs(admitted_inputs.spec, admitted_inputs.repo)

    assert result["source_disk"] == str(admitted_inputs.disk)
    assert result["source_qcow2"] == str(admitted_inputs.qcow)
    assert result["source_disk_sha256"] == admitted_inputs.spec["peer_vmdk_sha256"]
    preparation = json.loads(Path(admitted_inputs.spec["peer_source_preparation"]["path"]).read_text(encoding="utf-8"))
    assert result["source_qcow2_sha512"] == preparation["sha512"]
    assert result["appliance_directory_identity"] == admitted_inputs.ownership["original_identities"]["directory"]
    assert len(admitted_inputs.ancestor_calls) == 3
    assert all(call == (admitted_inputs.repo, _RESOURCE_SOURCE, _FACTORY_SOURCE)
               for call in admitted_inputs.ancestor_calls)


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("task", "original_iso_binding_mismatch"),
        ("pr", "original_iso_binding_mismatch"),
        ("path", "original_iso_binding_mismatch"),
        ("source", "original_iso_boot_mismatch"),
        ("intent_digest", "original_iso_boot_mismatch"),
        ("boot_receipt", "original_iso_boot_mismatch"),
        ("root_identity", "original_iso_directory_changed"),
        ("mac", "original_iso_native_identity_mismatch"),
        ("cleanup_identity", "original_iso_native_identity_mismatch"),
        ("duplicate_key", "original_iso_duplicate_vmx_key"),
        ("extra_nic", "original_iso_native_identity_mismatch"),
    ],
)
def test_inspect_inputs_refuses_unbound_or_changed_original_state(
    admitted_inputs: SimpleNamespace,
    case: str,
    reason: str,
) -> None:
    """Refuse changed or unbound identities in the original appliance receipts.

    Args:
        admitted_inputs: Receipt-bound source fixture from the admission factory.
        case: Binding field or source element altered for this refusal case.
        reason: Expected stable refusal identifier for the changed state.
    """
    inputs = admitted_inputs
    if case == "task":
        inputs.ownership["task_id"] = "other-task"
        _rewrite_reference(inputs, "ownership", "appliance_ownership")
    elif case == "pr":
        inputs.intent["pull_request_number"] = _PR + 1
        _rewrite_reference(inputs, "intent", "appliance_intent")
    elif case == "path":
        inputs.boot["vmx_path"] = str(inputs.vmx.parent / "other.vmx")
        _rewrite_reference(inputs, "boot", "appliance_installed_boot")
    elif case == "source":
        inputs.ownership["source_commit"] = "c" * 40
        _rewrite_reference(inputs, "ownership", "appliance_ownership")
    elif case == "intent_digest":
        inputs.ownership["intent_sha256"] = "0" * 64
        _rewrite_reference(inputs, "ownership", "appliance_ownership")
    elif case == "boot_receipt":
        inputs.boot["original_receipt_sha256"] = "0" * 64
        _rewrite_reference(inputs, "boot", "appliance_installed_boot")
    elif case == "root_identity":
        wrong_identity = "00000000:0000000000000000"
        inputs.ownership["original_identities"]["directory"] = wrong_identity
        inputs.boot["original_directory_identity"] = wrong_identity
        _rewrite_reference(inputs, "ownership", "appliance_ownership")
        inputs.boot["original_receipt_sha256"] = inputs.spec["appliance_ownership"]["sha256"]
        inputs.boot["original_receipt_path"] = inputs.spec["appliance_ownership"]["path"]
        _rewrite_reference(inputs, "boot", "appliance_installed_boot")
    elif case in {"mac", "cleanup_identity", "duplicate_key", "extra_nic"}:
        vmx_text = inputs.vmx.read_text(encoding="utf-8")
        if case == "mac":
            vmx_text = vmx_text.replace(_APPLIANCE_MAC, "00:50:56:2a:11:99")
        elif case == "cleanup_identity":
            vmx_text = vmx_text.replace(_CLEANUP_ID, "e" * 32)
        elif case == "duplicate_key":
            vmx_text += 'ethernet0.present = "TRUE"\n'
        else:
            vmx_text = vmx_text.replace('ethernet1.present = "FALSE"', 'ethernet1.present = "TRUE"')
        inputs.vmx.write_text(vmx_text, encoding="utf-8")

    with pytest.raises(factory.Refusal, match=reason):
        factory.inspect_inputs(inputs.spec, inputs.repo)


@pytest.mark.parametrize("reference_name", ["appliance_intent", "appliance_ownership", "appliance_installed_boot"])
def test_inspect_inputs_refuses_tampered_original_receipt(
    admitted_inputs: SimpleNamespace,
    reference_name: str,
) -> None:
    """Refuse original receipt bytes that no longer match their bound digest.

    Args:
        admitted_inputs: Receipt-bound source fixture from the admission factory.
        reference_name: Spec key naming the original receipt to tamper with.
    """
    path = Path(admitted_inputs.spec[reference_name]["path"])
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(factory.Refusal, match="original_receipt_changed"):
        factory.inspect_inputs(admitted_inputs.spec, admitted_inputs.repo)


def test_bound_json_refuses_oversized_receipt_even_when_digest_matches(tmp_path: Path) -> None:
    """Refuse a receipt that exceeds the bounded JSON reader limit.

    Args:
        tmp_path: Pytest-owned location for the oversized receipt.
    """
    path = tmp_path / "oversized.json"
    data = b" " * 262145
    path.write_bytes(data)

    with pytest.raises(factory.Refusal, match="original_receipt_changed"):
        factory.bound_json({"path": str(path), "sha256": hashlib.sha256(data).hexdigest()})


def test_require_ancestor_refuses_non_ancestor_without_exposing_git_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Refuse a source commit outside the admitted ancestry without exposing diagnostics.

    Args:
        monkeypatch: Pytest patch manager for the simulated Git result.
        tmp_path: Pytest-owned repository path supplied to the ancestry check.
    """
    observed: list[list[str]] = []

    def run(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        """Capture the bounded Git call and return a private failure diagnostic.

        Args:
            arguments: Git command and source ancestry operands.
            **kwargs: Process capture and timeout controls from the caller.
        """
        observed.append(arguments)
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 15
        return SimpleNamespace(returncode=1, stderr=b"private git diagnostic")

    monkeypatch.setattr(factory.subprocess, "run", run)

    with pytest.raises(factory.Refusal, match="original_source_not_ancestor"):
        factory.require_ancestor(tmp_path, _RESOURCE_SOURCE, _FACTORY_SOURCE)

    assert observed == [[
        "git", "--no-replace-objects", "-C", str(tmp_path), "merge-base", "--is-ancestor",
        _RESOURCE_SOURCE, _FACTORY_SOURCE,
    ]]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"magic": b"NOPE"}, "peer_source_not_monolithic_sparse"),
        ({"descriptor": '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=00000000\ncreateType="monolithicSparse"\nRW 4194304 SPARSE "peer.vmdk"\n'}, "peer_source_has_external_extent_or_parent"),
        ({"descriptor": '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="monolithicSparse"\nparentFileNameHint="parent.vmdk"\nRW 4194304 SPARSE "peer.vmdk"\n'}, "peer_source_has_external_extent_or_parent"),
        ({"descriptor": '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="monolithicSparse"\nRW 4194304 SPARSE "peer.vmdk"\nRW 1 FLAT "external.vmdk" 0\n'}, "peer_source_has_external_extent_or_parent"),
        ({"descriptor": '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="streamOptimized"\nRW 4194304 SPARSE "peer.vmdk"\n'}, "peer_source_has_external_extent_or_parent"),
        ({"descriptor": '# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="monolithicSparse"\nRW 4194304 SPARSE "external.vmdk"\n'}, "peer_source_has_external_extent_or_parent"),
        ({"offset": 20}, "peer_source_descriptor_invalid"),
        ({"sectors": 129}, "peer_source_descriptor_invalid"),
    ],
)
def test_standalone_disk_refuses_parent_or_external_extent_before_tool_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    reason: str,
) -> None:
    """Refuse sparse disks with parent links or extents outside the source file.

    Args:
        tmp_path: Pytest-owned path for the malformed VMDK fixture.
        monkeypatch: Pytest patch manager used to forbid external tool execution.
        kwargs: Sparse-header fields that create the malformed disk case.
        reason: Stable refusal identifier expected for the malformed extent.
    """
    disk = tmp_path / _VMDK_NAME
    disk.write_bytes(_sparse_vmdk(**kwargs))
    monkeypatch.setattr(factory.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("Unexpected tool execution"))

    with pytest.raises(factory.Refusal, match=reason):
        factory.standalone_disk(disk)


def test_public_file_refuses_hard_link_and_symlink_inputs(tmp_path: Path) -> None:
    """Refuse receipt inputs that are links instead of ordinary files.

    Args:
        tmp_path: Pytest-owned location for the target and linked paths.
    """
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    hard_link = tmp_path / "hard-link.json"
    os.link(target, hard_link)
    with pytest.raises(FileRefusal):
        with factory.public_file(hard_link):
            pass

    symlink = tmp_path / "symlink.json"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"Windows symlink creation is unavailable: {exc}")
    with pytest.raises(FileRefusal):
        with factory.public_file(symlink):
            pass

    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(tmp_path, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Windows directory symlink creation is unavailable: {exc}")
    with pytest.raises(FileRefusal):
        with factory.public_file(linked_parent / target.name):
            pass
