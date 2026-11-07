"""Read-only original-input admission for the standalone ISO certificate peer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
from contextlib import ExitStack, contextmanager
from pathlib import Path

from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.interop.certificate_peer_factory_config import validate_spec


class Refusal(ValueError):
    """A fixed public prerequisite category; no input or command output is exposed."""


@contextmanager
def public_file(path: Path):
    """Pin every ordinary ancestor before opening a bounded public input.

    Args:
        path: Absolute public input; no redirected or shared file is admitted.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise Refusal("public_input_path_invalid")
    files = WindowsFiles()
    with ExitStack() as pins:
        for parent in reversed(path.parents):
            pins.enter_context(files.opened(parent, directory=True))
        pins.enter_context(files.opened(path, directory=False))
        yield


def bound_json(reference: dict) -> dict:
    """Read one bounded public receipt against its preserved digest.

    Args:
        reference: Absolute original receipt path and SHA-256.
    """
    path = Path(reference["path"])
    with public_file(path):
        with path.open("rb") as stream:
            data = stream.read(262145)
        if len(data) > 262144 or hashlib.sha256(data).hexdigest() != reference["sha256"]:
            raise Refusal("original_receipt_changed")
        value = json.loads(data)
    if not isinstance(value, dict):
        raise Refusal("original_receipt_invalid")
    return value


def standalone_disk(path: Path) -> None:
    """Refuse external extents or parent chains before any disk-tool execution.

    Args:
        path: Checksum-admitted single-file sparse source disk.
    """
    with public_file(path), path.open("rb") as stream:
        header = stream.read(512)
        if len(header) != 512 or header[:4] != b"KDMV":
            raise Refusal("peer_source_not_monolithic_sparse")
        capacity = struct.unpack_from("<Q", header, 12)[0]
        offset, sectors = struct.unpack_from("<QQ", header, 28)
        if offset < 1 or sectors < 1 or sectors > 128 or offset * 512 + sectors * 512 > path.stat().st_size:
            raise Refusal("peer_source_descriptor_invalid")
        stream.seek(offset * 512)
        descriptor = stream.read(sectors * 512).rstrip(b"\0").decode("ascii")
    extents = re.findall(r'^(?:RW|RDONLY|NOACCESS)\s+.*$', descriptor, re.M)
    expected = rf'RW {capacity} SPARSE "{re.escape(path.name)}"'
    if (len(extents) != 1 or not re.fullmatch(expected, extents[0].strip())
            or not re.search(r'^createType="monolithicSparse"\s*$', descriptor, re.M)
            or not re.search(r'^parentCID=ffffffff\s*$', descriptor, re.M)
            or "parentFileNameHint" in descriptor):
        raise Refusal("peer_source_has_external_extent_or_parent")


def require_ancestor(repository: Path, source: str, head: str) -> None:
    """Require original creation sources to remain ancestors without relabelling.

    Args:
        repository: Source-guarded task checkout.
        source: Immutable original resource source.
        head: Current admitted factory source.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", str(source)):
        raise Refusal("original_source_invalid")
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), "merge-base", "--is-ancestor", source, head],
        capture_output=True, timeout=15, check=False,
    )
    if result.returncode:
        raise Refusal("original_source_not_ancestor")


def inspect_inputs(spec: dict, repository: Path) -> dict:
    """Admit an original ISO appliance and independently verified read-only source disk.

    The caller retains ordinary Windows source/receipt pins throughout creation.
    This function performs no provider operation, creates no receipt and adopts no VM.

    Args:
        spec: Public factory specification, validated before filesystem access.
        repository: Exact task checkout admitted by the owning PowerShell wrapper.
    """
    spec = validate_spec(spec)
    intent = bound_json(spec["appliance_intent"])
    original = bound_json(spec["appliance_ownership"])
    boot = bound_json(spec["appliance_installed_boot"])
    vmx = Path(spec["appliance_vmx"])
    root = vmx.parent
    for record in (intent, original, boot):
        if (record.get("schema") != 1 or record.get("task_id") != spec["task_id"]
                or record.get("repository") != spec["repository"]
                or record.get("pull_request_number") != spec["pr"]
                or record.get("vmx_path") != str(vmx) or record.get("output_directory") != str(root)):
            raise Refusal("original_iso_binding_mismatch")
        require_ancestor(repository, record.get("source_commit", ""), spec["source_commit"])
    if (intent.get("phase") != "installation-pending"
            or original.get("phase") != "original-installation-vm-created"
            or original.get("source_commit") != intent.get("source_commit")
            or original.get("intent_sha256") != spec["appliance_intent"]["sha256"]
            or boot.get("phase") != "installation-boot-without-media"
            or boot.get("original_receipt_sha256") != spec["appliance_ownership"]["sha256"]
            or boot.get("original_receipt_path") != spec["appliance_ownership"]["path"]
            or boot.get("original_directory_identity") != original.get("original_identities", {}).get("directory")
            or not re.fullmatch(r"[0-9a-f]{64}", str(original.get("installation_iso", {}).get("sha256", "")))):
        raise Refusal("original_iso_boot_mismatch")
    with WindowsFiles().opened(root, directory=True) as (_, identity, _):
        directory_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
        if directory_identity != original.get("original_identities", {}).get("directory"):
            raise Refusal("original_iso_directory_changed")
    with public_file(vmx):
        with vmx.open("rb") as stream:
            data = stream.read(1048577)
        if len(data) > 1048576:
            raise Refusal("original_iso_vmx_too_large")
        text = data.decode("utf-8")
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([A-Za-z0-9_.:]+)\s*=\s*"([^"\r\n]*)"\s*', line)
        if match:
            key = match[1].lower()
            if key in values:
                raise Refusal("original_iso_duplicate_vmx_key")
            values[key] = match[2]
    cleanup = values.get("guestinfo.atlaso.test_vm_cleanup_identity", "")
    address_type = values.get("ethernet0.addresstype", "generated").lower()
    observed_mac = values.get("ethernet0.address" if address_type == "static" else "ethernet0.generatedaddress", "")
    if (not re.fullmatch(r"[0-9a-f]{32}", cleanup)
            or hashlib.sha256(cleanup.encode()).hexdigest() != str(original.get("persistent_vm_identity_sha256", "")).lower()
            or address_type not in {"static", "generated"}
            or observed_mac.lower() != spec["appliance_mac"]
            or values.get("ethernet0.present", "").upper() != "TRUE"
            or any(key.startswith("ethernet") and key.endswith(".present") and key != "ethernet0.present"
                   and value.upper() == "TRUE" for key, value in values.items())):
        raise Refusal("original_iso_native_identity_mismatch")
    preparation = bound_json(spec["peer_source_preparation"])
    disk = Path(str(preparation.get("vmdk") or ""))
    qcow = Path(str(preparation.get("qcow2") or ""))
    if not disk.is_absolute() or not qcow.is_absolute() or disk == qcow:
        raise Refusal("peer_source_paths_invalid")
    canonical = repository / "scripts/windows/vmware/prepare-tiny-linux-client.ps1"
    source = canonical.read_text(encoding="utf-8")
    pins = re.findall(r"\[string\]\$ExpectedSha512 = '([0-9a-f]{128})'", source)
    if len(pins) != 1 or str(preparation.get("sha512", "")).lower() != pins[0]:
        raise Refusal("peer_source_release_pin_mismatch")
    for path, algorithm, expected in ((qcow, "sha512", pins[0]), (disk, "sha256", spec["peer_vmdk_sha256"])):
        with public_file(path), path.open("rb") as stream:
            if hashlib.file_digest(stream, algorithm).hexdigest() != expected:
                raise Refusal("peer_source_content_changed")
    standalone_disk(disk)
    return {"spec": spec, "appliance_directory_identity": directory_identity,
            "source_disk": str(disk), "source_qcow2": str(qcow),
            "source_disk_sha256": spec["peer_vmdk_sha256"], "source_qcow2_sha512": pins[0]}


def main() -> int:
    """Inspect public inputs and emit only an admitted projection or fixed refusal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--shape-only", action="store_true")
    args = parser.parse_args()
    try:
        with public_file(args.plan):
            if args.plan.stat().st_size > 32768:
                raise Refusal("factory_plan_too_large")
            spec = json.loads(args.plan.read_bytes())
        result = validate_spec(spec) if args.shape_only else inspect_inputs(spec, args.repository)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, FileRefusal, subprocess.SubprocessError):
        print(json.dumps({"success": False, "reason": "factory_original_input_admission_failed"}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
