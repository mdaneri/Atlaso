"""Admit a development wheel separately from an ISO fixture's original signed software."""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from certificate_peer_proof import (  # type: ignore[import-not-found]  # The receipt-bound bootstrap inserts this sibling directory.
    bound_json,
    plan_pr,
    publish,
)

from scripts.installation.content_inspection import (  # noqa: E402 - Receipt-bound source root.
    guest_content_program,
    validate_content_report,
)
from scripts.installation.inspection import (  # noqa: E402 - Receipt-bound source root.
    deployment_inputs,
    guest_program,
    validate_report,
)
from scripts.installation.network_inspection import validate_network_report  # noqa: E402 - Receipt-bound source root.

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_HOST_KEY = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_WHEEL = re.compile(r"atlaso-[A-Za-z0-9_.+\-]+\.whl\Z")
_REFERENCES = ("appliance_intent", "appliance_ownership", "appliance_installed_boot", "installed_inspection")
_MEASUREMENT_KEYS = {
    "schema", "wheel_payload_sha256", "installed_payload_sha256", "verified_payload_files",
    "wheel_sha256", "helper_sha256", "interface", "mac", "address", "version", "machine_id_sha256",
}


class Refusal(ValueError):
    """Expose only a fixed public refusal category, never guest output or credentials."""


def reference_binding(reference: dict[str, Any]) -> dict[str, str]:
    """Keep an original receipt path and digest distinct from a preserved readable copy.

    Args:
        reference: Independently pinned original receipt or its preserved-copy reference.
    """
    path = reference.get("original_path", reference.get("path"))
    checksum = reference.get("sha256")
    if not isinstance(path, str) or not isinstance(checksum, str) or not _DIGEST.fullmatch(checksum):
        raise Refusal("iso_deployment_original_reference_invalid")
    return {"path": path, "sha256": checksum}


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    """Read bounded immutable Git data without inheriting native credential values.

    Args:
        repository: Original task checkout recorded by the admitted ISO VM.
        *arguments: Fixed Git operation and its public immutable selectors.
    """
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("ATLASO_NATIVE_")
                   and key not in {"OP_SERVICE_ACCOUNT_TOKEN", "DEFAULT_ADMIN_PASSWORD"}}
    result = subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True,
                            check=False, timeout=30, env=environment)
    if result.returncode or len(result.stdout) > 128 * 1024**2:
        raise Refusal("iso_deployment_source_object_unavailable")
    return result.stdout


def original_context(plan: dict[str, Any]) -> dict[str, Any]:
    """Admit original media and installed identity without relabelling their software.

    Args:
        plan: Trusted-host fixture plan containing the original ISO references.
    """
    if plan.get("trust_model") != "trusted-host":
        raise Refusal("iso_deployment_requires_trusted_iso")
    ownership = bound_json(plan["appliance_ownership"])
    if ownership.get("phase") != "original-installation-vm-created":
        raise Refusal("iso_deployment_requires_original_iso")
    media = ownership["installation_iso"]
    expected, assets = deployment_inputs(Path(media["path"]), media["sha256"])
    installed = bound_json(plan["installed_inspection"])
    try:
        report_expected = {key: value for key, value in expected.items()
                           if key not in {"installer_source_commit", "helper_sha256"}}
        validate_report(json.dumps(installed).encode(), report_expected)
    except (ValueError, TypeError, KeyError):
        raise Refusal("iso_deployment_original_inspection_invalid") from None
    if (ownership.get("task_id") != plan.get("task_id")
            or ownership.get("repository") != "mdaneri/Atlaso"
            or ownership.get("pull_request_number") != plan_pr(plan)):
        raise Refusal("iso_deployment_original_owner_mismatch")
    return {"ownership": ownership, "installed": installed, "expected": expected, "assets": assets}


def payload_program(expected: dict[str, Any], wheel: str, address: str) -> str:
    """Measure the active wheel with the original ISO's authenticated payload comparator.

    Args:
        expected: Original media expectation containing the payload inspector digest.
        wheel: Unique retained remote wheel whose bytes were verified before installation.
        address: Originally admitted host-only address or later private-peer address.
    """
    target = str(ipaddress.IPv4Address(address))
    path = PurePosixPath(wheel)
    if (not path.is_absolute() or ".." in path.parts or len(path.parts) != 5
            or not re.fullmatch(r"atlaso-certificate-deploy-[0-9a-f]{32}", path.parts[3])
            or path.parts[1:3] != ("var", "tmp") or not _WHEEL.fullmatch(path.name)):
        raise Refusal("iso_deployment_remote_wheel_path_invalid")
    checksum = expected.get("payload_inspector_sha256", "")
    if not isinstance(checksum, str) or not _DIGEST.fullmatch(checksum):
        raise Refusal("iso_deployment_payload_inspector_invalid")
    source = f'''import hashlib,importlib.metadata,json,os,stat,types
from pathlib import Path
p=Path('/opt/atlaso/scripts/interop/routing_deployment_inspection.py')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno());b=f.read(65537)
if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or len(b)>65536 or hashlib.sha256(b).hexdigest()!={checksum!r}: raise ValueError()
m=types.ModuleType('_atlaso_deployment_payload');exec(compile(b,str(p),'exec'),m.__dict__)
r=m.deployment_evidence(Path({wheel!r}),{target!r})
fd=os.open('/etc/machine-id',os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno());mid=f.read(129).strip()
if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or len(mid)!=32 or any(c not in b'0123456789abcdef' for c in mid): raise ValueError()
r.update(version=importlib.metadata.version('atlaso'),machine_id_sha256=hashlib.sha256(mid).hexdigest())
print(json.dumps(r,sort_keys=True,separators=(',',':')))
'''
    encoded = base64.b64encode(source.encode()).decode("ascii")
    return "/opt/atlaso/.venv/bin/python -I -B -c \"import base64;exec(base64.b64decode('" + encoded + "'))\""


def validate_measurement(value: dict[str, Any], *, wheel_sha256: str, helper_sha256: str,
                         installed: dict[str, Any], address: str, mac: str, version: str) -> dict[str, Any]:
    """Require the exact deployed wheel, original machine and native management owner.

    Args:
        value: Bounded public active-payload report returned over pinned SSH.
        wheel_sha256: Sole wheel digest retained by the immutable source builder.
        helper_sha256: Unchanged original ISO helper digest.
        installed: Original signed-software and public machine inspection.
        address: Exact address independently admitted for this observation.
        mac: Original ISO appliance interface MAC.
        version: Version from the built wheel's metadata.
    """
    if (set(value) != _MEASUREMENT_KEYS or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("wheel_sha256") != wheel_sha256 or value.get("helper_sha256") != helper_sha256
            or value.get("machine_id_sha256") != installed.get("machine_id_sha256")
            or value.get("interface") != "eth0" or value.get("address") != str(ipaddress.IPv4Address(address))
            or not isinstance(value.get("mac"), str) or value["mac"].replace("-", ":").lower() != mac.replace("-", ":").lower()
            or value.get("version") != version or type(value.get("verified_payload_files")) is not int
            or not 1 <= value["verified_payload_files"] <= 10000):
        raise Refusal("iso_deployment_active_identity_mismatch")
    wanted = value.get("wheel_payload_sha256")
    if (not isinstance(wanted, str) or not _DIGEST.fullmatch(wanted)
            or value.get("installed_payload_sha256") != wanted):
        raise Refusal("iso_deployment_active_payload_mismatch")
    return value


def admit_deployment(plan: dict[str, Any], *, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Require a successful independent PR-wheel receipt when a fixture selects one.

    Args:
        plan: Original trusted-host certificate plan with an optional deployment reference.
        context: Already admitted original media context from this invocation, when available.

    Returns:
        The independently bound deployment, or no overlay for the unchanged signed ISO path.
    """
    if "iso_wheel_deployment" not in plan:
        return None
    if not isinstance(plan["iso_wheel_deployment"], dict):
        raise Refusal("iso_deployment_reference_invalid")
    original = context if context is not None else original_context(plan)
    ownership, installed, expected = original["ownership"], original["installed"], original["expected"]
    receipt = bound_json(plan["iso_wheel_deployment"])
    commit = plan.get("deployed_commit")
    if (not isinstance(commit, str) or not _COMMIT.fullmatch(commit)
            or commit != plan.get("source_commit") or receipt.get("source_commit") != commit
            or receipt.get("schema") != 1 or type(receipt.get("schema")) is not int
            or receipt.get("kind") != "certificate-iso-pr-wheel-deployment"
            or receipt.get("repository") != "mdaneri/Atlaso" or receipt.get("pr") != plan_pr(plan)
            or receipt.get("task_id") != plan.get("task_id") or receipt.get("status") != "succeeded"
            or receipt.get("whole_job_quiescent") is not True
            or not isinstance(receipt.get("mac"), str)
            or not isinstance(receipt.get("measurement"), dict)
            or not isinstance(receipt.get("network_binding"), dict)
            or not isinstance(receipt.get("remote_wheel"), str)
            or receipt.get("vmx_path") != ownership.get("vmx_path")
            or receipt.get("original_software_source_commit") != expected["source_commit"]
            or receipt.get("installer_source_commit") != expected["installer_source_commit"]
            or receipt.get("host_key_sha256") != installed["host_key_sha256"]
            or not _HOST_KEY.fullmatch(str(receipt.get("host_key_sha256", "")))):
        raise Refusal("iso_deployment_receipt_binding_mismatch")
    references = {key: reference_binding(plan[key]) for key in _REFERENCES}
    if receipt.get("original_references") != references:
        raise Refusal("iso_deployment_original_receipt_mismatch")
    intent = bound_json(receipt["deployment_intent"])
    if (intent.get("kind") != "certificate-iso-pr-wheel-deployment-intent"
            or any(intent.get(key) != receipt.get(key) for key in (
                "schema", "repository", "pr", "task_id", "source_commit", "vmx_path",
                "original_references", "build_receipt", "remote_wheel", "host_key_sha256",
                "network_inspection", "network_binding", "mac"))):
        raise Refusal("iso_deployment_intent_mismatch")
    build = bound_json(receipt["build_receipt"])
    if (build.get("kind") != "certificate-pr-wheel-build" or type(build.get("schema")) is not int or build["schema"] != 1
            or build.get("repository") != "mdaneri/Atlaso" or build.get("pr") != plan_pr(plan)
            or build.get("task_id") != plan.get("task_id") or build.get("source_commit") != commit
            or build.get("source_guards_verified") is not True
            or not isinstance(build.get("wheel_sha256"), str) or not _DIGEST.fullmatch(build["wheel_sha256"])
            or not _WHEEL.fullmatch(str(build.get("wheel_filename", "")))
            or type(build.get("wheel_size")) is not int or not 1 <= build["wheel_size"] <= 268435456
            or not isinstance(build.get("version"), str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", build["version"])):
        raise Refusal("iso_deployment_build_binding_mismatch")
    repository = Path(ownership["worktree"])
    head = _git_bytes(repository, "rev-parse", "HEAD").decode().strip()
    if head != commit:
        raise Refusal("iso_deployment_source_head_mismatch")
    archive = _git_bytes(repository, "archive", "--format=zip", commit)
    if hashlib.sha256(archive).hexdigest() != build.get("archive_sha256"):
        raise Refusal("iso_deployment_source_archive_mismatch")
    probe = _git_bytes(repository, "show", commit + ":scripts/interop/routing_deployment_inspection.py")
    if hashlib.sha256(probe).hexdigest() != expected["payload_inspector_sha256"]:
        raise Refusal("iso_deployment_original_payload_inspector_changed")
    payload_program(expected, receipt["remote_wheel"], receipt["measurement"]["address"])
    if PurePosixPath(receipt["remote_wheel"]).name != build["wheel_filename"]:
        raise Refusal("iso_deployment_remote_wheel_binding_mismatch")
    network = bound_json(receipt["network_inspection"])
    binding = receipt["network_binding"]
    try:
        validate_network_report(json.dumps(network).encode(), expected["iso_sha256"], receipt["mac"],
                                binding["subnet"], binding["prefixlen"])
    except (ValueError, KeyError, TypeError):
        raise Refusal("iso_deployment_network_observation_mismatch") from None
    validate_measurement(receipt["measurement"], wheel_sha256=build["wheel_sha256"],
                         helper_sha256=expected["helper_sha256"], installed=installed,
                         address=network["address"], mac=receipt["mac"], version=build["version"])
    if (not isinstance(plan.get("mac"), str)
            or receipt["mac"].replace("-", ":").lower() != plan["mac"].replace("-", ":").lower()):
        raise Refusal("iso_deployment_original_mac_mismatch")
    try:
        validate_content_report(json.dumps(receipt["assets_report"]).encode(), original["assets"])
    except (ValueError, KeyError, TypeError):
        raise Refusal("iso_deployment_original_assets_changed") from None
    return {**receipt, "build": build, "original": original}


def asset_program(context: dict[str, Any]) -> str:
    """Reuse the existing strict original-media asset check after wheel deployment.

    Args:
        context: Original ISO identity and asset expectations admitted before credentials.
    """
    return guest_content_program(context["assets"])


def _reference(path: Path) -> dict[str, str]:
    """Bind a newly published public artifact to its exact bytes.

    Args:
        path: Existing immutable owner output.
    """
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _metadata(raw: bytes) -> tuple[str, list[str]]:
    """Read only bounded Atlaso wheel metadata for offline compatibility admission.

    Args:
        raw: Exact candidate or original signed application wheel bytes.
    """
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        names = [name for name in wheel.namelist() if re.fullmatch(r"atlaso-[^/]+\.dist-info/METADATA", name)]
        if len(names) != 1 or wheel.getinfo(names[0]).file_size > 131072:
            raise Refusal("iso_deployment_wheel_metadata_invalid")
        metadata = email.parser.BytesParser().parsebytes(wheel.read(names[0]))
    if metadata.get_all("Name") != ["atlaso"] or len(metadata.get_all("Version", [])) != 1:
        raise Refusal("iso_deployment_wheel_metadata_invalid")
    version = str(metadata["Version"])
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise Refusal("iso_deployment_wheel_version_invalid")
    return version, sorted(str(value) for value in metadata.get_all("Requires-Dist", []))


def _appliance_requirements(raw: bytes) -> list[str]:
    """Keep exact dependency declarations except the never-selected sole dev extra.

    Args:
        raw: Original signed or reviewed candidate wheel metadata container.
    """
    try:
        from packaging.requirements import InvalidRequirement, Requirement
    except ImportError:
        raise Refusal("iso_deployment_wheel_metadata_parser_unavailable") from None
    selected = []
    for value in _metadata(raw)[1]:
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            raise Refusal("iso_deployment_wheel_requirements_invalid") from None
        # The deployer installs a bare wheel with --no-deps, never [dev]. Do
        # not evaluate host/platform markers or discard broader expressions:
        # every other declaration must still match the original bytes exactly.
        if requirement.marker is not None and str(requirement.marker) == 'extra == "dev"':
            continue
        selected.append(value)
    return selected


def admit_offline_wheels(context: dict[str, Any], candidate: bytes, directory: Path) -> dict[str, str]:
    """Require original signed wheels and unchanged declarations outside the sole dev extra.

    Args:
        context: Original ISO identity already admitted by the canonical inspector.
        candidate: Exact immutable development wheel produced from the reviewed Git archive.
        directory: Complete original signed cp314 dependency directory retained by the owner.
    """
    import pycdlib

    from scripts.installation import iso as installation_iso
    from scripts.installation.inspection import _iso_member, _NamedBufferedReader

    media = context["ownership"]["installation_iso"]
    pinned = installation_iso._open_pinned(Path(media["path"]))
    if not isinstance(pinned.stream, io.RawIOBase):
        raise Refusal("iso_deployment_original_media_unavailable")
    stream = _NamedBufferedReader(pinned.stream, str(media["path"]))
    try:
        if pinned.digest != media["sha256"]:
            raise Refusal("iso_deployment_original_media_changed")
        stream.seek(0)
        iso = pycdlib.PyCdlib()
        iso.open_fp(stream)
        try:
            release_raw = _iso_member(iso, "/atlaso/software/release-manifest.json")
            if hashlib.sha256(release_raw).hexdigest() != context["expected"]["release_manifest_sha256"]:
                raise Refusal("iso_deployment_original_release_changed")
            release = json.loads(release_raw)
            names = {PurePosixPath(name).name: checksum for name, checksum in release["content_hashes"].items()
                     if re.fullmatch(r"wheelhouse/cp314/[^/]+\.whl", name)}
            source = json.loads(_iso_member(iso, "/atlaso/software/virtualization-source.json"))
            original_raw = _iso_member(iso, "/atlaso/software/" + source["application_wheel"])
            if hashlib.sha256(original_raw).hexdigest() != context["expected"]["wheel_sha256"]:
                raise Refusal("iso_deployment_original_wheel_changed")
        finally:
            iso.close()
        installation_iso._verify_pinned(pinned)
    finally:
        stream.close()
    if _appliance_requirements(candidate) != _appliance_requirements(original_raw):
        raise Refusal("iso_deployment_offline_requirements_changed")
    actual = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()
              if path.suffix == ".whl" and path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1}
    if not names or actual != names:
        raise Refusal("iso_deployment_offline_wheelhouse_mismatch")
    return names


def prepare_context(plan: dict[str, Any], native: dict[str, Any]) -> dict[str, Any]:
    """Bind pre-LAN ownership, console observations and the original backed-up transition.

    Args:
        plan: Original immutable deployment plan without private-LAN fixture substitutions.
        native: Fresh output from the canonical read-only installed-VM AdmitNetwork owner.
    """
    context = original_context(plan)
    owner = context["ownership"]
    commit = plan.get("source_commit")
    repository = Path(owner["worktree"])
    if (plan.get("task_id") != os.environ.get("CODEX_THREAD_ID") or not isinstance(commit, str)
            or not _COMMIT.fullmatch(commit) or plan.get("deployed_commit") != commit
            or _git_bytes(repository, "rev-parse", "HEAD").decode().strip() != commit
            or _git_bytes(repository, "status", "--porcelain=v1", "--untracked-files=all").strip()
            or _git_bytes(repository, "branch", "--show-current").decode().strip() in {"", "main"}):
        raise Refusal("iso_deployment_clean_task_source_required")
    references = {name: reference_binding(plan[name]) for name in (*_REFERENCES, "appliance_disk_baseline")}
    for name, phase in (("appliance_intent", "installation-pending"),
                        ("appliance_disk_baseline", "installation-disk-baseline"),
                        ("appliance_installed_boot", "installation-boot-without-media")):
        record = bound_json(plan[name])
        source = record.get("source_commit", "")
        if (record.get("schema") != 1 or record.get("phase") != phase
                or record.get("task_id") != plan["task_id"] or record.get("repository") != "mdaneri/Atlaso"
                or record.get("pull_request_number") != plan_pr(plan) or record.get("vmx_path") != owner["vmx_path"]
                or record.get("output_directory") != owner["output_directory"]
                or not isinstance(source, str) or not _COMMIT.fullmatch(source)):
            raise Refusal("iso_deployment_original_boot_binding_invalid")
        # The caller's snapshot is deliberately not a Git checkout. Use the bound original.
        if _git_bytes(repository, "merge-base", commit, source).decode().strip() != source:
            raise Refusal("iso_deployment_original_source_not_ancestor")
    boot = bound_json(plan["appliance_installed_boot"])
    transition = bound_json(plan["host_only_transition"])
    backup = Path(transition["backup_path"])
    if (transition.get("kind") != "certificate-iso-host-only-transition" or transition.get("schema") != 1
            or transition.get("task_id") != plan["task_id"] or transition.get("source_commit") != commit
            or transition.get("repository") != "mdaneri/Atlaso" or transition.get("pr") != plan_pr(plan)
            or transition.get("vmx_path") != owner["vmx_path"]
            or transition.get("ownership") != references["appliance_ownership"]
            or transition.get("boot") != references["appliance_installed_boot"]
            or not backup.is_absolute() or backup.is_symlink() or backup.stat().st_nlink != 1
            or hashlib.sha256(backup.read_bytes()).hexdigest() != transition.get("backup_sha256")
            or transition.get("stopped_vm_verified") is not True
            or transition.get("unselected_disk_unchanged") is not True
            or transition.get("boot_configuration_sha256") != boot.get("after_sha256")
            or transition.get("vmnet") != plan["deployment_network_binding"]["vmnet"]):
        raise Refusal("iso_deployment_original_host_only_transition_invalid")
    binding = plan["deployment_network_binding"]
    if (native.get("VmxPath") != owner["vmx_path"]
            or native.get("OriginalReceiptPath") != references["appliance_ownership"]["path"]
            or native.get("OriginalReceiptSha256") != references["appliance_ownership"]["sha256"]
            or native.get("BaselineReceiptPath") != references["appliance_disk_baseline"]["path"]
            or native.get("BaselineReceiptSha256") != references["appliance_disk_baseline"]["sha256"]
            or native.get("BootReceiptPath") != references["appliance_installed_boot"]["path"]
            or native.get("BootReceiptSha256") != references["appliance_installed_boot"]["sha256"]
            or native.get("Network", {}).get("Mac") != plan.get("mac")
            or native["Network"].get("Subnet") != binding["subnet"]
            or native["Network"].get("PrefixLength") != binding["prefixlen"]):
        raise Refusal("iso_deployment_native_admission_mismatch")
    network = bound_json(plan["deployment_network_inspection"])
    validate_network_report(json.dumps(network).encode(), context["expected"]["iso_sha256"], plan["mac"],
                            binding["subnet"], binding["prefixlen"])
    context.update(network=network, native=native)
    return context


def prepare(args: argparse.Namespace) -> None:
    """Publish build and deployment intent before the existing deployer may mutate the VM.

    Args:
        args: Public producer paths pinned by the owning PowerShell invocation.
    """
    plan = json.loads(args.plan.read_bytes())
    native = json.loads(args.native_admission.read_bytes())
    context = prepare_context(plan, native)
    expected = context["expected"]
    candidate = args.wheel.read_bytes()
    version, _requirements = _metadata(candidate)
    offline = admit_offline_wheels(context, candidate, args.runtime_dependency_directory)
    commit = plan["source_commit"]
    archive_sha = hashlib.sha256(args.source_archive.read_bytes()).hexdigest()
    if (archive_sha != hashlib.sha256(_git_bytes(Path(context["ownership"]["worktree"]), "archive", "--format=zip", commit)).hexdigest()
            or hashlib.sha256(_git_bytes(Path(context["ownership"]["worktree"]), "show",
                                        commit + ":scripts/interop/routing_deployment_inspection.py")).hexdigest()
            != expected["payload_inspector_sha256"]):
        raise Refusal("iso_deployment_reviewed_archive_mismatch")
    output = args.output_root
    common = {"schema": 1, "task_id": plan["task_id"], "repository": "mdaneri/Atlaso", "pr": plan_pr(plan),
              "source_commit": commit}
    build = {**common, "kind": "certificate-pr-wheel-build", "source_guards_verified": True,
             "archive_sha256": archive_sha, "wheel_filename": args.wheel.name,
             "wheel_sha256": hashlib.sha256(candidate).hexdigest(), "wheel_size": len(candidate), "version": version,
             "offline_wheels": offline}
    publish(output / "build.json", build)
    # The same archive is measured after the private-LAN handoff reboot.
    remote = "/var/tmp/atlaso-certificate-deploy-" + uuid.uuid4().hex
    intent = {**common, "kind": "certificate-iso-pr-wheel-deployment-intent",
              "vmx_path": context["ownership"]["vmx_path"], "mac": plan["mac"],
              "host_key_sha256": context["installed"]["host_key_sha256"],
              "original_references": {key: reference_binding(plan[key]) for key in _REFERENCES},
              "build_receipt": _reference(output / "build.json"), "remote_wheel": remote + "/" + args.wheel.name,
              "network_inspection": reference_binding(plan["deployment_network_inspection"]),
              "network_binding": {key: plan["deployment_network_binding"][key] for key in ("subnet", "prefixlen")}}
    publish(output / "intent.json", intent)
    from scripts.completed_task_files import WindowsFiles

    with WindowsFiles().opened(output, directory=True) as (_, identity, _):
        native_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
    original_expected = {key: value for key, value in expected.items()
                         if key not in {"installer_source_commit", "helper_sha256"}}
    request = {**common, "kind": "certificate-iso-wheel-deployment-request",
               "repository_root": context["ownership"]["worktree"], "source_root": str(args.source_root),
               "output_root": str(output), "output_root_identity": native_identity,
               "source_snapshot_sha256": args.snapshot_sha256, "source_snapshot_file_count": args.snapshot_file_count,
               "sdk_wheel_directory": str(output / "sdk-wheels"), "wheel_path": str(args.wheel),
               **{key: build[key] for key in ("wheel_filename", "wheel_sha256", "wheel_size", "version")},
               "host_address": context["network"]["address"], "host_key_sha256": intent["host_key_sha256"],
               "mac": plan["mac"], "remote_directory": remote, "remote_wheel": intent["remote_wheel"],
               "helper_sha256": expected["helper_sha256"], "original_expected": original_expected,
               "original_inspection": context["installed"], "preflight_command": guest_program(original_expected),
               "assets_command": asset_program(context), "assets_expected": context["assets"],
               "payload_command": payload_program(expected, intent["remote_wheel"], context["network"]["address"]),
               "inspection_output": str(output / "live-inspection.json")}
    publish(output / "request.json", request)


def finish_deployment(args: argparse.Namespace) -> None:
    """Admit fresh native readback and publish success only after the owner reports quiescence.

    Args:
        args: Original plan and retained owner namespace after a successful bounded child.
    """
    output = args.output_root
    plan = json.loads(args.plan.read_bytes())
    context = prepare_context(plan, json.loads(args.native_admission.read_bytes()))
    before = json.loads((output / "native-before.json").read_bytes())
    if context["native"] != before:
        raise Refusal("iso_deployment_native_binding_changed")
    intent = json.loads((output / "intent.json").read_bytes())
    live = json.loads((output / "live-inspection.json").read_bytes())
    owner_result = json.loads((output / "deployer-exited.json").read_bytes())
    if (owner_result.get("whole_job_quiescent") is not True or owner_result.get("exit_code") != 0
            or owner_result.get("source_guards_verified") is not True):
        raise Refusal("iso_deployment_owner_not_quiescent")
    receipt = {**intent, "kind": "certificate-iso-pr-wheel-deployment", "status": "succeeded",
               "whole_job_quiescent": True, "deployment_intent": _reference(output / "intent.json"),
               "original_software_source_commit": context["expected"]["source_commit"],
               "installer_source_commit": context["expected"]["installer_source_commit"],
               "measurement": live["measurement"], "assets_report": live["assets_report"]}
    # Validate the complete terminal receipt before publication, without a writable substitute.
    pending = output / "deployment-candidate.json"
    publish(pending, receipt)
    admit_deployment({**plan, "iso_wheel_deployment": _reference(pending)}, context=context)
    publish(output / "deployment.json", receipt)


def main() -> int:
    """Run only public receipt preparation or final validation for the retaining owner."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for operation in ("inspect", "prepare", "finish"):
        command = sub.add_parser(operation)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--output-root", type=Path, required=True)
        command.add_argument("--native-admission", type=Path, required=True)
        if operation == "prepare":
            for option in ("source-root", "wheel", "source-archive", "runtime-dependency-directory"):
                command.add_argument("--" + option, type=Path, required=True)
            command.add_argument("--snapshot-sha256", required=True)
            command.add_argument("--snapshot-file-count", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "inspect":
            plan = json.loads(args.plan.read_bytes())
            context = prepare_context(plan, json.loads(args.native_admission.read_bytes()))
            publish(args.output_root / "inspection.json", {
                "schema": 1, "kind": "certificate-iso-wheel-deployment-inspection", "task_id": plan["task_id"],
                "source_commit": plan["source_commit"], "vmx_path": context["ownership"]["vmx_path"],
                "original_software_source_commit": context["expected"]["source_commit"],
                "installer_source_commit": context["expected"]["installer_source_commit"],
                "host_key_sha256": context["installed"]["host_key_sha256"], "network": context["network"],
            })
        elif args.operation == "prepare":
            prepare(args)
        else:
            finish_deployment(args)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print("Original-ISO deployment receipt refused; preserve the owning invocation's records.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
