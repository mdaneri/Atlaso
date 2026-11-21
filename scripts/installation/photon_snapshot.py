"""Retain bounded Photon repository evidence for approved release captures."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.completed_task_files import read_bounded_regular
from scripts.installation.build import package_selection
from scripts.installation.manifest import canonical_json
from scripts.verify_virtualization_guest_wheel import (
    PHOTON_REPOSITORY_URLS,
    _download_photon_repository_document,
    _photon_repository_inventory,
    _photon_repository_metadata,
    _run_runtime_tool,
)

SNAPSHOT = "photon-snapshot.json"
MAX_SNAPSHOT_BYTES = 48 * 1024**2
MAX_SNAPSHOT_AGE = timedelta(days=30)
RPM_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~^-]{0,191}")

Package = tuple[str, str, str, str, str, str]


def requirements_sha256(source: Path) -> str:
    """Hash capture requirements using the target tree's data and reviewed identities."""
    files = [
        "image/common/powershell/powercli-lock.json",
        "image/common/scripts/build-qemu-guest-agent-rpm.sh",
        "image/common/guest-agents/atlaso-qemu-guest-agent.spec",
        "image/common/guest-agents/qemu-guest-agent.service",
        "scripts/installation/guest_tools.py",
    ]
    keys = source / "image/common/photon-rpm-gpg"
    files.extend(path.relative_to(source).as_posix() for path in sorted(keys.glob("VMWARE-RPM-GPG-KEY*")))
    pins = {
        name: {
            target.id: ast.literal_eval(node.value)
            for node in ast.parse((source / "scripts/installation" / name).read_bytes()).body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id.startswith(("PHOTON_", "SOURCE_ISO_SHA512"))
        }
        for name in ("content_inspection.py", "manifest.py")
    }
    build_source = ast.parse((source / "scripts/installation/build.py").read_bytes())
    base_packages, = (
        ast.literal_eval(node.value)
        for node in build_source.body if isinstance(node, ast.Assign)
        if any(isinstance(target, ast.Name) and target.id == "BASE_PACKAGES" for target in node.targets)
    )
    value = {
        "schema": 1,
        "packages": package_selection(source, base_packages=base_packages),
        "pins": pins,
        "files": {
            path: hashlib.sha256((source / path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            for path in files
        },
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


def collect(captured_utc: str) -> bytes:
    """Retain the exact official index and primary bytes used to admit RPMs."""
    documents: dict[str, str] = {}

    def download(url: str, limit: int) -> bytes:
        content = _download_photon_repository_document(url, limit)
        documents[url] = base64.b64encode(content).decode("ascii")
        return content

    _photon_repository_inventory(download)
    content = canonical_json({"schema": 1, "captured_utc": captured_utc, "documents": documents})
    read_snapshot(content)
    return content


def read_snapshot(content: bytes, *, now: datetime | None = None) -> set[Package]:
    """Verify the approval lifetime and re-derive the package identities offline."""
    if not 0 < len(content) <= MAX_SNAPSHOT_BYTES:
        raise ValueError("Photon snapshot exceeds its size limit")
    value = json.loads(content)
    if (not isinstance(value, dict) or set(value) != {"schema", "captured_utc", "documents"}
            or type(value["schema"]) is not int or value["schema"] != 1 or not isinstance(value["captured_utc"], str)
            or not isinstance(value["documents"], dict) or len(value["documents"]) != 2 * len(PHOTON_REPOSITORY_URLS)
            or canonical_json(value) != content):
        raise ValueError("Photon snapshot metadata is invalid")
    captured = datetime.fromisoformat(value["captured_utc"].replace("Z", "+00:00"))
    age = (now or datetime.now(UTC)) - captured if captured.utcoffset() == timedelta(0) else None
    if age is None or not timedelta(0) <= age < MAX_SNAPSHOT_AGE:
        raise ValueError("Photon snapshot is expired or has an invalid capture time")
    documents = dict(value["documents"])

    def download(url: str, limit: int) -> bytes:
        encoded = documents.pop(url, None)
        if not isinstance(encoded, str) or len(encoded) > 4 * ((limit + 2) // 3):
            raise ValueError("Photon snapshot is missing a required bounded metadata document")
        result = base64.b64decode(encoded, validate=True)
        if not 0 < len(result) <= limit:
            raise ValueError("Photon snapshot metadata document exceeds its size limit")
        return result

    packages = _photon_repository_inventory(download)
    if documents:
        raise ValueError("Photon snapshot contains unused metadata documents")
    return packages


def read_pinned_snapshot(path: Path, expected: str) -> set[Package]:
    """Bind a local snapshot to the checksum obtained during protected admission."""
    content = read_bounded_regular(path, MAX_SNAPSHOT_BYTES)
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Photon snapshot differs from the admitted capture")
    return read_snapshot(content)


def captured_packages(inventory: set[Package], rpm_inventory: list[dict]) -> set[Package]:
    """Require catalog membership for every RPM except the separately verified local QEMU agent."""
    if any(not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
           or not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
           for entry in rpm_inventory):
        raise ValueError("Photon snapshot capture inventory is invalid")
    hashes = {
        entry["sha256"]
        for entry in rpm_inventory
        if entry["path"].endswith(".rpm")
        and not re.fullmatch(r"guest-tools/qemu/atlaso-qemu-guest-agent-[A-Za-z0-9._+-]+[.]rpm", entry["path"])
    }
    selected = {package for package in inventory if package[-1] in hashes}
    if not hashes or {package[-1] for package in selected} != hashes:
        raise ValueError("approved Photon snapshot does not cover the complete captured RPM inventory")
    return selected


def audit(selected: set[Package]) -> dict:
    """Compare selected RPM identities and security advisories against the live catalog."""
    current = _photon_repository_inventory()
    by_name_arch: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for name, epoch, version, release, arch, _ in selected:
        by_name_arch.setdefault((name, arch), set()).add((epoch, version, release))
    updates = ET.fromstring(_photon_repository_metadata(PHOTON_REPOSITORY_URLS[-1], "updateinfo"))
    if updates.tag != "updates" or not list(updates):
        raise ValueError("Photon security advisory metadata is invalid")
    advisories = set()
    for update in updates.findall("update"):
        if update.get("type") != "security":
            continue
        advisory = update.findtext("id") or ""
        if not re.fullmatch(r"PHSA-[0-9]{4}-5[.]0-[0-9]+", advisory):
            raise ValueError("Photon security advisory identity is invalid")
        for package in update.findall("./pkglist/collection/package"):
            name, arch = package.get("name", ""), package.get("arch", "")
            fixed = (package.get("epoch", ""), package.get("version", ""), package.get("release", ""))
            if any(_older_than(installed, fixed) for installed in by_name_arch.get((name, arch), ())):
                advisories.add((advisory, name, arch))
    return {"missing_from_current_metadata": sorted(selected - current), "security_advisories": sorted(advisories)}


def _older_than(installed: tuple[str, str, str], fixed: tuple[str, str, str]) -> bool:
    """Compare package versions with RPM's own version ordering."""
    if not all(RPM_COMPONENT.fullmatch(part) for part in (*installed, *fixed)):
        raise ValueError("Photon package version has an unsupported RPM identity")
    if not all(re.fullmatch(r"[0-9]{1,10}", epoch) for epoch in (installed[0], fixed[0])):
        raise ValueError("Photon package epoch is invalid")
    if int(installed[0]) != int(fixed[0]):
        return int(installed[0]) < int(fixed[0])
    script = (
        f'local v=rpm.vercmp("{installed[1]}","{fixed[1]}"); '
        f'if v==0 then v=rpm.vercmp("{installed[2]}","{fixed[2]}") end; print(v)'
    )
    result = _run_runtime_tool(["rpm", "--eval", "%{lua:" + script + "}"]).strip()
    if result not in {"-1", "0", "1"}:
        raise ValueError("Photon security advisory version comparison failed")
    return result == "-1"
