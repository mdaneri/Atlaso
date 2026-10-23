"""Verify offline installation content using Atlaso's detached-signature format."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

MANIFEST = "payload-manifest.json"
SIGNATURE = MANIFEST + ".sig"
KEY_ID = "atlaso-release-2026-01"
SOURCE_ISO_SHA512 = "6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f"
PHOTON_INSTALLER_SHA256 = "8e3c361b7f05012d124d04ddf3bba503542b0f955bd8ba39f8a263999c825902"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def digest(path: Path) -> str:
    """Hash a regular single-link file without accepting a linked ancestor.

    Args:
        path: Filesystem path to the input or target."""
    if path.resolve(strict=True) != path.absolute():
        raise ValueError("installation inputs cannot contain symbolic links")
    with path.open("rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("installation inputs must be ordinary single-link files")
        result = hashlib.sha256()
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
        after = os.fstat(handle.fileno())
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise ValueError("installation input changed while reading")
    return result.hexdigest()


def canonical_json(value: dict) -> bytes:
    """Reuse the canonical representation used by Atlaso release signers.

    Args:
        value: Value to validate or serialize."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def verify_signature(document: Path, signature: Path, trust_key: Path, *, scratch: Path) -> dict:
    """Verify Ed25519 with Photon's OpenSSL instead of bootstrapping Python deps.

    Args:
        document: Signed metadata document to verify.
        signature: Detached signature file for the metadata document.
        trust_key: Trusted public key used to verify signed metadata.
        scratch: Existing private directory for temporary validation data."""
    for path in (document, signature, trust_key):
        digest(path)
    if document.stat().st_size > 8 * 1024 * 1024 or signature.stat().st_size > 4096:
        raise ValueError("signed installation metadata exceeds its bound")
    raw = json.loads(signature.read_bytes())
    if not isinstance(raw, dict) or raw.get("schema_version") != 1 or raw.get("key_id") != KEY_ID:
        raise ValueError("installation signature does not use the pinned Atlaso key")
    binary = base64.b64decode(raw.get("signature", ""), validate=True)
    if len(binary) != 64:
        raise ValueError("installation signature has an invalid size")
    with tempfile.TemporaryDirectory(prefix="signature-", dir=scratch) as temporary:
        signature_file = Path(temporary) / "signature.bin"
        signature_file.write_bytes(binary)
        subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(trust_key), "-rawin", "-in", str(document), "-sigfile", str(signature_file)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    value = json.loads(document.read_bytes())
    if not isinstance(value, dict) or value.get("signing_key_id") != KEY_ID:
        raise ValueError("installation manifest signing identity differs")
    return value


def inventory(root: Path) -> list[dict]:
    """Enumerate exact media files without admitting links or special entries.

    Args:
        root: Root directory containing the files being checked."""
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError("installation media contains a link or special entry")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name in {MANIFEST, SIGNATURE}:
            continue
        records.append({"path": name, "size": path.stat().st_size, "sha256": digest(path)})
    return records


def verify_media(root: Path, trust_key: Path, *, scratch: Path) -> dict:
    """Authenticate every embedded byte before permitting disk writes.

    Args:
        root: Root directory containing the files being checked.
        trust_key: Trusted public key used to verify signed metadata.
        scratch: Existing private directory for temporary validation data."""
    value = verify_signature(root / MANIFEST, root / SIGNATURE, trust_key, scratch=scratch)
    if value.get("schema") != 1 or value.get("architecture") != "x86_64" or value.get("photon_installer") != "2.2":
        raise ValueError("installation media schema or architecture is unsupported")
    if value.get("photon_iso_sha512") != SOURCE_ISO_SHA512 or value.get("photon_installer_sha256") != PHOTON_INSTALLER_SHA256:
        raise ValueError("installation media Photon inputs differ from their pinned identities")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value.get("version", "")) or not re.fullmatch(r"[0-9a-f]{40}", value.get("source_commit", "")):
        raise ValueError("installation software identity is invalid")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages or not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", name) for name in packages) or len(packages) != len(set(packages)):
        raise ValueError("installation package selection is invalid")
    files = value.get("files")
    if not isinstance(files, list) or not files or len(files) > 100000:
        raise ValueError("installation file inventory is invalid")
    names = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ValueError("installation file record is invalid")
        name = item["path"]
        if not isinstance(name, str) or PurePosixPath(name).is_absolute() or PurePosixPath(name).as_posix() != name or any(part in {".", ".."} for part in name.split("/")) or "\\" in name:
            raise ValueError("installation file path is invalid")
        if name in names or type(item["size"]) is not int or item["size"] < 0 or not isinstance(item["sha256"], str) or not HEX.fullmatch(item["sha256"]):
            raise ValueError("installation file identity is invalid or duplicated")
        names.add(name)
    required = {
        "software/release-manifest.json", "software/release-manifest.json.sig", "software/virtualization-source.json",
        "source/scripts/installation/installer.py", "source/image/common/scripts/provision-atlaso.sh", "tdnf.conf",
    }
    if not required <= names or not any(name.startswith("rpms/") and name.endswith(".rpm") for name in names) or not any(name.startswith("powercli/") for name in names):
        raise ValueError("installation media is incomplete")
    if files != inventory(root):
        raise ValueError("installation media differs from its signed file inventory")
    rpms = value.get("rpm_inventory")
    if not isinstance(rpms, list) or not rpms:
        raise ValueError("installation RPM inventory is missing")
    rpm_names = set()
    rpm_files = set()
    checksums = {item["path"]: item["sha256"] for item in files}
    for rpm in rpms:
        if not isinstance(rpm, dict) or set(rpm) != {"file", "name", "version", "architecture", "sha256"}:
            raise ValueError("installation RPM record is invalid")
        if not all(isinstance(rpm[field], str) and rpm[field] for field in rpm):
            raise ValueError("installation RPM fields are invalid")
        name = rpm["file"]
        if "/" in name or "\\" in name or not name.endswith(".rpm") or rpm["architecture"] not in {"x86_64", "noarch"}:
            raise ValueError("installation RPM file or architecture is invalid")
        if rpm["name"] in rpm_names or name in rpm_files or checksums.get("rpms/" + name) != rpm["sha256"]:
            raise ValueError("installation RPM inventory differs from its files")
        rpm_names.add(rpm["name"])
        rpm_files.add(name)
    if not set(packages) <= rpm_names or {"rpms/" + name for name in rpm_files} != {name for name in names if name.startswith("rpms/") and name.endswith(".rpm")}:
        raise ValueError("installation RPM inventory is incomplete")
    source = json.loads((root / "software/virtualization-source.json").read_bytes())
    if source.get("version") != value["version"] or source.get("source_commit") != value["source_commit"]:
        raise ValueError("installation and software identities differ")
    if digest(root / "software/release-manifest.json") != source.get("release_manifest_sha256"):
        raise ValueError("embedded software release manifest differs")
    return value
