"""Authenticate and fully read back an assembled development installation ISO."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pycdlib

from scripts.installation import iso as installation_iso
from scripts.installation.manifest import (
    DEVELOPMENT_KEY_ID,
    MANIFEST,
    PHOTON_INSTALLER_SHA256,
    SIGNATURE,
    SOURCE_ISO_SHA512,
    canonical_json,
)

_MAX_ISO = 16 * 1024**3
_MAX_MANIFEST = 16 * 1024**2
_MAX_SIGNATURE = 4096
_MAX_FILES = 100_000
_MAX_MEMBER = 8 * 1024**3
_MAX_TOTAL = 16 * 1024**3
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]*\Z")
_TEST_SEED = bytes(range(32))
ROOT = Path(__file__).resolve().parents[2]
TRUST_KEY = ROOT / "image/common/update-trust/atlaso-release-2026-01.pem"


def _trusted_sources(repository: Path, commit: str) -> dict[str, bytes]:
    """Bind installer source to the clean, pinned checkout's exact Git archive.

    Args:
        repository: Trusted Atlaso checkout containing the admitted source files.
        commit: Exact full Git commit whose source bytes are required.
    """
    from scripts.installation.development import _source_archive

    return _source_archive(repository, commit)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before authenticating the parsed structure.

    Args:
        pairs: Decoded JSON key/value pairs, including any duplicate keys.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("installation metadata contains duplicate keys")
        result[key] = value
    return result


def _parse_manifest(raw: bytes, signature_raw: bytes) -> dict[str, Any]:
    """Verify the explicit public development trust and validate media identities.

    Args:
        raw: Canonical manifest bytes to authenticate and parse.
        signature_raw: Detached signature envelope bytes accompanying the manifest.
    """
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        signature = json.loads(signature_raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("development installation metadata is invalid JSON") from exc
    if not isinstance(value, dict) or not isinstance(signature, dict):
        raise ValueError("development installation metadata schema is invalid")
    if canonical_json(value) != raw:
        raise ValueError("development installation manifest is not canonical")
    if (
        set(signature) != {"schema_version", "algorithm", "key_id", "signature"}
        or signature.get("schema_version") != 1
        or signature.get("algorithm") != "ed25519"
        or signature.get("key_id") != DEVELOPMENT_KEY_ID
    ):
        raise ValueError("development installation signature identity is invalid")
    try:
        encoded_signature = base64.b64decode(signature.get("signature", ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("development installation signature encoding is invalid") from exc
    if len(encoded_signature) != 64:
        raise ValueError("development installation signature size is invalid")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_key = Ed25519PrivateKey.from_private_bytes(_TEST_SEED).public_key()
    try:
        public_key.verify(encoded_signature, raw)
    except InvalidSignature as exc:
        raise ValueError("development installation manifest signature is invalid") from exc

    development = value.get("development")
    if (
        value.get("schema") != 1
        or value.get("architecture") != "x86_64"
        or value.get("photon_installer") != "2.2"
        or value.get("photon_installer_sha256") != PHOTON_INSTALLER_SHA256
        or value.get("photon_iso_sha512") != SOURCE_ISO_SHA512
        or value.get("signing_key_id") != DEVELOPMENT_KEY_ID
        or not isinstance(development, dict)
        or set(development) != {"schema", "software_source_commit", "non_production"}
        or development.get("schema") != 1
        or development.get("non_production") is not True
    ):
        raise ValueError("installation ISO is not admitted development media")
    if (
        not isinstance(value.get("source_commit"), str)
        or not _COMMIT.fullmatch(value["source_commit"])
        or not isinstance(development.get("software_source_commit"), str)
        or not _COMMIT.fullmatch(development["software_source_commit"])
        or not isinstance(value.get("version"), str)
        or not _VERSION.fullmatch(value["version"])
    ):
        raise ValueError("installation source or software identity is invalid")
    if not isinstance(value.get("packages"), list) or not value["packages"]:
        raise ValueError("installation package selection is invalid")
    if (
        any(not isinstance(name, str) or not _PACKAGE.fullmatch(name) for name in value["packages"])
        or len(set(value["packages"])) != len(value["packages"])
    ):
        raise ValueError("installation package selection is invalid")
    records = value.get("files")
    if not isinstance(records, list) or not records or len(records) > _MAX_FILES:
        raise ValueError("installation file inventory is invalid")
    names: set[str] = set()
    total = 0
    for item in records:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ValueError("installation file inventory record is invalid")
        name, size, checksum = item["path"], item["size"], item["sha256"]
        path = PurePosixPath(name) if isinstance(name, str) else None
        if (
            path is None
            or path.is_absolute()
            or path.as_posix() != name
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or "\\" in name
        ):
            raise ValueError("installation file path is invalid")
        if (
            name in names
            or type(size) is not int
            or size < 0
            or size > _MAX_MEMBER
            or not isinstance(checksum, str)
            or not _DIGEST.fullmatch(checksum)
        ):
            raise ValueError("installation file inventory identity is invalid")
        names.add(name)
        total += size
        if total > _MAX_TOTAL:
            raise ValueError("installation payload exceeds the readback bound")
    required = {
        "software/release-manifest.json",
        "software/release-manifest.json.sig",
        "software/virtualization-source.json",
        "source/scripts/installation/installer.py",
        "source/image/common/scripts/provision-atlaso.sh",
        "source/image/common/update-trust/atlaso-release-2026-01.pem",
        "tdnf.conf",
    }
    if (
        not required <= names
        or not any(name.startswith("rpms/") and name.endswith(".rpm") for name in names)
        or not any(name.startswith("powercli/") for name in names)
    ):
        raise ValueError("installation media is incomplete")
    if not isinstance(value.get("rpm_inventory"), list) or not value["rpm_inventory"]:
        raise ValueError("installation RPM inventory is missing")
    rpm_records = value["rpm_inventory"]
    rpm_names: set[str] = set()
    rpm_files: set[str] = set()
    checksums = {item["path"]: item["sha256"] for item in records}
    for rpm in rpm_records:
        if not isinstance(rpm, dict) or set(rpm) != {"file", "name", "version", "architecture", "sha256"}:
            raise ValueError("installation RPM record is invalid")
        if not all(isinstance(rpm[field], str) and rpm[field] for field in rpm):
            raise ValueError("installation RPM identity is invalid")
        filename = rpm["file"]
        if (
            "/" in filename
            or "\\" in filename
            or not filename.endswith(".rpm")
            or rpm["architecture"] not in {"x86_64", "noarch"}
        ):
            raise ValueError("installation RPM file identity is invalid")
        if (
            rpm["name"] in rpm_names
            or filename in rpm_files
            or checksums.get("rpms/" + filename) != rpm["sha256"]
        ):
            raise ValueError("installation RPM inventory differs from its signed files")
        rpm_names.add(rpm["name"])
        rpm_files.add(filename)
    if (
        not set(value["packages"]) <= rpm_names
        or {"rpms/" + name for name in rpm_files}
        != {name for name in names if name.startswith("rpms/") and name.endswith(".rpm")}
    ):
        raise ValueError("installation RPM inventory is incomplete")
    if "source/scripts/installation/guest_tools.py" in names:
        if not {"guest-tools/compatibility.json", "guest-tools/SHA256SUMS"} <= names or any(
            not any(name.startswith("guest-tools/" + profile + "/") and name.endswith(".rpm") for name in names)
            for profile in ("vmware", "hyperv", "qemu")
        ):
            raise ValueError("installation guest-tools payload is incomplete")
    return value


def _stream_digest(iso: pycdlib.PyCdlib, rr_path: str, expected_size: int) -> tuple[int, str]:
    """Hash one bounded ISO member through PyCdlib's streaming reader.

    Args:
        iso: Open read-only ISO filesystem used for payload inspection.
        rr_path: Exact Rock Ridge path inside the ISO filesystem.
        expected_size: Authenticated byte count required for this ISO member.
    """
    record = iso.get_record(rr_path=rr_path)
    if record.is_dir() or record.is_symlink() or record.data_length != expected_size or expected_size > _MAX_MEMBER:
        raise ValueError("installation ISO member size differs from its signed inventory")
    result = hashlib.sha256()
    count = 0
    with iso.open_file_from_iso(rr_path=rr_path) as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > expected_size:
                raise ValueError("installation ISO member exceeds its signed size")
            result.update(chunk)
    if count != expected_size:
        raise ValueError("installation ISO member is truncated")
    return count, result.hexdigest()


def _member_bytes(iso: pycdlib.PyCdlib, rr_path: str, maximum: int) -> bytes:
    """Read one small ISO metadata member after checking the declared size.

    Args:
        iso: Open read-only ISO filesystem used for payload inspection.
        rr_path: Exact Rock Ridge path inside the ISO filesystem.
        maximum: Maximum admitted number of bytes for this metadata member.
    """
    record = iso.get_record(rr_path=rr_path)
    if record.is_dir() or record.is_symlink() or record.data_length > maximum:
        raise ValueError("installation ISO metadata exceeds its bound")
    output = io.BytesIO()
    iso.get_file_from_iso_fp(output, rr_path=rr_path)
    value = output.getvalue()
    if len(value) != record.data_length:
        raise ValueError("installation ISO metadata is truncated")
    return value


def _walk_payload(iso: pycdlib.PyCdlib, root: str):
    """Follow logical Rock Ridge paths without basename-based relocation lookup.

    Args:
        iso: Open read-only ISO filesystem.
        root: Absolute Rock Ridge directory to enumerate.
    """
    pending = [root]
    seen_directories: set[int] = set()
    count = 0
    while pending:
        directory = pending.pop()
        record = iso.get_record(rr_path=directory)
        extent = record.extent_location()
        if extent in seen_directories:
            raise ValueError("installation ISO payload contains aliased directories")
        seen_directories.add(extent)
        names: set[str] = set()
        for child in record.children:
            if child.is_dot() or child.is_dotdot():
                continue
            if child.rock_ridge is None:
                raise ValueError("installation ISO payload lacks a Rock Ridge name")
            name = child.rock_ridge.name().decode("utf-8")
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError("installation ISO payload contains an invalid path")
            if name in names:
                raise ValueError("installation ISO payload contains duplicate paths")
            names.add(name)
            count += 1
            if count > 2 * _MAX_FILES + 2:
                raise ValueError("installation ISO payload contains too many entries")
            path = directory + "/" + name
            # get_record follows the exact CL extent. PyCdlib.walk instead
            # selects relocated directories by basename, aliasing repeated names.
            resolved = iso.get_record(rr_path=path)
            if resolved.is_symlink():
                raise ValueError("installation ISO payload contains a symbolic link")
            is_directory = resolved.is_dir()
            yield path, is_directory
            if is_directory:
                pending.append(path)


def _all_payload_paths(iso: pycdlib.PyCdlib) -> tuple[set[str], set[str]]:
    """Enumerate every Rock Ridge payload file and directory, rejecting excess.

    Args:
        iso: Open read-only ISO filesystem used for payload inspection.
    """
    files: list[str] = []
    directories: list[str] = [""]
    for path, is_directory in _walk_payload(iso, "/atlaso"):
        relative = path.removeprefix("/atlaso/")
        (directories if is_directory else files).append(relative)
    if len(files) != len(set(files)) or len(directories) != len(set(directories)):
        raise ValueError("installation ISO payload contains duplicate paths")
    return set(files), set(directories)


class _IsoReadStream(io.RawIOBase):
    """Provide readinto for the canonical streaming software digest verifier."""

    def __init__(self, stream):
        """Initialize the read-only ISO stream or path adapter.

        Args:
            stream: Unopened PyCdlib stream whose context initializes the file offset.
        """
        super().__init__()
        self.stream = stream.__enter__()

    def readable(self):
        return True

    def readinto(self, buffer):
        """Read the next initialized ISO stream chunk into a writable buffer.

        Args:
            buffer: Writable buffer receiving the next chunk of ISO file bytes.
        """
        data = self.stream.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        self.stream.close()
        super().close()


class _IsoSoftwarePath:
    """Read-only Path interface for the existing exact signed-software checker."""

    def __init__(self, image, path="/atlaso/software"):
        """Initialize the read-only ISO stream or path adapter.

        Args:
            image: Open read-only PyCdlib filesystem backing this path adapter.
            path: Exact Rock Ridge software path exposed through the read-only adapter.
        """
        self.image, self.path = image, path

    def is_symlink(self):
        return self.image.get_record(rr_path=self.path).is_symlink()

    def is_junction(self):
        return False  # ISO records have no NTFS junction representation.

    def is_dir(self):
        return self.image.get_record(rr_path=self.path).is_dir()

    def is_file(self):
        record = self.image.get_record(rr_path=self.path)
        return not record.is_dir() and stat.S_ISREG(record.rock_ridge.get_file_mode())

    def rglob(self, pattern):
        """Enumerate the complete signed software tree without extraction.

        Args:
            pattern: Traversal pattern; only the complete wildcard is supported.
        """
        if pattern != "*":
            raise ValueError("unsupported software readback traversal")
        for path, _ in _walk_payload(self.image, self.path):
            yield _IsoSoftwarePath(self.image, path)

    def relative_to(self, root):
        """Express this ISO member relative to its software root.

        Args:
            root: Software root adapter against which the member path is expressed.
        """
        return PurePosixPath(self.path).relative_to(PurePosixPath(root.path))

    def read_bytes(self):
        return _member_bytes(self.image, self.path, _MAX_MANIFEST)

    def read_text(self, encoding="utf-8"):
        """Decode one bounded ISO metadata file.

        Args:
            encoding: Text encoding used to decode bounded metadata bytes.
        """
        return self.read_bytes().decode(encoding)

    def open(self, mode):
        """Open one ISO payload member for streaming binary verification.

        Args:
            mode: Requested file mode; only binary reading is supported.
        """
        if mode != "rb":
            raise ValueError("software ISO readback is read-only")
        return _IsoReadStream(self.image.open_file_from_iso(rr_path=self.path))


def full_readback(
    iso_path: Path,
    iso_sha256: str,
    *,
    installer_commit: str,
    software_commit: str,
    software_version: str,
    repository: Path = ROOT,
    trust_key: Path = TRUST_KEY,
    capture_inventory: dict[str, list[dict]] | None = None,
) -> dict[str, object]:
    """Authenticate signed development media and hash every embedded payload byte.

    This verifies the development ISO's signed inventory and distinct installer
    and signed-software identities. RPM signatures, official metadata, and the
    complete native RPM transaction remain the build admission's responsibility.

    Args:
        iso_path: Existing development ISO selected for readback.
        iso_sha256: Independently captured digest expected for the complete ISO.
        installer_commit: Exact full source commit embedded in the installer.
        software_commit: Exact signed application software source commit.
        software_version: Exact signed application release version.
        repository: Independent clean source checkout pinned by the native owner.
        trust_key: Independent host production trust key, never selected by media.
        capture_inventory: Optional independently admitted original RPM/PowerCLI input identity.
    """
    if not _DIGEST.fullmatch(iso_sha256):
        raise ValueError("installation ISO digest is invalid")
    if not _COMMIT.fullmatch(installer_commit) or not _COMMIT.fullmatch(software_commit):
        raise ValueError("installation source commit is invalid")
    if not _VERSION.fullmatch(software_version):
        raise ValueError("installation software version is invalid")

    checked = installation_iso._checked_path(Path(iso_path), final_kind="file")
    pinned = installation_iso._open_pinned(checked)
    iso_file = None
    image = pycdlib.PyCdlib()
    opened = False
    try:
        if pinned.identity[2] > _MAX_ISO or pinned.digest != iso_sha256:
            raise ValueError("installation ISO differs from its admitted digest or size")
        iso_file = checked.open("rb", buffering=0)
        if installation_iso._identity(os.fstat(iso_file.fileno())) != pinned.identity:
            raise ValueError("installation ISO changed after its admitted digest")
        image.open_fp(iso_file)
        opened = True
        if not image.rock_ridge:
            raise ValueError("installation ISO lacks Rock Ridge payload paths")
        raw_manifest = _member_bytes(image, "/atlaso/payload-manifest.json", _MAX_MANIFEST)
        raw_signature = _member_bytes(image, "/atlaso/payload-manifest.json.sig", _MAX_SIGNATURE)
        value = _parse_manifest(raw_manifest, raw_signature)
        if value["source_commit"] != installer_commit:
            raise ValueError("installation media source differs from the admitted installer commit")
        development = value["development"]
        if development["software_source_commit"] != software_commit or value["version"] != software_version:
            raise ValueError("installation media differs from the admitted signed software identity")

        signed_records = value["files"]
        expected_files = {item["path"]: item for item in signed_records}
        expected_files[MANIFEST] = {"path": MANIFEST, "size": len(raw_manifest), "sha256": hashlib.sha256(raw_manifest).hexdigest()}
        expected_files[SIGNATURE] = {"path": SIGNATURE, "size": len(raw_signature), "sha256": hashlib.sha256(raw_signature).hexdigest()}
        expected_dirs = {""}
        for name in expected_files:
            parent = PurePosixPath(name).parent
            while parent.as_posix() != ".":
                expected_dirs.add(parent.as_posix())
                parent = parent.parent
        actual_files, actual_dirs = _all_payload_paths(image)
        if actual_files != set(expected_files) or actual_dirs != expected_dirs:
            raise ValueError("installation ISO payload paths differ from the authenticated inventory")
        for directory in actual_dirs - {""}:
            record = image.get_record(rr_path="/atlaso/" + directory)
            if not record.is_dir() or record.is_symlink():
                raise ValueError("installation ISO payload contains a non-directory path")

        file_extents: set[tuple[int, int]] = set()
        for name, item in expected_files.items():
            record = image.get_record(rr_path="/atlaso/" + name)
            if record.is_symlink() or not stat.S_ISREG(record.rock_ridge.get_file_mode()):
                raise ValueError("installation ISO payload contains a non-regular file")
            extent = (record.extent_location(), record.data_length)
            if record.data_length and extent in file_extents:
                raise ValueError("installation ISO payload contains aliased file extents")
            file_extents.add(extent)
            size, checksum = item["size"], item["sha256"]
            if name in {MANIFEST, SIGNATURE}:
                raw = raw_manifest if name == MANIFEST else raw_signature
                observed = (len(raw), hashlib.sha256(raw).hexdigest())
            else:
                observed = _stream_digest(image, "/atlaso/" + name, size)
            if observed != (size, checksum):
                raise ValueError("installation ISO payload differs from the authenticated inventory")

        source_inventory = {item["path"]: item["sha256"] for item in signed_records}
        if capture_inventory is not None:
            if set(capture_inventory) != {"rpms", "powercli"}:
                raise ValueError("original capture inventory schema differs")
            expected_capture = {}
            for kind, items in capture_inventory.items():
                for item in items:
                    if kind == "rpms" and item["path"].startswith("guest-tools/"):
                        expected_capture[item["path"]] = item["sha256"]
                        continue
                    if kind == "rpms" and not item["path"].endswith(".rpm"):
                        continue  # Repository metadata is regenerated by canonical assembly.
                    expected_capture[kind + "/" + item["path"]] = item["sha256"]
            actual_capture = {name: checksum for name, checksum in source_inventory.items()
                              if name.startswith(("powercli/", "guest-tools/")) or (name.startswith("rpms/") and name.endswith(".rpm"))}
            if expected_capture != actual_capture:
                raise ValueError("installation media differs from original complete captured input identities")
        trusted_sources = _trusted_sources(repository, installer_commit)
        expected_source = {"source/" + name: hashlib.sha256(raw).hexdigest()
                           for name, raw in trusted_sources.items()}
        actual_source = {name: checksum for name, checksum in source_inventory.items() if name.startswith("source/")}
        if actual_source != expected_source:
            raise ValueError("installation source bytes differ from the trusted exact-commit archive")
        release_raw = _member_bytes(image, "/atlaso/software/release-manifest.json", _MAX_MANIFEST)
        release_signature_raw = _member_bytes(image, "/atlaso/software/release-manifest.json.sig", _MAX_SIGNATURE)
        software_source_raw = _member_bytes(image, "/atlaso/software/virtualization-source.json", _MAX_MANIFEST)
        software_source = json.loads(software_source_raw, object_pairs_hook=_unique_object)
        release = json.loads(release_raw, object_pairs_hook=_unique_object)
        if not isinstance(software_source, dict) or not isinstance(release, dict):
            raise ValueError("signed software identity is invalid")
        if (
            release.get("schema_version") != 2
            or release.get("kind") != "atlaso-release"
            or software_source.get("version") != software_version
            or software_source.get("source_commit") != software_commit
            or release.get("version") != software_version
            or release.get("git_commit") != software_commit
            or release.get("signing_key_id") != "atlaso-release-2026-01"
            or software_source.get("release_manifest_sha256") != source_inventory.get("software/release-manifest.json")
        ):
            raise ValueError("signed software release identity differs from admitted inputs")
        wheel = software_source.get("application_wheel")
        wheel_digest = software_source.get("application_wheel_sha256")
        if (
            not isinstance(wheel, str)
            or not wheel.startswith("packages/")
            or PurePosixPath(wheel).is_absolute()
            or ".." in PurePosixPath(wheel).parts
            or not isinstance(wheel_digest, str)
            or not _DIGEST.fullmatch(wheel_digest)
            or source_inventory.get("software/" + wheel) != wheel_digest
        ):
            raise ValueError("signed software wheel identity differs from admitted media")
        release_envelope = json.loads(release_signature_raw, object_pairs_hook=_unique_object)
        if (
            not isinstance(release_envelope, dict)
            or set(release_envelope) != {"schema_version", "key_id", "signature"}
            or release_envelope.get("schema_version") != 1
            or release_envelope.get("key_id") != "atlaso-release-2026-01"
        ):
            raise ValueError("signed software release signature identity is invalid")
        try:
            release_signature = base64.b64decode(release_envelope["signature"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("signed software release signature encoding is invalid") from exc
        if len(release_signature) != 64:
            raise ValueError("signed software release signature size is invalid")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key_raw = _member_bytes(
            image,
            "/atlaso/source/image/common/update-trust/atlaso-release-2026-01.pem",
            1024 * 1024,
        )
        # The development signer is public test data. Embedded trust alone cannot
        # authenticate production software: use the independent host source pin.
        from scripts.completed_task_files import read_bounded_regular

        trusted_key_raw = read_bounded_regular(trust_key, 1024**2)
        if key_raw != trusted_key_raw:
            raise ValueError("embedded software trust differs from the independent host trust key")
        trusted_key = serialization.load_pem_public_key(trusted_key_raw)
        if not isinstance(trusted_key, Ed25519PublicKey):
            raise ValueError("signed software release key is not Ed25519")
        try:
            trusted_key.verify(release_signature, release_raw)
        except InvalidSignature as exc:
            raise ValueError("signed software release manifest signature is invalid") from exc
        # Reuse the complete existing software contract, including signed content
        # hashes, exactly one application wheel, the canonical offline wheelhouse
        # lock, CPython ABI and exact virtualization-source metadata. The ISO
        # adapter streams bytes without extracting another mutable input tree.
        specification = importlib.util.spec_from_file_location(
            "installation_readback_software", repository / "image/common/scripts/verify-template-software.py"
        )
        if specification is None or specification.loader is None:
            raise ValueError("canonical software verifier is unavailable")
        verifier = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(verifier)
        try:
            verifier.verify(_IsoSoftwarePath(image), hashlib.sha256(release_raw).hexdigest(), software_version, software_commit)
        except SystemExit as exc:
            raise ValueError("installation software differs from its complete authenticated contract") from exc
        installation_iso._verify_pinned(pinned)
        return {
            "schema": 1,
            "result": "passed",
            "kind": "authenticated-development-iso-readback",
            "iso_sha256": iso_sha256,
            "installer_source_commit": installer_commit,
            "software_source_commit": software_commit,
            "software_version": software_version,
            "payload_file_count": len(expected_files),
            "payload_bytes": sum(item["size"] for item in expected_files.values()),
            "rpm_count": len(value["rpm_inventory"]),
            "authenticated_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
            "rpm_native_transaction_retested": False,
            "installer_source_archive_verified": True,
            "captured_input_inventory_verified": capture_inventory is not None,
            "captured_input_inventory_sha256": hashlib.sha256(canonical_json(capture_inventory)).hexdigest() if capture_inventory is not None else None,
        }
    finally:
        if opened:
            image.close()
        if iso_file is not None:
            iso_file.close()
        if pinned.stream is not None:
            pinned.stream.close()


__all__ = ["full_readback"]
