"""Prepare and validate bounded read-only evidence from an installed ISO guest."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
import textwrap
import zlib
from pathlib import Path
from typing import Any

import pycdlib

from scripts.installation import iso as installation_iso

_MAX_MANIFEST = 16 * 1024 * 1024
_MAX_ISO = 16 * 1024 * 1024 * 1024
_MAX_REPORT = 4096
_MAX_PROGRAM = 3500
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_MEDIA_FILES = {
    "software/release-manifest.json",
    "source/image/common/scripts/verify-template-software.py",
    "source/scripts/interop/routing_deployment_inspection.py",
}
_REPORT_KEYS = {
    "schema", "machine_id_sha256", "host_key_sha256", "version", "source_commit",
    "wheel_sha256", "wheel_payload_sha256", "installed_payload_sha256", "verified_payload_files",
}
_EXPECTED_KEYS = {
    "schema", "iso_sha256", "version", "source_commit", "release_manifest_sha256",
    "software_verifier_sha256", "payload_inspector_sha256", "wheel_sha256",
}


class _BoundedBuffer(io.BytesIO):
    """Collect one bounded ISO member."""

    def __init__(self, maximum: int) -> None:
        """Create a member sink with a fixed limit.

        Args:
            maximum: Maximum number of bytes accepted.
        """
        super().__init__()
        self.maximum = maximum

    def write(self, value: bytes) -> int:
        """Append a block while enforcing the member limit.

        Args:
            value: Next block from the ISO reader.
        """
        if self.tell() + len(value) > self.maximum:
            raise ValueError("ISO member exceeds the inspection bound")
        return super().write(value)


class _NamedBufferedReader(io.BufferedReader):
    """Expose a path name to PyCdlib while retaining the pinned input handle."""

    def __init__(self, raw: io.RawIOBase, name: str) -> None:
        """Wrap the already opened input and provide its validated name.

        Args:
            raw: Open, identity-pinned file stream.
            name: Absolute validated filesystem path for PyCdlib diagnostics.
        """
        super().__init__(raw)
        self._validated_name = name

    @property
    def name(self) -> str:
        """Return the path that was checked before the handle was opened."""
        return self._validated_name


def _sha256(data: bytes) -> str:
    """Return the SHA-256 digest of a bounded media member.

    Args:
        data: Public authenticated media bytes.
    """
    return hashlib.sha256(data).hexdigest()


def _iso_member(iso: pycdlib.PyCdlib, path: str) -> bytes:
    """Read a Rock Ridge member after checking its declared size.

    Args:
        iso: Open checksum-admitted ISO image.
        path: Absolute Rock Ridge media path.
    """
    record = iso.get_record(rr_path=path)
    if record.is_dir() or record.data_length > _MAX_MANIFEST:
        raise ValueError("ISO member exceeds the inspection bound")
    stream = _BoundedBuffer(_MAX_MANIFEST)
    iso.get_file_from_iso_fp(stream, rr_path=path)
    return stream.getvalue()


def _admitted_inputs(iso_path: Path, iso_sha256: str, *, content: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Bind base and optional content expectations to the original installer.

    Args:
        iso_path: Original development ISO selected by the VM receipt.
        iso_sha256: Independently preserved digest of that ISO.
        content: Also prepare the fixed existing-validator content checks.
    """
    if not _DIGEST.fullmatch(iso_sha256):
        raise ValueError("installation ISO digest is invalid")
    checked_path = installation_iso._checked_path(iso_path, final_kind="file")
    if checked_path.stat().st_size > _MAX_ISO:
        raise ValueError("installation ISO is outside the inspection bound")
    pinned = installation_iso._open_pinned(checked_path)
    stream = _NamedBufferedReader(pinned.stream, str(checked_path))
    with contextlib.closing(stream):
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_ISO:
            raise ValueError("installation ISO is outside the inspection bound")
        if pinned.digest != iso_sha256:
            raise ValueError("installation ISO differs from its admitted digest")
        stream.seek(0)
        iso = pycdlib.PyCdlib()
        opened = False
        try:
            iso.open_fp(stream)
            opened = True
            manifest_raw = _iso_member(iso, "/atlaso/payload-manifest.json")
            if not manifest_raw or len(manifest_raw) > _MAX_MANIFEST:
                raise ValueError("installation manifest is outside the inspection bound")
            manifest = json.loads(manifest_raw)
            if not isinstance(manifest, dict) or manifest.get("schema") != 1:
                raise ValueError("installation manifest schema is unsupported")
            development = manifest.get("development")
            if (not isinstance(development, dict)
                    or set(development) != {"schema", "software_source_commit", "non_production"}
                    or development.get("schema") != 1 or development.get("non_production") is not True):
                raise ValueError("installation ISO is not admitted development media")
            version, commit = manifest.get("version"), development.get("software_source_commit")
            if (not isinstance(version, str) or not _VERSION.fullmatch(version)
                    or not isinstance(commit, str) or not _COMMIT.fullmatch(commit)):
                raise ValueError("installation software identity is invalid")
            records = manifest.get("files")
            if not isinstance(records, list) or len(records) > 100_000:
                raise ValueError("installation file inventory is invalid")
            inventory: dict[str, str] = {}
            for item in records:
                if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
                    raise ValueError("installation file inventory record is invalid")
                name, digest = item["path"], item["sha256"]
                if (not isinstance(name, str) or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
                        or type(item["size"]) is not int or item["size"] < 0 or name in inventory):
                    raise ValueError("installation file inventory identity is invalid")
                inventory[name] = digest
            if not _MEDIA_FILES <= inventory.keys():
                raise ValueError("installation media lacks required inspection inputs")
            release = _iso_member(iso, "/atlaso/software/release-manifest.json")
            if (not release or len(release) > _MAX_MANIFEST
                    or _sha256(release) != inventory["software/release-manifest.json"]):
                raise ValueError("release manifest differs from signed media inventory")
            release_value = json.loads(release)
            if (not isinstance(release_value, dict) or release_value.get("version") != version
                    or release_value.get("git_commit") != commit):
                raise ValueError("release manifest software identity differs")
            source_raw = _iso_member(iso, "/atlaso/software/virtualization-source.json")
            if len(source_raw) > _MAX_MANIFEST:
                raise ValueError("software source identity is outside the inspection bound")
            if _sha256(source_raw) != inventory.get("software/virtualization-source.json"):
                raise ValueError("software source differs from signed media inventory")
            source = json.loads(source_raw)
            if not isinstance(source, dict):
                raise ValueError("signed software source identity is invalid")
            wheel_path = source.get("application_wheel")
            wheel_digest = source.get("application_wheel_sha256")
            if (source.get("release_manifest_sha256") != inventory["software/release-manifest.json"]
                    or source.get("version") != version or source.get("source_commit") != commit
                    or not isinstance(wheel_path, str) or not wheel_path.startswith("packages/atlaso-")
                    or not isinstance(wheel_digest, str) or not _DIGEST.fullmatch(wheel_digest)):
                raise ValueError("signed software wheel identity is invalid")
            if inventory.get("software/" + wheel_path) != wheel_digest:
                raise ValueError("application wheel differs from signed media inventory")
            installation_iso._verify_pinned(pinned)
            expected = {
                "schema": 1, "iso_sha256": iso_sha256, "version": version, "source_commit": commit,
                "release_manifest_sha256": inventory["software/release-manifest.json"],
                "software_verifier_sha256": inventory["source/image/common/scripts/verify-template-software.py"],
                "payload_inspector_sha256": inventory["source/scripts/interop/routing_deployment_inspection.py"],
                "wheel_sha256": wheel_digest,
            }
            checks = []
            if content:
                from scripts.installation.content_inspection import (
                    SOURCE_MEMBERS,
                    prepare_content_inputs,
                )

                sources = {name: _iso_member(iso, "/atlaso/" + name) for name in SOURCE_MEMBERS}
                checks = prepare_content_inputs(expected, manifest, sources)
                installation_iso._verify_pinned(pinned)
            return expected, checks
        finally:
            if opened:
                iso.close()


def expected_inputs(iso_path: Path, iso_sha256: str) -> dict[str, Any]:
    """Bind the existing application/identity check to a checksum-admitted ISO.

    Args:
        iso_path: Original development ISO selected by the VM receipt.
        iso_sha256: Independently preserved digest of that ISO.
    """
    return _admitted_inputs(iso_path, iso_sha256)[0]


def guest_program(
    expected: dict[str, Any], *, atlaso_root: str | Path = "/opt/atlaso",
    software_root: str | Path = "/var/lib/atlaso/installation-inspection/software", identity_root: str | Path = "/"
) -> str:
    """Return a bounded shell command that prints only public inspection data.

    Args:
        expected: Output of :func:`expected_inputs`.
        atlaso_root: Installed source root; injectable only for isolated fixtures.
        software_root: Staged signed software root; injectable only for isolated fixtures.
        identity_root: Public identity filesystem root; injectable only for isolated fixtures.
    """
    if set(expected) != _EXPECTED_KEYS or expected.get("schema") != 1:
        raise ValueError("inspection expectations are invalid")
    for field in ("iso_sha256", "release_manifest_sha256", "software_verifier_sha256", "payload_inspector_sha256", "wheel_sha256"):
        if not isinstance(expected[field], str) or not _DIGEST.fullmatch(expected[field]):
            raise ValueError("inspection expectation digest is invalid")
    expected_json = base64.b64encode(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).decode()
    source_root_json = json.dumps(str(atlaso_root))
    software_root_json = json.dumps(str(software_root))
    identity_root_json = json.dumps(str(identity_root))
    body = f'''import base64,hashlib,importlib.metadata,json,os,re,stat,types
e=json.loads(base64.b64decode("{expected_json}"))
def load(p,h,n):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);s=os.fdopen(fd,"rb");z=os.fstat(fd);b=s.read(1048577);s.close()
 if not stat.S_ISREG(z.st_mode) or z.st_nlink!=1 or len(b)>1048576 or hashlib.sha256(b).hexdigest()!=h: raise ValueError()
 m=types.ModuleType(n);exec(compile(b,p,"exec"),m.__dict__);return m
from pathlib import Path
phase="source-helpers"
v=load({source_root_json}+"/image/common/scripts/verify-template-software.py",e["software_verifier_sha256"],"_atlaso_verified_software")
i=load({source_root_json}+"/scripts/interop/routing_deployment_inspection.py",e["payload_inspector_sha256"],"_atlaso_verified_payload")
phase="software-staging"
if not Path({software_root_json}).is_dir(): raise ValueError()
phase="software-verification"
s=v.verify(Path({software_root_json}),e["release_manifest_sha256"],e["version"],e["source_commit"])
w=Path({software_root_json},s["application_wheel"])
phase="application-payload"
p=i.installed_payload(w,Path(importlib.metadata.distribution("atlaso").locate_file("")))
def read(p,n):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);s=os.fdopen(fd,"rb");z=os.fstat(fd);b=s.read(n+1);s.close()
 if not stat.S_ISREG(z.st_mode) or z.st_nlink!=1 or len(b)>n: raise ValueError()
 return b
phase="public-identities"
mid=read(str(Path({identity_root_json})/"etc/machine-id"),128).strip()
k=read(str(Path({identity_root_json})/"etc/ssh/ssh_host_ed25519_key.pub"),4096).split(None,2)
if not re.fullmatch(b"[0-9a-f]{{32}}",mid) or mid==b"0"*32 or len(k)<2 or k[0]!=b"ssh-ed25519": raise ValueError()
b=base64.b64decode(k[1],validate=True)
if len(b)!=51 or int.from_bytes(b[:4],"big")!=11 or b[4:15]!=b"ssh-ed25519" or int.from_bytes(b[15:19],"big")!=32: raise ValueError()
r={{"schema":1,"machine_id_sha256":hashlib.sha256(mid).hexdigest(),"host_key_sha256":"SHA256:"+base64.b64encode(hashlib.sha256(b).digest()).decode().rstrip("="),"version":s["version"],"source_commit":s["source_commit"],"wheel_sha256":i.file_digest(w,268435456),**p}}
x=json.dumps(r,sort_keys=True,separators=(",",":")).encode()
if len(x)>2048: raise ValueError()
print("ATLASO-INSPECTION:"+base64.b64encode(x).decode()+":END")'''
    program = 'phase="initialization"\ntry:\n' + textwrap.indent(body, " ") + '\nexcept BaseException:\n print("ATLASO-INSPECTION-FAILED:"+phase)'
    command = "/opt/atlaso/.venv/bin/python -B -I -c 'exec(__import__(\"zlib\").decompress(__import__(\"base64\").b64decode(\"" + base64.b64encode(zlib.compress(program.encode(), 9)).decode() + "\")))'"
    if len(command) > _MAX_PROGRAM or not command.isascii():
        raise ValueError("read-only inspection command exceeds the console bound")
    return command


def validate_report(raw: bytes, expected: dict[str, Any]) -> dict[str, Any]:
    """Validate and reduce a bounded public guest report.

    Args:
        raw: Exact JSON bytes recovered from the private console marker.
        expected: Original ISO-bound expected inputs.
    """
    if not raw or len(raw) > _MAX_REPORT:
        raise ValueError("inspection report is outside the bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("inspection report is invalid") from exc
    if (not isinstance(value, dict) or set(value) != _REPORT_KEYS or type(value.get("schema")) is not int
            or value["schema"] != 1):
        raise ValueError("inspection report schema is invalid")
    for key in ("machine_id_sha256", "wheel_sha256", "wheel_payload_sha256", "installed_payload_sha256"):
        if not isinstance(value.get(key), str) or not _DIGEST.fullmatch(value[key]):
            raise ValueError("inspection report digest is invalid")
    fingerprint = value.get("host_key_sha256")
    try:
        fingerprint_bytes = base64.b64decode(fingerprint[7:] + "=", validate=True) if isinstance(fingerprint, str) else b""
    except base64.binascii.Error:
        fingerprint_bytes = b""
    if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:") or len(fingerprint_bytes) != 32:
        raise ValueError("inspection host key identity is invalid")
    if value["wheel_payload_sha256"] != value["installed_payload_sha256"]:
        raise ValueError("installed application payload differs from its wheel")
    if (set(expected) != _EXPECTED_KEYS or expected.get("schema") != 1
            or value.get("version") != expected.get("version") or value.get("source_commit") != expected.get("source_commit")
            or value.get("wheel_sha256") != expected.get("wheel_sha256")):
        raise ValueError("installed software identity differs from the admitted ISO")
    if type(value.get("verified_payload_files")) is not int or not 1 <= value["verified_payload_files"] <= 10_000:
        raise ValueError("inspection payload file count is invalid")
    return {key: value[key] for key in sorted(_REPORT_KEYS)}


def _decode(value: str) -> bytes:
    """Decode a strict base64 CLI argument within a fixed size limit.

    Args:
        value: Encoded public report or ISO expectations.
    """
    if len(value) > 8192:
        raise ValueError("encoded inspection input exceeds the bound")
    return base64.b64decode(value, validate=True)


def main() -> int:
    """Serve the PowerShell bounded consumer with prepare/validate operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--iso", type=Path, required=True)
    prepare.add_argument("--iso-sha256", required=True)
    prepare.add_argument("--content", action="store_true")
    validate = sub.add_parser("validate")
    validate.add_argument("--expected", required=True)
    validate.add_argument("--report", required=True)
    content_validate = sub.add_parser("validate-content")
    content_validate.add_argument("--expected", required=True)
    content_validate.add_argument("--report", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            if args.content:
                expected, checks = _admitted_inputs(args.iso, args.iso_sha256, content=True)
            else:
                expected, checks = expected_inputs(args.iso, args.iso_sha256), []
            result = {"expected": expected, "command": guest_program(expected)}
            if args.content:
                from scripts.installation.content_inspection import (
                    guest_content_program,
                    rpm_diagnostic_packages,
                )

                result["content"] = [{"expected": check, "command": guest_content_program(check),
                                      "diagnostic_packages": rpm_diagnostic_packages(check)} for check in checks]
        elif args.operation == "validate-content":
            from scripts.installation.content_inspection import validate_content_report

            expected = json.loads(_decode(args.expected))
            result = validate_content_report(_decode(args.report), expected)
        else:
            expected = json.loads(_decode(args.expected))
            result = validate_report(_decode(args.report), expected)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        limit = 32768 if args.operation == "prepare" and args.content else _MAX_REPORT
        if len(encoded) > limit:
            raise ValueError("inspection output exceeds the bound")
        sys.stdout.write(encoded + "\n")
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, base64.binascii.Error,
            pycdlib.pycdlibexception.PyCdlibException):
        sys.stderr.write("Installed inspection could not validate its bounded inputs.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
