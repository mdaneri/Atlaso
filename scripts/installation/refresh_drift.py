"""Report Photon ISO capture drift without changing runtime admission policy."""

from __future__ import annotations

import difflib
import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from scripts.installation import content_inspection
from scripts.installation.build import package_selection
from scripts.installation.iso import _checked_path, _open_pinned, _verify_pinned
from scripts.verify_virtualization_guest_wheel import _photon_repository_inventory

MAX_CAPTURE_PACKAGES = 1024
MAX_NATIVE_FILES = 10_000
MAX_NATIVE_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_SCRIPTLET_BYTES = 512 * 1024
MAX_SCRIPTLET_DIFF_BYTES = 128 * 1024
MAX_RPM_COMMAND_SECONDS = 30
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,191}\Z")

# Values are imported from the same constants used by content inspection.
_RUNTIME_PROFILES = {
    "filesystem": content_inspection.PHOTON_FILESYSTEM_SHA256,
    "systemd": content_inspection.PHOTON_SYSTEMD_SHA256,
    "audit": content_inspection.PHOTON_AUDIT_SHA256,
    "rpcbind": content_inspection.PHOTON_RPCBIND_SHA256,
    "openssh-server": content_inspection.PHOTON_OPENSSH_SHA256,
    "openldap-servers": content_inspection.PHOTON_OPENLDAP_SHA256,
    "shim-signed": content_inspection.PHOTON_SHIM_SHA256,
    "grub2-efi-image": content_inspection.PHOTON_GRUB_EFI_SHA256,
}


def capture_drift_report(
    captured: list[dict[str, Any]],
    current: list[dict[str, Any]],
    package_names: list[str],
) -> dict[str, Any]:
    """Compare a complete captured closure with current official identities and pins.

    This is diagnostic only. A clean report does not authenticate packages or
    replace the normal complete-transaction validation.
    """
    if len(captured) > MAX_CAPTURE_PACKAGES or len(current) > 100_000:
        raise ValueError("package inventory exceeds its bound")
    if (len(package_names) > MAX_CAPTURE_PACKAGES
            or any(not isinstance(name, str) or not _PACKAGE.fullmatch(name) for name in package_names)
            or len(package_names) != len(set(package_names))):
        raise ValueError("selected package inventory is invalid")
    captured_by_name = _index_records(captured)
    current_by_name: dict[str, list[dict[str, Any]]] = {}
    for record in current:
        key, value = next(iter(_index_records([record]).items()))
        current_by_name.setdefault(key, []).append(value)

    packages: list[dict[str, Any]] = []
    for name in sorted(set(package_names) | captured_by_name.keys()):
        old = captured_by_name.get(name)
        available = current_by_name.get(name, [])
        if old is None:
            packages.append({"name": name, "status": "requires_capture", "current_candidates": len(available),
                             "current": sorted(available, key=_identity)[:8]})
        elif not any(_identity(old) == _identity(item) for item in available):
            packages.append({"name": name, "status": "stale_metadata", "captured": old,
                             "current_candidates": len(available),
                             "current": sorted(available, key=_identity)[:8]})
        else:
            packages.append({"name": name, "status": "current", "captured": old})

    profile_names = set(_RUNTIME_PROFILES) | set(content_inspection.PHOTON_MODULE_RPMS)
    # The bootstrap pair is conditionally present in ISO manifests; when present,
    # its exact reviewed bytes remain mandatory.
    bootstrap_names = set(content_inspection.PHOTON_BOOTSTRAP_PIP_RPMS)
    profile_names |= bootstrap_names & (captured_by_name.keys() | set(package_names))
    profiles = []
    for name in sorted(profile_names):
        expected = (_RUNTIME_PROFILES.get(name)
                    or content_inspection.PHOTON_MODULE_RPMS.get(name)
                    or content_inspection.PHOTON_BOOTSTRAP_PIP_RPMS.get(name))
        record = captured_by_name.get(name)
        official = current_by_name.get(name, [])
        pin_available = any(item["sha256"] == expected for item in official)
        if not pin_available:
            status = "requires_review"
        elif record is None:
            status = "requires_capture"
        elif record["sha256"] != expected:
            status = "requires_review"
        else:
            status = "reviewed_profile"
        profiles.append({"name": name, "status": status,
                         "captured_sha256": record["sha256"] if record else None,
                         "reviewed_sha256": expected,
                         "official_pin_available": pin_available,
                         "official_candidates": len(official),
                         "official_sha256": sorted({item["sha256"] for item in official})[:8]})

    statuses = {record["status"] for record in packages}
    profile_statuses = {record["status"] for record in profiles}
    return {
        "schema": 1,
        "diagnostic_only": True,
        "authenticated_transaction_validated": False,
        "requires_full_transaction_validation": True,
        "status": "requires_review" if profile_statuses & {"requires_review", "unknown_profile"} else
                  "stale_metadata" if "stale_metadata" in statuses else
                  "requires_capture" if "requires_capture" in statuses | profile_statuses else "current",
        "packages": packages,
        "profiles": profiles,
    }


def _index_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    required = {"file", "name", "version", "architecture", "sha256"}
    for record in records:
        if (not isinstance(record, dict) or set(record) != required
                or not isinstance(record["name"], str) or not _PACKAGE.fullmatch(record["name"])
                or not isinstance(record["file"], str) or Path(record["file"]).name != record["file"]
                or record["architecture"] not in {"x86_64", "noarch"}
                or not isinstance(record["version"], str) or len(record["version"]) > 192
                or not isinstance(record["sha256"], str) or not _SHA256.fullmatch(record["sha256"])
                or record["name"] in indexed):
            raise ValueError("package inventory is invalid")
        indexed[record["name"]] = dict(record)
    return indexed


def _identity(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (record["name"], record["version"], record["architecture"], record["sha256"])


def compare_native_packages(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, review-only comparison of fixed RPM header/file/script data."""
    _validate_native_record(old)
    _validate_native_record(new)
    fields = ("name", "epoch", "version", "release", "architecture", "source_rpm",
              "license", "vendor", "group", "build_time", "installed_size", "archive_size")
    header = {field: {"old": old[field], "new": new[field]}
              for field in fields if old[field] != new[field]}
    old_files = {item["path"]: item for item in old["files"]}
    new_files = {item["path"]: item for item in new["files"]}
    all_paths = sorted(old_files.keys() | new_files.keys())
    file_changes = []
    file_change_count = 0
    file_change_hash = hashlib.sha256()
    for path in all_paths:
        before, after = old_files.get(path), new_files.get(path)
        if before != after:
            file_change_count += 1
            file_change_hash.update(path.encode("utf-8") + b"\0")
            file_change_hash.update(repr((before, after)).encode("utf-8") + b"\0")
            if len(file_changes) < 512:
                file_changes.append({"path": path, "old": before, "new": after})
    scripts_changed = old["scriptlets_sha256"] != new["scriptlets_sha256"]
    script_diff = "".join(difflib.unified_diff(
        old["scriptlets"].splitlines(keepends=True),
        new["scriptlets"].splitlines(keepends=True),
        fromfile="old-scriptlets", tofile="new-scriptlets", n=2,
    )) if scripts_changed else ""
    diff_truncated = len(script_diff.encode("utf-8")) > MAX_SCRIPTLET_DIFF_BYTES
    if diff_truncated:
        script_diff = script_diff.encode("utf-8")[:MAX_SCRIPTLET_DIFF_BYTES].decode("utf-8", "ignore")
    return {
        "schema": 1,
        "package": old["name"],
        "sha256_changed": old["sha256"] != new["sha256"],
        "identity_changed": any(field in header for field in fields[:6]),
        "header_changes": header,
        "file_changes": file_changes,
        "file_changes_truncated": file_change_count > 512,
        "file_change_count": file_change_count,
        "file_changes_sha256": file_change_hash.hexdigest(),
        "scriptlets_changed": scripts_changed,
        "old_scriptlets_sha256": old["scriptlets_sha256"],
        "new_scriptlets_sha256": new["scriptlets_sha256"],
        "scriptlets_diff": script_diff,
        "scriptlets_diff_truncated": diff_truncated,
        "runtime_behavior_changed": bool(file_change_count or scripts_changed),
        "digest_only_unchanged_behavior": old["sha256"] != new["sha256"] and not file_change_count and not scripts_changed,
        "requires_review": bool(old["sha256"] != new["sha256"] or header or file_change_count or scripts_changed),
    }


def _validate_native_record(record: dict[str, Any]) -> None:
    fields = {"name", "epoch", "version", "release", "architecture", "source_rpm", "license",
              "vendor", "group", "build_time", "installed_size", "archive_size", "files",
              "scriptlets_sha256", "scriptlets_bytes", "scriptlets", "sha256"}
    if (not isinstance(record, dict) or set(record) != fields
            or not isinstance(record["name"], str) or not _PACKAGE.fullmatch(record["name"])
            or not isinstance(record["files"], list) or len(record["files"]) > MAX_NATIVE_FILES
            or not isinstance(record["scriptlets_bytes"], int)
            or not 0 <= record["scriptlets_bytes"] <= MAX_SCRIPTLET_BYTES
            or not isinstance(record["scriptlets_sha256"], str)
            or not _SHA256.fullmatch(record["scriptlets_sha256"])
            or not isinstance(record["sha256"], str) or not _SHA256.fullmatch(record["sha256"])
            or not isinstance(record["scriptlets"], str)
            or len(record["scriptlets"].encode("utf-8")) != record["scriptlets_bytes"]
            or hashlib.sha256(record["scriptlets"].encode("utf-8")).hexdigest() != record["scriptlets_sha256"]):
        raise ValueError("native RPM report exceeds its schema or bounds")
    if sum(len(str(value).encode("utf-8")) for value in record.values()) > MAX_NATIVE_OUTPUT_BYTES:
        raise ValueError("native RPM header report exceeds its bound")
    seen: set[str] = set()
    for item in record["files"]:
        if (not isinstance(item, dict)
                or set(item) != {"path", "size", "mtime", "digest", "mode", "owner", "group", "flags",
                                 "isconfig", "isdoc", "rdev", "link"}
                or not isinstance(item["path"], str) or not item["path"].startswith("/")
                or len(item["path"]) > 4096 or item["path"] in seen
                or any("\n" in str(value) or "\t" in str(value) for value in item.values())):
            raise ValueError("native RPM file report is invalid")
        seen.add(item["path"])


def _run_rpm(arguments: list[str], *, byte_limit: int) -> bytes:
    """Run a fixed RPM query with a timeout and a hard combined output ceiling."""
    import os
    import threading

    if os.environ.get("ATLASO_NATIVE_RPM_CONTEXT"):
        from scripts.native_rpm_tools import run

        return run(["rpm", *arguments], byte_limit=byte_limit,
                   timeout_seconds=MAX_RPM_COMMAND_SECONDS).encode("utf-8")

    executable = shutil.which("rpm")
    if executable is None:
        raise RuntimeError("rpm_tool_unavailable")
    process = subprocess.Popen([executable, *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_chunks: list[bytes] = []
    size = 0
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(pipe: Any, keep: bool) -> None:
        nonlocal size
        while chunk := pipe.read(8192):
            with lock:
                size += len(chunk)
                if size > byte_limit:
                    exceeded.set()
                    process.kill()
                elif keep:
                    stdout_chunks.append(chunk)

    readers = [threading.Thread(target=drain, args=(process.stdout, True), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, False), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=MAX_RPM_COMMAND_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("rpm_query_timeout") from None
    finally:
        for reader in readers:
            reader.join(timeout=5)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
    if exceeded.is_set():
        raise RuntimeError("rpm_query_output_limit")
    if process.returncode:
        raise RuntimeError("rpm_query_failed")
    return b"".join(stdout_chunks)


def inspect_native_package(package: Path) -> dict[str, Any]:
    """Read only fixed public RPM header, file dump, and scriptlet data for review."""
    return _inspect_package(package, native=True)


def _inspect_package_identity(package: Path) -> dict[str, Any]:
    """Read only the bounded identity fields needed for early capture drift."""
    return _inspect_package(package, native=False)


def _inspect_package(package: Path, *, native: bool) -> dict[str, Any]:
    """Query a pinned RPM path and verify the same file after every read."""
    pinned = _open_pinned(package)
    if pinned.stream is None:
        raise ValueError("rpm_path_invalid")
    try:
        identity_fmt = "ATLASO\\t%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n"
        header = _run_rpm(["-qp", "--qf", identity_fmt, str(pinned.path)], byte_limit=16 * 1024)
        rows = [line.split("\t") for line in header.decode("utf-8", "strict").splitlines()
                if line.startswith("ATLASO\t")]
        if len(rows) != 1 or len(rows[0]) != 6:
            raise ValueError("rpm_header_invalid")
        name, epoch, version, release, architecture = rows[0][1:]
        identity = {"file": pinned.path.name, "name": name, "epoch": epoch,
                    "version": version, "release": release, "architecture": architecture,
                    "sha256": pinned.digest}
        if not native:
            _verify_pinned(pinned)
            return identity

        detail_fmt = ("ATLASO\\t%{SOURCERPM}\\t%{LICENSE}\\t%{VENDOR}\\t%{GROUP}\\t"
                      "%{BUILDTIME}\\t%{SIZE}\\t%{ARCHIVESIZE}\\n")
        detail_raw = _run_rpm(["-qp", "--qf", detail_fmt, str(pinned.path)], byte_limit=16 * 1024)
        details = [line.split("\t") for line in detail_raw.decode("utf-8", "strict").splitlines()
                   if line.startswith("ATLASO\t")]
        if len(details) != 1 or len(details[0]) != 8:
            raise ValueError("rpm_header_invalid")
        file_fmt = ("[%{FILENAMES}\\t%{FILESIZES}\\t%{FILEMTIMES}\\t%{FILEDIGESTS}\\t"
                    "%{FILEMODES}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\t%{FILEFLAGS}\\t"
                    "%{FILERDEVS}\\t%{FILELINKTOS}\\n]")
        files_raw = _run_rpm(["-qp", "--qf", file_fmt, str(pinned.path)], byte_limit=MAX_NATIVE_OUTPUT_BYTES)
        files = []
        for line in files_raw.decode("utf-8", "strict").splitlines():
            fields = line.split("\t")
            if len(fields) != 10 or len(files) >= MAX_NATIVE_FILES:
                raise ValueError("rpm_file_report_invalid")
            path, size, mtime, digest_value, mode, owner, group, flags, rdev, link = fields
            if not path.startswith("/") or ".." in Path(path).parts or any(ch in path for ch in "\t\r\n"):
                raise ValueError("rpm_file_path_invalid")
            try:
                flags_value = int(flags, 0)
            except ValueError as exc:
                raise ValueError("rpm_file_report_invalid") from exc
            files.append({"path": path, "size": size, "mtime": mtime, "digest": digest_value,
                          "mode": mode, "owner": owner, "group": group, "flags": flags,
                          "isconfig": bool(flags_value & 1), "isdoc": bool(flags_value & 2),
                          "rdev": rdev, "link": link})
        scripts_raw = _run_rpm(["-qp", "--scripts", str(pinned.path)], byte_limit=MAX_SCRIPTLET_BYTES)
        record = {key: value for key, value in identity.items() if key != "file"}
        record.update(dict(zip(("source_rpm", "license", "vendor", "group", "build_time",
                                "installed_size", "archive_size"), details[0][1:], strict=True)))
        record.update(files=files, scriptlets=scripts_raw.decode("utf-8", "strict"),
                      scriptlets_sha256=hashlib.sha256(scripts_raw).hexdigest(),
                      scriptlets_bytes=len(scripts_raw))
        _validate_native_record(record)
        _verify_pinned(pinned)
        return record
    finally:
        pinned.stream.close()


def _ordinary_file(path: Path) -> Path:
    """Resolve an existing regular single-link RPM under ordinary directories."""
    return _checked_path(path, final_kind="file")


def inspect_capture(
    repository: Path, rpms: Path, *, package_names: list[str] | None = None
) -> dict[str, Any]:
    """Inspect an existing capture against current official metadata and reviewed profiles.

    A returned current status is informational. Call the ordinary signed RPM and
    complete transaction validator before allowing any build or installation.
    """
    selected = package_selection(repository)
    if package_names is not None and package_names != selected:
        raise ValueError("selected package inventory differs from admitted source")
    package_names = selected
    try:
        rpms.lstat()
    except FileNotFoundError:
        current = [_current_record(item) for item in _photon_repository_inventory()
                   if item[4] in {"x86_64", "noarch"}]
        return capture_drift_report([], current, package_names)
    root = _ordinary_directory(rpms)
    if len(package_names) > MAX_CAPTURE_PACKAGES:
        raise ValueError("capture_path_invalid")
    entries = list(root.iterdir())
    packages = [item for item in entries if item.suffix == ".rpm"]
    repodata = [item for item in entries if item.name == "repodata"]
    if len(packages) > MAX_CAPTURE_PACKAGES:
        raise ValueError("capture_inventory_incomplete")
    allowed = {item.name for item in packages} | ({"repodata"} if repodata else set())
    if {item.name for item in entries} != allowed or len(repodata) > 1:
        raise ValueError("capture_inventory_invalid")
    if repodata:
        _validate_repodata(repodata[0])
    current_inventory = _photon_repository_inventory()
    current_records = [_current_record(item) for item in current_inventory
                       if item[4] in {"x86_64", "noarch"}]
    captured_records = []
    for package in sorted(packages):
        native = _inspect_package_identity(package)
        captured_records.append({"file": native["file"], "name": native["name"],
                                 "version": f"{native['epoch']}:{native['version']}-{native['release']}",
                                 "architecture": native["architecture"], "sha256": native["sha256"]})
    if not set(package_names) <= {record["name"] for record in captured_records}:
        raise ValueError("capture_inventory_incomplete")
    report = capture_drift_report(captured_records, current_records, package_names)
    report["native_inventory"] = captured_records
    report["authenticated_transaction_validated"] = False
    report["requires_full_transaction_validation"] = True
    return report


def _current_record(identity: tuple[str, str, str, str, str, str]) -> dict[str, Any]:
    name, epoch, version, release, architecture, sha256 = identity
    return {"file": "", "name": name, "version": f"{epoch}:{version}-{release}",
            "architecture": architecture, "sha256": sha256}


def _validate_repodata(path: Path) -> None:
    """Admit a bounded, ordinary flat metadata directory inside an RPM capture."""
    directory = _ordinary_directory(path)
    entries = list(directory.iterdir())
    if len(entries) > 64:
        raise ValueError("capture_repodata_invalid")
    for entry in entries:
        _ordinary_file(entry)


def _ordinary_directory(path: Path) -> Path:
    """Require an existing directory and every parent component to be unlinked."""
    return _checked_path(path, final_kind="directory")
