"""Test deterministic, non-admitting Photon capture drift reports."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from scripts.installation import content_inspection, guest_tools, refresh_drift


def _record(name: str, version: str, digest: str) -> dict[str, Any]:
    """Build one RPM inventory record.

    Args:
        name: Package name recorded by the fixture.
        version: Epoch, version, and release string for the package.
        digest: SHA-256 digest associated with the package.
    """
    return {
        "file": f"{name}-1.0-1.ph5.x86_64.rpm",
        "name": name,
        "version": version,
        "architecture": "x86_64",
        "sha256": digest,
    }


def _native(scriptlets: str = "", *, file_mode: str = "0100755") -> dict[str, Any]:
    """Build one native RPM metadata record.

    Args:
        scriptlets: RPM scriptlet text included in the record.
        file_mode: Mode string assigned to the fixture file entry.
    """
    raw = scriptlets.encode("utf-8")
    return {
        "name": "openssh-server", "epoch": "0", "version": "10.6p1", "release": "2.ph5",
        "sha256": "a" * 64,
        "architecture": "x86_64", "source_rpm": "openssh-10.6p1-2.ph5.src.rpm",
        "license": "BSD", "vendor": "Photon", "group": "System",
        "build_time": "1", "installed_size": "10", "archive_size": "20",
        "files": [{"path": "/usr/share/empty.sshd", "size": "0", "mtime": "1",
                   "digest": "X", "mode": file_mode, "owner": "root", "group": "root",
                   "flags": "0", "isconfig": False, "isdoc": False, "rdev": "0", "link": "X"}],
        "scriptlets": scriptlets,
        "scriptlets_sha256": hashlib.sha256(raw).hexdigest(),
        "scriptlets_bytes": len(raw),
    }


def test_capture_report_accepts_only_current_identity_and_retains_non_admitting_marker() -> None:
    profiles = {**refresh_drift._RUNTIME_PROFILES, **content_inspection.PHOTON_MODULE_RPMS}
    records = [_record(name, "0:1-1.ph5", sha) for name, sha in profiles.items()]
    names = sorted(profiles)

    report = refresh_drift.capture_drift_report(records, records, names)

    assert report["status"] == "current"
    assert report["diagnostic_only"] is True
    assert report["authenticated_transaction_validated"] is False
    assert all(item["status"] == "current" for item in report["packages"])


def test_capture_report_distinguishes_missing_capture_from_stale_metadata() -> None:
    old = _record("bash", "0:5.1-1.ph5", "a" * 64)
    now = _record("bash", "0:5.2-1.ph5", "b" * 64)
    profiles = {**refresh_drift._RUNTIME_PROFILES, **content_inspection.PHOTON_MODULE_RPMS}
    current_profiles = [_record(name, "0:1-1.ph5", sha) for name, sha in profiles.items()]

    stale = refresh_drift.capture_drift_report([old, *current_profiles], [now, *current_profiles], ["bash"])
    missing = refresh_drift.capture_drift_report([], [now, *current_profiles], ["bash"])

    assert stale["status"] == "stale_metadata"
    assert next(item for item in stale["packages"] if item["name"] == "bash")["status"] == "stale_metadata"
    assert missing["status"] == "requires_capture"


def test_capture_report_blocks_capture_when_official_runtime_pin_is_unavailable() -> None:
    expected = content_inspection.PHOTON_OPENSSH_SHA256
    captured = [_record("openssh-server", "0:10.6p1-2.ph5", expected)]
    current = [_record("openssh-server", "0:10.7p1-1.ph5", "d" * 64)]

    report = refresh_drift.capture_drift_report(captured, current, ["openssh-server"])

    profile = next(item for item in report["profiles"] if item["name"] == "openssh-server")
    assert report["status"] == "requires_review"
    assert profile["official_pin_available"] is False
    assert profile["status"] == "requires_review"


def test_profile_digest_drift_requires_review_and_unknown_profile_refuses() -> None:
    expected = content_inspection.PHOTON_OPENSSH_SHA256
    captured = [_record("openssh-server", "0:10.6p1-2.ph5", "c" * 64)]
    current = [_record("openssh-server", "0:10.6p1-2.ph5", "c" * 64)]

    report = refresh_drift.capture_drift_report(captured, current, ["openssh-server"])

    profile = next(item for item in report["profiles"] if item["name"] == "openssh-server")
    assert profile["name"] == "openssh-server"
    assert profile["status"] == "requires_review"
    assert profile["captured_sha256"] == "c" * 64
    assert profile["reviewed_sha256"] == expected
    assert report["status"] == "requires_review"


def test_native_comparison_shows_metadata_and_bounded_scriptlet_diff() -> None:
    report = refresh_drift.compare_native_packages(_native("mkdir /var/lib/example\n"),
                                                  _native("mkdir /var/lib/changed\n", file_mode="0100700"))

    assert report["requires_review"] is True
    assert report["identity_changed"] is False
    assert len(report["file_changes"]) == 1
    assert report["scriptlets_changed"] is True
    assert "-mkdir /var/lib/example" in report["scriptlets_diff"]
    assert "+mkdir /var/lib/changed" in report["scriptlets_diff"]
    assert report["scriptlets_diff_truncated"] is False


def test_native_comparison_rejects_oversized_or_forged_scriptlet_data() -> None:
    oversized = _native("x" * (refresh_drift.MAX_SCRIPTLET_BYTES + 1))
    forged = _native("echo x")
    forged["scriptlets_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="native RPM report"):
        refresh_drift.compare_native_packages(oversized, _native())
    with pytest.raises(ValueError, match="native RPM report"):
        refresh_drift.compare_native_packages(forged, _native())


def test_capture_report_rejects_duplicate_package_names_and_unbounded_inventory() -> None:
    record = _record("bash", "0:5.2-1.ph5", "a" * 64)

    with pytest.raises(ValueError, match="package inventory"):
        refresh_drift.capture_drift_report([record, record], [], ["bash"])
    with pytest.raises(ValueError, match="package inventory"):
        refresh_drift.capture_drift_report([record] * (refresh_drift.MAX_CAPTURE_PACKAGES + 1), [], ["bash"])


def test_native_comparison_reports_changes_after_display_bound() -> None:
    old = _native()
    new = _native()
    old["files"] = [{"path": f"/a/{index:04}", "size": "1", "mtime": "1", "digest": "X",
                     "mode": "0100644", "owner": "root", "group": "root", "flags": "0",
                     "isconfig": False, "isdoc": False, "rdev": "0", "link": "X"}
                    for index in range(513)]
    new["files"] = [dict(item) for item in old["files"]]
    new["files"][-1]["mode"] = "0100600"

    report = refresh_drift.compare_native_packages(old, new)

    assert report["runtime_behavior_changed"] is True
    assert report["file_change_count"] == 1
    assert report["file_changes_truncated"] is False
    assert report["file_changes"][0]["path"] == "/a/0512"


def test_native_comparison_separates_identity_digest_from_runtime_behavior() -> None:
    old = _native()
    new = _native()
    new["version"] = "10.7p1"
    new["sha256"] = "b" * 64

    report = refresh_drift.compare_native_packages(old, new)

    assert report["sha256_changed"] is True
    assert report["identity_changed"] is True
    assert report["runtime_behavior_changed"] is False
    assert report["digest_only_unchanged_behavior"] is True
    assert report["requires_review"] is True


def test_capture_without_directory_reports_current_profile_availability(monkeypatch, tmp_path) -> None:
    """Report official profile availability when no capture directory exists.

    Args:
        monkeypatch: Pytest patcher for package selection and repository metadata.
        tmp_path: Isolated source and absent RPM directory paths.
    """
    selected = ["openssh-server"]
    current = {("openssh-server", "0", "10.7p1", "1.ph5", "x86_64", "d" * 64)}
    monkeypatch.setattr(refresh_drift, "package_selection", lambda _repository: selected)
    monkeypatch.setattr(refresh_drift, "_photon_repository_inventory", lambda: current)

    report = refresh_drift.inspect_capture(tmp_path / "source", tmp_path / "absent-rpms")

    assert report["status"] == "requires_review"
    assert next(item for item in report["profiles"] if item["name"] == "openssh-server")["official_pin_available"] is False


def test_native_reader_parses_tab_delimited_metadata_with_spaces(monkeypatch, tmp_path: Path) -> None:
    """Parse native RPM records whose file paths contain spaces.

    Args:
        monkeypatch: Pytest patcher for pinned-file access and RPM command output.
        tmp_path: Isolated directory containing the pinned RPM fixture.
    """
    package = tmp_path / "fixture.rpm"
    package.write_bytes(b"fixture")
    pinned = type("Pinned", (), {"path": package, "stream": io.BytesIO(b"fixture"),
                                 "digest": hashlib.sha256(b"fixture").hexdigest()})()
    outputs = iter((
        b"ATLASO\topenssh-server\t0\t10.6p1\t2.ph5\tx86_64\n",
        b"ATLASO\topenssh-10.6p1-2.ph5.src.rpm\tBSD\tPhoton\tSystem\t1\t10\t20\n",
        b"/usr/share/empty sshd\t0\t1\tX\t33133\troot\troot\t0\t0\tX\n",
        b"%post\nmkdir /usr/share/empty.sshd\n",
    ))
    monkeypatch.setattr(refresh_drift, "_open_pinned", lambda _path: pinned)
    monkeypatch.setattr(refresh_drift, "_verify_pinned", lambda _item: None)
    monkeypatch.setattr(refresh_drift, "_run_rpm", lambda *_args, **_kwargs: next(outputs))

    record = refresh_drift.inspect_native_package(package)

    assert record["sha256"] == hashlib.sha256(b"fixture").hexdigest()
    assert record["files"][0]["path"] == "/usr/share/empty sshd"
    assert record["files"][0]["isconfig"] is False
    assert record["files"][0]["isdoc"] is False
    assert record["scriptlets"] == "%post\nmkdir /usr/share/empty.sshd\n"


def _guest_tools_payload(root: Path) -> dict[str, str]:
    """Create the exact public closure layout accepted by payload_inventory."""
    root.mkdir(parents=True)
    inventory = {}
    for profile, package in guest_tools.PROFILES.items():
        path = root / profile / f"{package}.rpm"
        path.parent.mkdir()
        path.write_bytes(f"synthetic {profile} closure".encode())
        inventory[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (root / "compatibility.json").write_text(json.dumps(guest_tools.COMPATIBILITY), encoding="utf-8")
    sums = "".join(f"{checksum}  {name}\n" for name, checksum in sorted(inventory.items()))
    (root / "SHA256SUMS").write_text(sums, encoding="ascii")
    return inventory


def _inspect_fixture(tmp_path: Path, *, modern_source: bool = True) -> tuple[Path, Path, Path]:
    """Prepare one tiny source tree and captured top-level RPM for drift inspection."""
    source = tmp_path / "source"
    if modern_source:
        marker = source / "scripts/installation/guest_tools.py"
        marker.parent.mkdir(parents=True)
        marker.write_text("# retained guest-tools payload contract\n", encoding="utf-8")
    else:
        source.mkdir()
    rpms = tmp_path / "rpms"
    rpms.mkdir()
    package = rpms / "python3-3.14.0-1.ph5.x86_64.rpm"
    package.write_bytes(b"synthetic authenticated package bytes")
    return source, rpms, package


def _stub_capture_metadata(monkeypatch: pytest.MonkeyPatch, package: Path) -> None:
    """Provide one matching Photon record while leaving payload validation real."""
    sha256 = hashlib.sha256(package.read_bytes()).hexdigest()
    monkeypatch.setattr(refresh_drift, "package_selection", lambda _source: ["python3"])
    monkeypatch.setattr(
        refresh_drift,
        "_photon_repository_inventory",
        lambda: [("python3", "0", "3.14.0", "1.ph5", "x86_64", sha256)],
    )
    monkeypatch.setattr(refresh_drift, "_inspect_package_identity", lambda path: {
        "file": path.name, "name": "python3", "epoch": "0", "version": "3.14.0",
        "release": "1.ph5", "architecture": "x86_64", "sha256": sha256,
    })
    monkeypatch.setattr(refresh_drift, "capture_drift_report", lambda *_args: {"status": "current"})


def test_inspect_capture_validates_real_guest_tools_inventory_before_native_rpm_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate canonical companion bytes while keeping drift inspection non-authenticating."""
    source, rpms, package = _inspect_fixture(tmp_path)
    expected = _guest_tools_payload(rpms / "guest-tools")
    _stub_capture_metadata(monkeypatch, package)

    report = refresh_drift.inspect_capture(source, rpms)

    assert report["status"] == "current"
    assert report["authenticated_transaction_validated"] is False
    assert report["requires_full_transaction_validation"] is True
    assert [item["file"] for item in report["native_inventory"]] == [package.name]
    assert guest_tools.payload_inventory(rpms / "guest-tools") == expected


@pytest.mark.parametrize("defect", [
    "unexpected_entry", "missing_profile", "empty_profile", "checksum_mismatch",
])
def test_inspect_capture_rejects_invalid_guest_tools_before_official_or_native_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str,
) -> None:
    """Refuse malformed retained closures before consulting package metadata or RPM tools."""
    source, rpms, _package = _inspect_fixture(tmp_path)
    payload = rpms / "guest-tools"
    _guest_tools_payload(payload)
    if defect == "unexpected_entry":
        (payload / "unexpected.txt").write_text("extra", encoding="utf-8")
    elif defect == "missing_profile":
        shutil.rmtree(payload / "hyperv")
    elif defect == "empty_profile":
        (payload / "qemu" / f"{guest_tools.PROFILES['qemu']}.rpm").unlink()
    elif defect == "checksum_mismatch":
        (payload / "SHA256SUMS").write_text("0" * 64 + "  vmware/open-vm-tools.rpm\n", encoding="ascii")

    calls = []

    def should_not_read_metadata(*_args, **_kwargs):
        calls.append("metadata-or-rpm")
        raise AssertionError("guest-tools admission ran after native metadata")

    monkeypatch.setattr(refresh_drift, "package_selection", lambda _source: ["python3"])
    monkeypatch.setattr(refresh_drift, "_photon_repository_inventory", should_not_read_metadata)
    monkeypatch.setattr(refresh_drift, "_inspect_package_identity", should_not_read_metadata)

    with pytest.raises((ValueError, OSError)):
        refresh_drift.inspect_capture(source, rpms)

    assert calls == []


@pytest.mark.skipif(os.name != "nt", reason="Reparse admission requires Windows filesystem semantics")
def test_inspect_capture_rejects_reparse_guest_tools_before_metadata(tmp_path, monkeypatch):
    """Refuse a directory-link substitution before any metadata or native RPM read."""
    source, rpms, _package = _inspect_fixture(tmp_path)
    target = tmp_path / "payload-target"
    _guest_tools_payload(target)
    try:
        os.symlink(target, rpms / "guest-tools", target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation unavailable: {type(error).__name__}")

    def should_not_read_metadata(*_args, **_kwargs):
        raise AssertionError("guest-tools reparse admission ran after native metadata")

    monkeypatch.setattr(refresh_drift, "package_selection", lambda _source: ["python3"])
    monkeypatch.setattr(refresh_drift, "_photon_repository_inventory", should_not_read_metadata)
    monkeypatch.setattr(refresh_drift, "_inspect_package_identity", should_not_read_metadata)
    with pytest.raises((ValueError, OSError)):
        refresh_drift.inspect_capture(source, rpms)


def test_inspect_capture_requires_new_payload_but_keeps_legacy_source_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require the companion for current source while allowing old source captures without it."""
    source, rpms, package = _inspect_fixture(tmp_path)
    _stub_capture_metadata(monkeypatch, package)

    with pytest.raises(ValueError, match="capture_inventory_incomplete"):
        refresh_drift.inspect_capture(source, rpms)

    legacy_source = tmp_path / "legacy-source"
    legacy_source.mkdir()
    report = refresh_drift.inspect_capture(legacy_source, rpms)
    assert report["status"] == "current"
    assert report["authenticated_transaction_validated"] is False
