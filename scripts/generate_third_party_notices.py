#!/usr/bin/env python3
"""Generate a deterministic third-party notice inventory for LabFoundry releases."""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from email.parser import Parser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_ENTRY_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def locked_packages(path: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = LOCK_ENTRY_RE.match(raw_line.strip())
        if match is None:
            continue
        name, version = match.groups()
        key = normalize_name(name)
        if key in entries and entries[key][0] != version:
            raise ValueError(f"lock contains conflicting versions for {name}")
        entries[key] = (version, name)
    if not entries:
        raise ValueError(f"no pinned packages found in {path}")
    return entries


def license_from_metadata(metadata) -> str:
    expression = (metadata.get("License-Expression") or "").strip()
    if expression:
        return expression
    declared = (metadata.get("License") or "").strip()
    if declared and declared.upper() not in {"UNKNOWN", "SEE LICENSE FILE"}:
        return declared
    classifiers = [item.removeprefix("License :: ") for item in metadata.get_all("Classifier", []) if item.startswith("License :: ")]
    if classifiers:
        return "; ".join(classifiers)
    return ""


def source_from_metadata(metadata) -> str:
    homepage = (metadata.get("Home-page") or "").strip()
    if homepage:
        return homepage
    project_urls = metadata.get_all("Project-URL", [])
    for project_url in project_urls:
        label, separator, url = project_url.partition(",")
        if separator and label.strip().lower() in {"homepage", "source", "repository"}:
            return url.strip()
    for project_url in project_urls:
        _label, separator, url = project_url.partition(",")
        if separator and url.strip().startswith(("https://", "http://")):
            return url.strip()
    return ""


def wheel_records(wheelhouse: Path, expected: dict[str, tuple[str, str]]) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for wheel in sorted(wheelhouse.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            metadata_paths = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            candidates = []
            for metadata_path in metadata_paths:
                metadata = Parser().parsestr(archive.read(metadata_path).decode("utf-8"))
                name = (metadata.get("Name") or "").strip()
                version = (metadata.get("Version") or "").strip()
                expected_record = expected.get(normalize_name(name))
                if expected_record is not None and version == expected_record[0]:
                    candidates.append(metadata)
            if len(candidates) != 1:
                raise ValueError(f"{wheel} must contain metadata for exactly one locked package")
            metadata = candidates[0]
        name = (metadata.get("Name") or "").strip()
        version = (metadata.get("Version") or "").strip()
        key = normalize_name(name)
        if key not in expected:
            raise ValueError(f"wheelhouse contains unlocked package {name or wheel.name}")
        expected_version, _expected_name = expected[key]
        if version != expected_version:
            raise ValueError(f"wheelhouse version mismatch for {name}: expected {expected_version}, found {version}")
        license_name = license_from_metadata(metadata)
        if not license_name:
            raise ValueError(f"wheel metadata is missing a license for {name} {version}")
        source = source_from_metadata(metadata)
        if not source:
            raise ValueError(f"wheel metadata is missing a source URL for {name} {version}")
        record = {"name": name, "version": version, "license": license_name, "source": source}
        previous = records.get(key)
        if previous is not None and previous != record:
            raise ValueError(f"wheelhouse has inconsistent metadata for {name} {version}")
        records[key] = record
    missing = sorted(set(expected) - set(records))
    if missing:
        raise ValueError(f"wheelhouse is missing locked packages: {', '.join(missing)}")
    return records


def installed_python_records(
    environment: Path, expected: dict[str, tuple[str, str]] | None = None
) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    metadata_paths = {
        metadata_path
        for pattern in (
            "lib/python*/site-packages/*.dist-info/METADATA",
            "lib64/python*/site-packages/*.dist-info/METADATA",
            "Lib/site-packages/*.dist-info/METADATA",
        )
        for metadata_path in environment.glob(pattern)
    }
    for metadata_path in sorted(metadata_paths):
        metadata = Parser().parsestr(metadata_path.read_text(encoding="utf-8"))
        name = (metadata.get("Name") or "").strip()
        version = (metadata.get("Version") or "").strip()
        if not name or not version:
            raise ValueError(f"installed metadata is incomplete: {metadata_path}")
        key = normalize_name(name)
        if expected is not None:
            if key not in expected:
                continue
            expected_version, _expected_name = expected[key]
            if version != expected_version:
                raise ValueError(f"installed Python version mismatch for {name}: expected {expected_version}, found {version}")
        license_name = license_from_metadata(metadata)
        source = source_from_metadata(metadata)
        if not license_name or not source:
            raise ValueError(f"installed metadata is missing license or source for {name} {version}")
        record = {"name": name, "version": version, "license": license_name, "source": source}
        previous = records.get(key)
        if previous is not None and previous != record:
            raise ValueError(f"installed environment has conflicting metadata for {name}")
        records[key] = record
    if not records:
        raise ValueError(f"no installed Python metadata found under {environment}")
    if expected is not None:
        missing = sorted(set(expected) - set(records))
        if missing:
            raise ValueError(f"installed environment is missing locked packages: {', '.join(missing)}")
    return records


def rpm_records(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        name, version, license_name, source = (part.strip() for part in line.split("\t", 3))
        if not name or not version or not license_name:
            raise ValueError(f"RPM inventory has incomplete record: {line!r}")
        records.append({"name": name, "version": version, "license": license_name, "source": source or "Package metadata"})
    if not records:
        raise ValueError(f"RPM inventory is empty: {path}")
    return records


def vendored_records(config_path: Path) -> list[dict[str, str]]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    records = config.get("vendored_components")
    if not isinstance(records, list) or not records:
        raise ValueError("vendored component configuration is empty")
    normalized: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("vendored component record must be an object")
        required = {key: str(record.get(key) or "").strip() for key in ("name", "version", "license", "source", "notice_path")}
        if not all(required.values()):
            raise ValueError("vendored component record is incomplete")
        if not (ROOT / required["notice_path"]).is_file():
            raise ValueError(f"vendored notice is missing: {required['notice_path']}")
        normalized.append(required)
    return normalized


def render_section(title: str, records: list[dict[str, str]], *, notice_column: bool = False) -> list[str]:
    lines = [f"## {title}", ""]
    header = "| Component | Version | License | Source |"
    divider = "| --- | --- | --- | --- |"
    if notice_column:
        header = "| Component | Version | License | Source | Included notice |"
        divider = "| --- | --- | --- | --- | --- |"
    lines.extend([header, divider])
    for record in sorted(records, key=lambda item: (item["name"].lower(), item["version"])):
        row = [markdown(record[key]) for key in ("name", "version", "license", "source")]
        if notice_column:
            row.append(markdown(record["notice_path"]))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return lines


def generate_notice(*, output: Path, version: str, python_records: dict[str, dict[str, str]], vendored: list[dict[str, str]], rpms: list[dict[str, str]] | None) -> None:
    lines = [
        "# LabFoundry Third-Party Notices",
        "",
        f"Generated for LabFoundry {version}. Do not edit this file manually.",
        "",
        "LabFoundry-authored code is licensed under the MIT License. Components below retain their own terms; their package-provided or bundled license texts remain authoritative.",
        "",
    ]
    lines.extend(render_section("Python runtime packages", list(python_records.values())))
    lines.extend(render_section("Bundled components", vendored, notice_column=True))
    if rpms is not None:
        lines.extend(render_section("Photon appliance RPM packages", rpms))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--wheelhouse", type=Path, action="append", default=[])
    parser.add_argument("--python-environment", type=Path)
    parser.add_argument("--rpm-inventory", type=Path)
    parser.add_argument("--vendored-config", type=Path, default=ROOT / "scripts/third_party_notices.json")
    args = parser.parse_args()
    if args.wheelhouse and not args.lock:
        raise SystemExit("--wheelhouse requires --lock")
    if args.wheelhouse and args.python_environment:
        raise SystemExit("use wheelhouses or an installed Python environment, not both")
    if not args.wheelhouse and not args.python_environment:
        raise SystemExit("supply --wheelhouse or --python-environment")
    try:
        if args.python_environment:
            expected = locked_packages(args.lock) if args.lock else None
            python_records = installed_python_records(args.python_environment, expected)
        else:
            expected = locked_packages(args.lock)
            combined: dict[str, dict[str, str]] = {}
            for wheelhouse in args.wheelhouse:
                records = wheel_records(wheelhouse, expected)
                for key, record in records.items():
                    if key in combined and combined[key] != record:
                        raise ValueError(f"wheelhouses disagree on metadata for {record['name']}")
                    combined[key] = record
            python_records = combined
        generate_notice(
            output=args.output,
            version=args.version,
            python_records=python_records,
            vendored=vendored_records(args.vendored_config),
            rpms=rpm_records(args.rpm_inventory) if args.rpm_inventory else None,
        )
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise SystemExit(f"third-party notice generation failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
