#!/usr/bin/env python3
"""Stage one exact validated Atlaso virtualization asset set for publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not __package__:
    sys.path.insert(0, str(ROOT))

from scripts.publish_release import (  # noqa: E402 - Script path bootstrap must precede the local import.
    MAXIMUM_GITHUB_ASSET_BYTES,
    verify_vmware_release_assets,
)

SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VMWARE_SUFFIXES = (".ova", ".ovf", ".mf", ".vmdk", "-provenance.json")
RELEASE_HELPERS = (
    ROOT / "scripts" / "virtualization" / "templates" / "import-atlaso-proxmox.sh",
    ROOT / "scripts" / "virtualization" / "templates" / "import-atlaso-kvm.sh",
    ROOT / "scripts" / "virtualization" / "validate_ova.py",
    ROOT / "scripts" / "virtualization" / "normalize_libvirt.py",
    ROOT / "scripts" / "verify_virtualization_artifact_index.py",
)


def _sha256(path: Path) -> str:
    """Return one file's SHA-256 digest.

    Args:
        path: File to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ordinary_asset(path: Path, label: str) -> Path:
    """Return a bounded ordinary release asset path.

    Args:
        path: Candidate asset path.
        label: Human-readable asset role for failures.
    """

    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} must be an ordinary file, not a symlink: {path}")
    size = path.stat().st_size
    if size <= 0 or size >= MAXIMUM_GITHUB_ASSET_BYTES:
        raise SystemExit(
            f"{label} is empty or exceeds the GitHub asset limit: {path.name}"
        )
    return path.resolve(strict=True)


def _copy_exact(source: Path, destination: Path) -> None:
    """Copy one asset without replacing different existing bytes.

    Args:
        source: Verified source asset.
        destination: Flat staging destination.
    """

    if destination.exists() or destination.is_symlink():
        if (
            not destination.is_file()
            or destination.is_symlink()
            or _sha256(source) != _sha256(destination)
        ):
            raise SystemExit(
                f"release staging destination already contains different bytes: {destination.name}"
            )
        return
    shutil.copy2(source, destination)
    if _sha256(source) != _sha256(destination):
        raise SystemExit(
            f"release staging copy verification failed: {destination.name}"
        )


def _json_object(path: Path, label: str) -> dict[str, object]:
    """Load one candidate evidence document as a JSON object.

    Args:
        path: Evidence path.
        label: Human-readable evidence role.
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return value


def stage(
    *,
    ova_directory: Path,
    hyperv_zip: Path,
    output: Path,
    version: str,
    commit: str,
    source_metadata: Path | None = None,
    windows_smoke_evidence: Path | None = None,
) -> list[str]:
    """Validate and stage the complete virtualization release asset set.

    Args:
        ova_directory: Canonical OVA package directory.
        hyperv_zip: Converted Hyper-V package.
        output: Exact release staging directory.
        version: Atlaso semantic version.
        commit: Full source commit.
        source_metadata: Verified automatic software-release identity metadata.
        windows_smoke_evidence: Bounded evidence from VMware and Hyper-V smoke.
    """

    if (
        SEMVER_PATTERN.fullmatch(version) is None
        or COMMIT_PATTERN.fullmatch(commit) is None
    ):
        raise SystemExit("version or source commit has an invalid release identity")
    if ova_directory.is_symlink() or not ova_directory.is_dir():
        raise SystemExit("OVA package source must be an ordinary directory")
    ova_root = ova_directory.resolve(strict=True)
    vmware_sources = sorted(
        path
        for path in ova_root.iterdir()
        if path.is_file() and path.name.lower().endswith(VMWARE_SUFFIXES)
    )
    vmware_names = {path.name for path in vmware_sources}
    verify_vmware_release_assets(
        ova_root,
        vmware_names,
        expected_version=version,
        expected_commit=commit,
    )
    expected_hyperv_name = f"atlaso-v{version}-hyperv-x86_64.zip"
    hyperv_source = _ordinary_asset(hyperv_zip, "Hyper-V package")
    if hyperv_source.name != expected_hyperv_name:
        raise SystemExit(f"Hyper-V package must be named {expected_hyperv_name}")
    sources = [*_ordinary_sources(vmware_sources), hyperv_source]
    sources.extend(
        _ordinary_asset(path, "virtualization import helper")
        for path in RELEASE_HELPERS
    )
    if source_metadata is not None:
        source = _ordinary_asset(source_metadata, "software release source metadata")
        if source.name != "virtualization-source.json":
            raise SystemExit(
                "software release source metadata must be named virtualization-source.json"
            )
        sources.append(source)
        source_document = _json_object(source, "software release source metadata")
        if (
            source_document.get("schema_version") != 1
            or source_document.get("kind") != "atlaso-virtualization-source"
            or source_document.get("version") != version
            or source_document.get("source_commit") != commit
            or source_document.get("source_software_tag") != f"v{version}"
            or source_document.get("python_abi") != "cp314"
        ):
            raise SystemExit(
                "software release source metadata does not match the staged identity"
            )
    if windows_smoke_evidence is not None:
        evidence = _ordinary_asset(windows_smoke_evidence, "Windows smoke evidence")
        if evidence.name != "windows-smoke-evidence.json":
            raise SystemExit(
                "Windows smoke evidence must be named windows-smoke-evidence.json"
            )
        sources.append(evidence)
        evidence_document = _json_object(evidence, "Windows smoke evidence")
        ova_source = next(
            path for path in vmware_sources if path.suffix.lower() == ".ova"
        )
        if (
            evidence_document.get("schema_version") != 1
            or evidence_document.get("kind") != "atlaso-windows-virtualization-smoke"
            or evidence_document.get("version") != version
            or evidence_document.get("source_commit") != commit
            or evidence_document.get("vmware") != "success"
            or evidence_document.get("hyperv") != "success"
            or evidence_document.get("ova_sha256") != _sha256(ova_source)
            or evidence_document.get("hyperv_sha256") != _sha256(hyperv_source)
        ):
            raise SystemExit(
                "Windows smoke evidence does not bind the exact staged assets"
            )
    expected_names = {source.name for source in sources}
    if len(expected_names) != len(sources):
        raise SystemExit("virtualization release sources must have unique flat names")

    if output.exists() and (output.is_symlink() or not output.is_dir()):
        raise SystemExit("release staging output must be an ordinary directory")
    output_parent = output.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    if output_parent.is_symlink() or not output_parent.is_dir():
        raise SystemExit("release staging parent must be an ordinary directory")
    resolved_parent = output_parent.resolve(strict=True)
    prospective_output = resolved_parent / output.name
    if prospective_output == ova_root or ova_root in prospective_output.parents:
        raise SystemExit(
            "release staging output cannot be the OVA source or its descendant"
        )
    if output.exists():
        output_root = output.resolve(strict=True)
        existing_names = {entry.name for entry in output_root.iterdir()}
        unexpected_names = sorted(existing_names - expected_names)
        if unexpected_names:
            raise SystemExit(
                f"release staging output contains unexpected assets: {unexpected_names}"
            )
        for source in sources:
            _copy_exact(source, output_root / source.name)
        staged_names = {entry.name for entry in output_root.iterdir()}
        if staged_names != expected_names:
            raise SystemExit(
                "release staging output does not contain the exact virtualization asset set"
            )
        return sorted(expected_names)

    partial = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.partial-", dir=resolved_parent)
    )
    try:
        for source in sources:
            _copy_exact(source, partial / source.name)
        staged_names = {entry.name for entry in partial.iterdir()}
        if staged_names != expected_names:
            raise SystemExit(
                "release staging output does not contain the exact virtualization asset set"
            )
        # The final directory appears only after every byte and name has passed.
        # Same-directory rename prevents interruption from publishing a partial
        # candidate that would wedge the documented retry path.
        partial.replace(prospective_output)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return sorted(expected_names)


def verify_staged_candidate(
    *,
    candidate: Path,
    version: str,
    commit: str,
    source_metadata: Path,
) -> list[str]:
    """Verify a retained candidate without rebuilding or replacing its bytes.

    Args:
        candidate: Existing flat candidate asset directory.
        version: Atlaso semantic version.
        commit: Full source commit.
        source_metadata: Freshly verified automatic software-release metadata.
    """

    if (
        SEMVER_PATTERN.fullmatch(version) is None
        or COMMIT_PATTERN.fullmatch(commit) is None
    ):
        raise SystemExit("version or source commit has an invalid release identity")
    if candidate.is_symlink() or not candidate.is_dir():
        raise SystemExit("retained candidate must be an ordinary directory")
    root = candidate.resolve(strict=True)
    entries = sorted(root.iterdir(), key=lambda path: path.name)
    if any(not path.is_file() or path.is_symlink() for path in entries):
        raise SystemExit("retained candidate contains a non-file or symlink entry")

    names = {path.name for path in entries}
    vmware_names = {
        name for name in names if name.lower().endswith(VMWARE_SUFFIXES)
    }
    verify_vmware_release_assets(
        root,
        vmware_names,
        expected_version=version,
        expected_commit=commit,
    )
    hyperv_name = f"atlaso-v{version}-hyperv-x86_64.zip"
    fixed_names = {
        hyperv_name,
        "virtualization-source.json",
        "windows-smoke-evidence.json",
        *(path.name for path in RELEASE_HELPERS),
    }
    expected_names = vmware_names | fixed_names
    if names != expected_names:
        raise SystemExit(
            "retained candidate contains an incomplete or unexpected asset set: "
            f"{sorted(names)}"
        )
    for entry in entries:
        _ordinary_asset(entry, "retained virtualization candidate asset")

    expected_source = _ordinary_asset(
        source_metadata, "fresh software release source metadata"
    )
    retained_source = root / "virtualization-source.json"
    if _sha256(expected_source) != _sha256(retained_source):
        raise SystemExit(
            "retained candidate software release source metadata has different bytes"
        )
    source_document = _json_object(
        retained_source, "retained software release source metadata"
    )
    if (
        source_document.get("schema_version") != 1
        or source_document.get("kind") != "atlaso-virtualization-source"
        or source_document.get("version") != version
        or source_document.get("source_commit") != commit
        or source_document.get("source_software_tag") != f"v{version}"
        or source_document.get("python_abi") != "cp314"
    ):
        raise SystemExit(
            "retained software release source metadata does not match the candidate identity"
        )

    for helper in RELEASE_HELPERS:
        helper_source = _ordinary_asset(helper, "virtualization import helper")
        if _sha256(helper_source) != _sha256(root / helper.name):
            raise SystemExit(
                f"retained candidate contains different helper bytes: {helper.name}"
            )

    ova = next(path for path in entries if path.suffix.lower() == ".ova")
    hyperv = root / hyperv_name
    evidence = _json_object(
        root / "windows-smoke-evidence.json", "retained Windows smoke evidence"
    )
    if (
        evidence.get("schema_version") != 1
        or evidence.get("kind") != "atlaso-windows-virtualization-smoke"
        or evidence.get("version") != version
        or evidence.get("source_commit") != commit
        or evidence.get("vmware") != "success"
        or evidence.get("hyperv") != "success"
        or evidence.get("ova_sha256") != _sha256(ova)
        or evidence.get("hyperv_sha256") != _sha256(hyperv)
    ):
        raise SystemExit(
            "retained Windows smoke evidence does not bind the exact candidate assets"
        )
    return sorted(names)


def _ordinary_sources(paths: list[Path]) -> list[Path]:
    """Validate and return an ordered collection of ordinary source assets.

    Args:
        paths: Candidate VMware package assets.
    """

    return [_ordinary_asset(path, "VMware OVA package asset") for path in paths]


def main(argv: list[str] | None = None) -> int:
    """Run the staging command-line interface.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ova-directory", type=Path)
    mode.add_argument("--verify-existing", type=Path)
    parser.add_argument("--hyperv-zip", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-metadata", type=Path, required=True)
    parser.add_argument("--windows-smoke-evidence", type=Path)
    args = parser.parse_args(argv)
    if args.verify_existing is not None:
        if args.hyperv_zip is not None or args.output is not None:
            parser.error("--verify-existing cannot be combined with staging outputs")
        staged = verify_staged_candidate(
            candidate=args.verify_existing,
            version=args.version,
            commit=args.commit,
            source_metadata=args.source_metadata,
        )
    else:
        if (
            args.ova_directory is None
            or args.hyperv_zip is None
            or args.output is None
            or args.windows_smoke_evidence is None
        ):
            parser.error(
                "staging requires --ova-directory, --hyperv-zip, --output, "
                "and --windows-smoke-evidence"
            )
        staged = stage(
            ova_directory=args.ova_directory,
            hyperv_zip=args.hyperv_zip,
            output=args.output,
            version=args.version,
            commit=args.commit,
            source_metadata=args.source_metadata,
            windows_smoke_evidence=args.windows_smoke_evidence,
        )
    print(json.dumps({"assets": staged, "count": len(staged)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
