"""Focused tests for exact virtualization release asset staging."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import stage_virtualization_release as staging
from tests.test_virtualization_ova import _members, _write_ova


def _ova_package(path: Path) -> Path:
    """Write one valid extracted package and matching canonical OVA.

    Args:
        path: Package directory destination.
    """

    path.mkdir()
    members = _members()
    for name, content in members.items():
        (path / name).write_bytes(content)
    ova = path / "atlaso-v0.9.216.ova"
    _write_ova(ova, members)
    return ova


def test_stages_validated_ova_hyperv_and_flat_helpers_idempotently(tmp_path: Path) -> None:
    """The publication directory receives one exact, repeatable virtualization set.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_root = tmp_path / "ova"
    _ova_package(ova_root)
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    output = tmp_path / "release"

    first = staging.stage(
        ova_directory=ova_root,
        hyperv_zip=hyperv,
        output=output,
        version="0.9.216",
        commit="a" * 40,
    )
    second = staging.stage(
        ova_directory=ova_root,
        hyperv_zip=hyperv,
        output=output,
        version="0.9.216",
        commit="a" * 40,
    )

    assert first == second
    assert len(first) == 12
    assert {path.name for path in output.iterdir()} == set(first)
    assert "import-atlaso-proxmox.sh" in first
    assert "import-atlaso-kvm.sh" in first
    assert "verify_virtualization_artifact_index.py" in first


def test_refuses_mismatched_release_identity_or_existing_destination(tmp_path: Path) -> None:
    """Version/commit mismatches and non-idempotent replacement fail before publication.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_root = tmp_path / "ova"
    _ova_package(ova_root)
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    output = tmp_path / "release"

    with pytest.raises(SystemExit, match="provenance version"):
        staging.stage(
            ova_directory=ova_root,
            hyperv_zip=hyperv,
            output=output,
            version="0.9.217",
            commit="a" * 40,
        )

    staging.stage(
        ova_directory=ova_root,
        hyperv_zip=hyperv,
        output=output,
        version="0.9.216",
        commit="a" * 40,
    )
    (output / "import-atlaso-kvm.sh").write_bytes(b"different")
    with pytest.raises(SystemExit, match="different bytes"):
        staging.stage(
            ova_directory=ova_root,
            hyperv_zip=hyperv,
            output=output,
            version="0.9.216",
            commit="a" * 40,
        )


def test_refuses_stale_or_unrelated_staging_assets(tmp_path: Path) -> None:
    """The signed virtualization set cannot inherit an unrelated file from an older run.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_root = tmp_path / "ova"
    _ova_package(ova_root)
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    output = tmp_path / "release"
    output.mkdir()
    (output / "stale-qcow2-export.zip").write_bytes(b"obsolete")

    with pytest.raises(SystemExit, match="unexpected assets"):
        staging.stage(
            ova_directory=ova_root,
            hyperv_zip=hyperv,
            output=output,
            version="0.9.216",
            commit="a" * 40,
        )


def test_verifies_retained_complete_candidate_without_rebuilding(tmp_path: Path) -> None:
    """A retry accepts only the exact previously smoked candidate bytes.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_root = tmp_path / "ova"
    ova = _ova_package(ova_root)
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    source = tmp_path / "virtualization-source.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "atlaso-virtualization-source",
                "version": "0.9.216",
                "source_commit": "a" * 40,
                "source_software_tag": "v0.9.216",
                "python_abi": "cp314",
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "windows-smoke-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "atlaso-windows-virtualization-smoke",
                "version": "0.9.216",
                "source_commit": "a" * 40,
                "ova_sha256": hashlib.sha256(ova.read_bytes()).hexdigest(),
                "hyperv_sha256": hashlib.sha256(hyperv.read_bytes()).hexdigest(),
                "vmware": "success",
                "hyperv": "success",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "release"
    staged = staging.stage(
        ova_directory=ova_root,
        hyperv_zip=hyperv,
        output=output,
        version="0.9.216",
        commit="a" * 40,
        source_metadata=source,
        windows_smoke_evidence=evidence,
    )

    assert staging.verify_staged_candidate(
        candidate=output,
        version="0.9.216",
        commit="a" * 40,
        source_metadata=source,
    ) == staged

    (output / "atlaso-v0.9.216-hyperv-x86_64.zip").write_bytes(b"changed")
    with pytest.raises(SystemExit, match="smoke evidence"):
        staging.verify_staged_candidate(
            candidate=output,
            version="0.9.216",
            commit="a" * 40,
            source_metadata=source,
        )


def test_staging_command_is_directly_executable() -> None:
    """The workflow entry point resolves sibling release validation when run by path."""

    result = subprocess.run(
        [sys.executable, "scripts/stage_virtualization_release.py", "--help"],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--ova-directory" in result.stdout
    assert "--verify-existing" in result.stdout
