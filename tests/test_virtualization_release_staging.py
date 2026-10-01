"""Focused tests for exact virtualization release asset staging."""

from __future__ import annotations

import hashlib
import json
import shutil
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


@pytest.mark.parametrize("nested", [False, True])
def test_export_handoff_stages_actual_package_directory(tmp_path: Path, nested: bool) -> None:
    """Execute the export handoff and stage flat or builder-named OVF packages.

    Args:
        tmp_path: Owned fixture root.
        nested: Whether OVF Tool creates its deterministic builder child.
    """

    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is required to execute the producer handoff")
    repo = Path(__file__).resolve().parents[1]
    export_root = tmp_path / "image/vmware-workstation/ovf/atlaso-v0.9.216"
    export_root.mkdir(parents=True)
    package = export_root / (
        "Atlaso-Release-v0-9-216-aaaaaaaaaaaa-Photon-Builder-VMware" if nested else "flat"
    )
    ova = _ova_package(package)
    external_ova = export_root.parent / ova.name
    ova.replace(external_ova)
    if not nested:
        for asset in package.iterdir():
            asset.replace(export_root / asset.name)
        package.rmdir()
        package = export_root
    exporter = (repo / "scripts/windows/vmware/export-ovf.ps1").read_text(encoding="utf-8")
    producer = (repo / "scripts/windows/virtualization/Atlaso.VirtualizationRelease.psm1").read_text(
        encoding="utf-8"
    )
    # Execute the actual caller block with only the expensive export operation replaced.
    handoff = producer.split("    $ovaRoot = ''", 1)[1].split("    $hypervRoot =", 1)[0]
    export_result = exporter[exporter.rindex("if ($null -ne $ExportPackageDirectory)"):]
    fake_export = tmp_path / "scripts/windows/vmware/export-ovf.ps1"
    fake_export.parent.mkdir(parents=True)
    fake_export.write_text(
        "param($SourceVmxPath, $Name, [switch]$Force, $VirtualizationSourceMetadata, "
        "[switch]$ProtectedExport, [ref]$ExportPackageDirectory)\n"
        "$ovfPath = Get-OvfDescriptorPath -OutputDirectory "
        "(Join-Path $RepoRoot \"image/vmware-workstation/ovf/$Name\")\n"
        "$ovfPackageDirectory = Split-Path -Parent $ovfPath\n"
        + export_result,
        encoding="utf-8",
    )
    script = r"""
param($RepoRoot, $ActualRepo, $Handoff)
$ErrorActionPreference = 'Stop'
foreach ($entry in @(
    @('scripts/windows/vmware/export-ovf.ps1', 'Get-OvfDescriptorPath'),
    @('scripts/windows/virtualization/Atlaso.VirtualizationRelease.psm1', 'Copy-AtlasoVirtualizationExactAsset')
)) {
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $ActualRepo $entry[0]), [ref]$null, [ref]$null)
    $function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $entry[1]}, $true)
    . ([scriptblock]::Create($function.Extent.Text))
}
$identity = @{Version='0.9.216'}
$name = 'atlaso-v0.9.216'
$vmx = 'unused'
$sourceMetadata = 'unused'
$LASTEXITCODE = 0
$ovaRoot = ''
. ([scriptblock]::Create($Handoff))
$ovaRoot | ConvertTo-Json -Compress
"""
    harness = tmp_path / "handoff.ps1"
    harness.write_text(script, encoding="utf-8")
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(harness), str(tmp_path), str(repo), handoff],
        capture_output=True, text=True, check=True,
    )
    actual_package = Path(json.loads(result.stdout))
    assert actual_package == package
    assert (package / ova.name).read_bytes() == external_ova.read_bytes()
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    staged = staging.stage(
        ova_directory=actual_package, hyperv_zip=hyperv, output=tmp_path / "release",
        version="0.9.216", commit="a" * 40,
    )
    assert len(staged) == 12


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


@pytest.mark.parametrize("nested", [False, True])
def test_verifies_retained_complete_candidate_without_rebuilding(tmp_path: Path, nested: bool) -> None:
    """A retry accepts only the exact previously smoked candidate bytes.

    Args:
        tmp_path: Temporary directory provided by pytest.
        nested: Whether the package is beneath a deterministic builder directory.
    """

    ova_root = tmp_path / "ova"
    if nested:
        ova_root.mkdir()
        ova_root /= "Atlaso-Release-v0-9-216-aaaaaaaaaaaa-Photon-Builder-VMware"
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
    members = {path.name: path.read_bytes() for path in ova_root.iterdir() if path.suffix != ".ova"}
    provenance = json.loads(members["atlaso-provenance.json"])
    provenance["template_contract"] = {
        "schema_version": 1, "state": "uninitialized", "software_source": json.loads(source.read_text()),
    }
    members["atlaso-provenance.json"] = json.dumps(provenance).encode()
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n"
        for name, content in sorted(members.items()) if name != "atlaso.mf"
    ).encode()
    for name, content in members.items():
        (ova_root / name).write_bytes(content)
    _write_ova(ova, members)
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
    assert len(staged) == 14

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


def test_interrupted_staging_never_publishes_partial_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed copy leaves the final candidate absent and retryable.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to interrupt one staging copy.
    """

    ova_root = tmp_path / "ova"
    _ova_package(ova_root)
    hyperv = tmp_path / "atlaso-v0.9.216-hyperv-x86_64.zip"
    hyperv.write_bytes(b"hyperv-package")
    output = tmp_path / "release"
    real_copy = staging.shutil.copy2
    copies = 0

    def interrupt_copy(source: Path, destination: Path) -> None:
        """Fail after one successful partial-directory copy.

        Args:
            source: Exact source asset.
            destination: Invocation-owned partial destination.
        """

        nonlocal copies
        copies += 1
        if copies == 2:
            raise OSError("simulated interruption")
        real_copy(source, destination)

    monkeypatch.setattr(staging.shutil, "copy2", interrupt_copy)
    with pytest.raises(OSError, match="simulated interruption"):
        staging.stage(
            ova_directory=ova_root,
            hyperv_zip=hyperv,
            output=output,
            version="0.9.216",
            commit="a" * 40,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".release.partial-*"))

    monkeypatch.setattr(staging.shutil, "copy2", real_copy)
    assert staging.stage(
        ova_directory=ova_root,
        hyperv_zip=hyperv,
        output=output,
        version="0.9.216",
        commit="a" * 40,
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


@pytest.mark.parametrize("contract", [None, {"schema_version": 1, "state": "initialized"},
                                      {"schema_version": 1, "state": "uninitialized", "software_source": {"source_commit": "b" * 40}}])
def test_retained_template_contract_is_required(tmp_path: Path, contract: dict | None) -> None:
    """Retained candidates cannot acquire missing or mismatched template evidence.

    Args:
        tmp_path: Retained candidate directory.
        contract: Legacy, consumed, or differently bound evidence.
    """
    path = tmp_path / "atlaso-provenance.json"
    path.write_text(json.dumps({"template_contract": contract}))
    before = path.read_bytes()
    with pytest.raises(SystemExit, match="preserve it and rebuild"):
        staging.verify_template_contract(tmp_path, {"source_commit": "a" * 40})
    assert path.read_bytes() == before
