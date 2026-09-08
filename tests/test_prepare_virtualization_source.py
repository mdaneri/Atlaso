"""Focused tests for consuming the exact automatic software release."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import prepare_virtualization_source as source_preparer

VERSION = "0.9.237"
COMMIT = "a" * 40
KEY_ID = "atlaso-release-2026-01"


def _canonical(value: object) -> bytes:
    """Return canonical signed JSON bytes.

    Args:
        value: JSON-compatible value to serialize.
    """

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _release_fixture(
    tmp_path: Path, *, unsafe_member: str = "", lock_override: bytes | None = None,
) -> tuple[Path, Path, Path, Path]:
    """Create one minimal valid signed software Release fixture.

    Args:
        tmp_path: Temporary directory provided by pytest.
        unsafe_member: Optional unsafe archive member to include.
        lock_override: Optional signed dependency lock defect.
    """

    members = {
        f"packages/atlaso-{VERSION}-py3-none-any.whl": b"exact-application-wheel",
        "wheelhouse/cp314/requirements-wheelhouse.lock": b"dependency==1 --hash=sha256:"
        + hashlib.sha256(b"exact-dependency-wheel").hexdigest().encode(),
        "wheelhouse/cp314/dependency-1-py3-none-any.whl": b"exact-dependency-wheel",
        "requirements-appliance.lock": b"dependency==1 --hash=sha256:" + b"c" * 64,
        "bundle-metadata.json": b"{}\n",
    }
    if unsafe_member:
        members[unsafe_member] = b"unsafe"
    if lock_override is not None:
        members["wheelhouse/cp314/requirements-wheelhouse.lock"] = lock_override
    bundle = tmp_path / f"atlaso-appliance-{VERSION}.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    key = Ed25519PrivateKey.generate()
    trust = tmp_path / KEY_ID
    trust = trust.with_suffix(".pem")
    trust.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    manifest_value = {
        "schema_version": 2,
        "kind": "atlaso-release",
        "version": VERSION,
        "git_commit": COMMIT,
        "built_at": "2026-08-28T00:00:00Z",
        "signing_key_id": KEY_ID,
        "updater_protocol": 2,
        "database_schema_version": 1,
        "supported_python_abis": ["cp314"],
        "bundle": {
            "url": f"https://github.com/mdaneri/Atlaso/releases/download/v{VERSION}/{bundle.name}",
            "size": bundle.stat().st_size,
            "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        },
        "content_hashes": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in members.items()
        },
    }
    manifest = tmp_path / "release-manifest.json"
    manifest.write_bytes(_canonical(manifest_value))
    signature = tmp_path / "release-manifest.json.sig"
    signature.write_bytes(
        _canonical(
            {
                "schema_version": 1,
                "key_id": KEY_ID,
                "signature": base64.b64encode(key.sign(manifest.read_bytes())).decode(),
            }
        )
    )
    return manifest, signature, bundle, trust


@pytest.mark.parametrize("shortfall", [0, 1])
def test_source_expansion_admission_precedes_payload_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shortfall: int,
) -> None:
    """Admit exact aggregate capacity and refuse one byte short before extraction.

    Args:
        tmp_path: Isolated signed bundle and source destination.
        monkeypatch: Restore the scaled source budget and extraction spy.
        shortfall: Bytes removed from the exact aggregate capacity boundary.
    """
    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    with tarfile.open(bundle, "r:gz") as archive:
        declared_bytes = sum(member.size for member in archive.getmembers())
    required = (
        declared_bytes + manifest.stat().st_size + signature.stat().st_size
        + source_preparer.SOURCE_RECORD_RESERVE_BYTES
    )
    monkeypatch.setattr(source_preparer, "MAXIMUM_SOURCE_BYTES", required - shortfall)
    original_extract = tarfile.TarFile.extractfile
    extracted: list[str] = []

    def observe_extract(archive: tarfile.TarFile, member: tarfile.TarInfo):
        """Record payload extraction after admission.

        Args:
            archive: Verified archive whose selected payload is being opened.
            member: Declared member requested by source reconstruction.
        """
        extracted.append(member.name)
        return original_extract(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observe_extract)
    output = tmp_path / "verified"
    arguments = dict(
        manifest_path=manifest, signature_path=signature, bundle_path=bundle,
        trust_key_path=trust, output=output,
        expected_version=VERSION, expected_commit=COMMIT,
    )
    if shortfall:
        with pytest.raises(SystemExit, match="16 GiB expansion budget"):
            source_preparer.prepare(**arguments)
        assert not extracted
        assert not output.exists()
        assert not list(tmp_path.glob(".verified.partial-*"))
    else:
        source_preparer.prepare(**arguments)
        assert extracted
        assert output.is_dir()


def test_extracts_exact_signed_cp314_inputs_and_records_digests(tmp_path: Path) -> None:
    """The producer consumes the published wheel and wheelhouse without rebuilding.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    output = tmp_path / "verified"
    result = source_preparer.prepare(
        manifest_path=manifest,
        signature_path=signature,
        bundle_path=bundle,
        trust_key_path=trust,
        output=output,
        expected_version=VERSION,
        expected_commit=COMMIT,
    )
    source = json.loads(
        (output / "virtualization-source.json").read_text(encoding="utf-8")
    )
    wheel = Path(result["application_wheel"])
    assert wheel.read_bytes() == b"exact-application-wheel"
    assert (output / "wheelhouse/cp314/requirements-wheelhouse.lock").is_file()
    assert source["source_software_tag"] == f"v{VERSION}"
    assert (
        source["release_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert (
        source["application_wheel_sha256"]
        == hashlib.sha256(wheel.read_bytes()).hexdigest()
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows source ACL contract")
@pytest.mark.parametrize(
    "bytecode_environment", ["legacy", "unset", "empty", "enabled", "prefix", "external-prefix"],
)
def test_production_software_verification_preserves_source_inventory(
    tmp_path: Path, bytecode_environment: str,
) -> None:
    """Run the real parent and child verification blocks against signed fixtures.

    Args:
        tmp_path: Isolated source, software, and diagnostic root.
        bytecode_environment: Caller bytecode setting, including a cache inside source.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required")
    repository = Path(__file__).resolve().parents[1]
    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    software = tmp_path / "verified"
    source_preparer.prepare(
        manifest_path=manifest, signature_path=signature, bundle_path=bundle,
        trust_key_path=trust, output=software, expected_version=VERSION,
        expected_commit=COMMIT,
    )
    source = tmp_path / "source"
    # Copy tracked Python sources only to form a fresh, writable import fixture.
    # Inventory comparisons below include every file, including any added cache.
    paths = subprocess.check_output(
        ["git", "ls-files", "atlaso/*.py", "scripts/prepare_virtualization_source.py",
         "image/common/scripts/verify-template-software.py"],
        cwd=repository, text=True,
    ).splitlines()
    for relative in paths:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository / relative, target)
    trust_target = source / "image/common/update-trust" / trust.name
    trust_target.parent.mkdir(parents=True)
    shutil.copyfile(trust, trust_target)
    wrapper = (repository / "scripts/windows/vmware/build-photon-image.ps1").read_text()
    parent = wrapper.split("        $softwareSnapshot = $null\n", 1)[1].split(
        "        $pipGlobalIndexSecure =", 1,
    )[0]
    child = wrapper.split("$softwareManifestSha256 = ''\n", 1)[1].split(
        "$packerVariables =", 1,
    )[0]
    if bytecode_environment == "legacy":
        parent = parent.replace("& python -B ", "& python ")
    harness = tmp_path / "verify.ps1"
    harness.write_text(
        """param($RepositoryRoot, $SourceRoot, $SoftwareRoot, $TestRoot, $Version, $Commit)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1')
$before = Get-AtlasoSourceSnapshotInventory -Root $SourceRoot
$before | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $TestRoot 'before.json')
$sourceSnapshot = [pscustomobject]@{
    Root = $SourceRoot; Sha256 = $before.Sha256; FileCount = $before.FileCount; Commit = $Commit
}
$VirtualizationSourceDirectory = $SoftwareRoot
$ReleaseVersion = $Version
$childSensitiveBuildDirectory = $TestRoot
$softwareRoot = Join-Path $TestRoot 'software'
try {
""" + parent + """
$SourceSnapshotRoot = $SourceRoot
$SourceCommit = $Commit
$sensitiveBuildRoot = $TestRoot
$VirtualizationSourceDirectory = $softwareRoot
1..2 | ForEach-Object {
""" + child + """
    $null = Assert-AtlasoSourceSnapshot -Root $SourceRoot -ExpectedSha256 $before.Sha256 -ExpectedFileCount $before.FileCount
}
} finally {
    Get-AtlasoSourceSnapshotInventory -Root $SourceRoot | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $TestRoot 'after.json')
    Unprotect-AtlasoSourceSnapshot -Root $SourceRoot
    if (Test-Path -LiteralPath $softwareRoot) { Unprotect-AtlasoSourceSnapshot -Root $softwareRoot }
}
""", encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    environment.pop("PYTHONPYCACHEPREFIX", None)
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment["PATH"]
    environment["TEMP"] = environment["TMP"] = str(tmp_path)
    if bytecode_environment in {"empty", "enabled"}:
        environment["PYTHONDONTWRITEBYTECODE"] = "1" if bytecode_environment == "enabled" else ""
    if bytecode_environment == "prefix":
        environment["PYTHONPYCACHEPREFIX"] = str(source / "redirected-cache")
    if bytecode_environment == "external-prefix":
        environment["PYTHONPYCACHEPREFIX"] = str(tmp_path / "external-cache")
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(harness),
         str(repository), str(source), str(software), str(tmp_path), VERSION, COMMIT],
        env=environment, capture_output=True, text=True, check=False, timeout=120,
    )
    before = json.loads((tmp_path / "before.json").read_text(encoding="utf-8-sig"))
    after = json.loads((tmp_path / "after.json").read_text(encoding="utf-8-sig"))
    added = sorted(set(after["Records"]) - set(before["Records"]))
    if bytecode_environment == "legacy":
        assert result.returncode != 0
        assert "no longer matches its admitted byte inventory" in result.stderr
        assert not set(before["Records"]) - set(after["Records"])
        assert {record.split("\t")[0] for record in added} == {
            "atlaso/__pycache__/__init__.cpython-314.pyc",
            "atlaso/app/__pycache__/__init__.cpython-314.pyc",
            "atlaso/app/services/__pycache__/__init__.cpython-314.pyc",
            "atlaso/app/services/__pycache__/release_updates.cpython-314.pyc",
            "image/common/scripts/__pycache__/verify-template-software.cpython-314.pyc",
        }
        return
    assert result.returncode == 0, result.stdout + result.stderr + repr(added)
    assert after == before
    assert not (tmp_path / "external-cache").exists()


@pytest.mark.parametrize("lock", [
    b"dependency @ https://example.invalid/dependency.whl",
    b"--index-url https://example.invalid/simple",
    b"dependency==1 --hash=sha256:" + b"f" * 64,
    b"# incomplete lock\n",
])
def test_signed_lock_cannot_download_or_omit_dependencies(tmp_path: Path, lock: bytes) -> None:
    """Even signed inputs must supply a complete closed offline install set.

    Args:
        tmp_path: Private software staging root.
        lock: Non-offline or incomplete dependency specification.
    """
    manifest, signature, bundle, trust = _release_fixture(tmp_path, lock_override=lock)
    output = tmp_path / "verified"
    with pytest.raises(SystemExit, match="(offline hash lock|complete locked dependency set)"):
        source_preparer.prepare(
            manifest_path=manifest, signature_path=signature, bundle_path=bundle,
            trust_key_path=trust, output=output, expected_version=VERSION, expected_commit=COMMIT,
        )
    assert not output.exists()


def test_rejects_changed_bundle_and_changed_resume_destination(tmp_path: Path) -> None:
    """Digest mismatches and changed cached release inputs fail closed.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    bundle.write_bytes(bundle.read_bytes() + b"changed")
    with pytest.raises(SystemExit, match="size and digest"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=tmp_path / "verified",
            expected_version=VERSION,
            expected_commit=COMMIT,
        )
    output = tmp_path / "occupied"
    output.mkdir()
    (output / "unexpected").write_text("stale", encoding="utf-8")
    fresh_root = tmp_path / "fresh"
    fresh_root.mkdir()
    manifest, signature, bundle, trust = _release_fixture(fresh_root)
    with pytest.raises(SystemExit, match="does not exactly match"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=output,
            expected_version=VERSION,
            expected_commit=COMMIT,
        )


def test_exact_cached_source_is_revalidated_and_reused(tmp_path: Path) -> None:
    """An exact retained source is accepted, while later byte drift is rejected.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    output = tmp_path / "verified"
    arguments = {
        "manifest_path": manifest,
        "signature_path": signature,
        "bundle_path": bundle,
        "trust_key_path": trust,
        "output": output,
        "expected_version": VERSION,
        "expected_commit": COMMIT,
    }
    first = source_preparer.prepare(**arguments)
    second = source_preparer.prepare(**arguments)
    assert second == first
    verified = source_preparer.verify_directory(output, trust, VERSION, COMMIT)
    assert verified["application_wheel_sha256"] == first["application_wheel_sha256"]

    Path(first["application_wheel"]).write_bytes(b"locally changed wheel")
    with pytest.raises(SystemExit, match="does not exactly match"):
        source_preparer.prepare(**arguments)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "wheel",
        "metadata",
        "manifest",
        "signature",
        "version",
        "commit",
    ],
)
def test_builder_reauthenticates_complete_source(tmp_path: Path, mutation: str) -> None:
    """Builder admission rejects changed bytes, identity, or transfer inventory.

    Args:
        tmp_path: Isolated test input root.
        mutation: Corruption applied after valid signed input preparation.
    """
    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    output = tmp_path / "verified"
    result = source_preparer.prepare(
        manifest_path=manifest,
        signature_path=signature,
        bundle_path=bundle,
        trust_key_path=trust,
        output=output,
        expected_version=VERSION,
        expected_commit=COMMIT,
    )
    if mutation == "missing":
        (output / "wheelhouse/cp314/dependency-1-py3-none-any.whl").unlink()
    elif mutation == "extra":
        (output / "unexpected.whl").write_bytes(b"extra")
    elif mutation == "wheel":
        Path(result["application_wheel"]).write_bytes(b"tampered")
    elif mutation == "metadata":
        (output / "virtualization-source.json").write_text("{}")
    elif mutation in {"manifest", "signature"}:
        target = output / (
            "release-manifest.json" + (".sig" if mutation == "signature" else "")
        )
        target.write_bytes(b"{}")
    with pytest.raises((SystemExit, ValueError)):
        source_preparer.verify_directory(
            output,
            trust,
            "0.9.238" if mutation == "version" else VERSION,
            "b" * 40 if mutation == "commit" else COMMIT,
        )


def test_rejects_signed_unsafe_archive_member(tmp_path: Path) -> None:
    """A valid signature cannot authorize path traversal during extraction.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    manifest, signature, bundle, trust = _release_fixture(
        tmp_path, unsafe_member="../escape.whl"
    )
    with pytest.raises(ValueError, match="unsafe path"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=tmp_path / "verified",
            expected_version=VERSION,
            expected_commit=COMMIT,
        )
    assert not (tmp_path / "verified").exists()


def test_atomic_publication_failure_leaves_resumable_destination_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted final rename cannot expose a partial verified source.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest helper for injecting the interrupted rename.
    """

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    output = tmp_path / "verified"

    def interrupted_replace(source: Path, destination: Path) -> None:
        """Simulate interruption at the final atomic publication boundary.

        Args:
            source: Complete temporary extraction directory.
            destination: Final verified-source directory.
        """

        assert source.is_dir()
        assert destination == output
        raise OSError("interrupted atomic publication")

    monkeypatch.setattr(source_preparer.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="interrupted atomic publication"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=output,
            expected_version=VERSION,
            expected_commit=COMMIT,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".verified.partial-*"))
