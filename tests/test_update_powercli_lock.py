"""Check deterministic suite refresh, no-op behavior, and failure-before-write gates."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import update_powercli_lock as updater


class FakeGallery(updater.Gallery):
    """Expose a new suite with old-compatible floors and newer component releases."""

    def hashes(self, name: str, version: str) -> dict[str, str]:
        """Return inert reviewed test package digests."""
        return {"archive_sha256": "a" * 64, "content_sha256": "b" * 64}

    def latest(self) -> str:
        """Return the latest stable suite fixture."""
        return "9.1.1"

    def dependencies(self, name: str, version: str) -> list[tuple[str, str]]:
        """Return metadata only for the selected release family."""
        return {
            ("VCF.PowerCLI", "9.1.1"): [
                ("VMware.OpenAPI", "[2.0.0, )"),
                ("VMware.Vim", "[3.0.0, 3.0.0]"),
            ],
            ("VMware.OpenAPI", "2.0.0"): [("VMware.Vim", "[3.0.0, )")],
            ("VMware.Vim", "3.0.0"): [],
        }[(name, version)]


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """Write minimal baseline consumers and a deliberately noncanonical lock format."""
    path = tmp_path / updater.LOCK
    path.parent.mkdir(parents=True)
    path.write_text(
        '{ "schema_version": 2, "suite_version": "9.1.0", "modules": {} }',
        encoding="utf-8",
    )
    for relative in updater.CONSUMERS:
        consumer = tmp_path / relative
        consumer.parent.mkdir(parents=True, exist_ok=True)
        consumer.write_text('PowerCLI baseline "9.1.0"\n', encoding="utf-8")
    return tmp_path


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    """Capture content and timestamps to prove no-op and failure leave files untouched."""
    return {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


def test_refresh_updates_complete_closure_and_consumers(checkout: Path) -> None:
    """Suite refresh selects compatible floors and updates all baseline references."""
    assert updater.refresh(checkout, FakeGallery(), None, False)
    lock = json.loads((checkout / updater.LOCK).read_text(encoding="utf-8"))
    assert lock["modules"] == {
        "VCF.PowerCLI": "9.1.1",
        "VMware.OpenAPI": "2.0.0",
        "VMware.Vim": "3.0.0",
    }
    assert all(
        '"9.1.1"' in (checkout / path).read_text(encoding="utf-8")
        for path in updater.CONSUMERS
    )
    before = snapshot(checkout)
    assert not updater.refresh(checkout, FakeGallery(), None, False)
    assert snapshot(checkout) == before


def test_current_release_preserves_bytes_and_timestamps(checkout: Path) -> None:
    """An already-current baseline is not reformatted or rewritten."""
    before = snapshot(checkout)
    assert not updater.refresh(checkout, FakeGallery(), "9.1.0", False)
    assert snapshot(checkout) == before


@pytest.mark.parametrize("check,version", [(True, None), (False, "9.0.0")])
def test_release_check_and_downgrade_never_write(
    checkout: Path, check: bool, version: str | None
) -> None:
    """Immutable release and downgrade admission preserve every tracked file."""
    before = snapshot(checkout)
    with pytest.raises(ValueError):
        updater.refresh(checkout, FakeGallery(), version, check)
    assert snapshot(checkout) == before


def test_conflicting_metadata_fails_before_write(checkout: Path) -> None:
    """A newer transitive requirement cannot silently override the suite's pin."""

    class Conflict(FakeGallery):
        """Model the incompatible family that originally broke provisioning."""

        def dependencies(self, name: str, version: str) -> list[tuple[str, str]]:
            """Require a later Vim from the suite's selected OpenAPI."""
            if name == "VMware.OpenAPI":
                return [("VMware.Vim", "[4.0.0, )")]
            return super().dependencies(name, version)

    before = snapshot(checkout)
    with pytest.raises(ValueError, match="Incompatible Gallery closure"):
        updater.refresh(checkout, Conflict(), None, False)
    assert snapshot(checkout) == before


def test_consumer_drift_fails_before_write(checkout: Path) -> None:
    """A missing baseline reference cannot leave the lock partially synchronized."""
    (checkout / updater.CONSUMERS[-1]).write_text(
        "unexpected content", encoding="utf-8"
    )
    before = snapshot(checkout)
    with pytest.raises(ValueError, match="baseline missing"):
        updater.refresh(checkout, FakeGallery(), None, False)
    assert snapshot(checkout) == before


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_interrupted_publication_recovers_complete_update(
    checkout: Path, monkeypatch, failure
) -> None:
    """A write failure or process interruption after one replacement remains resumable."""
    original = updater.replace_file
    completed = 0

    def interrupted(path: Path, payload: bytes) -> None:
        """Interrupt after one tracked consumer has already been replaced."""
        nonlocal completed
        if path != checkout / updater.JOURNAL:
            completed += 1
            if completed == 2:
                raise failure("simulated interrupted update")
        original(path, payload)

    monkeypatch.setattr(updater, "replace_file", interrupted)
    with pytest.raises(failure):
        updater.refresh(checkout, FakeGallery(), None, False)
    assert (checkout / updater.JOURNAL).exists()
    monkeypatch.setattr(updater, "replace_file", original)
    assert updater.refresh(checkout, FakeGallery(), None, False)
    assert not (checkout / updater.JOURNAL).exists()
    assert all(
        '"9.1.1"' in (checkout / path).read_text(encoding="utf-8")
        for path in updater.CONSUMERS
    )
    assert (
        json.loads((checkout / updater.LOCK).read_text(encoding="utf-8"))[
            "suite_version"
        ]
        == "9.1.1"
    )
    before = snapshot(checkout)
    assert not updater.refresh(checkout, FakeGallery(), None, False)
    assert snapshot(checkout) == before


def test_recovery_preserves_independent_edits(checkout: Path, monkeypatch) -> None:
    """A retry never overwrites maintainer edits made after an interrupted refresh."""
    original = updater.recover_transaction
    monkeypatch.setattr(updater, "recover_transaction", lambda root, check=False: False)
    updater.refresh(checkout, FakeGallery(), None, False)
    edited = checkout / updater.CONSUMERS[0]
    edited.write_text("maintainer edit", encoding="utf-8")
    monkeypatch.setattr(updater, "recover_transaction", original)
    before = snapshot(checkout)
    with pytest.raises(ValueError, match="independently edited"):
        updater.refresh(checkout, FakeGallery(), None, False)
    assert snapshot(checkout) == before


@pytest.mark.parametrize(
    "constraint,selected,expected",
    [
        ("[1.0.0, 2.0.0)", "2.0.0", False),
        ("[1.0.0, 2.0.0]", "2.0.0", True),
        ("[1.0.0]", "1.0.0", True),
        ("[1.0.0]", "1.0.1", False),
        ("1.0.0", "2.0.0", True),
    ],
)
def test_gallery_constraint_boundaries(
    constraint: str, selected: str, expected: bool
) -> None:
    """Inclusive, exclusive, exact, and minimum bounds retain Gallery semantics."""
    assert updater.satisfies(selected, constraint) is expected


@pytest.mark.parametrize(
    "entry,release,child,status,admitted",
    [
        ("build-photon-image.ps1", False, False, 0, True),
        ("build-photon-image.ps1", False, False, 3, False),
        ("build-photon-image.ps1", True, False, 1, False),
        ("build-photon-image.ps1", False, True, 1, True),
        ("export-ovf.ps1", False, False, 0, True),
        ("export-ovf.ps1", False, False, 3, False),
        ("export-ovf.ps1", True, False, 1, False),
    ],
)
def test_entry_point_refresh_admission(
    tmp_path: Path,
    entry: str,
    release: bool,
    child: bool,
    status: int,
    admitted: bool,
) -> None:
    """Execute the actual entry-point hook with a controlled refresh subprocess result."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required")
    source = (updater.ROOT / "scripts/windows/vmware" / entry).read_text(
        encoding="utf-8"
    )
    start = source.index("$repoRoot = (Resolve-Path")
    start = source.index("\n", start) + 1
    marker = (
        "$resolvedPackageSource = $null"
        if entry.startswith("build-")
        else "if ($Release -or $Prerelease) {\n    $releaseModule"
    )
    hook = source[start : source.index(marker, start)]
    wrapper = tmp_path / "hook.ps1"
    wrapper.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$repoRoot = $PSScriptRoot; $CredentialChild = ${str(child).lower()}\n"
        f"$ReleaseBuilder = ${str(release).lower()}; $Release = $ReleaseBuilder; $Prerelease = $false\n"
        f"function python {{ Write-Output ('REFRESH ' + ($args -join ' ')); $global:LASTEXITCODE = {status} }}\n"
        + hook
        + "\nWrite-Output 'ADMITTED'\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(wrapper)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert ("ADMITTED" in result.stdout) is admitted, result.stdout + result.stderr
    if child:
        assert "REFRESH" not in result.stdout
    else:
        assert "--before-build" in result.stdout
        assert ("--check" in result.stdout) is release
