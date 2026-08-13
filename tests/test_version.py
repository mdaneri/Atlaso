"""Test version behavior."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path("scripts/version.py")
POWERSHELL_WRAPPER = Path("scripts/version.ps1")
SPEC = importlib.util.spec_from_file_location("atlaso_version_script", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
versioning = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = versioning
SPEC.loader.exec_module(versioning)


def write_version_sources(
    root: Path,
    project: str,
    runtime: str | None = None,
    powershell: str | None = None,
    product: str = "Atlaso",
    distribution_name: str | None = None,
) -> None:
    """Persist version sources.

    Args:
        root: Root directory that bounds filesystem access.
        project: Project supplied by the caller.
        runtime: Runtime supplied by the caller.
        powershell: Powershell supplied by the caller.
        product: Product supplied by the caller.
        distribution_name: Distribution name supplied by the caller.
    """
    runtime = project if runtime is None else runtime
    powershell = project if powershell is None else powershell
    package = product.lower()
    distribution_name = package if distribution_name is None else distribution_name
    (root / package).mkdir(parents=True)
    (root / f"clients/powershell/{product}").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{distribution_name}"\nversion = "{project}"\n', encoding="utf-8"
    )
    (root / package / "__init__.py").write_text(
        f'try:\n    from {package}._build import BUILD_VERSION\nexcept ImportError:\n    BUILD_VERSION = "{runtime}"\n',
        encoding="utf-8",
    )
    (root / f"clients/powershell/{product}/{product}.psd1").write_text(
        f"@{{\n    ModuleVersion = '{powershell}'\n}}\n", encoding="utf-8"
    )


@pytest.mark.parametrize("value", ["1", "1.2", "1.2.3.4", "v1.2.3", "1.2.3-alpha", "01.2.3"])
def test_version_rejects_non_semver_values(value):
    """Verify that version rejects non semver values.

    Args:
        value: Candidate value consumed by test version rejects non semver values.
    """
    with pytest.raises(versioning.VersionError, match="X.Y.Z"):
        versioning.Version.parse(value)


def test_next_patch_handles_multi_digit_patch():
    """Verify that next patch handles multi digit patch."""
    assert str(versioning.Version.parse("12.34.99").next_patch()) == "12.34.100"


def test_read_project_version_accepts_crlf_without_other_version_sources(tmp_path):
    """Verify that read project version accepts crlf without other version sources.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    (tmp_path / "pyproject.toml").write_bytes(
        b'[project]\r\nname = "atlaso"\r\nversion = "1.2.3"\r\n'
    )

    assert versioning.read_project_version(tmp_path) == versioning.Version(1, 2, 3)


def test_read_project_version_reports_invalid_toml(tmp_path):
    """Verify that read project version reports invalid toml.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\nbroken = [\n', encoding="utf-8")

    with pytest.raises(versioning.VersionError, match="contains invalid TOML"):
        versioning.read_project_version(tmp_path)


def test_check_rejects_inconsistent_sources(tmp_path):
    """Verify that check rejects inconsistent sources.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_version_sources(tmp_path, "0.1.0", runtime="0.1.1")

    with pytest.raises(versioning.VersionError, match="version sources disagree"):
        versioning.check(tmp_path)


def test_bump_synchronizes_all_sources_from_base(tmp_path):
    """Verify that bump synchronizes all sources from base.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.1.9")
    write_version_sources(target, "0.1.9")

    bumped, changed = versioning.bump(target, base)

    assert (str(bumped), changed) == ("0.1.10", True)
    assert versioning.read_versions(target) == {
        "Python project": bumped,
        "Python runtime fallback": bumped,
        "PowerShell module": bumped,
    }
    assert all(
        b"\r\n" not in (target / relative_path).read_bytes()
        for relative_path in versioning.VERSION_PATHS.values()
    )
    assert versioning.check(target, base) == bumped


def test_bump_is_idempotent_when_target_is_expected_patch(tmp_path):
    """Verify that bump is idempotent when target is expected patch.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "2.4.6")
    write_version_sources(target, "2.4.7")

    bumped, changed = versioning.bump(target, base)

    assert (str(bumped), changed) == ("2.4.7", False)


def test_bump_uses_explicit_target_version(tmp_path):
    """Verify that bump uses explicit target version.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_version_sources(tmp_path, "2.4.6")

    bumped, changed = versioning.bump(
        tmp_path,
        target_version=versioning.Version(2, 4, 7),
    )

    assert (str(bumped), changed) == ("2.4.7", True)
    assert versioning.consistent_version(tmp_path) == bumped


def test_bump_explicit_current_version_is_idempotent(tmp_path):
    """Verify that bump explicit current version is idempotent.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_version_sources(tmp_path, "2.4.6")

    bumped, changed = versioning.bump(
        tmp_path,
        target_version=versioning.Version(2, 4, 6),
    )

    assert (str(bumped), changed) == ("2.4.6", False)
    assert versioning.consistent_version(tmp_path) == bumped


def test_bump_rejects_explicit_target_beyond_next_patch(tmp_path):
    """Verify that bump rejects explicit target beyond next patch.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_version_sources(tmp_path, "2.4.6")

    with pytest.raises(versioning.VersionError, match="next patch 2.4.7"):
        versioning.bump(
            tmp_path,
            target_version=versioning.Version(3, 0, 0),
        )

    assert versioning.consistent_version(tmp_path) == versioning.Version(2, 4, 6)


def test_bump_rejects_explicit_version_with_base_root(tmp_path):
    """Verify that bump rejects explicit version with base root.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "2.4.6")
    write_version_sources(target, "2.4.6")

    with pytest.raises(versioning.VersionError, match="cannot be combined"):
        versioning.bump(
            target,
            base,
            target_version=versioning.Version(3, 0, 0),
        )


def test_main_bump_accepts_explicit_version(tmp_path, capsys):
    """Verify that main bump accepts explicit version.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    write_version_sources(tmp_path, "2.4.6")

    result = versioning.main(["bump", "--root", str(tmp_path), "--version", "2.4.7"])

    assert result == 0
    assert capsys.readouterr().out == "Bumped repository version to 2.4.7\n"
    assert versioning.consistent_version(tmp_path) == versioning.Version(2, 4, 7)


def test_main_rejects_invalid_explicit_version(tmp_path, capsys):
    """Verify that main rejects invalid explicit version.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    write_version_sources(tmp_path, "2.4.6")

    result = versioning.main(["bump", "--root", str(tmp_path), "--version", "v2.5"])

    assert result == 1
    assert "--version must use X.Y.Z semantic versioning" in capsys.readouterr().err
    assert versioning.consistent_version(tmp_path) == versioning.Version(2, 4, 6)


def test_powershell_wrapper_delegates_to_version_script():
    """Verify that powershell wrapper delegates to version script."""
    wrapper = POWERSHELL_WRAPPER.read_text(encoding="utf-8")

    assert "ValidatePattern" in wrapper
    assert "(Join-Path $PSScriptRoot 'version.py')" in wrapper
    assert "'bump'" in wrapper
    assert "$versionArguments += @('--version', $Version)" in wrapper
    assert "if ($LASTEXITCODE -ne 0)" in wrapper


def test_check_discovers_version_sources_when_product_paths_change(tmp_path):
    """Verify that check discovers version sources when product paths change.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.17", product="Previous")
    write_version_sources(target, "0.9.18")

    assert versioning.check(target, base) == versioning.Version(0, 9, 18)


def test_bump_writes_discovered_version_sources_when_product_paths_change(tmp_path):
    """Verify that bump writes discovered version sources when product paths change.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(
        base,
        "0.9.17",
        product="Previous",
        distribution_name="atlaso",
    )
    write_version_sources(
        target,
        "0.9.17",
    )

    bumped, changed = versioning.bump(target, base)

    assert (str(bumped), changed) == ("0.9.18", True)
    assert versioning.consistent_version(target) == bumped


def test_check_allows_project_rename_to_retain_base_version(tmp_path):
    """Verify that check allows project rename to retain base version.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.18", product="Previous")
    write_version_sources(target, "0.9.18")

    assert versioning.check(target, base) == versioning.Version(0, 9, 18)
    bumped, changed = versioning.bump(target, base)
    assert (str(bumped), changed) == ("0.9.18", False)


@pytest.mark.parametrize("equivalent_name", ["atlas-o", "Atlas_O", "ATLAS.O"])
def test_check_does_not_treat_normalized_distribution_spelling_as_rename(
    tmp_path, equivalent_name
):
    """Verify that check does not treat normalized distribution spelling as rename.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        equivalent_name: Equivalent name supplied to the test scenario.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.18", distribution_name="atlas-o")
    write_version_sources(
        target,
        "0.9.18",
        distribution_name=equivalent_name,
    )

    with pytest.raises(versioning.VersionError, match="PR version must be 0.9.19"):
        versioning.check(target, base)


def test_check_allows_approved_pre_ga_release_line_transition(tmp_path):
    """Verify that check allows approved pre ga release line transition.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.1.11")
    write_version_sources(target, "0.9.0")

    assert versioning.check(target, base) == versioning.Version(0, 9, 0)
    bumped, changed = versioning.bump(target, base)
    assert (str(bumped), changed) == ("0.9.0", False)


def test_bump_rejects_unexpected_target_version(tmp_path):
    """Verify that bump rejects unexpected target version.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "2.4.6")
    write_version_sources(target, "3.0.0")

    with pytest.raises(versioning.VersionError, match="Cannot automatically replace"):
        versioning.bump(target, base)


def test_check_requires_an_allowed_version_above_base(tmp_path):
    """Verify that check requires an allowed version above base.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.8.4")
    write_version_sources(target, "0.8.4")

    with pytest.raises(versioning.VersionError, match="PR version must be"):
        versioning.check(target, base)
