from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path("scripts/version.py")
SPEC = importlib.util.spec_from_file_location("labfoundry_version_script", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
versioning = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = versioning
SPEC.loader.exec_module(versioning)


def write_version_sources(
    root: Path,
    project: str,
    runtime: str | None = None,
    powershell: str | None = None,
    product: str = "LabFoundry",
    distribution_name: str | None = None,
) -> None:
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
    with pytest.raises(versioning.VersionError, match="X.Y.Z"):
        versioning.Version.parse(value)


def test_next_patch_handles_multi_digit_patch():
    assert str(versioning.Version.parse("12.34.99").next_patch()) == "12.34.100"


def test_read_project_version_accepts_crlf_without_other_version_sources(tmp_path):
    (tmp_path / "pyproject.toml").write_bytes(
        b'[project]\r\nname = "labfoundry"\r\nversion = "1.2.3"\r\n'
    )

    assert versioning.read_project_version(tmp_path) == versioning.Version(1, 2, 3)


def test_read_project_version_reports_invalid_toml(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\nbroken = [\n', encoding="utf-8")

    with pytest.raises(versioning.VersionError, match="contains invalid TOML"):
        versioning.read_project_version(tmp_path)


def test_check_rejects_inconsistent_sources(tmp_path):
    write_version_sources(tmp_path, "0.1.0", runtime="0.1.1")

    with pytest.raises(versioning.VersionError, match="version sources disagree"):
        versioning.check(tmp_path)


def test_bump_synchronizes_all_sources_from_base(tmp_path):
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
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "2.4.6")
    write_version_sources(target, "2.4.7")

    bumped, changed = versioning.bump(target, base)

    assert (str(bumped), changed) == ("2.4.7", False)


def test_check_discovers_version_sources_when_product_paths_change(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.17")
    write_version_sources(target, "0.9.18", product="Renamed")

    assert versioning.check(target, base) == versioning.Version(0, 9, 18)


def test_bump_writes_discovered_version_sources_when_product_paths_change(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.17")
    write_version_sources(
        target,
        "0.9.17",
        product="Renamed",
        distribution_name="labfoundry",
    )

    bumped, changed = versioning.bump(target, base)

    assert (str(bumped), changed) == ("0.9.18", True)
    assert versioning.consistent_version(target) == bumped


def test_check_allows_project_rename_to_retain_base_version(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.18")
    write_version_sources(target, "0.9.18", product="Renamed")

    assert versioning.check(target, base) == versioning.Version(0, 9, 18)
    bumped, changed = versioning.bump(target, base)
    assert (str(bumped), changed) == ("0.9.18", False)


@pytest.mark.parametrize("equivalent_name", ["lab-foundry", "Lab_Foundry", "LAB.FOUNDRY"])
def test_check_does_not_treat_normalized_distribution_spelling_as_rename(
    tmp_path, equivalent_name
):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.9.18", distribution_name="lab-foundry")
    write_version_sources(
        target,
        "0.9.18",
        product="Renamed",
        distribution_name=equivalent_name,
    )

    with pytest.raises(versioning.VersionError, match="PR version must be 0.9.19"):
        versioning.check(target, base)


def test_check_allows_approved_pre_ga_release_line_transition(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.1.11")
    write_version_sources(target, "0.9.0")

    assert versioning.check(target, base) == versioning.Version(0, 9, 0)
    bumped, changed = versioning.bump(target, base)
    assert (str(bumped), changed) == ("0.9.0", False)


def test_bump_rejects_unexpected_target_version(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "2.4.6")
    write_version_sources(target, "3.0.0")

    with pytest.raises(versioning.VersionError, match="Cannot automatically replace"):
        versioning.bump(target, base)


def test_check_requires_an_allowed_version_above_base(tmp_path):
    base = tmp_path / "base"
    target = tmp_path / "target"
    write_version_sources(base, "0.8.4")
    write_version_sources(target, "0.8.4")

    with pytest.raises(versioning.VersionError, match="PR version must be"):
        versioning.check(target, base)
