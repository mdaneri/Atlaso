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


def write_version_sources(root: Path, project: str, runtime: str | None = None, powershell: str | None = None) -> None:
    runtime = project if runtime is None else runtime
    powershell = project if powershell is None else powershell
    (root / "labfoundry").mkdir(parents=True)
    (root / "clients/powershell/LabFoundry").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "labfoundry"\nversion = "{project}"\n', encoding="utf-8"
    )
    (root / "labfoundry/__init__.py").write_text(
        f'try:\n    from labfoundry._build import BUILD_VERSION\nexcept ImportError:\n    BUILD_VERSION = "{runtime}"\n',
        encoding="utf-8",
    )
    (root / "clients/powershell/LabFoundry/LabFoundry.psd1").write_text(
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
