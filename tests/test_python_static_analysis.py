"""Verify Atlaso's enforced Python static-analysis baseline."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from scripts.check_python_static_analysis import suppression_errors

ROOT = Path(__file__).resolve().parents[1]


def test_suppressions_require_rule_codes_and_rationales(tmp_path: Path) -> None:
    """Reject analyzer suppressions that cannot be reviewed from source.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    source = tmp_path / "sample.py"
    source.write_text(
        "\n".join(
            [
                "value = object()  # noqa",
                "other = object()  # type: ignore[attr-defined]",
            ]
        ),
        encoding="utf-8",
    )

    errors = suppression_errors([source], root=tmp_path)

    assert len(errors) == 2
    assert "Ruff suppression" in errors[0]
    assert "mypy suppression" in errors[1]


def test_suppressions_accept_rule_codes_with_rationales(tmp_path: Path) -> None:
    """Accept analyzer suppressions that identify a rule and local reason.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    source = tmp_path / "sample.py"
    source.write_text(
        "\n".join(
            [
                "value = object()  # noqa: F841 - fixture documents an intentionally unused value.",
                "other = object()  # type: ignore[attr-defined]  # Protocol attribute is runtime-only.",
            ]
        ),
        encoding="utf-8",
    )

    assert suppression_errors([source], root=tmp_path) == []


def test_suppressions_reject_file_wide_ruff_directives(tmp_path: Path) -> None:
    """Reject directives that disable Ruff for an entire source file.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for directive in ("# ruff: noqa", "# flake8: noqa"):
        source = tmp_path / "sample.py"
        source.write_text(f"{directive}\nvalue = object()\n", encoding="utf-8")

        errors = suppression_errors([source], root=tmp_path)

        assert errors == ["sample.py:1: file-wide Ruff suppressions are forbidden."]


def test_suppressions_validate_case_insensitive_ruff_directives(tmp_path: Path) -> None:
    """Apply the same rationale policy to Ruff's case-insensitive syntax.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    source = tmp_path / "sample.py"
    source.write_text("value = object()  # NOQA: F841\n", encoding="utf-8")

    errors = suppression_errors([source], root=tmp_path)

    assert errors == [
        "sample.py:1: Ruff suppression must use '# noqa: RULE123 - rationale'."
    ]
    source.write_text(
        "value = object()  # NOQA: F841 - fixture value is intentionally unused.\n",
        encoding="utf-8",
    )
    assert suppression_errors([source], root=tmp_path) == []


def test_suppressions_reject_file_wide_mypy_directives(tmp_path: Path) -> None:
    """Prevent per-file mypy configuration from weakening the strict ratchet.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for directive in (
        "# mypy: ignore-errors",
        "# mypy: disable-error-code=attr-defined",
    ):
        source = tmp_path / "sample.py"
        source.write_text(f"{directive}\nvalue = object()\n", encoding="utf-8")

        errors = suppression_errors([source], root=tmp_path)

        assert errors == [
            "sample.py:1: file-wide mypy configuration directives are forbidden."
        ]


def test_static_analysis_configuration_is_pinned_and_scoped() -> None:
    """Keep analyzer versions exact and the typed ratchet explicit."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    analyzer_requirements = set(
        (ROOT / "requirements-static-analysis.in")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    assert analyzer_requirements == {"ruff==0.16.1", "mypy==2.3.0"}
    assert project["tool"]["ruff"] == {
        "target-version": "py314",
        "extend-exclude": ["VCFDT", "third_party", "vcfDownloadTool"],
        "lint": {
            "select": ["E4", "E7", "E9", "F", "B", "BLE", "I"],
            "ignore": ["B008"],
        },
    }
    assert project["tool"]["mypy"] == {
        "python_version": "3.14",
        "strict": True,
        "show_error_codes": True,
        "warn_unused_configs": True,
        "follow_imports": "silent",
        "files": [
            "atlaso/app/routers/api_v1/physical_vlans.py",
            "atlaso/app/routers/contracts.py",
            "atlaso/app/routers/registry.py",
            "atlaso/app/routers/ui/physical_vlans.py",
            "atlaso/app/services/identity_credentials.py",
            "atlaso/app/services/interface_updates.py",
            "atlaso/app/services/physical_interfaces.py",
            "atlaso/app/services/service_registry.py",
        ],
    }


def test_static_analysis_uses_existing_repository_status_path() -> None:
    """Keep local and CI enforcement behind one stable command."""
    command = "python scripts/check_python_static_analysis.py"
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")

    assert command in workflow
    assert "repository-checks:" in workflow
    assert (
        "python -m pip install --require-hashes -r requirements-static-analysis.lock"
        in workflow
    )
    assert command in pre_commit


def test_static_analysis_includes_privileged_extensionless_python() -> None:
    """Keep privileged Python entry points inside lint and suppression coverage."""
    checker = (ROOT / "scripts/check_python_static_analysis.py").read_text(
        encoding="utf-8"
    )
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    hook = re.search(
        r"(?ms)- id: atlaso-python-static-analysis.*?files: '([^']+)'",
        pre_commit,
    )

    assert '"scripts/appliance/atlaso-bootstrap-https"' in checker
    assert '"scripts/appliance/atlaso-helper"' in checker
    assert hook is not None
    assert re.search(hook.group(1), "scripts/appliance/atlaso-bootstrap-https")
    assert re.search(hook.group(1), "scripts/appliance/atlaso-helper")
    assert re.search(hook.group(1), "requirements-static-analysis.in")
    assert re.search(hook.group(1), "requirements-static-analysis.lock")
