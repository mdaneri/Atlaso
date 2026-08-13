"""Verify Atlaso's enforced Python static-analysis baseline."""

from __future__ import annotations

import tomllib
from pathlib import Path

from scripts.check_python_static_analysis import suppression_errors

ROOT = Path(__file__).resolve().parents[1]


def test_suppressions_require_rule_codes_and_rationales(tmp_path: Path) -> None:
    """Reject analyzer suppressions that cannot be reviewed from source."""
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
    """Accept analyzer suppressions that identify a rule and local reason."""
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


def test_static_analysis_configuration_is_pinned_and_scoped() -> None:
    """Keep analyzer versions exact and the typed ratchet explicit."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    analyzer_requirements = set(
        (ROOT / "requirements-static-analysis.in")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    mypy_files = project["tool"]["mypy"]["files"]

    assert analyzer_requirements == {"ruff==0.16.1", "mypy==2.3.0"}
    assert mypy_files == [
        "atlaso/app/services/identity_credentials.py",
        "atlaso/app/services/interface_updates.py",
        "atlaso/app/services/service_registry.py",
    ]


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
