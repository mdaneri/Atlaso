"""Protect progressive routing, complete reviews, and measured policy budgets."""

import shutil
from pathlib import Path

import pytest

from scripts.check_repo import (
    COMPLETE_REVIEW_REQUIREMENTS,
    POLICY_BASELINE_BYTES,
    POLICY_ORDINARY_FILES,
    POLICY_REVIEW_FILES,
    POLICY_ROUTE_TARGETS,
    PROGRESSIVE_CORE_REQUIREMENTS,
    ROOT,
    check_progressive_policy,
    policy_context_sizes,
)


@pytest.fixture
def policy_root(tmp_path: Path) -> Path:
    """Copy only policy sources, with all fixture writes under pytest's owned root.

    Args:
        tmp_path: Isolated fixture directory below the configured task state root.
    """
    paths = set(POLICY_REVIEW_FILES)
    paths.update(path for targets in POLICY_ROUTE_TARGETS.values() for path in targets)
    for relative in paths:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return tmp_path


def test_repository_progressive_contract_and_budget() -> None:
    """The shipped complete ordinary read path meets the approved reduction target."""
    assert check_progressive_policy(ROOT) == []
    sizes = policy_context_sizes(ROOT)
    assert sizes["ordinary"] * 5 <= POLICY_BASELINE_BYTES
    assert sizes["core"] < sizes["ordinary"] < sizes["review"]
    assert "docs/assets/brand/BRAND_GUIDE.md" in POLICY_ORDINARY_FILES
    assert "SECURITY.md" not in POLICY_ORDINARY_FILES


@pytest.mark.parametrize("route", POLICY_ROUTE_TARGETS)
@pytest.mark.parametrize(
    "mutation", ["missing", "comment", "fence", "redirect", "empty", "duplicate"]
)
def test_routes_must_be_operative_and_point_to_owner(
    policy_root: Path, route: str, mutation: str
) -> None:
    """Neither hidden routing nor a different policy owner can waive an operation gate.

    Args:
        policy_root: Isolated complete policy fixture.
        route: Operation route selected for the negative case.
        mutation: Missing, hidden, ambiguous, or redirected table entry.
    """
    path = policy_root / "AGENTS.md"
    text = path.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith(f"| {route} |"))
    replacements = {
        "missing": "",
        "comment": f"<!--\n{row}\n-->",
        "fence": f"\n```text\n{row}\n```\n",
        "redirect": row.replace(POLICY_ROUTE_TARGETS[route][0], "wrong-owner.md"),
        "empty": f"| {route} | | " + row.split(" | ", 2)[2],
        "duplicate": row + "\n" + row,
    }
    path.write_text(text.replace(row, replacements[mutation]), encoding="utf-8")
    assert any(
        route in finding.message for finding in check_progressive_policy(policy_root)
    )


@pytest.mark.parametrize("route", POLICY_ROUTE_TARGETS)
def test_missing_specialized_policy_blocks_route(policy_root: Path, route: str) -> None:
    """A live route cannot silently refer to an unavailable specialized procedure.

    Args:
        policy_root: Isolated complete policy fixture.
        route: Operation whose canonical target is unavailable.
    """
    (policy_root / POLICY_ROUTE_TARGETS[route][0]).unlink()
    assert any(
        f"target is missing: {route}" in finding.message
        for finding in check_progressive_policy(policy_root)
    )


@pytest.mark.parametrize("requirement", COMPLETE_REVIEW_REQUIREMENTS)
@pytest.mark.parametrize("hidden", [False, True])
def test_complete_review_requirements_cannot_disappear(
    policy_root: Path, requirement: str, hidden: bool
) -> None:
    """Review coverage, consolidation, and justified re-review remain operative.

    Args:
        policy_root: Isolated complete policy fixture.
        requirement: Canonical review obligation selected for mutation.
        hidden: Whether to hide the requirement instead of removing it.
    """
    path = policy_root / "docs/contribute/pr-workflow.md"
    text = path.read_text(encoding="utf-8")
    # Normalize wrapped paragraphs while preserving the section boundaries.
    text = "\n\n".join(" ".join(paragraph.split()) for paragraph in text.split("\n\n"))
    assert requirement in text
    text = text.replace(requirement, f"<!-- {requirement} -->" if hidden else "")
    path.write_text(text, encoding="utf-8")
    assert any(
        requirement in finding.message
        for finding in check_progressive_policy(policy_root)
    )


def test_moving_startup_cost_to_required_document_does_not_game_budget(
    policy_root: Path,
) -> None:
    """Shortening the root cannot conceal growth in another mandatory ordinary read.

    Args:
        policy_root: Isolated complete policy fixture.
    """
    path = policy_root / "docs/contribute/agent-workflow.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n" + "extra policy " * 3000,
        encoding="utf-8",
    )
    assert any(
        "80%" in finding.message for finding in check_progressive_policy(policy_root)
    )


def test_measurement_normalizes_platform_line_endings(policy_root: Path) -> None:
    """Windows checkout line endings do not change the context regression baseline.

    Args:
        policy_root: Isolated complete policy fixture.
    """
    before = policy_context_sizes(policy_root)
    for relative in POLICY_REVIEW_FILES:
        path = policy_root / relative
        path.write_bytes(
            path.read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8")
        )
    assert policy_context_sizes(policy_root) == before


@pytest.mark.parametrize("requirement", PROGRESSIVE_CORE_REQUIREMENTS)
def test_conditional_policy_cannot_become_optional(policy_root: Path, requirement: str) -> None:
    """Core routing and fail-closed boundaries must remain visible instructions.

    Args:
        policy_root: Isolated complete policy fixture.
        requirement: Core obligation hidden in a Markdown comment.
    """
    path = policy_root / "AGENTS.md"
    text = path.read_text(encoding="utf-8").replace("`", "")
    text = "\n\n".join(" ".join(paragraph.split()) for paragraph in text.split("\n\n"))
    assert requirement in text
    path.write_text(text.replace(requirement, f"<!-- {requirement} -->"), encoding="utf-8")
    assert any(requirement in finding.message for finding in check_progressive_policy(policy_root))
