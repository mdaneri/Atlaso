"""Prove completed titles retain traceability under the desktop title budget."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.completed_task_title import (
    TITLE_BUDGET,
    completed_task_title,
    main,
    title_units,
    verify_completed_task_title,
)


def test_completed_title_preserves_all_identifiers() -> None:
    """The formerly truncated multi-PR title retains every number and Done."""
    title = completed_task_title("Fix Photon build completion", [735, 737], [736, 738])
    assert title == "Issues #735, #737 · PRs #736, #738 · Fix Photon build · Done"
    assert title_units(title) <= TITLE_BUDGET


def test_completed_title_drops_description_before_identifiers() -> None:
    """Long descriptions cannot displace the identity or final marker."""
    title = completed_task_title("x" * 100, [747], [748])
    assert title == "Issue #747 · PR #748 · Done"
    assert completed_task_title("", [747, 747], [748, 748]) == title


def test_completed_title_handles_unicode_and_whitespace() -> None:
    """Unicode descriptions remain within the UTF-16 budget and on one line."""
    title = completed_task_title("🧪 " * 30 + "\n cleanup", [747], [748])
    assert title_units(title) <= TITLE_BUDGET
    assert title.startswith("Issue #747 · PR #748 · ")
    assert title.endswith(" · Done")
    assert "\n" not in title


def test_completed_title_validates_before_truncating_description() -> None:
    """Truncation cannot hide an invalid completion marker in descriptive input."""
    with pytest.raises(ValueError, match="only the description"):
        completed_task_title("x" * 100 + " Done", [747], [748])


@pytest.mark.parametrize("issues, prs", [([], [1]), ([1], []), ([0], [1]), ([1], [-1]), ([True], [1])])
def test_completed_title_rejects_invalid_identity(issues: list[int], prs: list[int]) -> None:
    """Absent and nonpositive public identifiers block completion."""
    with pytest.raises(ValueError):
        completed_task_title("Cleanup", issues, prs)


def test_completed_title_never_truncates_overflowing_identifiers() -> None:
    """Too many linked items require direction instead of silently losing an ID."""
    with pytest.raises(ValueError, match="title budget"):
        completed_task_title("", list(range(100, 110)), [200])


def test_completed_title_accepts_verified_dependabot_exception() -> None:
    """GitHub-managed dependency PRs retain visible PR identity without an invented issue."""
    assert completed_task_title("Dependencies", [], [750], dependabot=True) == "PR #750 · Dependencies · Done"
    assert completed_task_title("", [747], [750], dependabot=True) == "Issue #747 · PR #750 · Done"


@pytest.mark.parametrize("issues, prs", [([0], [750]), ([], []), ([], [-1])])
def test_dependabot_exception_does_not_waive_identifier_validation(issues: list[int], prs: list[int]) -> None:
    """The exception permits only an absent issue list, never invalid or absent PR identity."""
    with pytest.raises(ValueError):
        completed_task_title("", issues, prs, dependabot=True)


def test_dependabot_cli_requires_explicit_exception(capsys: pytest.CaptureFixture[str]) -> None:
    """Ordinary missing-issue input fails while explicit Dependabot readback succeeds."""
    args = ["--pr", "750"]
    assert main(args) == 1
    assert "required" in capsys.readouterr().err
    assert main([*args, "--dependabot"]) == 0
    title = capsys.readouterr().out.strip()
    assert title == "PR #750 · Done"
    assert main([*args, "--dependabot", "--observed-title", title]) == 0


@pytest.mark.parametrize("description", [
    "Cleanup · Done", "Done", "Done - Cleanup", "Cleanup · Issue #747",
    "Issue #999 cleanup", "Cleanup PR #999 Done", "fix issues#999", "Fix PRs #999, #998",
    "Pull request #999 cleanup", "Fix pull requests #999", "cleanup DONE", "(done) cleanup",
    "Cleanup Issue: #999", "Cleanup PR: #999", "Cleanup pull-request #999", "Cleanup #999",
    "Cleanup (#999)", "Cleanup owner/repo#999", "Cleanup # 999",
    "Cleanup Issue 999", "Cleanup PR 999", "Follow up GH-999", "Fix GitHub: 999",
    "Cleanup issues: 999, 998", "Cleanup PRs/999", "Cleanup pull-request 999",
    "Cleanup pull_request: 999", "Cleanup pullrequest999", "https://github.com/owner/repo/issues/999",
    "Cleanup Issue number 999", "Cleanup PR no. 999",
    "Pull 999", "a/b/pull/9", "github.com/a/b/pull/9", "Cleanup pulls: 999",
    "Cleanup Issue ID 999", "Cleanup PR ID: 999", "Cleanup issue ref 999",
    "Cleanup issue reference number 999", "Cleanup PR tracked as 999",
])
def test_completed_title_rejects_existing_title_segments(description: str) -> None:
    """A retry must reuse the original description rather than append to a completed title."""
    with pytest.raises(ValueError, match="only the description"):
        completed_task_title(description, [747], [748])


def test_completed_title_accepts_descriptive_numbers() -> None:
    """Ordinary version numbers do not become traceability references."""
    assert completed_task_title("Python 3.14", [747], [748]) == "Issue #747 · PR #748 · Python 3.14 · Done"


@pytest.mark.parametrize("observed", ["Issue #747 · PR #748", "Issue #747 · PR #748 · …", "Issue #747 · PR #748 · Done · Done", "Issue #747 · PR #749 · Done"])
def test_completed_title_rejects_wrong_readback(observed: str) -> None:
    """A successful rename request cannot substitute for exact persisted readback."""
    with pytest.raises(ValueError, match="remains blocked"):
        verify_completed_task_title(completed_task_title("", [747], [748]), observed)


def test_completed_title_cli_readback_is_idempotent(capsys: pytest.CaptureFixture[str]) -> None:
    """Retries verify one canonical suffix without duplicating it."""
    args = ["--issue", "747", "--pr", "748"]
    assert main(args) == 0
    title = capsys.readouterr().out.strip()
    assert main([*args, "--observed-title", title]) == 0
    assert capsys.readouterr().out.strip() == title
    assert main([*args, "--observed-title", title + " · Done"]) == 1
    assert "remains blocked" in capsys.readouterr().err


def test_completed_title_cli_emits_utf8_under_windows_style_encoding() -> None:
    """The title's middle dots survive capture even with a legacy caller encoding."""
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/completed_task_title.py"),
         "--issue", "747", "--pr", "748"],
        env={**os.environ, "PYTHONIOENCODING": "ascii"},
        capture_output=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "Issue #747 · PR #748 · Done"
