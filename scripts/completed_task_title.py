#!/usr/bin/env python3
"""Format and verify public completed-task titles without changing task state."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from io import TextIOWrapper

TITLE_BUDGET = 60
DONE_SUFFIX = " · Done"


def title_units(value: str) -> int:
    """Count UTF-16 units so non-BMP descriptions fit desktop title limits."""
    return len(value.encode("utf-16-le")) // 2


def completed_task_title(
    description: str, issues: Sequence[int], pull_requests: Sequence[int], *, dependabot: bool = False
) -> str:
    """Keep every verified public identifier and completion marker visible.

    Args:
        description: Short description without issue/PR segments or a Done suffix.
        issues: Complete set of linked public issue numbers, verified by the caller.
        pull_requests: Complete set of linked public PR numbers, verified by the caller.
        dependabot: Caller verified the GitHub-managed Dependabot issue exception applies.

    Raises:
        ValueError: Identifiers are missing, invalid, or cannot fit without loss.
    """
    groups: list[str] = []
    for singular, plural, values in (
        ("Issue", "Issues", issues),
        ("PR", "PRs", pull_requests),
    ):
        if singular == "Issue" and not values and dependabot:
            continue
        if not values or any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("Positive issue and PR numbers are required except verified issue-less Dependabot tasks.")
        numbers = sorted(set(values))
        label = singular if len(numbers) == 1 else plural
        groups.append(label + " " + ", ".join(f"#{number}" for number in numbers))
    identity = " · ".join(groups)
    if title_units(identity + DONE_SUFFIX) > TITLE_BUDGET:
        raise ValueError("All issue/PR identifiers and Done exceed the title budget; maintainer direction is required.")
    description = " ".join(description.split())
    if "·" in description or re.search(
        r"\bdone\b|#\s*\d|\b(?:issues?|prs?|pull[\W_]*requests?|gh|github)"
        r"[\W_]*(?:(?:number|no)[\W_]*)?\d",
        description, re.IGNORECASE,
    ):
        raise ValueError("Supply only the description, without traceability or completion segments.")
    # Truncate only descriptive words. Identifiers and the completion marker are never shortened.
    words = description.split()
    while words and title_units(identity + " · " + " ".join(words) + DONE_SUFFIX) > TITLE_BUDGET:
        words.pop()
    return identity + (" · " + " ".join(words) if words else "") + DONE_SUFFIX


def verify_completed_task_title(expected: str, observed: str) -> None:
    """Reject truncated, stale, or otherwise altered persisted title readback."""
    if observed != expected:
        raise ValueError("Persisted title differs from the expected title; task_title_done remains blocked.")


def main(argv: Sequence[str] | None = None) -> int:
    """Print a title or verify supported-tool readback; never rename a task."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--description", default="", help="Description without traceability or Done segments.")
    parser.add_argument("--issue", type=int, action="append", default=[])
    parser.add_argument("--pr", type=int, action="append", required=True)
    parser.add_argument("--dependabot", action="store_true", help="Caller verified the GitHub-managed Dependabot issue exception.")
    parser.add_argument("--observed-title", help="Exact title read back through a supported task tool.")
    args = parser.parse_args(argv)
    try:
        expected = completed_task_title(args.description, args.issue, args.pr, dependabot=args.dependabot)
        if args.observed_title is not None:
            verify_completed_task_title(expected, args.observed_title)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(expected)
    return 0


if __name__ == "__main__":
    if isinstance(sys.stdout, TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
