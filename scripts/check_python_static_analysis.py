#!/usr/bin/env python3
"""Enforce Atlaso's Python lint, suppression, and typed-analysis baselines."""

from __future__ import annotations

import re
import subprocess
import sys
import tokenize
from collections.abc import Iterable
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTENSIONLESS_PYTHON_PATHS = (
    "scripts/appliance/atlaso-bootstrap-https",
    "scripts/appliance/atlaso-helper",
)
RUFF_PATHS = ("atlaso", "scripts", "tests", *EXTENSIONLESS_PYTHON_PATHS)
RUFF_SUPPRESSION_RE = re.compile(
    r"# noqa:\s*(?P<codes>[A-Z][A-Z0-9]*\d{3}(?:\s*,\s*[A-Z][A-Z0-9]*\d{3})*)"
    r"\s+-\s+(?P<reason>\S.*)$",
    re.IGNORECASE,
)
LINE_RUFF_SUPPRESSION_RE = re.compile(r"#\s*noqa\b", re.IGNORECASE)
MYPY_SUPPRESSION_RE = re.compile(
    r"# type:\s*ignore\[(?P<codes>[a-z][a-z0-9-]*(?:\s*,\s*[a-z][a-z0-9-]*)*)\]"
    r"\s{2,}#\s+(?P<reason>\S.*)$"
)
FILE_WIDE_RUFF_SUPPRESSION_RE = re.compile(
    r"#\s*(?:ruff|flake8):\s*noqa\b",
    re.IGNORECASE,
)
FILE_WIDE_MYPY_CONFIGURATION_RE = re.compile(r"#\s*mypy\s*:", re.IGNORECASE)


def tracked_python_files(root: Path = ROOT) -> list[Path]:
    """Return tracked Python sources under the repository root.

    Args:
        root: Repository root whose tracked files are inspected.
    """
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--", "*.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        tracked = [root / line for line in result.stdout.splitlines() if line]
        tracked.extend(root / path for path in EXTENSIONLESS_PYTHON_PATHS)
        return tracked
    return sorted(root.rglob("*.py"))


def suppression_errors(paths: Iterable[Path], *, root: Path = ROOT) -> list[str]:
    """Return suppression comments missing a code or concise rationale.

    Args:
        paths: Python files whose suppression comments are validated.
        root: Repository root used to render stable relative paths.
    """
    errors: list[str] = []
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            errors.append(f"{path}: unable to read Python source: {exc}")
            continue
        source = "\n".join(lines)
        comments = (
            token
            for token in tokenize.generate_tokens(StringIO(source).readline)
            if token.type == tokenize.COMMENT
        )
        for token in comments:
            line_number = token.start[0]
            comment = token.string
            if FILE_WIDE_RUFF_SUPPRESSION_RE.search(comment) is not None:
                errors.append(
                    f"{path.relative_to(root)}:{line_number}: file-wide Ruff "
                    "suppressions are forbidden."
                )
                continue
            if FILE_WIDE_MYPY_CONFIGURATION_RE.search(comment) is not None:
                errors.append(
                    f"{path.relative_to(root)}:{line_number}: file-wide mypy "
                    "configuration directives are forbidden."
                )
                continue
            if (
                LINE_RUFF_SUPPRESSION_RE.search(comment) is not None
                and RUFF_SUPPRESSION_RE.search(comment) is None
            ):
                errors.append(
                    f"{path.relative_to(root)}:{line_number}: Ruff suppression must use "
                    "'# noqa: RULE123 - rationale'."
                )
            if "# type: ignore" in comment and MYPY_SUPPRESSION_RE.search(comment) is None:
                errors.append(
                    f"{path.relative_to(root)}:{line_number}: mypy suppression must use "
                    "'# type: ignore[rule-code]  # rationale'."
                )
    return errors


def run_analyzer(module: str, *arguments: str) -> int:
    """Run one analyzer with the active Python interpreter.

    Args:
        module: Python module providing the analyzer entry point.
        arguments: Command-line arguments passed to the analyzer.
    """
    return subprocess.run(
        [sys.executable, "-m", module, *arguments],
        cwd=ROOT,
        check=False,
    ).returncode


def main() -> int:
    """Run suppression validation, Ruff, and the scoped mypy ratchet."""
    errors = suppression_errors(tracked_python_files())
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if run_analyzer("ruff", "check", *RUFF_PATHS) != 0:
        return 1
    if run_analyzer("mypy") != 0:
        return 1
    print("Python static-analysis baseline passed (Ruff and scoped mypy).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
