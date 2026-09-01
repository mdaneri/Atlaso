#!/usr/bin/env python3
"""Validate the physical identity of Atlaso's bootstrap virtual environment."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _display(value: object) -> str:
    """Return one bounded, escaped diagnostic value.

    Args:
        value: Diagnostic value to sanitize and bound.

    Returns:
        JSON-escaped diagnostic text.
    """
    text = str(value)
    if len(text) > 512:
        text = f"{text[:509]}..."
    return json.dumps(text, ensure_ascii=True)


def _fail(label: str, actual: object, expected: Path) -> int:
    """Report one sanitized identity mismatch.

    Args:
        label: Short identity category used in the diagnostic.
        actual: Observed identity value.
        expected: Required physical path identity.

    Returns:
        The fail-closed status code.
    """
    print(
        f"Atlaso bootstrap {label} identity mismatch: "
        f"actual={_display(actual)} expected={_display(expected)}",
        file=sys.stderr,
    )
    return 2


def _resolve(path: Path, label: str, expected: Path) -> tuple[Path | None, int]:
    """Resolve an existing path or emit a bounded failure.

    Args:
        path: Filesystem path to resolve strictly.
        label: Short identity category used on failure.
        expected: Required physical path identity.

    Returns:
        The resolved path and success status, or ``None`` and status 2.
    """
    try:
        return path.resolve(strict=True), 0
    except (OSError, RuntimeError):
        return None, _fail(label, f"unresolved:{path}", expected)


def validate(atlaso_home: Path, version: str, purelib: Path) -> tuple[int, Path | None]:
    """Validate compatibility links and return the physical purelib path.

    Args:
        atlaso_home: Physical Atlaso installation root.
        version: Strict bootstrap release version.
        purelib: Interpreter-reported purelib path to validate.

    Returns:
        The validation status and resolved physical purelib path when valid.
    """
    if not VERSION_PATTERN.fullmatch(version):
        print("Atlaso bootstrap version is not strict X.Y.Z metadata.", file=sys.stderr)
        return 2, None

    home, status = _resolve(atlaso_home, "home", atlaso_home)
    if status or home is None:
        return status, None

    expected_release = home / "releases" / f"bootstrap-{version}"
    expected_venv = expected_release / ".venv"
    expected_purelib = expected_venv / "lib" / "python3.14" / "site-packages"

    for label, path in (("release", expected_release), ("environment", expected_venv)):
        if path.is_symlink() or not path.is_dir():
            return _fail(label, path, path), None
        resolved_path, status = _resolve(path, label, path)
        if status or resolved_path is None:
            return status, None
        if resolved_path != path:
            return _fail(label, resolved_path, path), None

    resolved_expected_purelib, status = _resolve(
        expected_purelib, "purelib", expected_purelib
    )
    if status or resolved_expected_purelib is None:
        return status, None
    if resolved_expected_purelib != expected_purelib:
        return _fail("purelib", resolved_expected_purelib, expected_purelib), None

    current = home / "current"
    if not current.is_symlink():
        return _fail("current", current, expected_release), None
    resolved_current, status = _resolve(current, "current", expected_release)
    if status or resolved_current is None:
        return status, None
    if resolved_current != expected_release:
        return _fail("current", resolved_current, expected_release), None

    compatibility_venv = home / ".venv"
    if not compatibility_venv.is_symlink():
        return _fail("environment", compatibility_venv, expected_venv), None
    resolved_venv, status = _resolve(
        compatibility_venv, "environment", expected_venv
    )
    if status or resolved_venv is None:
        return status, None
    if resolved_venv != expected_venv:
        return _fail("environment", resolved_venv, expected_venv), None

    if not purelib.is_absolute():
        return _fail("purelib", purelib, expected_purelib), None
    resolved_purelib, status = _resolve(purelib, "purelib", expected_purelib)
    if status or resolved_purelib is None:
        return status, None
    if resolved_purelib != resolved_expected_purelib:
        return _fail("purelib", resolved_purelib, resolved_expected_purelib), None

    return 0, resolved_purelib


def main() -> int:
    """Parse arguments and print the validated physical purelib path."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--atlaso-home", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--purelib", required=True, type=Path)
    args = parser.parse_args()

    status, purelib = validate(args.atlaso_home, args.version, args.purelib)
    if status == 0 and purelib is not None:
        print(purelib)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
