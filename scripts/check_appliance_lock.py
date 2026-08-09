#!/usr/bin/env python3
"""Fail when appliance dependency declarations are not reflected in the hash lock."""

from __future__ import annotations

import re
import hashlib
import json
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "requirements-appliance.lock"
BOOTSTRAP_LOCK_PATH = ROOT / "requirements-appliance-bootstrap.lock"
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")
DECLARATION_HASH_RE = re.compile(r"^# atlaso-declarations-sha256: ([0-9a-f]{64})$")


def locked_names(lines: list[str]) -> set[str]:
    """Return locked names."""
    return {
        canonicalize_name(match.group(1))
        for line in lines
        if (match := PIN_RE.match(line))
    }


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = {canonicalize_name(Requirement(value).name) for value in project["dependencies"]}
    lines = LOCK_PATH.read_text(encoding="utf-8").splitlines()
    locked = locked_names(lines)
    missing = sorted(declared - locked)
    errors: list[str] = []
    if missing:
        errors.append(f"direct dependencies missing from {LOCK_PATH.name}: {', '.join(missing)}")
    for index, line in enumerate(lines):
        if not PIN_RE.match(line):
            continue
        next_pin = next(
            (candidate_index for candidate_index in range(index + 1, len(lines)) if PIN_RE.match(lines[candidate_index])),
            len(lines),
        )
        if not any(HASH_RE.search(candidate) for candidate in lines[index:next_pin]):
            errors.append(f"{LOCK_PATH.name}:{index + 1}: pinned requirement has no SHA256 hash")
    if "pip" not in locked or "wheel" not in locked or "setuptools" not in locked:
        errors.append(f"{LOCK_PATH.name} must lock pip, setuptools, and wheel bootstrap tools")
    bootstrap = [
        line.strip()
        for line in (ROOT / "requirements-appliance-bootstrap.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    bootstrap_lines = BOOTSTRAP_LOCK_PATH.read_text(encoding="utf-8").splitlines()
    bootstrap_requirements = [Requirement(value) for value in bootstrap]
    bootstrap_expected = {
        canonicalize_name(requirement.name): str(requirement.specifier)
        for requirement in bootstrap_requirements
    }
    bootstrap_locked = {
        canonicalize_name(match.group(1)): f"=={match.group(2)}"
        for line in bootstrap_lines
        if (match := PIN_RE.match(line))
    }
    if bootstrap_locked != bootstrap_expected:
        errors.append(
            f"{BOOTSTRAP_LOCK_PATH.name} must exactly match {ROOT.joinpath('requirements-appliance-bootstrap.in').name}"
        )
    for index, line in enumerate(bootstrap_lines):
        if not PIN_RE.match(line):
            continue
        next_pin = next(
            (
                candidate_index
                for candidate_index in range(index + 1, len(bootstrap_lines))
                if PIN_RE.match(bootstrap_lines[candidate_index])
            ),
            len(bootstrap_lines),
        )
        if not any(HASH_RE.search(candidate) for candidate in bootstrap_lines[index:next_pin]):
            errors.append(f"{BOOTSTRAP_LOCK_PATH.name}:{index + 1}: pinned requirement has no SHA256 hash")
    declaration_hash = hashlib.sha256(
        json.dumps(
            {
                "requires_python": project["requires-python"],
                "dependencies": project["dependencies"],
                "bootstrap": bootstrap,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    recorded = next(
        (match.group(1) for line in lines if (match := DECLARATION_HASH_RE.fullmatch(line))),
        "",
    )
    if recorded != declaration_hash:
        errors.append(
            f"{LOCK_PATH.name} declaration fingerprint is stale; regenerate the lock and record {declaration_hash}"
        )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"{LOCK_PATH.name} covers {len(declared)} direct dependencies and {len(locked)} exact packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
