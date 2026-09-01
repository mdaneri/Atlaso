#!/usr/bin/env python3
"""Verify that Packer selected the exact plugin versions required by a template."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_LINE = re.compile(
    r'^(?P<name>\S+)\s+(?P<source>\S+)\s+"(?P<constraint>[^"]+)"\s+(?P<binary>.+)$'
)
EXACT_VERSION = re.compile(r"^=\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")


def validate_packer_plugins(target: Path, packer: str) -> list[str]:
    """Return findings when Packer does not resolve exact installed plugin versions.

    Args:
        target: Packer template directory or exact template file to inspect.
        packer: Packer executable path or command name.
    """
    directory = target.parent if target.is_file() else target
    packer_target = target.name if target.is_file() else "."
    result = subprocess.run(
        [packer, "plugins", "required", packer_target],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        message = detail[-1] if detail else f"exit code {result.returncode}"
        return [f"packer plugins required failed: {message}"]

    findings: list[str] = []
    seen: set[tuple[str, str]] = set()
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return ["packer plugins required returned no plugins"]

    for line in lines:
        match = PLUGIN_LINE.fullmatch(line)
        if match is None:
            findings.append(f"unrecognized packer plugins required output: {line}")
            continue
        name = match.group("name")
        source = match.group("source")
        identity = (name, source)
        if identity in seen:
            findings.append(f"duplicate required plugin: {name} from {source}")
            continue
        seen.add(identity)

        constraint = match.group("constraint")
        version_match = EXACT_VERSION.fullmatch(constraint)
        if version_match is None:
            findings.append(
                f'{name} from {source} must use one exact X.Y.Z version; found "{constraint}"'
            )
            continue
        version = version_match.group("version")
        binary = match.group("binary").strip()
        binary_name = re.split(r"[\\/]", binary)[-1]
        plugin_name = source.rsplit("/", maxsplit=1)[-1]
        expected_prefix = f"packer-plugin-{plugin_name}_v{version}_"
        if not binary_name.startswith(expected_prefix):
            findings.append(
                f"{name} from {source} requires {version} but Packer selected {binary_name}"
            )
            continue
        if not Path(binary).is_file():
            findings.append(f"{name} from {source} selected a missing plugin binary: {binary}")

    return findings


def main(argv: list[str] | None = None) -> int:
    """Verify one or more initialized Packer template directories.

    Args:
        argv: Optional command-line arguments for testing or direct invocation.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--packer",
        default=shutil.which("packer") or "packer",
        help="Packer executable path or command name.",
    )
    parser.add_argument("targets", nargs="+", type=Path)
    args = parser.parse_args(argv)

    findings: list[str] = []
    for raw_target in args.targets:
        target = raw_target.resolve()
        if not target.exists() or (not target.is_dir() and not target.is_file()):
            findings.append(f"{target}: Packer template target is missing")
            continue
        findings.extend(
            f"{target}: {message}"
            for message in validate_packer_plugins(target, args.packer)
        )

    if findings:
        print(f"Packer plugin checks failed with {len(findings)} issue(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"Packer plugin checks passed for {len(args.targets)} template target(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
