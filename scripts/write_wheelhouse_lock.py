#!/usr/bin/env python3
"""Write a runtime hash lock for one verified ABI-specific wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from packaging.utils import canonicalize_name, parse_wheel_filename


ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def locked_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PIN_RE.match(line)
        if match:
            versions[canonicalize_name(match.group(1))] = match.group(2)
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--source-lock", type=Path, default=ROOT / "requirements-appliance.lock")
    parser.add_argument("--output-name", default="requirements-wheelhouse.lock")
    args = parser.parse_args()

    expected = locked_versions(args.source_lock)
    wheels: dict[str, tuple[str, Path]] = {}
    for wheel in sorted(args.wheelhouse.glob("*.whl")):
        name, version, _build, _tags = parse_wheel_filename(wheel.name)
        normalized = canonicalize_name(name)
        if normalized in wheels:
            raise SystemExit(f"wheelhouse contains multiple wheels for {normalized}")
        wheels[normalized] = (str(version), wheel)
    missing = sorted(set(expected) - set(wheels))
    extra = sorted(set(wheels) - set(expected))
    mismatched = sorted(
        name
        for name in set(expected) & set(wheels)
        if expected[name] != wheels[name][0]
    )
    if missing or extra or mismatched:
        raise SystemExit(
            "wheelhouse does not match the checked-in lock: "
            f"missing={missing}; extra={extra}; mismatched={mismatched}"
        )

    output = args.wheelhouse / args.output_name
    lines = [
        "# Generated from verified wheels; consumed offline by atlaso-helper.",
        *[
            f"{name}=={version} --hash=sha256:{sha256(wheel)}"
            for name, (version, wheel) in sorted(wheels.items())
        ],
        "",
    ]
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"{output} locks {len(wheels)} wheels.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
