#!/usr/bin/env python3
"""Keep Atlaso's repository version sources synchronized."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PYTHON_FALLBACK_RE = re.compile(r'(?m)^(\s*BUILD_VERSION\s*=\s*")[^"]+("\s*)$')
POWERSHELL_MODULE_RE = re.compile(r"(?m)^(\s*ModuleVersion\s*=\s*')[^']+('\s*)$")
PROJECT_VERSION_RE = re.compile(r'(?m)^(version\s*=\s*")[^"]+("\s*)$')
NORMALIZED_DISTRIBUTION_SEPARATOR_RE = re.compile(r"[-_.]+")


class VersionError(ValueError):
    """Raised when repository version state is invalid."""


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str, *, source: str = "version") -> Version:
        match = SEMVER_RE.fullmatch(value.strip())
        if match is None:
            raise VersionError(f"{source} must use X.Y.Z semantic versioning; found {value!r}")
        return cls(*(int(part) for part in match.groups()))

    def next_patch(self) -> Version:
        return Version(self.major, self.minor, self.patch + 1)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


PRE_GA_RELEASE_LINE = Version(0, 9, 0)


VERSION_PATHS = {
    "Python project": Path("pyproject.toml"),
    "Python runtime fallback": Path("atlaso/__init__.py"),
    "PowerShell module": Path("clients/powershell/Atlaso/Atlaso.psd1"),
}


def _version_path(root: Path, source: str) -> Path:
    configured = root / VERSION_PATHS[source]
    if configured.is_file() or source == "Python project":
        return configured
    pattern = "*/__init__.py" if source == "Python runtime fallback" else "clients/powershell/*/*.psd1"
    marker = "BUILD_VERSION" if source == "Python runtime fallback" else "ModuleVersion"
    candidates = [
        path
        for path in root.glob(pattern)
        if path.is_file() and marker in path.read_text(encoding="utf-8", errors="ignore")
    ]
    if len(candidates) != 1:
        raise VersionError(
            f"Expected exactly one {source} version source under {root}; found {len(candidates)}"
        )
    return candidates[0]


def _read_text(root: Path, source: str) -> str:
    path = _version_path(root, source)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VersionError(f"Cannot read {source} version from {path}: {exc}") from exc


def read_project_version(root: Path) -> Version:
    root = root.resolve()
    path = root / VERSION_PATHS["Python project"]
    project_text = _read_text(root, "Python project")
    try:
        document = tomllib.loads(project_text)
    except tomllib.TOMLDecodeError as exc:
        raise VersionError(f"{path} contains invalid TOML: {exc}") from exc

    project = document.get("project")
    if not isinstance(project, dict) or "version" not in project:
        raise VersionError(f"{path} must define [project].version")
    project_value = project["version"]
    if not isinstance(project_value, str):
        raise VersionError(f"{path} [project].version must be a string")
    return Version.parse(project_value, source=f"{path} [project].version")


def read_project_name(root: Path) -> str:
    root = root.resolve()
    path = root / VERSION_PATHS["Python project"]
    try:
        document = tomllib.loads(_read_text(root, "Python project"))
    except tomllib.TOMLDecodeError as exc:
        raise VersionError(f"{path} contains invalid TOML: {exc}") from exc
    project = document.get("project")
    value = project.get("name") if isinstance(project, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise VersionError(f"{path} must define [project].name")
    return value.strip()


def normalize_distribution_name(value: str) -> str:
    """Return the canonical comparison form defined for Python distributions."""
    return NORMALIZED_DISTRIBUTION_SEPARATOR_RE.sub("-", value).casefold()


def read_versions(root: Path) -> dict[str, Version]:
    root = root.resolve()
    project_version = read_project_version(root)

    python_text = _read_text(root, "Python runtime fallback")
    python_path = _version_path(root, "Python runtime fallback")
    python_match = PYTHON_FALLBACK_RE.search(python_text)
    if python_match is None:
        raise VersionError(f"{python_path} must define the BUILD_VERSION fallback")

    powershell_text = _read_text(root, "PowerShell module")
    powershell_path = _version_path(root, "PowerShell module")
    powershell_match = POWERSHELL_MODULE_RE.search(powershell_text)
    if powershell_match is None:
        raise VersionError(f"{powershell_path} must define ModuleVersion")

    return {
        "Python project": project_version,
        "Python runtime fallback": Version.parse(
            python_match.group(0).split('"', 2)[1], source="Python runtime fallback version"
        ),
        "PowerShell module": Version.parse(
            powershell_match.group(0).split("'", 2)[1], source="PowerShell module version"
        ),
    }


def consistent_version(root: Path) -> Version:
    versions = read_versions(root)
    unique = set(versions.values())
    if len(unique) != 1:
        detail = ", ".join(f"{source}={version}" for source, version in versions.items())
        raise VersionError(f"Repository version sources disagree: {detail}")
    return next(iter(unique))


def expected_version(base_root: Path) -> Version:
    return consistent_version(base_root).next_patch()


def allowed_pr_versions(base_root: Path, target_root: Path | None = None) -> set[Version]:
    base = consistent_version(base_root)
    allowed = {base.next_patch()}
    if target_root is not None and normalize_distribution_name(
        read_project_name(target_root)
    ) != normalize_distribution_name(read_project_name(base_root)):
        allowed.add(base)
    if base.major == 0 and base < PRE_GA_RELEASE_LINE:
        allowed.add(PRE_GA_RELEASE_LINE)
    return allowed


def check(root: Path, base_root: Path | None = None) -> Version:
    current = consistent_version(root)
    if base_root is not None:
        allowed = allowed_pr_versions(base_root, root)
        if current not in allowed:
            expected = " or ".join(str(value) for value in sorted(allowed))
            raise VersionError(f"PR version must be {expected}; found {current}")
    return current


def _replace_version(path: Path, pattern: re.Pattern[str], version: Version, source: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(rf"\g<1>{version}\g<2>", text, count=1)
    if count != 1:
        raise VersionError(f"Could not update {source} version in {path}")
    path.write_text(updated, encoding="utf-8", newline="\n")


def bump(
    root: Path,
    base_root: Path | None = None,
    target_version: Version | None = None,
) -> tuple[Version, bool]:
    root = root.resolve()
    current = consistent_version(root)
    if target_version is not None:
        if base_root is not None:
            raise VersionError("--version cannot be combined with --base-root")
        if current == target_version:
            return current, False
        expected = current.next_patch()
        if target_version != expected:
            raise VersionError(
                f"--version must be the current version {current} or next patch {expected}; "
                f"found {target_version}"
            )
    else:
        base_root = root if base_root is None else base_root.resolve()
        base = consistent_version(base_root)
        expected = base.next_patch()
        allowed = allowed_pr_versions(base_root, root)
        if current in allowed:
            return current, False
        if current != base:
            raise VersionError(
                f"Cannot automatically replace {current}; target must match base {base} "
                f"or expected patch {expected}"
            )

    _replace_version(_version_path(root, "Python project"), PROJECT_VERSION_RE, expected, "Python project")
    _replace_version(
        _version_path(root, "Python runtime fallback"),
        PYTHON_FALLBACK_RE,
        expected,
        "Python runtime fallback",
    )
    _replace_version(
        _version_path(root, "PowerShell module"), POWERSHELL_MODULE_RE, expected, "PowerShell module"
    )
    check(root)
    return expected, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("bump", "check", "get", "project-get"))
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository checkout to inspect or update.")
    parser.add_argument(
        "--base-root",
        type=Path,
        help="Base-branch checkout; check requires exactly one patch above it and bump derives from it.",
    )
    parser.add_argument(
        "--version",
        help="Explicit current or next-patch X.Y.Z target; when omitted, bump increments the patch.",
    )
    args = parser.parse_args(argv)

    try:
        if args.version is not None and args.command != "bump":
            raise VersionError("--version is only valid with the bump command")
        target_version = (
            Version.parse(args.version, source="--version") if args.version is not None else None
        )
        if args.command == "project-get":
            print(read_project_version(args.root))
        elif args.command == "get":
            version = consistent_version(args.root)
            print(version)
        elif args.command == "check":
            version = check(args.root, args.base_root)
            print(f"Version policy passed: {version}")
        else:
            version, changed = bump(args.root, args.base_root, target_version)
            action = "Bumped repository version to" if changed else "Repository version already at"
            print(f"{action} {version}")
    except VersionError as exc:
        print(f"Version policy failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
