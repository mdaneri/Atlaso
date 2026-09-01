#!/usr/bin/env python3
"""Regenerate all Atlaso Python locks under the minimum package-age policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (3, 14)
EXPECTED_PIP_TOOLS = "7.6.0"
MINIMUM_PIP = (26, 0)
MINIMUM_AGE = "P7D"
DEFAULT_INDEX_URL = "https://pypi.org/simple"
DECLARATION_HASH_RE = re.compile(r"^# atlaso-declarations-sha256: [0-9a-f]{64}$")
ONEPASSWORD_LOCK = "requirements-onepassword-deploy.lock"
ONEPASSWORD_MANIFEST = Path("scripts/windows/vmware/onepassword-sdk-cp314-wheel.json")
ONEPASSWORD_CP314_WHEEL = "onepassword_sdk-0.4.1-cp314-cp314-win_amd64.whl"


@dataclass(frozen=True)
class LockTarget:
    """Represent lock target.

    Attributes:
        output: Output maintained by this locktarget.
        inputs: Inputs maintained by this locktarget.
        allow_unsafe: Whether unsafe is permitted.
        strip_extras: Strip extras maintained by this locktarget.
    """
    output: str
    inputs: tuple[str, ...]
    allow_unsafe: bool
    strip_extras: bool


LOCK_TARGETS = (
    LockTarget(
        "requirements-appliance-bootstrap.lock",
        ("requirements-appliance-bootstrap.in",),
        True,
        True,
    ),
    LockTarget(
        "requirements-appliance.lock",
        ("pyproject.toml", "requirements-appliance-bootstrap.in"),
        True,
        True,
    ),
    LockTarget("requirements-docs.lock", ("requirements-docs.in",), False, True),
    LockTarget(
        "requirements-static-analysis.lock",
        ("requirements-static-analysis.in",),
        False,
        True,
    ),
    LockTarget(
        "requirements-release-tools.lock",
        ("requirements-release-tools.in",),
        True,
        True,
    ),
    LockTarget(
        "requirements-onepassword-deploy.lock",
        ("requirements-onepassword-deploy.in",),
        False,
        True,
    ),
    LockTarget(
        "requirements-virtualization-smoke.lock",
        ("requirements-virtualization-smoke.in",),
        False,
        True,
    ),
)


def _toolchain_error() -> str:
    """Return toolchain error."""
    if sys.version_info[:2] != EXPECTED_PYTHON:
        return (
            f"Python {EXPECTED_PYTHON[0]}.{EXPECTED_PYTHON[1]} is required; "
            f"found {sys.version_info.major}.{sys.version_info.minor}"
        )
    try:
        installed = version("pip-tools")
    except PackageNotFoundError:
        return f"pip-tools {EXPECTED_PIP_TOOLS} is required but is not installed"
    if installed != EXPECTED_PIP_TOOLS:
        return f"pip-tools {EXPECTED_PIP_TOOLS} is required; found {installed}"
    installed_pip = version("pip")
    pip_match = re.match(r"^(\d+)\.(\d+)", installed_pip)
    if pip_match is None or tuple(map(int, pip_match.groups())) < MINIMUM_PIP:
        return (
            f"pip {MINIMUM_PIP[0]}.{MINIMUM_PIP[1]} or newer is required; "
            f"found {installed_pip}"
        )
    return ""


def _compile_command(
    target: LockTarget,
    *,
    upgrade: bool,
    index_url: str = DEFAULT_INDEX_URL,
) -> list[str]:
    """Return compile command.

    Args:
        target: Target resource or location affected by the operation.
        upgrade: Whether upgrade applies to the operation.
        index_url: URL used for index.
    """
    command = [
        sys.executable,
        "-m",
        "piptools",
        "compile",
        "--generate-hashes",
        f"--index-url={index_url}",
        "--no-config",
        "--no-emit-index-url",
        "--quiet",
        f"--output-file={target.output}",
        f"--uploaded-prior-to={MINIMUM_AGE}",
    ]
    if target.allow_unsafe:
        command.append("--allow-unsafe")
    if target.strip_extras:
        command.append("--strip-extras")
    if upgrade:
        command.append("--upgrade")
    command.extend(target.inputs)
    return command


def _validated_index_url(index_url: str) -> str:
    """Return validated index url.

    Args:
        index_url: URL used for index.


    Raises:
        RuntimeError: If the operation cannot be completed safely.
    """
    parsed = urlsplit(index_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("the package index must use an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError("the package index URL must not contain embedded credentials")
    return index_url.rstrip("/")


def _assert_index_provides_upload_times(index_url: str) -> None:
    """Check index provides upload times.

    Args:
        index_url: URL used for index.


    Raises:
        RuntimeError: If the operation cannot be completed safely.
    """
    request = urllib.request.Request(
        f"{index_url}/pip/",
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        raise RuntimeError(
            "the package index upload-time metadata check failed"
        ) from exc
    files = payload.get("files") if isinstance(payload, dict) else None
    if not files or any(
        not isinstance(file, dict) or not file.get("upload-time") for file in files
    ):
        raise RuntimeError(
            "the package index does not provide complete upload-time metadata; "
            f"cannot enforce --uploaded-prior-to={MINIMUM_AGE}"
        )


def _compile_environment() -> dict[str, str]:
    """Return compile environment."""
    environment = os.environ.copy()
    for name in (
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_NO_INDEX",
    ):
        environment.pop(name, None)
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


def _appliance_declaration_hash() -> str:
    """Return appliance declaration hash."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    bootstrap = [
        line.strip()
        for line in (ROOT / "requirements-appliance-bootstrap.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return hashlib.sha256(
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


def _record_appliance_declaration_hash() -> None:
    """Persist appliance declaration hash.

    Raises:
        RuntimeError: If the operation cannot be completed safely.
    """
    path = ROOT / "requirements-appliance.lock"
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not DECLARATION_HASH_RE.fullmatch(line)
    ]
    command_end = next(
        (
            index
            for index, line in enumerate(lines)
            if index > 4 and line == "#"
        ),
        -1,
    )
    if command_end < 0:
        raise RuntimeError(f"{path.name} does not contain a pip-compile header")
    lines.insert(
        command_end + 1,
        f"# atlaso-declarations-sha256: {_appliance_declaration_hash()}",
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _onepassword_artifact_hash() -> str:
    """Return the approved fork wheel hash from the strict artifact manifest."""
    payload = json.loads((ROOT / ONEPASSWORD_MANIFEST).read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("asset_name") != ONEPASSWORD_CP314_WHEEL
        or payload.get("wheel_tag") != "cp314-cp314-win_amd64"
        or payload.get("repository") != "mdaneri/onepassword-sdk-python"
        or payload.get("release_tag") != "atlaso-wheel-v0.4.1-cp314.1"
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("asset_sha256", "")))
    ):
        raise RuntimeError("the approved 1Password CPython 3.14 wheel manifest is invalid")
    return str(payload["asset_sha256"])


def _assert_no_eligible_official_onepassword_wheel(index_url: str) -> None:
    """Require retirement of the fork after an official wheel ages seven days.

    Args:
        index_url: Trusted Python simple-index base URL to inspect.
    """
    request = urllib.request.Request(
        f"{index_url}/onepassword-sdk/",
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        raise RuntimeError("the official 1Password wheel retirement check failed") from exc
    cutoff = datetime.now(UTC) - timedelta(days=7)
    for file in payload.get("files", []):
        if not isinstance(file, dict) or file.get("filename") != ONEPASSWORD_CP314_WHEEL:
            continue
        uploaded = file.get("upload-time")
        if not isinstance(uploaded, str):
            raise RuntimeError("the official 1Password wheel lacks upload-time metadata")
        if datetime.fromisoformat(uploaded.replace("Z", "+00:00")) <= cutoff:
            raise RuntimeError(
                "an official onepassword-sdk 0.4.1 cp314-win_amd64 wheel is now "
                "seven-days eligible; remove the temporary fork manifest and dependency"
            )


def _record_onepassword_artifact_hash() -> None:
    """Add the approved immutable fork wheel digest to the generated lock."""
    path = ROOT / ONEPASSWORD_LOCK
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith("onepassword-sdk==0.4.1 \\")),
        -1,
    )
    if start < 0:
        raise RuntimeError(f"{path.name} does not pin onepassword-sdk==0.4.1")
    end = start + 1
    while end < len(lines) and lines[end].lstrip().startswith("--hash=sha256:"):
        end += 1
    hashes = {
        match.group(1)
        for line in lines[start:end]
        if (match := re.search(r"--hash=sha256:([0-9a-f]{64})", line))
    }
    hashes.add(_onepassword_artifact_hash())
    replacement = ["onepassword-sdk==0.4.1 \\"]
    ordered = sorted(hashes)
    replacement.extend(
        f"    --hash=sha256:{digest}{' \\' if index < len(ordered) - 1 else ''}"
        for index, digest in enumerate(ordered)
    )
    lines[start:end] = replacement
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Upgrade eligible packages while retaining the seven-day cutoff.",
    )
    parser.add_argument(
        "--index-url",
        default=DEFAULT_INDEX_URL,
        help=(
            "PEP 691/700 package index used for resolution "
            f"(default: {DEFAULT_INDEX_URL})."
        ),
    )
    args = parser.parse_args()
    error = _toolchain_error()
    if error:
        print(error, file=sys.stderr)
        return 2
    try:
        index_url = _validated_index_url(args.index_url)
        _onepassword_artifact_hash()
        _assert_index_provides_upload_times(index_url)
        _assert_no_eligible_official_onepassword_wheel(index_url)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    environment = _compile_environment()
    for target in LOCK_TARGETS:
        subprocess.run(
            _compile_command(target, upgrade=args.upgrade, index_url=index_url),
            cwd=ROOT,
            env=environment,
            check=True,
        )
    _record_appliance_declaration_hash()
    _record_onepassword_artifact_hash()
    print(
        f"Regenerated {len(LOCK_TARGETS)} locks with packages uploaded at least "
        f"{MINIMUM_AGE.removeprefix('P').removesuffix('D')} days ago."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
