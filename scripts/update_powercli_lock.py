#!/usr/bin/env python3
"""Refresh the image PowerCLI closure from public PowerShell Gallery metadata.

Choose the suite's declared dependency floors, then verify every reachable edge.
Never independently upgrade a component to Gallery latest or execute package code.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
LOCK = Path("image/common/powershell/powercli-lock.json")
API = "https://www.powershellgallery.com/api/v2/"
SUITE = "VCF.PowerCLI"
# These consumers describe the image baseline, not independently selected releases.
CONSUMERS = (
    "image/common/scripts/provision-atlaso.sh",
    "atlaso/app/seed.py",
    "scripts/interop/lifecycle_test.py",
    "image/vmware-workstation/README.md",
    "docs/reference/full-technical-reference.md",
    "docs/reference/vmware-workstation-lifecycle-testing.md",
)
JOURNAL = Path(".atlaso-local/powercli-refresh-transaction.json")


def content_digest(files: dict[str, bytes]) -> str:
    """Bind every archive-relative path and byte sequence in ordinal path order."""
    lines = []
    folded = set()
    for name, payload in sorted(files.items()):
        if (
            not name
            or not name.isascii()
            or any(ord(char) < 32 for char in name)
            or "\\" in name
            or ":" in name
            or name.startswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or name.lower() in folded
        ):
            raise ValueError(f"Unsafe or ambiguous package path: {name!r}")
        folded.add(name.lower())
        lines.append(name + "\0" + hashlib.sha256(payload).hexdigest() + "\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def replace_file(path: Path, data: bytes) -> None:
    """Durably stage one same-directory replacement before atomic rename."""
    staged = path.with_name(path.name + ".powercli-pending")
    with staged.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(staged, path)


def recover_transaction(root: Path, check: bool = False) -> bool:
    """Roll an interrupted update forward, preserving any independently edited file."""
    journal = root / JOURNAL
    if not journal.exists():
        return False
    transaction = json.loads(journal.read_text(encoding="utf-8"))
    expected = {*CONSUMERS, LOCK.as_posix()}
    entries = transaction["files"]
    if set(entries) != expected:
        raise ValueError("Unexpected PowerCLI transaction file inventory")
    for relative, entry in entries.items():
        current = (root / relative).read_bytes()
        if current not in (
            entry["before"].encode("utf-8"),
            entry["after"].encode("utf-8"),
        ):
            raise ValueError(
                f"PowerCLI recovery preserves independently edited {relative}"
            )
    if check:
        raise ValueError(
            "Pending PowerCLI refresh requires recovery in a development worktree"
        )
    for relative, entry in entries.items():
        destination = root / relative
        payload = entry["after"].encode("utf-8")
        if destination.read_bytes() != payload:
            replace_file(destination, payload)
    journal.unlink()
    return True


def publish_transaction(root: Path, updates: dict[Path, str]) -> None:
    """Journal the complete update before any tracked write so retries can finish it."""
    journal = root / JOURNAL
    journal.parent.mkdir(parents=True, exist_ok=True)
    transaction = {
        "files": {
            path.relative_to(root).as_posix(): {
                "before": path.read_bytes().decode("utf-8"),
                "after": content,
            }
            for path, content in updates.items()
        }
    }
    replace_file(journal, (json.dumps(transaction, indent=2) + "\n").encode("utf-8"))
    recover_transaction(root)


def version_key(value: str) -> tuple[int, ...]:
    """Accept stable PowerShell versions and compare missing revision as zero."""
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", value):
        raise ValueError(f"Unsupported stable module version: {value!r}")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def dependency_floor(requirement: str) -> str:
    """Return an inclusive published floor; reject ranges requiring guessing."""
    if requirement.startswith("[") and requirement.endswith(("]", ")")):
        floor = requirement[1:-1].split(",")[0].strip()
    elif requirement and requirement[0].isdigit():
        floor = requirement
    else:
        raise ValueError(f"Dependency has no inclusive version floor: {requirement!r}")
    version_key(floor)
    return floor


def satisfies(version: str, requirement: str) -> bool:
    """Evaluate numeric NuGet exact, minimum, and bounded dependency constraints."""
    candidate = version_key(version)
    if requirement[0].isdigit():
        return candidate >= version_key(requirement)
    if requirement[0] not in "[(" or requirement[-1] not in "])":
        raise ValueError(f"Unsupported dependency constraint: {requirement!r}")
    bounds = requirement[1:-1].split(",")
    if len(bounds) == 1:
        if requirement[0] != "[" or requirement[-1] != "]":
            raise ValueError(f"Unsupported exact constraint: {requirement!r}")
        return candidate == version_key(bounds[0].strip())
    if len(bounds) != 2:
        raise ValueError(f"Unsupported dependency constraint: {requirement!r}")
    low, high = (bound.strip() for bound in bounds)
    return (
        not low
        or candidate > version_key(low)
        or (requirement[0] == "[" and candidate == version_key(low))
    ) and (
        not high
        or candidate < version_key(high)
        or (requirement[-1] == "]" and candidate == version_key(high))
    )


class Gallery:
    """Read bounded official Gallery XML without loading downloaded modules."""

    def read(self, query: str) -> ET.Element:
        """Fetch one metadata document with a timeout and response-size bound."""
        request = urllib.request.Request(
            API + query, headers={"User-Agent": "Atlaso-PowerCLI-lock"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(4 * 1024 * 1024 + 1)
        if len(payload) > 4 * 1024 * 1024:
            raise ValueError("Gallery metadata exceeds the supported size")
        return ET.fromstring(payload)

    def latest(self) -> str:
        """Read the Gallery's latest stable suite, not a component release."""
        document = self.read(
            "Packages?"
            + urlencode(
                {
                    "$filter": "Id eq 'VCF.PowerCLI' and IsLatestVersion eq true",
                    "$top": "2",
                }
            )
        )
        versions = [
            node.text for node in document.iter() if node.tag.endswith("}Version")
        ]
        if len(versions) != 1 or not versions[0]:
            raise ValueError(
                "Gallery did not identify one latest stable PowerCLI suite"
            )
        version_key(versions[0])
        return versions[0]

    def dependencies(self, name: str, version: str) -> list[tuple[str, str]]:
        """Read and validate the requested package identity and dependency edges."""
        if not re.fullmatch(r"(?:VCF|VMware)\.[A-Za-z0-9.]+", name):
            raise ValueError(f"Unsupported PowerCLI dependency: {name!r}")
        version_key(version)
        document = self.read(f"Packages(Id='{name}',Version='{version}')")
        properties = {
            node.tag.rsplit("}", 1)[-1]: node.text or ""
            for node in document.iter()
            if node.tag.startswith(
                "{http://schemas.microsoft.com/ado/2007/08/dataservices}"
            )
        }
        if (
            properties.get("Id", "").lower() != name.lower()
            or properties.get("Version") != version
        ):
            raise ValueError(f"Gallery package identity mismatch: {name} {version}")
        result = []
        for entry in properties.get("Dependencies", "").split("|"):
            if not entry:
                continue
            fields = entry.split(":")
            if len(fields) != 3 or fields[2]:
                raise ValueError(f"Unsupported target-specific dependency: {entry!r}")
            dependency, constraint, _ = fields
            satisfies("0.0.0", constraint)
            result.append((dependency, constraint))
        return result

    def hashes(self, name: str, version: str) -> dict[str, str]:
        """Download inert package bytes and bind both archive and extracted contents."""
        with urllib.request.urlopen(
            API + f"package/{name}/{version}", timeout=300
        ) as response:
            archive = response.read(512 * 1024 * 1024 + 1)
        if len(archive) > 512 * 1024 * 1024:
            raise ValueError(f"PowerCLI archive too large: {name}")
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            members = [item for item in package.infolist() if not item.is_dir()]
            if len({item.filename for item in members}) != len(members):
                raise ValueError(f"Duplicate archive member: {name}")
            if sum(item.file_size for item in members) > 1024 * 1024 * 1024:
                raise ValueError(f"PowerCLI expanded archive too large: {name}")
            files = {item.filename: package.read(item) for item in members}
        return {
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "content_sha256": content_digest(files),
        }


def resolve(gallery: Gallery, suite_version: str) -> dict[str, object]:
    """Resolve vendor floors and reject incompatible or unbounded closures.

    A suite floor is authoritative. Conflicting transitive floors fail for review
    instead of silently selecting a different release family.
    """
    version_key(suite_version)
    selected = {SUITE: suite_version}
    pending = [SUITE]
    edges = []
    while pending:
        name = pending.pop(0)
        for dependency, constraint in gallery.dependencies(name, selected[name]):
            edges.append((name, dependency, constraint))
            if dependency not in selected:
                if len(selected) >= 200:
                    raise ValueError("PowerCLI dependency closure exceeds 200 modules")
                selected[dependency] = dependency_floor(constraint)
                pending.append(dependency)
    for parent, dependency, constraint in edges:
        if not satisfies(selected[dependency], constraint):
            raise ValueError(
                f"Incompatible Gallery closure: {parent} requires {dependency} "
                f"{constraint}, selected {selected[dependency]}"
            )
    return {
        "schema_version": 2,
        "suite_version": suite_version,
        "modules": dict(sorted(selected.items())),
        "hashes": {
            name: gallery.hashes(name, selected[name]) for name in sorted(selected)
        },
    }


def refresh(root: Path, gallery: Gallery, version: str | None, check: bool) -> bool:
    """Validate a complete candidate before writing; preserve current bytes on no-op."""
    if recover_transaction(root, check):
        print(
            "Recovered the complete PowerCLI refresh; review and commit before building."
        )
        return True
    path = root / LOCK
    previous = json.loads(path.read_text(encoding="utf-8"))
    target = version or gallery.latest()
    if version_key(target) < version_key(previous["suite_version"]):
        raise ValueError("Refusing to downgrade the PowerCLI suite")
    if target == previous["suite_version"] and previous.get("schema_version") == 2:
        print(f"PowerCLI {target} is current; no files changed.")
        return False
    candidate = resolve(gallery, target)
    if check:
        raise ValueError(
            f"PowerCLI {target} is available. Refresh in a development worktree, "
            "review and commit the lock, then rebuild; immutable release source was not changed."
        )
    old = previous["suite_version"]
    updates = {}
    for relative in CONSUMERS:
        consumer = root / relative
        content = consumer.read_text(encoding="utf-8")
        if old not in content:
            raise ValueError(
                f"PowerCLI baseline missing from {relative}; no files changed"
            )
        updates[consumer] = content.replace(old, target)
    # Resolve and validate all inputs before the first tracked write.
    updates[path] = json.dumps(candidate, indent=2) + "\n"
    publish_transaction(root, updates)
    print(
        f"Updated PowerCLI {old} -> {target} and {len(candidate['modules'])} locked modules."
    )
    return True


def main() -> int:
    """Expose manual refresh and automatic pre-build refresh with explicit exit codes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", help="Exact stable suite release; default: Gallery latest"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Read-only gate for immutable release source",
    )
    parser.add_argument(
        "--before-build",
        action="store_true",
        help="Exit 3 after updates so source can be committed",
    )
    args = parser.parse_args()
    try:
        changed = refresh(ROOT, Gallery(), args.version, args.check)
    except (ValueError, OSError, ET.ParseError) as error:
        parser.exit(1, f"PowerCLI refresh failed: {error}\n")
    if changed and args.before_build:
        print(
            "Review and commit the PowerCLI update, then rerun the build/export command."
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
