#!/usr/bin/env python3
"""Build and verify the immutable automatic Atlaso wheel artifact contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_release_bundle import (  # noqa: E402 - local script path precedes the sibling import.
    build_application_wheel,
    project_version,
)

COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
WHEEL_NAME_PATTERN = re.compile(r"^atlaso-[A-Za-z0-9_.+!-]+-py3-none-any\.whl$")
IDENTITY_NAME = "wheel-identity.json"
RETENTION_DAYS = 90
MAXIMUM_WHEEL_BYTES = 256 * 1024 * 1024


class WheelArtifactError(ValueError):
    """Report an invalid wheel artifact or identity handoff."""


def sha256(path: Path) -> str:
    """Return the lowercase SHA-256 digest of an ordinary file.

    Args:
        path: File to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(payload: dict[str, object]) -> bytes:
    """Serialize a wheel identity with stable byte ordering.

    Args:
        payload: Identity document to serialize.
    """

    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def artifact_name(version: str, commit: str) -> str:
    """Return the one artifact name reserved for a version and commit.

    Args:
        version: Atlaso semantic version.
        commit: Full source commit.
    """

    if SEMVER_PATTERN.fullmatch(version) is None:
        raise WheelArtifactError("wheel artifact version must be semantic X.Y.Z")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise WheelArtifactError("wheel artifact commit must be a full lowercase hexadecimal commit")
    return f"atlaso-wheel-v{version}-{commit}"


def _positive_integer(value: object, *, field: str) -> int:
    """Validate a GitHub run identity integer.

    Args:
        value: Candidate integer.
        field: Field name used in validation errors.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise WheelArtifactError(f"{field} must be a positive integer")
    return value


def _validate_timestamp(value: object) -> str:
    """Validate the exact timezone-aware commit build timestamp.

    Args:
        value: Candidate timestamp.
    """

    if not isinstance(value, str):
        raise WheelArtifactError("built_at must be a timezone-aware ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WheelArtifactError("built_at must be a timezone-aware ISO 8601 timestamp") from exc
    if parsed.utcoffset() is None:
        raise WheelArtifactError("built_at must be a timezone-aware ISO 8601 timestamp")
    return value


def _read_wheel_metadata(wheel: Path) -> tuple[str, str, str]:
    """Read and validate the wheel package and embedded build identity.

    Args:
        wheel: Atlaso wheel to inspect.
    """

    try:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise WheelArtifactError("wheel contains duplicate archive members")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name:
                    raise WheelArtifactError("wheel contains an unsafe archive member")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise WheelArtifactError("wheel must contain exactly one dist-info METADATA file")
            message = BytesParser().parsebytes(archive.read(metadata_names[0]))
            package_name = message.get("Name", "")
            package_version = message.get("Version", "")
            build_text = archive.read("atlaso/_build.py").decode("utf-8")
    except (KeyError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise WheelArtifactError("wheel is missing valid Atlaso build metadata") from exc

    commit_match = re.search(r'^GIT_COMMIT = "([0-9a-f]{40})"\r?$', build_text, re.MULTILINE)
    version_match = re.search(r'^BUILD_VERSION = "([^"]+)"\r?$', build_text, re.MULTILINE)
    time_match = re.search(r'^BUILD_TIME_UTC = "([^"]+)"\r?$', build_text, re.MULTILINE)
    if not commit_match or not version_match or not time_match:
        raise WheelArtifactError("wheel Atlaso build metadata is incomplete")
    if package_name != "atlaso" or package_version != version_match.group(1):
        raise WheelArtifactError("wheel package metadata disagrees with Atlaso build metadata")
    return version_match.group(1), commit_match.group(1), time_match.group(1)


def load_identity(root: Path) -> dict[str, object]:
    """Load one canonical wheel identity document.

    Args:
        root: Extracted artifact root.
    """

    path = root / IDENTITY_NAME
    if not path.is_file() or path.is_symlink():
        raise WheelArtifactError("wheel identity is missing or unsafe")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise WheelArtifactError("wheel identity is missing or malformed") from exc
    if not isinstance(payload, dict) or raw != canonical_json(payload):
        raise WheelArtifactError("wheel identity must use canonical JSON encoding")
    return payload


def extract_artifact(args: argparse.Namespace) -> None:
    """Safely extract one downloaded GitHub artifact ZIP.

    Args:
        args: Parsed extract command arguments.
    """

    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise WheelArtifactError("wheel artifact extraction output must be absent or empty")
    try:
        with zipfile.ZipFile(args.archive) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise WheelArtifactError("wheel artifact ZIP contains duplicate members")
            wheel_names = [name for name in names if WHEEL_NAME_PATTERN.fullmatch(name)]
            if set(names) != {IDENTITY_NAME, *wheel_names} or len(wheel_names) != 1:
                raise WheelArtifactError("wheel artifact ZIP contains an unexpected payload")
            if any(
                info.is_dir()
                or len(PurePosixPath(info.filename).parts) != 1
                or info.file_size > MAXIMUM_WHEEL_BYTES
                for info in infos
            ):
                raise WheelArtifactError("wheel artifact ZIP contains an unsafe member")
            output.mkdir(parents=True, exist_ok=True)
            for info in infos:
                target = output / info.filename
                with archive.open(info) as source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                if target.stat().st_size != info.file_size:
                    raise WheelArtifactError("wheel artifact ZIP extraction size mismatch")
    except zipfile.BadZipFile as exc:
        raise WheelArtifactError("wheel artifact ZIP is malformed") from exc


def verify_artifact(
    root: Path,
    *,
    expected_repository: str,
    expected_version: str,
    expected_commit: str,
    expected_publisher_run_id: int | None = None,
) -> tuple[Path, dict[str, object]]:
    """Verify one extracted automatic wheel artifact.

    Args:
        root: Extracted artifact root.
        expected_repository: Exact source repository.
        expected_version: Exact Atlaso version.
        expected_commit: Exact source commit.
        expected_publisher_run_id: Optional GitHub publisher run bound to the artifact record.
    """

    identity = load_identity(root)
    required = {
        "schema_version",
        "kind",
        "repository",
        "version",
        "commit",
        "built_at",
        "source_ci",
        "publisher",
        "artifact",
        "wheel",
    }
    if set(identity) != required:
        raise WheelArtifactError("wheel identity fields do not match schema 1")
    if identity["schema_version"] != 1 or identity["kind"] != "atlaso-python-wheel":
        raise WheelArtifactError("wheel identity schema or kind is unsupported")
    if identity["repository"] != expected_repository:
        raise WheelArtifactError("wheel identity repository does not match the requested repository")
    if identity["version"] != expected_version or identity["commit"] != expected_commit:
        raise WheelArtifactError("wheel identity version or commit does not match the release target")
    built_at = _validate_timestamp(identity["built_at"])
    expected_name = artifact_name(expected_version, expected_commit)

    source_ci = identity["source_ci"]
    publisher = identity["publisher"]
    artifact = identity["artifact"]
    wheel_record = identity["wheel"]
    if not all(isinstance(value, dict) for value in (source_ci, publisher, artifact, wheel_record)):
        raise WheelArtifactError("wheel identity nested records must be objects")
    assert isinstance(source_ci, dict)
    assert isinstance(publisher, dict)
    assert isinstance(artifact, dict)
    assert isinstance(wheel_record, dict)
    if set(source_ci) != {"workflow", "workflow_file", "run_id", "run_attempt"}:
        raise WheelArtifactError("wheel source CI identity fields do not match schema 1")
    if source_ci["workflow"] != "CI" or source_ci["workflow_file"] != "ci.yml":
        raise WheelArtifactError("wheel source CI workflow identity is invalid")
    _positive_integer(source_ci["run_id"], field="source_ci.run_id")
    _positive_integer(source_ci["run_attempt"], field="source_ci.run_attempt")
    publisher_fields = {"workflow", "workflow_file", "run_id", "run_attempt"}
    if set(publisher) not in (publisher_fields, publisher_fields | {"trigger"}):
        raise WheelArtifactError("wheel publisher identity fields do not match schema 1")
    if publisher["workflow"] != "Publish Python wheel" or publisher["workflow_file"] != "wheel.yml":
        raise WheelArtifactError("wheel publisher workflow identity is invalid")
    publisher_run_id = _positive_integer(publisher["run_id"], field="publisher.run_id")
    _positive_integer(publisher["run_attempt"], field="publisher.run_attempt")
    if "trigger" in publisher and publisher["trigger"] not in {"automatic-main", "replay"}:
        raise WheelArtifactError("wheel publisher trigger is invalid")
    if expected_publisher_run_id is not None and publisher_run_id != expected_publisher_run_id:
        raise WheelArtifactError("wheel publisher run does not match the GitHub artifact record")
    if artifact != {"name": expected_name, "retention_days": RETENTION_DAYS}:
        raise WheelArtifactError("wheel artifact name or retention does not match the immutable contract")

    if set(wheel_record) != {"filename", "sha256", "size"}:
        raise WheelArtifactError("wheel file identity fields do not match schema 1")
    filename = wheel_record["filename"]
    if not isinstance(filename, str) or WHEEL_NAME_PATTERN.fullmatch(filename) is None:
        raise WheelArtifactError("wheel filename is invalid")
    wheel = root / filename
    if not wheel.is_file() or wheel.is_symlink():
        raise WheelArtifactError("wheel artifact payload is missing or unsafe")
    expected_files = {IDENTITY_NAME, filename}
    if {path.name for path in root.iterdir()} != expected_files:
        raise WheelArtifactError("wheel artifact contains an unexpected payload")
    if wheel_record["size"] != wheel.stat().st_size:
        raise WheelArtifactError("wheel size does not match its identity")
    digest = sha256(wheel)
    if not isinstance(wheel_record["sha256"], str) or DIGEST_PATTERN.fullmatch(wheel_record["sha256"]) is None:
        raise WheelArtifactError("wheel digest is malformed")
    if wheel_record["sha256"] != digest:
        raise WheelArtifactError("wheel digest does not match its identity")
    wheel_version, wheel_commit, wheel_built_at = _read_wheel_metadata(wheel)
    if (wheel_version, wheel_commit, wheel_built_at) != (expected_version, expected_commit, built_at):
        raise WheelArtifactError("wheel embedded build identity does not match its manifest")
    return wheel, identity


def create_artifact(args: argparse.Namespace) -> None:
    """Build one automatic wheel artifact and its canonical identity.

    Args:
        args: Parsed create command arguments.
    """

    source_root = args.source_root.resolve(strict=True)
    version = project_version(source_root)
    if args.version != version:
        raise WheelArtifactError(f"requested version {args.version} does not match repository version {version}")
    _validate_timestamp(args.built_at)
    name = artifact_name(version, args.commit)
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise WheelArtifactError("wheel artifact output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="atlaso-wheel-") as temporary:
        built = build_application_wheel(
            Path(temporary),
            commit=args.commit,
            built_at=args.built_at,
            source_root=source_root,
        )
        wheel = output / built.name
        shutil.copy2(built, wheel)
    identity: dict[str, object] = {
        "schema_version": 1,
        "kind": "atlaso-python-wheel",
        "repository": args.repository,
        "version": version,
        "commit": args.commit,
        "built_at": args.built_at,
        "source_ci": {
            "workflow": "CI",
            "workflow_file": "ci.yml",
            "run_id": args.source_ci_run_id,
            "run_attempt": args.source_ci_run_attempt,
        },
        "publisher": {
            "workflow": "Publish Python wheel",
            "workflow_file": "wheel.yml",
            "run_id": args.publisher_run_id,
            "run_attempt": args.publisher_run_attempt,
            "trigger": args.publisher_trigger,
        },
        "artifact": {"name": name, "retention_days": RETENTION_DAYS},
        "wheel": {"filename": wheel.name, "sha256": sha256(wheel), "size": wheel.stat().st_size},
    }
    (output / IDENTITY_NAME).write_bytes(canonical_json(identity))
    verify_artifact(
        output,
        expected_repository=args.repository,
        expected_version=version,
        expected_commit=args.commit,
        expected_publisher_run_id=args.publisher_run_id,
    )
    print(json.dumps({"artifact_name": name, "wheel_sha256": sha256(wheel)}, sort_keys=True))


def select_artifact(args: argparse.Namespace) -> None:
    """Fail closed on collisions and select the required exact wheel handoff.

    Args:
        args: Parsed select command arguments.
    """

    candidates = [path for path in args.candidates.iterdir() if path.is_dir()]
    if not candidates:
        raise WheelArtifactError("no retained automatic wheel artifact is available for the release target")
    expected_publisher_run_id = getattr(args, "publisher_run_id", None)
    expected_publisher_run_attempt = getattr(args, "publisher_run_attempt", None)
    expected_publisher_trigger = getattr(args, "publisher_trigger", None)
    if (expected_publisher_run_attempt is not None or expected_publisher_trigger is not None) and (
        expected_publisher_run_id is None
    ):
        raise WheelArtifactError("publisher attempt or trigger requires an exact publisher run")
    verified: list[tuple[int, int, int, Path, dict[str, object]]] = []
    expected_bytes: bytes | None = None
    for candidate in candidates:
        candidate_identity = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)", candidate.name)
        if candidate_identity is None:
            raise WheelArtifactError("wheel candidate directory must name its publisher run and artifact")
        publisher_run_id = int(candidate_identity.group(1))
        artifact_id = int(candidate_identity.group(2))
        wheel, identity = verify_artifact(
            candidate,
            expected_repository=args.repository,
            expected_version=args.version,
            expected_commit=args.commit,
            expected_publisher_run_id=publisher_run_id,
        )
        publisher = identity["publisher"]
        assert isinstance(publisher, dict)
        publisher_run_attempt = _positive_integer(
            publisher["run_attempt"], field="publisher.run_attempt"
        )
        publisher_trigger = publisher.get("trigger")
        if expected_publisher_run_id is not None and publisher_run_id != expected_publisher_run_id:
            continue
        if (
            expected_publisher_run_attempt is not None
            and publisher_run_attempt != expected_publisher_run_attempt
        ):
            continue
        if expected_publisher_trigger is not None and publisher_trigger != expected_publisher_trigger:
            continue
        wheel_bytes = wheel.read_bytes()
        if expected_bytes is None:
            expected_bytes = wheel_bytes
        elif wheel_bytes != expected_bytes:
            raise WheelArtifactError("retained automatic wheel artifacts collide with different bytes")
        verified.append((publisher_run_id, publisher_run_attempt, artifact_id, wheel, identity))
    if not verified:
        raise WheelArtifactError("no retained automatic wheel artifact matches the required publisher identity")
    # Keep the first published identity stable so a byte-identical retry cannot
    # change signed bundle inputs after an immutable Release already exists.
    _run_id, _run_attempt, _artifact_id, wheel, identity = min(
        verified, key=lambda item: item[:3]
    )
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise WheelArtifactError("selected wheel output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(wheel, output / wheel.name)
    (output / IDENTITY_NAME).write_bytes(canonical_json(identity))
    print(json.dumps(identity, sort_keys=True))


def verify_command(args: argparse.Namespace) -> None:
    """Verify one extracted artifact from its expected immutable identity.

    Args:
        args: Parsed verify command arguments.
    """

    wheel, identity = verify_artifact(
        args.root,
        expected_repository=args.repository,
        expected_version=args.version,
        expected_commit=args.commit,
        expected_publisher_run_id=args.publisher_run_id,
    )
    print(
        json.dumps(
            {
                "identity": str(args.root / IDENTITY_NAME),
                "wheel": str(wheel),
                "wheel_sha256": identity["wheel"]["sha256"],
            },
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    """Create the command-line parser for wheel artifact operations."""

    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Build one exact automatic wheel artifact.")
    create.add_argument("--source-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--built-at", required=True)
    create.add_argument("--source-ci-run-id", type=int, required=True)
    create.add_argument("--source-ci-run-attempt", type=int, required=True)
    create.add_argument("--publisher-run-id", type=int, required=True)
    create.add_argument("--publisher-run-attempt", type=int, required=True)
    create.add_argument(
        "--publisher-trigger", choices=("automatic-main", "replay"), required=True
    )
    create.set_defaults(handler=create_artifact)
    extract = commands.add_parser("extract", help="Safely extract one downloaded artifact ZIP.")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    extract.set_defaults(handler=extract_artifact)
    verify = commands.add_parser("verify", help="Verify one extracted automatic wheel artifact.")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--commit", required=True)
    verify.add_argument("--publisher-run-id", type=int)
    verify.set_defaults(handler=verify_command)
    select = commands.add_parser("select", help="Verify retained candidates and select one exact handoff.")
    select.add_argument("--candidates", type=Path, required=True)
    select.add_argument("--output", type=Path, required=True)
    select.add_argument("--repository", required=True)
    select.add_argument("--version", required=True)
    select.add_argument("--commit", required=True)
    select.add_argument("--publisher-run-id", type=int)
    select.add_argument("--publisher-run-attempt", type=int)
    select.add_argument("--publisher-trigger", choices=("automatic-main", "replay"))
    select.set_defaults(handler=select_artifact)
    return root


def main(argv: list[str] | None = None) -> int:
    """Run the wheel artifact command-line interface.

    Args:
        argv: Optional command arguments.
    """

    args = parser().parse_args(argv)
    args.handler(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WheelArtifactError as exc:
        raise SystemExit(str(exc)) from exc
