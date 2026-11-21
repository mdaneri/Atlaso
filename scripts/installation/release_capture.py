"""Package and admit pinned native installation captures for release CI."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
from pathlib import Path

from scripts.completed_task_files import read_bounded_regular
from scripts.installation import photon_snapshot
from scripts.installation.build import unpack_inputs
from scripts.installation.manifest import (
    SOURCE_ISO_SHA512,
    canonical_json,
    digest,
    inventory,
)
from scripts.installation.refresh import check_capture, read, source_input_sha256

MAX_CAPTURE = 16 * 1024**3
GIB = 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


def pack(state: Path, archive: Path, *, legacy: bool = False) -> None:
    """Export the original completed capture, without its private paths or other state.

    Args:
        state: Directory containing the original native capture plan and receipts.
        archive: Absent path for the capture archive to create.
        legacy: Export the original format for pre-snapshot workflows.
    """
    plan = read(state / "plan.json")
    check_capture(plan, state)
    receipt = state / "capture-inputs.json"
    if plan["capture_receipt"] is not None:
        raise ValueError("export from the original capture operation")
    value = read(receipt)
    metadata = {
        "schema": 1 if legacy else 2,
        "kind": value["kind"],
        "repository": value["repository"],
        "source_commit": value["source_commit"],
        "receipt_sha256": digest(receipt),
        "inventory": value["inventory"],
    }
    snapshot = b""
    if legacy:
        metadata["source_input_sha256"] = source_input_sha256(portable=True)
    else:
        report_path = state / "admit-report.json"
        result = read(state / "admit-result.json")
        capture = read(state / "capture-result.json")
        report = read(report_path)
        if (result.get("status") != "succeeded" or result.get("whole_job_quiescent") is not True
                or any(result.get(key) != capture.get(key) for key in ("plan_sha256", "task_id", "installer_commit"))
                or result.get("report_sha256") != digest(report_path)
                or report.get("report", {}).get("authenticated_transaction_validated") is not True):
            raise ValueError("Photon snapshot export requires successful original native admission")
        snapshot_sha256 = report["report"].get("snapshot_sha256")
        snapshot = read_bounded_regular(state / photon_snapshot.SNAPSHOT, photon_snapshot.MAX_SNAPSHOT_BYTES)
        if hashlib.sha256(snapshot).hexdigest() != snapshot_sha256:
            raise ValueError("Photon snapshot differs from the original native admission")
        photon_snapshot.captured_packages(photon_snapshot.read_snapshot(snapshot), value["inventory"]["rpms"])
        root = Path(__file__).resolve().parents[2]
        requirements = photon_snapshot.requirements_sha256(root)
        if requirements != report["report"].get("requirements_sha256"):
            raise ValueError("Photon snapshot requirements differ from the original native admission")
        metadata["requirements_sha256"] = requirements
        metadata["snapshot_sha256"] = snapshot_sha256
    metadata_bytes = canonical_json(metadata)
    if (
        sum(item["size"] for records in value["inventory"].values() for item in records)
        + len(metadata_bytes) + len(snapshot) > MAX_CAPTURE
    ):
        raise ValueError("capture exceeds the release input size limit")
    with (
        archive.open("xb") as target,
        tarfile.open(fileobj=target, mode="w:gz") as output,
    ):
        documents = {"capture.json": metadata_bytes}
        if snapshot:
            documents[photon_snapshot.SNAPSHOT] = snapshot
        for name, content in documents.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))
        for name in ("rpms", "powercli"):
            for item in value["inventory"][name]:
                path = Path(plan[name]) / item["path"]
                member = tarfile.TarInfo(f"{name}/{item['path']}")
                member.size = item["size"]
                with path.open("rb") as source:
                    output.addfile(member, source)
    check_capture(plan, state)
    print(digest(archive))


def verify_archive(archive: Path, expected: str) -> None:
    """Check the protected capture archive checksum before reading its contents.

    Args:
        archive: Path to the downloaded capture archive.
        expected: Pinned SHA-256 of the capture archive.
    """
    if (
        not SHA256.fullmatch(expected)
        or archive.is_symlink()
        or not archive.is_file()
        or not 0 < archive.stat().st_size <= MAX_CAPTURE
    ):
        raise ValueError("installation capture archive or protected pin is invalid")
    if digest(archive) != expected:
        raise ValueError("installation capture SHA-256 differs from the protected pin")


def _archive_document(source: tarfile.TarFile, name: str, limit: int) -> bytes:
    """Read one required bounded archive member in its canonical order.

    Args:
        source: Open capture archive at the next expected member.
        name: Exact required member name.
        limit: Maximum permitted member size in bytes.
    """
    member = source.next()
    if member is None or member.name != name or not member.isfile() or not 0 < member.size <= limit:
        raise ValueError(f"capture archive must contain bounded {name} in order")
    stream = source.extractfile(member)
    assert stream is not None
    return stream.read()


def _inspect_archive(
    archive: Path, target: Path, repo_name: str, *, require_snapshot: bool,
) -> tuple[dict, set[photon_snapshot.Package]]:
    """Validate provenance and select the approved Photon RPM inventory.

    Args:
        archive: Exact capture archive whose checksum was already verified.
        target: Exact target release source checkout.
        repo_name: Repository allowed to produce this capture.
        require_snapshot: Require the current snapshot archive format.
    """
    with tarfile.open(archive, "r:gz") as source:
        value = json.loads(_archive_document(source, "capture.json", 16 * 1024**2))
        if (
            not isinstance(value, dict)
            or type(value.get("schema")) is not int
            or value["schema"] not in (1, 2)
            or value.get("kind") != "installation-refresh-capture"
            or value.get("repository") != repo_name
            or not COMMIT.fullmatch(str(value.get("source_commit", "")))
            or not SHA256.fullmatch(str(value.get("receipt_sha256", "")))
            or not isinstance(value.get("inventory"), dict)
            or set(value["inventory"]) != {"rpms", "powercli"}
            or not all(isinstance(items, list) and items for items in value["inventory"].values())
        ):
            raise ValueError("installation capture provenance differs")
        if value["schema"] == 1:
            if require_snapshot:
                raise ValueError("release staging requires an approved Photon snapshot")
            if value.get("source_input_sha256") != source_input_sha256(target, portable=True):
                raise ValueError("installation capture source compatibility differs")
            return value, set()
        if value.get("requirements_sha256") != photon_snapshot.requirements_sha256(target):
            raise ValueError("approved Photon snapshot is incompatible with the release requirements")
        snapshot = _archive_document(source, photon_snapshot.SNAPSHOT, photon_snapshot.MAX_SNAPSHOT_BYTES)
        if hashlib.sha256(snapshot).hexdigest() != value.get("snapshot_sha256"):
            raise ValueError("Photon snapshot differs from the approved archive metadata")
        packages = photon_snapshot.captured_packages(photon_snapshot.read_snapshot(snapshot), value["inventory"]["rpms"])
        return value, packages


def admit(archive: Path, output: Path, target: Path, repo_name: str, *, require_snapshot: bool = False) -> str:
    """Check the capture origin and source compatibility before bounded extraction.

    Args:
        archive: Path to the capture archive whose SHA-256 has been checked.
        output: Absent destination for extracted capture files.
        target: Exact Atlaso source checkout that will consume the capture.
        repo_name: Repository that produced the admitted capture.
        require_snapshot: Require the snapshot format for production staging.
    """
    value, _ = _inspect_archive(archive, target, repo_name, require_snapshot=require_snapshot)
    # A capture can come from a reviewed PR commit. The protected archive pin
    # authenticates the original capture receipt, and target compatibility is
    # determined independently from the exact main release tree.
    unpack_inputs(archive, output)
    expected = {"capture.json", "rpms", "powercli"}
    if value["schema"] == 2:
        expected.add(photon_snapshot.SNAPSHOT)
    if {item.name for item in output.iterdir()} != expected:
        raise ValueError("capture contains unexpected top-level inputs")
    observed = {name: inventory(output / name) for name in ("rpms", "powercli")}
    if not all(observed.values()) or value.get("inventory") != observed:
        raise ValueError("capture inventory differs from the admitted native receipt")
    return value.get("snapshot_sha256", "")


def check_capacity(inputs: Path, source_iso: Path, *, prepared: bool) -> None:
    """Admit the pinned boot media and the disk needed before exposing signing material.

    Args:
        inputs: Capture or prepared payload directory to size.
        source_iso: Path to the downloaded Photon boot media.
        prepared: Whether inputs already include the prepared installer payload.
    """
    with source_iso.open("rb") as stream:
        if hashlib.file_digest(stream, "sha512").hexdigest() != SOURCE_ISO_SHA512:
            raise ValueError("Photon source ISO differs from its pinned SHA-512")
    payload = sum(item["size"] for item in inventory(inputs))
    # Before preparation, allow room for the extracted software, tracked source,
    # and the prepared copy of the captured tree in addition to ISO assembly.
    required = 2 * (source_iso.stat().st_size + payload) + 2 * GIB
    if not prepared:
        required += payload + GIB
    if (
        not 0 < payload <= MAX_CAPTURE
        or shutil.disk_usage(source_iso.parent).free < required
    ):
        raise ValueError(
            f"installation build needs at least {required // (1024**2) + 1} MiB available disk"
        )


def main() -> None:
    """Export a native capture or admit it for a protected build."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    export = commands.add_parser("pack")
    export.add_argument("--capture-state", type=Path, required=True)
    export.add_argument("--archive", type=Path, required=True)
    export.add_argument("--legacy", action="store_true")
    receive = commands.add_parser("admit")
    audit = commands.add_parser("audit")
    for command in (receive, audit):
        command.add_argument("--archive", type=Path, required=True)
        command.add_argument("--sha256", required=True)
        command.add_argument("--target", type=Path, required=True)
    receive.add_argument("--output", type=Path, required=True)
    receive.add_argument("--require-snapshot", action="store_true")
    capacity = commands.add_parser("check-capacity")
    source = capacity.add_mutually_exclusive_group(required=True)
    source.add_argument("--capture", type=Path)
    source.add_argument("--payload", type=Path)
    capacity.add_argument("--source-iso", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "pack":
        pack(args.capture_state, args.archive, legacy=args.legacy)
    elif args.operation == "check-capacity":
        check_capacity(
            args.payload or args.capture,
            args.source_iso,
            prepared=args.payload is not None,
        )
    else:
        verify_archive(args.archive, args.sha256)
        repository = os.environ["GITHUB_REPOSITORY"]
        if args.operation == "audit":
            _, packages = _inspect_archive(args.archive, args.target, repository, require_snapshot=True)
            print(json.dumps(photon_snapshot.audit(packages), sort_keys=True))
        else:
            snapshot_sha256 = admit(args.archive, args.output, args.target, repository, require_snapshot=args.require_snapshot)
            if snapshot_sha256:
                print(snapshot_sha256)


if __name__ == "__main__":
    main()
