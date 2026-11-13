"""Package an admitted native capture and retrieve its pinned bytes in release CI."""

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
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

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


class NoRedirect(HTTPRedirectHandler):
    """Keep the read-only credential scoped to the configured storage endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise URLError("capture storage redirects are disabled")


def pack(state: Path, archive: Path) -> None:
    """Export the original completed capture, without its private paths or other state."""
    plan = read(state / "plan.json")
    check_capture(plan, state)
    receipt = state / "capture-inputs.json"
    if plan["capture_receipt"] is not None:
        raise ValueError("export from the original capture operation")
    value = read(receipt)
    metadata = canonical_json(
        {
            "schema": 1,
            "kind": value["kind"],
            "repository": value["repository"],
            "source_commit": value["source_commit"],
            "source_input_sha256": source_input_sha256(portable=True),
            "receipt_sha256": digest(receipt),
            "inventory": value["inventory"],
        }
    )
    if (
        sum(item["size"] for records in value["inventory"].values() for item in records)
        > MAX_CAPTURE
    ):
        raise ValueError("capture exceeds the release input size limit")
    with (
        archive.open("xb") as target,
        tarfile.open(fileobj=target, mode="w:gz") as output,
    ):
        member = tarfile.TarInfo("capture.json")
        member.size = len(metadata)
        output.addfile(member, io.BytesIO(metadata))
        for name in ("rpms", "powercli"):
            for item in value["inventory"][name]:
                path = Path(plan[name]) / item["path"]
                member = tarfile.TarInfo(f"{name}/{item['path']}")
                member.size = item["size"]
                with path.open("rb") as source:
                    output.addfile(member, source)
    check_capture(plan, state)
    print(digest(archive))


def fetch(archive: Path, expected: str, url: str, token: str) -> None:
    """Download an explicitly pinned capture without logging the URL or credential."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        raise ValueError("protected installation capture URL is invalid") from None
    if (
        not SHA256.fullmatch(expected)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not token
    ):
        raise ValueError(
            "protected installation capture configuration is missing or invalid"
        )
    limit = min(MAX_CAPTURE, shutil.disk_usage(archive.parent).free - 2 * GIB)
    try:
        request = Request(url, headers={"Authorization": f"Bearer {token}"})
        with (
            build_opener(NoRedirect()).open(request, timeout=60) as response,
            archive.open("xb") as output,
        ):
            total = 0
            while block := response.read(1024**2):
                total += len(block)
                if total > limit:
                    raise ValueError(
                        "capture exceeds the archive size or available capacity"
                    )
                output.write(block)
    except OSError, ValueError:
        raise ValueError("could not download the pinned installation capture") from None
    if digest(archive) != expected:
        raise ValueError("installation capture SHA-256 differs from the protected pin")


def admit(archive: Path, output: Path, target: Path, repo_name: str) -> None:
    """Check the capture origin and source compatibility before bounded extraction."""
    with tarfile.open(archive, "r:gz") as source:
        member = source.next()
        if (
            member is None
            or member.name != "capture.json"
            or not member.isfile()
            or not 0 < member.size <= 16 * 1024**2
        ):
            raise ValueError("capture archive must begin with bounded provenance")
        stream = source.extractfile(member)
        assert stream is not None
        value = json.load(stream)
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or value.get("kind") != "installation-refresh-capture"
        or value.get("repository") != repo_name
        or not COMMIT.fullmatch(str(value.get("source_commit", "")))
        or not SHA256.fullmatch(str(value.get("receipt_sha256", "")))
        or value.get("source_input_sha256") != source_input_sha256(target, portable=True)
    ):
        raise ValueError(
            "installation capture provenance or source compatibility differs"
        )
    # A capture can come from a reviewed PR commit. The protected archive pin
    # authenticates the original capture receipt, and target compatibility is
    # determined independently from the exact main release tree.
    unpack_inputs(archive, output)
    if {item.name for item in output.iterdir()} != {"capture.json", "rpms", "powercli"}:
        raise ValueError("capture contains unexpected top-level inputs")
    observed = {name: inventory(output / name) for name in ("rpms", "powercli")}
    if not all(observed.values()) or value.get("inventory") != observed:
        raise ValueError("capture inventory differs from the admitted native receipt")


def check_capacity(inputs: Path, source_iso: Path, *, prepared: bool) -> None:
    """Admit the pinned boot media and the disk needed before exposing signing material."""
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
    """Export a native capture or download and admit it for a protected build."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    export = commands.add_parser("pack")
    export.add_argument("--capture-state", type=Path, required=True)
    export.add_argument("--archive", type=Path, required=True)
    receive = commands.add_parser("fetch")
    receive.add_argument("--archive", type=Path, required=True)
    receive.add_argument("--output", type=Path, required=True)
    receive.add_argument("--target", type=Path, required=True)
    capacity = commands.add_parser("check-capacity")
    source = capacity.add_mutually_exclusive_group(required=True)
    source.add_argument("--capture", type=Path)
    source.add_argument("--payload", type=Path)
    capacity.add_argument("--source-iso", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "pack":
        pack(args.capture_state, args.archive)
    elif args.operation == "check-capacity":
        check_capacity(
            args.payload or args.capture,
            args.source_iso,
            prepared=args.payload is not None,
        )
    else:
        fetch(
            args.archive,
            os.getenv("INSTALLATION_CAPTURE_SHA256", ""),
            os.getenv("INSTALLATION_CAPTURE_URL", ""),
            os.getenv("INSTALLATION_CAPTURE_TOKEN", ""),
        )
        admit(args.archive, args.output, args.target, os.environ["GITHUB_REPOSITORY"])


if __name__ == "__main__":
    main()
