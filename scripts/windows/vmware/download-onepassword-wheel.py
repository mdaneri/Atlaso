#!/usr/bin/env python3
"""Download the approved temporary 1Password CPython 3.14 wheel safely."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

EXPECTED_REPOSITORY = "mdaneri/onepassword-sdk-python"
EXPECTED_TAG = "atlaso-wheel-v0.4.1-cp314.1"
EXPECTED_ASSET = "onepassword_sdk-0.4.1-cp314-cp314-win_amd64.whl"
EXPECTED_WHEEL_TAG = "cp314-cp314-win_amd64"
EXPECTED_UPSTREAM_TAG = "v0.4.1"
EXPECTED_UPSTREAM_COMMIT = "50b2adadef5d1cd6b71c387ea36599af62318100"
EXPECTED_SDIST_SHA256 = "4b9224208aa6e35e13bad8534e6521d3abf5ba166ea4efd370fcdc918c4a4d26"
ALLOWED_REDIRECT_HOSTS = frozenset(
    {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ApprovedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects away from GitHub's release delivery hosts."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        _validate_delivery_url(newurl, redirect=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_delivery_url(url: str, *, redirect: bool) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        raise ValueError("the 1Password wheel URL must use credential-free HTTPS")
    allowed = ALLOWED_REDIRECT_HOSTS if redirect else frozenset({"github.com"})
    if parsed.hostname not in allowed:
        raise ValueError("the 1Password wheel URL uses an unapproved release host")


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and strictly validate the checked-in artifact identity."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected_keys = {
        "schema_version",
        "repository",
        "release_tag",
        "asset_name",
        "asset_url",
        "asset_sha256",
        "asset_size",
        "attestation_repository",
        "attestation_workflow",
        "release_commit",
        "upstream_tag",
        "upstream_commit",
        "sdist_sha256",
        "wheel_tag",
        "license",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("the 1Password wheel manifest schema is invalid")
    expected_values = {
        "schema_version": 1,
        "repository": EXPECTED_REPOSITORY,
        "release_tag": EXPECTED_TAG,
        "asset_name": EXPECTED_ASSET,
        "attestation_repository": EXPECTED_REPOSITORY,
        "attestation_workflow": ".github/workflows/atlaso-cp314-wheel.yml",
        "upstream_tag": EXPECTED_UPSTREAM_TAG,
        "upstream_commit": EXPECTED_UPSTREAM_COMMIT,
        "sdist_sha256": EXPECTED_SDIST_SHA256,
        "wheel_tag": EXPECTED_WHEEL_TAG,
        "license": "MIT",
    }
    for key, expected in expected_values.items():
        if payload.get(key) != expected:
            raise ValueError(f"the 1Password wheel manifest has an invalid {key}")
    expected_url = (
        f"https://github.com/{EXPECTED_REPOSITORY}/releases/download/"
        f"{EXPECTED_TAG}/{EXPECTED_ASSET}"
    )
    if payload["asset_url"] != expected_url:
        raise ValueError("the 1Password wheel manifest has an invalid asset_url")
    _validate_delivery_url(payload["asset_url"], redirect=False)
    for key in ("asset_sha256", "release_commit"):
        value = payload.get(key)
        expected_pattern = SHA256_RE if key == "asset_sha256" else re.compile(r"^[0-9a-f]{40}$")
        if not isinstance(value, str) or expected_pattern.fullmatch(value) is None:
            raise ValueError(f"the 1Password wheel manifest has an invalid {key}")
    if not isinstance(payload["asset_size"], int) or payload["asset_size"] <= 0:
        raise ValueError("the 1Password wheel manifest has an invalid asset_size")
    return payload


def download(manifest: dict[str, Any], destination: Path, *, timeout: int, max_size: int) -> Path:
    """Download, bound, and hash-verify the exact manifest asset."""
    if timeout < 1 or max_size < 1 or manifest["asset_size"] > max_size:
        raise ValueError("the 1Password wheel download bounds are invalid")
    destination.mkdir(parents=True, exist_ok=True)
    final_path = destination / manifest["asset_name"]
    temporary_path: Path | None = None
    opener = urllib.request.build_opener(ApprovedRedirectHandler())
    request = urllib.request.Request(
        manifest["asset_url"],
        headers={"Accept": "application/octet-stream", "User-Agent": "Atlaso-wheel-fetch/1"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            _validate_delivery_url(response.geturl(), redirect=True)
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > min(max_size, manifest["asset_size"]):
                raise ValueError("the 1Password wheel exceeds the approved size")
            digest = hashlib.sha256()
            size = 0
            handle, temporary_name = tempfile.mkstemp(prefix=".onepassword-wheel-", dir=destination)
            temporary_path = Path(temporary_name)
            with os.fdopen(handle, "wb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > min(max_size, manifest["asset_size"]):
                        raise ValueError("the 1Password wheel exceeds the approved size")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        if size != manifest["asset_size"] or digest.hexdigest() != manifest["asset_sha256"]:
            raise ValueError("the 1Password wheel does not match the approved digest and size")
        os.replace(temporary_path, final_path)
        temporary_path = None
        return final_path
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--max-size-bytes", type=int, default=10 * 1024 * 1024)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        path = download(
            manifest,
            args.destination,
            timeout=args.timeout_seconds,
            max_size=args.max_size_bytes,
        )
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        raise SystemExit(f"approved 1Password wheel download failed: {exc}") from None
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
