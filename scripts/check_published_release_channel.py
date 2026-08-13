#!/usr/bin/env python3
"""Verify one published Atlaso release channel through the appliance trust contract."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse
from urllib.request import urlopen

from atlaso.app.services.release_updates import signature_document, verify_signed_json

MAX_DOCUMENT_BYTES = 1024 * 1024


def fetch_document(url: str, *, timeout_seconds: float) -> bytes:
    """Download one bounded HTTPS release document.

    Args:
        url: Public HTTPS document URL.
        timeout_seconds: Per-request network timeout.

    Returns:
        The downloaded document bytes.

    Raises:
        ValueError: If the URL is unsafe or the document exceeds the size limit.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("Published release documents require HTTPS URLs without embedded credentials.")
    with urlopen(url, timeout=timeout_seconds) as response:
        document = response.read(MAX_DOCUMENT_BYTES + 1)
    if len(document) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"Published release document exceeds {MAX_DOCUMENT_BYTES} bytes: {url}")
    return document


def verify_channel(
    channel_url: str,
    *,
    expected_channel: str,
    expected_python_abi: str,
    trusted_key: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Verify a published channel, immutable release, and ABI compatibility.

    Args:
        channel_url: Published channel-manifest URL.
        expected_channel: Channel name required in the signed pointer.
        expected_python_abi: Appliance Python ABI required by the release.
        trusted_key: Exact checked-in public key selected for verification.
        timeout_seconds: Per-request network timeout.

    Returns:
        The verified channel and release metadata.

    Raises:
        ValueError: If publication identity or compatibility does not match.
    """
    expected_suffix = f"/channels/{expected_channel}/manifest.json"
    if not urlparse(channel_url).path.endswith(expected_suffix):
        raise ValueError(f"Published {expected_channel} URL must end with {expected_suffix}.")
    if not trusted_key.is_file():
        raise ValueError(f"Trusted release key is missing: {trusted_key}")

    raw_channel = fetch_document(channel_url, timeout_seconds=timeout_seconds)
    raw_channel_signature = fetch_document(f"{channel_url}.sig", timeout_seconds=timeout_seconds)
    if signature_document(raw_channel_signature)["key_id"] != trusted_key.stem:
        raise ValueError("Published channel does not use the selected named trust key.")
    channel = verify_signed_json(
        raw_channel,
        raw_channel_signature,
        trust_dir=trusted_key.parent,
        document_kind="channel",
    )
    if channel["channel"] != expected_channel:
        raise ValueError(
            f"Published channel is {channel['channel']}, expected {expected_channel}."
        )

    release_url = str(channel["release_manifest_url"])
    raw_release = fetch_document(release_url, timeout_seconds=timeout_seconds)
    raw_release_signature = fetch_document(
        f"{release_url}.sig",
        timeout_seconds=timeout_seconds,
    )
    if signature_document(raw_release_signature)["key_id"] != trusted_key.stem:
        raise ValueError("Published release does not use the selected named trust key.")
    release = verify_signed_json(
        raw_release,
        raw_release_signature,
        trust_dir=trusted_key.parent,
        document_kind="release",
    )
    if release["version"] != channel["version"] or release["git_commit"] != channel["git_commit"]:
        raise ValueError("Published channel does not match its immutable release manifest.")
    if expected_python_abi not in release["supported_python_abis"]:
        raise ValueError(
            f"Published release {release['version']} does not support {expected_python_abi}."
        )
    return {"channel": channel, "release": release}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the published-channel verification command.

    Args:
        argv: Optional command-line arguments.

    Returns:
        Zero after successful verification.

    Raises:
        SystemExit: If the published channel cannot be verified after all attempts.
    """
    parser = argparse.ArgumentParser(
        description="Verify a published Atlaso channel through signature and compatibility validation."
    )
    parser.add_argument("--channel-url", required=True)
    parser.add_argument(
        "--expected-channel",
        required=True,
        choices=("stable", "preview", "development"),
    )
    parser.add_argument("--expected-python-abi", default="cp314")
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--retry-delay-seconds", type=float, default=10.0)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.attempts < 1:
        parser.error("--attempts must be at least 1")
    if args.retry_delay_seconds < 0 or args.timeout_seconds <= 0:
        parser.error("retry delay cannot be negative and timeout must be positive")

    last_error: Exception | None = None
    for attempt in range(1, args.attempts + 1):
        try:
            result = verify_channel(
                args.channel_url,
                expected_channel=args.expected_channel,
                expected_python_abi=args.expected_python_abi,
                trusted_key=args.trusted_key,
                timeout_seconds=args.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - retries cover Pages propagation and validation failures.
            last_error = exc
            if attempt < args.attempts:
                time.sleep(args.retry_delay_seconds)
                continue
            break
        channel = result["channel"]
        print(
            "verified published "
            f"{channel['channel']} channel v{channel['version']} at {channel['git_commit']}"
        )
        return 0
    raise SystemExit(
        f"Published {args.expected_channel} channel failed verification after "
        f"{args.attempts} attempt(s): {last_error}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
