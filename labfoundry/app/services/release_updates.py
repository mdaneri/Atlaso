from __future__ import annotations

import base64
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


CHANNEL_MANIFEST_SCHEMA = 2
RELEASE_MANIFEST_SCHEMA = 2
SIGNATURE_SCHEMA = 1
UPDATER_PROTOCOL = 2
SUPPORTED_PYTHON_ABIS = ("cp314",)
UPDATE_TRUST_DIR = Path("/etc/labfoundry/update-trust.d")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ReleaseManifestError(ValueError):
    """Raised when a signed release or channel document is invalid."""


def current_python_abi() -> str:
    return f"cp{sys.version_info.major}{sys.version_info.minor}"


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise ReleaseManifestError(f"Manifest field {key} is required.")
    return value


def _https_url(payload: dict[str, Any], key: str) -> str:
    value = _required_text(payload, key)
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ReleaseManifestError(f"Manifest field {key} must be an HTTPS URL without embedded credentials.")
    return value


def _sha256(payload: dict[str, Any], key: str) -> str:
    value = _required_text(payload, key).lower()
    if SHA256_RE.fullmatch(value) is None:
        raise ReleaseManifestError(f"Manifest field {key} must be a SHA256 digest.")
    return value


def _timestamp(payload: dict[str, Any], key: str) -> str:
    value = _required_text(payload, key)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseManifestError(f"Manifest field {key} must be an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ReleaseManifestError(f"Manifest field {key} must include a timezone.")
    return value


def validate_channel_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != CHANNEL_MANIFEST_SCHEMA or payload.get("kind") != "labfoundry-channel":
        raise ReleaseManifestError("Unsupported LabFoundry channel manifest.")
    channel = _required_text(payload, "channel")
    if channel not in {"stable", "preview", "development"}:
        raise ReleaseManifestError("Channel must be stable, preview, or development.")
    commit = _required_text(payload, "git_commit").lower()
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReleaseManifestError("Channel git_commit must be a full hexadecimal commit.")
    key_id = _required_text(payload, "signing_key_id")
    if KEY_ID_RE.fullmatch(key_id) is None:
        raise ReleaseManifestError("Channel signing_key_id is invalid.")
    _https_url(payload, "release_manifest_url")
    if VERSION_RE.fullmatch(_required_text(payload, "version")) is None:
        raise ReleaseManifestError("Channel version must use X.Y.Z semantic versioning.")
    _timestamp(payload, "issued_at")
    return payload


def validate_release_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != RELEASE_MANIFEST_SCHEMA or payload.get("kind") != "labfoundry-release":
        raise ReleaseManifestError("Unsupported LabFoundry release manifest.")
    updater_protocol = payload.get("updater_protocol")
    if (
        not isinstance(updater_protocol, int)
        or isinstance(updater_protocol, bool)
        or updater_protocol < 1
        or updater_protocol > UPDATER_PROTOCOL
    ):
        raise ReleaseManifestError("Release updater_protocol is missing or unsupported.")
    schema_version = payload.get("database_schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version < 1:
        raise ReleaseManifestError("Release database_schema_version must be a positive integer.")
    commit = _required_text(payload, "git_commit").lower()
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReleaseManifestError("Release git_commit must be a full hexadecimal commit.")
    key_id = _required_text(payload, "signing_key_id")
    if KEY_ID_RE.fullmatch(key_id) is None:
        raise ReleaseManifestError("Release signing_key_id is invalid.")
    python_abis = payload.get("supported_python_abis")
    if (
        not isinstance(python_abis, list)
        or not python_abis
        or any(str(value) not in SUPPORTED_PYTHON_ABIS for value in python_abis)
        or len(set(python_abis)) != len(python_abis)
    ):
        raise ReleaseManifestError("Release supported_python_abis is invalid.")
    bundle = payload.get("bundle")
    if not isinstance(bundle, dict):
        raise ReleaseManifestError("Release bundle must be an object.")
    _https_url(bundle, "url")
    _sha256(bundle, "sha256")
    if not isinstance(bundle.get("size"), int) or int(bundle["size"]) <= 0:
        raise ReleaseManifestError("Release bundle size must be a positive integer.")
    content_hashes = payload.get("content_hashes")
    if not isinstance(content_hashes, dict) or not content_hashes:
        raise ReleaseManifestError("Release content_hashes must be a non-empty object.")
    for path, digest in content_hashes.items():
        if (
            not isinstance(path, str)
            or not path
            or path.startswith(("/", "\\"))
            or "\\" in path
            or ".." in Path(path).parts
        ):
            raise ReleaseManifestError("Release content_hashes contains an unsafe path.")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest.lower()) is None:
            raise ReleaseManifestError(f"Release content hash for {path} is invalid.")
    if VERSION_RE.fullmatch(_required_text(payload, "version")) is None:
        raise ReleaseManifestError("Release version must use X.Y.Z semantic versioning.")
    _timestamp(payload, "built_at")
    return payload


def signature_document(raw_signature: bytes) -> dict[str, str]:
    try:
        payload = json.loads(raw_signature.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError("Detached signature is not valid JSON.") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SIGNATURE_SCHEMA:
        raise ReleaseManifestError("Detached signature schema is unsupported.")
    key_id = _required_text(payload, "key_id")
    if KEY_ID_RE.fullmatch(key_id) is None:
        raise ReleaseManifestError("Detached signature key_id is invalid.")
    signature = _required_text(payload, "signature")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        raise ReleaseManifestError("Detached signature is not valid base64.") from exc
    if len(decoded) != 64:
        raise ReleaseManifestError("Detached Ed25519 signature must be 64 bytes.")
    return {"key_id": key_id, "signature": signature}


def verify_signed_json(
    raw_document: bytes,
    raw_signature: bytes,
    *,
    trust_dir: Path = UPDATE_TRUST_DIR,
    document_kind: str,
) -> dict[str, Any]:
    signature = signature_document(raw_signature)
    public_key_path = trust_dir / f"{signature['key_id']}.pem"
    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except OSError as exc:
        raise ReleaseManifestError(f"Signing key {signature['key_id']} is not trusted.") from exc
    except ValueError as exc:
        raise ReleaseManifestError(f"Signing key {signature['key_id']} is malformed.") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReleaseManifestError(f"Signing key {signature['key_id']} is not Ed25519.")
    try:
        public_key.verify(base64.b64decode(signature["signature"]), raw_document)
    except InvalidSignature as exc:
        raise ReleaseManifestError("Detached manifest signature is invalid.") from exc
    try:
        payload = json.loads(raw_document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError("Signed manifest is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ReleaseManifestError("Signed manifest must be a JSON object.")
    if payload.get("signing_key_id") != signature["key_id"]:
        raise ReleaseManifestError("Manifest and detached signature key IDs do not match.")
    if document_kind == "channel":
        return validate_channel_manifest(payload)
    if document_kind == "release":
        return validate_release_manifest(payload)
    raise ValueError(f"Unsupported document kind {document_kind}.")
