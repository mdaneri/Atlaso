"""Bounded, authenticated KMIP recovery archives, separate from settings backup.

Only encrypted archives cross the privileged helper boundary. Plaintext snapshots
stay in memory; candidate files are created only in a private, newly owned root.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"ATLASO-KMIP-RECOVERY\x00\x01"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
AAD = MAGIC + b"scrypt:N=32768,r=8,p=1;AES-256-GCM"
FIELDS = ("provider_id", "key_id", "algorithm", "key_length", "name", "state",
          "created_at", "activated_at", "nonce", "ciphertext", "aad_json")


class RecoveryError(ValueError):
    """Safe error suitable for operator surfaces; never contains input values."""


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate JSON properties rather than choosing an ambiguous value.

    Args:
        pairs: Decoded JSON name/value pairs checked for duplicate names.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("Recovery data contains duplicate fields.")
        result[key] = value
    return result


def _derive(passphrase: str, salt: bytes) -> bytes:
    """Derive an archive key with fixed, bounded work and memory requirements.

    Args:
        passphrase: Request-bound recovery passphrase, never retained or logged.
        salt: Random archive salt used for key derivation.
    """
    if not isinstance(passphrase, str) or not 12 <= len(passphrase.encode("utf-8")) <= 1024:
        raise RecoveryError("Use a recovery passphrase containing 12 to 1,024 UTF-8 bytes.")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt(snapshot: dict[str, Any], passphrase: str) -> bytes:
    """Encrypt one validated in-memory snapshot; no password verifier is emitted.

    Args:
        snapshot: Authenticated logical snapshot whose key custody and trust are validated.
        passphrase: Request-bound recovery passphrase, never retained or logged.
    """
    plaintext = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode()
    if len(plaintext) > MAX_ARCHIVE_BYTES - 128:
        raise RecoveryError("Recovery store exceeds the supported archive limit.")
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_derive(passphrase, salt)).encrypt(nonce, plaintext, AAD)


def decrypt(archive: bytes, passphrase: str) -> dict[str, Any]:
    """Authenticate the entire archive before parsing any candidate state.

    Args:
        archive: Bounded encrypted recovery bundle supplied by the caller.
        passphrase: Request-bound recovery passphrase, never retained or logged.
    """
    if not isinstance(archive, bytes) or not len(MAGIC) + 44 <= len(archive) <= MAX_ARCHIVE_BYTES:
        raise RecoveryError("Recovery archive is incomplete or exceeds the supported limit.")
    if not archive.startswith(MAGIC):
        raise RecoveryError("Recovery archive format or version is unsupported.")
    offset = len(MAGIC)
    salt, nonce = archive[offset:offset + 16], archive[offset + 16:offset + 28]
    try:
        plaintext = AESGCM(_derive(passphrase, salt)).decrypt(nonce, archive[offset + 28:], AAD)
        snapshot = json.loads(plaintext, object_pairs_hook=_json_pairs)
        if not isinstance(snapshot, dict) or set(snapshot) != {"schema", "keys", "metadata", "kek", "master", "trust"}:
            raise RecoveryError("Recovery snapshot is incomplete or unsupported.")
        if type(snapshot["schema"]) is not int or snapshot["schema"] != 1:
            raise RecoveryError("Recovery snapshot schema is unsupported.")
        validate_trust(snapshot["trust"])
        if not isinstance(snapshot["keys"], list) or not isinstance(snapshot["metadata"], list):
            raise RecoveryError("Recovery store data is incomplete.")
        return snapshot
    except (InvalidTag, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("Recovery authentication failed; check the passphrase and archive.") from exc


def validate_trust(trust: Any) -> None:
    """Validate exact public provider identities and certificate relationships.

    Args:
        trust: Public provider, vCenter and certificate relationships.
    """
    from uuid import UUID


    if not isinstance(trust, dict) or set(trust) != {"providers", "vcenters", "certificates"}:
        raise RecoveryError("Recovery public trust is incomplete.")
    expected = {
        "providers": {"id", "name", "description", "enabled"},
        "vcenters": {"id", "provider_id", "name", "hostname", "description", "enabled"},
        "certificates": {"id", "trusted_vcenter_id", "certificate_pem", "fingerprint_sha256"},
    }
    ids: dict[str, set[str]] = {}
    fingerprints: set[str] = set()
    names: set[str] = set()
    vcenter_names: set[tuple[str, str]] = set()
    try:
        for kind, fields in expected.items():
            rows = trust[kind]
            if not isinstance(rows, list) or len(rows) > 10000:
                raise RecoveryError("Recovery public trust exceeds supported bounds.")
            ids[kind] = set()
            for row in rows:
                if not isinstance(row, dict) or set(row) != fields:
                    raise RecoveryError("Recovery public trust is incomplete.")
                identifier = row["id"]
                if not isinstance(identifier, str) or str(UUID(identifier)) != identifier or identifier in ids[kind]:
                    raise RecoveryError("Recovery identities are invalid or duplicated.")
                ids[kind].add(identifier)
                if kind != "certificates":
                    if type(row["enabled"]) is not bool or not isinstance(row["name"], str) or not 1 <= len(row["name"]) <= 120:
                        raise RecoveryError("Recovery trust metadata is invalid.")
                    if not isinstance(row["description"], str) or len(row["description"]) > 4096:
                        raise RecoveryError("Recovery trust description is invalid.")
                if kind == "providers":
                    if row["name"] in names:
                        raise RecoveryError("Recovery provider names are duplicated.")
                    names.add(row["name"])
                elif kind == "vcenters":
                    if row["provider_id"] not in ids["providers"] or not isinstance(row["hostname"], str) or len(row["hostname"]) > 253:
                        raise RecoveryError("Recovery vCenter relationship is invalid.")
                    scoped_name = (row["provider_id"], row["name"])
                    if scoped_name in vcenter_names:
                        raise RecoveryError("Recovery vCenter names are duplicated within a provider.")
                    vcenter_names.add(scoped_name)
                else:
                    if row["trusted_vcenter_id"] not in ids["vcenters"]:
                        raise RecoveryError("Recovery certificate relationship is invalid.")
                    from atlaso.app.services.vsphere_key_providers import (
                        parse_public_certificate,
                    )

                    cert = parse_public_certificate(row["certificate_pem"], require_current=False)
                    fingerprint = row["fingerprint_sha256"]
                    if cert["fingerprint_sha256"] != fingerprint or fingerprint in fingerprints:
                        raise RecoveryError("Recovery certificate fingerprint is invalid or duplicated.")
                    fingerprints.add(fingerprint)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RecoveryError("Recovery public trust validation failed.") from exc


def capture(store: Any, trust: dict[str, Any]) -> dict[str, Any]:
    """Capture authenticated wrapped rows and their exact KEK under one store lock.

    The caller must quiesce the daemon across this call; a Python lock alone does
    not serialize another process. No plaintext operational key is exported.

    Args:
        store: Opened wrapped-key store used for the consistent snapshot.
        trust: Public provider, vCenter and certificate relationships.
    """
    validate_trust(trust)
    with store._lock, store._connect() as db:
        db.execute("BEGIN")
        store._verify_store_commitment(db)
        rows = []
        provider_ids = {row["id"] for row in trust["providers"]}
        for row in db.execute("SELECT " + ",".join(FIELDS) + " FROM wrapped_keys ORDER BY provider_id,key_id"):
            if row["provider_id"] not in provider_ids:
                raise RecoveryError("Recovery trust omits a stored provider.")
            item = dict(row)
            for field in ("nonce", "ciphertext"):
                item[field] = base64.b64encode(item[field]).decode("ascii")
            rows.append(item)
        return {"schema": 1, "keys": rows,
                "metadata": [list(row) for row in db.execute("SELECT name,value FROM store_metadata ORDER BY name")],
                "kek": base64.b64encode(store.kek_path.read_bytes()).decode("ascii"),
                "master": base64.b64encode(bytes(store._master_key)).decode("ascii"), "trust": trust}


def build_candidate(snapshot: dict[str, Any], directory: Path, *, secrets_key: str) -> None:
    """Create and authenticate a complete candidate in a caller-owned private root.

    Args:
        snapshot: Authenticated decoded snapshot, still treated as untrusted input.
        directory: Newly created private directory, never an active store.
        secrets_key: Target appliance credential used only to seal master custody.
    """
    from atlaso.app.kmip.store import (
        STORE_SCHEMA_SQL,
        KeyStoreError,
        WrappedKeyStore,
        _master_key,
    )

    validate_trust(snapshot["trust"])
    if directory.is_symlink() or list(directory.iterdir()):
        raise RecoveryError("Recovery candidate must be a new private empty directory.")
    try:
        master = base64.b64decode(snapshot["master"], validate=True)
        kek = base64.b64decode(snapshot["kek"], validate=True)
        if len(master) != 32 or len(kek) > 8192:
            raise RecoveryError("Recovery KEK custody is invalid.")
        # Each file is created exclusively; all paths are beneath the private root.
        for name, value in (("kek.json", kek),):
            _exclusive_file(directory / name, value)
        nonce = os.urandom(12)
        sealed = nonce + AESGCM(_master_key(secrets_key)).encrypt(nonce, master, b"atlaso-kmip-recovery-master-v1")
        _exclusive_file(directory / "recovery-master.bin", sealed)
        _exclusive_file(directory / "public-trust.json", json.dumps(snapshot["trust"], sort_keys=True).encode())
        _exclusive_file(directory / "store.db", b"")
        with closing(sqlite3.connect(directory / "store.db")) as db:
            db.executescript(STORE_SCHEMA_SQL)
            with db:
                db.executemany("INSERT INTO store_metadata(name,value) VALUES (?,?)", snapshot["metadata"])
                provider_ids = {row["id"] for row in snapshot["trust"]["providers"]}
                for row in snapshot["keys"]:
                    if not isinstance(row, dict) or set(row) != set(FIELDS) or row["provider_id"] not in provider_ids:
                        raise RecoveryError("Recovery wrapped-key metadata is incomplete.")
                    values = [base64.b64decode(row[k], validate=True) if k in {"nonce", "ciphertext"} else row[k] for k in FIELDS]
                    db.execute("INSERT INTO wrapped_keys(" + ",".join(FIELDS) + ") VALUES (" + ",".join("?" for _ in FIELDS) + ")", values)
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        store = WrappedKeyStore(directory / "store.db", directory / "kek.json", secrets_key=secrets_key, read_only=True)
        try:
            store.lifecycle_counts(provider_ids)
        finally:
            store.close()
        # Pending-commit recovery must never silently change an imported envelope.
        if (directory / "kek.json").read_bytes() != kek:
            raise RecoveryError("Recovery KEK snapshot was not transactionally settled.")
        for path in directory.iterdir():
            with path.open("r+b") as stream:
                os.fsync(stream.fileno())
    except (ValueError, TypeError, KeyError, sqlite3.Error, KeyStoreError) as exc:
        raise RecoveryError("Recovery store validation failed; active state was preserved.") from exc


def _exclusive_file(path: Path, data: bytes) -> None:
    """Create sensitive candidate material without a permissive creation window.

    Args:
        path: Filesystem entry whose ownership and contents are checked.
        data: Bytes written privately and flushed before publication.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
