"""Envelope-encrypted operational key storage for the Atlaso KMIP service."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


STORE_SCHEMA_VERSION = 2
KEK_ENVELOPE_FORMAT = "atlaso-kmip-kek-v1"
KEK_AAD = b"atlaso-kmip-kek-v1"
KEY_AAD_FIELDS = (
    "schema_version",
    "provider_id",
    "key_id",
    "algorithm",
    "length",
    "name",
    "state",
    "created_at",
    "activated_at",
)


class KeyStoreError(RuntimeError):
    """Base class for safe operational-store errors."""


class KeyNotFoundError(KeyStoreError):
    """Raised when a key is absent from the authenticated provider namespace."""


class KeyStateError(KeyStoreError):
    """Raised when a key lifecycle transition is invalid."""


@dataclass(frozen=True)
class StoredKey:
    provider_id: str
    key_id: str
    algorithm: str
    length: int
    name: str | None
    state: str
    created_at: str
    activated_at: str | None


def _validated_uuid(value: str, *, label: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a UUID.") from exc


def _canonical_aad(metadata: StoredKey) -> bytes:
    document = {
        "schema_version": STORE_SCHEMA_VERSION,
        "provider_id": metadata.provider_id,
        "key_id": metadata.key_id,
        "algorithm": metadata.algorithm,
        "length": metadata.length,
        "name": metadata.name,
        "state": metadata.state,
        "created_at": metadata.created_at,
        "activated_at": metadata.activated_at,
    }
    assert tuple(document) == KEY_AAD_FIELDS
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _master_key(secrets_key: str) -> bytes:
    if not secrets_key:
        raise KeyStoreError("ATLASO_SECRETS_KEY is required for the KMIP operational store.")
    return sha256(b"atlaso-kmip-master-v1\0" + secrets_key.encode("utf-8")).digest()


def _decode_envelope_value(envelope: dict[str, object], field: str) -> bytes:
    value = envelope.get(field)
    if not isinstance(value, str):
        raise KeyStoreError("KMIP KEK envelope is invalid.")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise KeyStoreError("KMIP KEK envelope is invalid.") from exc


def _load_or_create_kek(path: Path, *, secrets_key: str) -> bytes:
    master = AESGCM(_master_key(secrets_key))
    if path.exists():
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict) or envelope.get("format") != KEK_ENVELOPE_FORMAT:
                raise KeyStoreError("KMIP KEK envelope format is unsupported.")
            nonce = _decode_envelope_value(envelope, "nonce")
            ciphertext = _decode_envelope_value(envelope, "ciphertext")
            kek = master.decrypt(nonce, ciphertext, KEK_AAD)
            if len(kek) != 32:
                raise KeyStoreError("KMIP KEK envelope is invalid.")
            os.chmod(path, 0o600)
            return kek
        except (InvalidTag, json.JSONDecodeError, OSError) as exc:
            raise KeyStoreError(
                "KMIP KEK could not be opened with the configured appliance secrets key."
            ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    kek = os.urandom(32)
    nonce = os.urandom(12)
    envelope = {
        "format": KEK_ENVELOPE_FORMAT,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(master.encrypt(nonce, kek, KEK_AAD)).decode("ascii"),
    }
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(envelope, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return kek


class WrappedKeyStore:
    """SQLite metadata store whose only key material is AES-GCM wrapped."""

    def __init__(self, database_path: Path, kek_path: Path, *, secrets_key: str) -> None:
        self.database_path = database_path
        self.kek_path = kek_path
        self._lock = threading.RLock()
        if self.database_path.exists() != self.kek_path.exists():
            raise KeyStoreError(
                "KMIP operational store and KEK envelope must exist together."
            )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.database_path.parent, 0o700)
        self._kek = bytearray(_load_or_create_kek(self.kek_path, secrets_key=secrets_key))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                CREATE TABLE IF NOT EXISTS store_metadata (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wrapped_keys (
                    provider_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL CHECK (algorithm = 'AES'),
                    key_length INTEGER NOT NULL CHECK (key_length = 256),
                    name TEXT CHECK (name IS NULL OR length(name) BETWEEN 1 AND 256),
                    state TEXT NOT NULL CHECK (state IN ('Pre-Active', 'Active')),
                    created_at TEXT NOT NULL,
                    activated_at TEXT,
                    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                    ciphertext BLOB NOT NULL,
                    aad_json TEXT NOT NULL,
                    PRIMARY KEY (provider_id, key_id)
                );
                """
            )
            row = connection.execute(
                "SELECT value FROM store_metadata WHERE name = 'schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO store_metadata(name, value) VALUES ('schema_version', ?)",
                    (str(STORE_SCHEMA_VERSION),),
                )
            elif row["value"] != str(STORE_SCHEMA_VERSION):
                raise KeyStoreError("KMIP operational store schema version is unsupported.")
        os.chmod(self.database_path, 0o600)

    def create_key(self, provider_id: str, *, name: str | None = None) -> StoredKey:
        normalized_provider = _validated_uuid(provider_id, label="provider_id")
        if name is not None and (
            not isinstance(name, str) or not 1 <= len(name) <= 256
        ):
            raise ValueError("name must contain 1 to 256 characters.")
        key_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        metadata = StoredKey(
            provider_id=normalized_provider,
            key_id=key_id,
            algorithm="AES",
            length=256,
            name=name,
            state="Pre-Active",
            created_at=created_at,
            activated_at=None,
        )
        aad = _canonical_aad(metadata)
        plaintext = bytearray(os.urandom(32))
        nonce = os.urandom(12)
        try:
            ciphertext = AESGCM(bytes(self._kek)).encrypt(nonce, bytes(plaintext), aad)
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO wrapped_keys(
                        provider_id, key_id, algorithm, key_length, name, state,
                        created_at, activated_at, nonce, ciphertext, aad_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.provider_id,
                        metadata.key_id,
                        metadata.algorithm,
                        metadata.length,
                        metadata.name,
                        metadata.state,
                        metadata.created_at,
                        metadata.activated_at,
                        nonce,
                        ciphertext,
                        aad.decode("utf-8"),
                    ),
                )
            return metadata
        finally:
            plaintext[:] = b"\0" * len(plaintext)

    def _row(self, provider_id: str, key_id: str) -> sqlite3.Row:
        normalized_provider = _validated_uuid(provider_id, label="provider_id")
        normalized_key = _validated_uuid(key_id, label="key_id")
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT provider_id, key_id, algorithm, key_length, name, state,
                       created_at, activated_at, nonce, ciphertext, aad_json
                FROM wrapped_keys
                WHERE provider_id = ? AND key_id = ?
                """,
                (normalized_provider, normalized_key),
            ).fetchone()
        if row is None:
            raise KeyNotFoundError("KMIP key was not found in the authenticated provider.")
        return row

    @staticmethod
    def _metadata(row: sqlite3.Row) -> StoredKey:
        return StoredKey(
            provider_id=row["provider_id"],
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            length=row["key_length"],
            name=row["name"],
            state=row["state"],
            created_at=row["created_at"],
            activated_at=row["activated_at"],
        )

    def get_key(self, provider_id: str, key_id: str) -> tuple[StoredKey, bytes]:
        row = self._row(provider_id, key_id)
        metadata = self._metadata(row)
        expected_aad = _canonical_aad(metadata)
        if row["aad_json"].encode("utf-8") != expected_aad:
            raise KeyStoreError("KMIP key metadata integrity validation failed.")
        try:
            plaintext = AESGCM(bytes(self._kek)).decrypt(
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
                expected_aad,
            )
        except InvalidTag as exc:
            raise KeyStoreError("KMIP wrapped key integrity validation failed.") from exc
        if len(plaintext) != 32:
            raise KeyStoreError("KMIP wrapped key length is invalid.")
        return metadata, plaintext

    def get_metadata(self, provider_id: str, key_id: str) -> StoredKey:
        return self._metadata(self._row(provider_id, key_id))

    def activate_key(self, provider_id: str, key_id: str) -> StoredKey:
        with self._lock:
            row = self._row(provider_id, key_id)
            metadata = self._metadata(row)
            if metadata.state == "Active":
                return metadata
            if metadata.state != "Pre-Active":
                raise KeyStateError("KMIP key cannot be activated from its current state.")
            updated = StoredKey(
                provider_id=metadata.provider_id,
                key_id=metadata.key_id,
                algorithm=metadata.algorithm,
                length=metadata.length,
                name=metadata.name,
                state="Active",
                created_at=metadata.created_at,
                activated_at=datetime.now(UTC).isoformat(),
            )
            old_aad = _canonical_aad(metadata)
            if row["aad_json"].encode("utf-8") != old_aad:
                raise KeyStoreError("KMIP key metadata integrity validation failed.")
            try:
                plaintext = bytearray(
                    AESGCM(bytes(self._kek)).decrypt(
                        bytes(row["nonce"]),
                        bytes(row["ciphertext"]),
                        old_aad,
                    )
                )
            except InvalidTag as exc:
                raise KeyStoreError("KMIP wrapped key integrity validation failed.") from exc
            nonce = os.urandom(12)
            new_aad = _canonical_aad(updated)
            try:
                ciphertext = AESGCM(bytes(self._kek)).encrypt(nonce, bytes(plaintext), new_aad)
                with self._connect() as connection:
                    cursor = connection.execute(
                        """
                        UPDATE wrapped_keys
                        SET state = ?, activated_at = ?, nonce = ?, ciphertext = ?, aad_json = ?
                        WHERE provider_id = ? AND key_id = ? AND state = 'Pre-Active'
                        """,
                        (
                            updated.state,
                            updated.activated_at,
                            nonce,
                            ciphertext,
                            new_aad.decode("utf-8"),
                            updated.provider_id,
                            updated.key_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise KeyStateError("KMIP key activation was not applied.")
                return updated
            finally:
                plaintext[:] = b"\0" * len(plaintext)

    def locate_keys(
        self,
        provider_id: str,
        *,
        state: str | None = None,
        name: str | None = None,
        limit: int = 1024,
    ) -> list[str]:
        normalized_provider = _validated_uuid(provider_id, label="provider_id")
        if state not in {None, "Pre-Active", "Active"}:
            raise ValueError("state is outside the supported KMIP lifecycle.")
        if not 1 <= limit <= 1024:
            raise ValueError("limit must be between 1 and 1024.")
        sql = "SELECT key_id FROM wrapped_keys WHERE provider_id = ?"
        parameters: tuple[object, ...] = (normalized_provider,)
        if state is not None:
            sql += " AND state = ?"
            parameters += (state,)
        if name is not None:
            if not isinstance(name, str) or not 1 <= len(name) <= 256:
                raise ValueError("name must contain 1 to 256 characters.")
            sql += " AND name = ?"
            parameters += (name,)
        sql += " ORDER BY created_at, key_id LIMIT ?"
        parameters += (limit,)
        with self._lock, self._connect() as connection:
            return [row["key_id"] for row in connection.execute(sql, parameters).fetchall()]

    def close(self) -> None:
        self._kek[:] = b"\0" * len(self._kek)
        self._kek = bytearray()
