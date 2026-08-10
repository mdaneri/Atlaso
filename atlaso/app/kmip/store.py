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
KEK_ENVELOPE_FORMAT = "atlaso-kmip-kek-v2"
KEK_AAD = b"atlaso-kmip-kek-v2"
LEGACY_KEK_ENVELOPE_FORMAT = "atlaso-kmip-kek-v1"
LEGACY_KEK_AAD = b"atlaso-kmip-kek-v1"
STORE_COMMITMENT_FORMAT = "atlaso-kmip-store-commitment-v1"
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
    """Represent stored key.

    Attributes:
        provider_id: Identifier of the associated provider.
        key_id: Identifier of the associated key.
        algorithm: Algorithm maintained by this storedkey.
        length: Length maintained by this storedkey.
        name: Operator-facing name of the resource.
        state: Current lifecycle state.
        created_at: UTC timestamp when the resource was created.
        activated_at: UTC timestamp associated with activated.
    """
    provider_id: str
    key_id: str
    algorithm: str
    length: int
    name: str | None
    state: str
    created_at: str
    activated_at: str | None


@dataclass(frozen=True)
class _KekEnvelope:
    """Represent kek envelope.

    Attributes:
        kek: Kek maintained by this kekenvelope.
        generation: Generation maintained by this kekenvelope.
        commitment: Commitment maintained by this kekenvelope.
        pending_generation: Pending generation maintained by this kekenvelope.
        pending_commitment: Pending commitment maintained by this kekenvelope.
    """
    kek: bytes
    generation: int
    commitment: str
    pending_generation: int | None = None
    pending_commitment: str | None = None


def _validated_uuid(value: str, *, label: str) -> str:
    """Return validated uuid.

    Args:
        value: Candidate value consumed by validated UUID.
        label: Human-readable label used to identify the result.


    Raises:
        ValueError: If an input value is invalid.
    """
    try:
        return str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a UUID.") from exc


def _canonical_aad(metadata: StoredKey) -> bytes:
    """Return canonical aad.

    Args:
        metadata: Structured metadata associated with the artifact or operation.
    """
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
    """Return master key.

    Args:
        secrets_key: Secrets key consumed by master key.


    Raises:
        KeyStoreError: If the operation encounters an invalid state.
    """
    if not secrets_key:
        raise KeyStoreError("ATLASO_SECRETS_KEY is required for the KMIP operational store.")
    return sha256(b"atlaso-kmip-master-v1\0" + secrets_key.encode("utf-8")).digest()


def _decode_envelope_value(envelope: dict[str, object], field: str) -> bytes:
    """Deserialize envelope value.

    Args:
        envelope: Envelope consumed by decode envelope value.
        field: Field consumed by decode envelope value.


    Returns:
        The decode envelope value result.

    Raises:
        KeyStoreError: If the operation encounters an invalid state.
    """
    value = envelope.get(field)
    if not isinstance(value, str):
        raise KeyStoreError("KMIP KEK envelope is invalid.")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise KeyStoreError("KMIP KEK envelope is invalid.") from exc


def _write_kek_envelope(
    path: Path,
    *,
    master_key: bytes,
    envelope: _KekEnvelope,
) -> None:
    """Persist kek envelope.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        master_key: Master key supplied by the caller.
        envelope: Envelope supplied by the caller.
    """
    plaintext = json.dumps(
        {
            "kek": base64.b64encode(envelope.kek).decode("ascii"),
            "generation": envelope.generation,
            "commitment": envelope.commitment,
            "pending_generation": envelope.pending_generation,
            "pending_commitment": envelope.pending_commitment,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    nonce = os.urandom(12)
    document = {
        "format": KEK_ENVELOPE_FORMAT,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(
            AESGCM(master_key).encrypt(nonce, plaintext, KEK_AAD)
        ).decode("ascii"),
    }
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, separators=(",", ":"), sort_keys=True)
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


def _load_or_create_kek(
    path: Path,
    *,
    secrets_key: str,
) -> tuple[bytes, _KekEnvelope]:
    """Return or create kek.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        secrets_key: Secrets key supplied by the caller.

    Raises:
        KeyStoreError: If the operation encounters an invalid state.
    """
    master = AESGCM(_master_key(secrets_key))
    if path.exists():
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict) or envelope.get("format") not in {
                KEK_ENVELOPE_FORMAT,
                LEGACY_KEK_ENVELOPE_FORMAT,
            }:
                raise KeyStoreError("KMIP KEK envelope format is unsupported.")
            nonce = _decode_envelope_value(envelope, "nonce")
            ciphertext = _decode_envelope_value(envelope, "ciphertext")
            if envelope["format"] == LEGACY_KEK_ENVELOPE_FORMAT:
                kek = master.decrypt(nonce, ciphertext, LEGACY_KEK_AAD)
                state = _KekEnvelope(kek=kek, generation=0, commitment="")
            else:
                plaintext = master.decrypt(nonce, ciphertext, KEK_AAD)
                payload = json.loads(plaintext)
                if not isinstance(payload, dict):
                    raise KeyStoreError("KMIP KEK envelope is invalid.")
                encoded_kek = payload.get("kek")
                if not isinstance(encoded_kek, str):
                    raise KeyStoreError("KMIP KEK envelope is invalid.")
                kek = base64.b64decode(encoded_kek, validate=True)
                generation = payload.get("generation")
                commitment = payload.get("commitment")
                pending_generation = payload.get("pending_generation")
                pending_commitment = payload.get("pending_commitment")
                if (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation < 0
                    or not isinstance(commitment, str)
                    or pending_generation is not None
                    and (
                        not isinstance(pending_generation, int)
                        or isinstance(pending_generation, bool)
                        or pending_generation != generation + 1
                    )
                    or pending_commitment is not None
                    and not isinstance(pending_commitment, str)
                    or (pending_generation is None) != (pending_commitment is None)
                ):
                    raise KeyStoreError("KMIP KEK envelope is invalid.")
                state = _KekEnvelope(
                    kek=kek,
                    generation=generation,
                    commitment=commitment,
                    pending_generation=pending_generation,
                    pending_commitment=pending_commitment,
                )
            if len(kek) != 32:
                raise KeyStoreError("KMIP KEK envelope is invalid.")
            os.chmod(path, 0o600)
            return _master_key(secrets_key), state
        except (InvalidTag, json.JSONDecodeError, OSError, ValueError) as exc:
            raise KeyStoreError(
                "KMIP KEK could not be opened with the configured appliance secrets key."
            ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    kek = os.urandom(32)
    master_key = _master_key(secrets_key)
    state = _KekEnvelope(kek=kek, generation=0, commitment="")
    _write_kek_envelope(path, master_key=master_key, envelope=state)
    return master_key, state


def _store_commitment(connection: sqlite3.Connection) -> str:
    """Persist commitment.

    Args:
        connection: Connection consumed by store commitment.


    Returns:
        The store commitment result.
    """
    document = {
        "format": STORE_COMMITMENT_FORMAT,
        "metadata": [
            [row["name"], row["value"]]
            for row in connection.execute(
                "SELECT name, value FROM store_metadata ORDER BY name"
            ).fetchall()
        ],
        "keys": [
            {
                "provider_id": row["provider_id"],
                "key_id": row["key_id"],
                "algorithm": row["algorithm"],
                "key_length": row["key_length"],
                "name": row["name"],
                "state": row["state"],
                "created_at": row["created_at"],
                "activated_at": row["activated_at"],
                "nonce": base64.b64encode(bytes(row["nonce"])).decode("ascii"),
                "ciphertext": base64.b64encode(bytes(row["ciphertext"])).decode("ascii"),
                "aad_json": row["aad_json"],
            }
            for row in connection.execute(
                """
                SELECT provider_id, key_id, algorithm, key_length, name, state,
                       created_at, activated_at, nonce, ciphertext, aad_json
                FROM wrapped_keys
                ORDER BY provider_id, key_id
                """
            ).fetchall()
        ],
    }
    return sha256(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


class WrappedKeyStore:
    """SQLite metadata store whose only key material is AES-GCM wrapped.

    Attributes:
        database_path: Filesystem path used for database.
        kek_path: Filesystem path used for kek.
    """

    def __init__(self, database_path: Path, kek_path: Path, *, secrets_key: str) -> None:
        """Initialize the wrapped key store.

        Args:
            database_path: Filesystem path used for database.
            kek_path: Filesystem path used for kek.
            secrets_key: Secrets key consumed by init.


        Raises:
            KeyStoreError: If the operation encounters an invalid state.
        """
        self.database_path = database_path
        self.kek_path = kek_path
        self._lock = threading.RLock()
        if self.database_path.exists() != self.kek_path.exists():
            raise KeyStoreError(
                "KMIP operational store and KEK envelope must exist together."
            )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.database_path.parent, 0o700)
        master_key, envelope = _load_or_create_kek(
            self.kek_path,
            secrets_key=secrets_key,
        )
        self._master_key = bytearray(master_key)
        self._kek = bytearray(envelope.kek)
        self._envelope = envelope
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        """Return connect."""
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        """Handle initialize.

        Raises:
            KeyStoreError: If the operation encounters an invalid state.
        """
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
            self._verify_store_commitment(connection)
        os.chmod(self.database_path, 0o600)

    def _write_envelope(self, envelope: _KekEnvelope) -> None:
        """Persist envelope.

        Args:
            envelope: Envelope consumed by write envelope.
        """
        _write_kek_envelope(
            self.kek_path,
            master_key=bytes(self._master_key),
            envelope=envelope,
        )
        self._envelope = envelope

    def _verify_store_commitment(self, connection: sqlite3.Connection) -> None:
        """Validate store commitment.

        Args:
            connection: Connection consumed by verify store commitment.


        Raises:
            KeyStoreError: If the operation encounters an invalid state.
        """
        observed = _store_commitment(connection)
        if not self._envelope.commitment:
            self._write_envelope(
                _KekEnvelope(
                    kek=bytes(self._kek),
                    generation=self._envelope.generation,
                    commitment=observed,
                )
            )
            return
        if observed == self._envelope.commitment:
            if self._envelope.pending_commitment is not None:
                self._write_envelope(
                    _KekEnvelope(
                        kek=bytes(self._kek),
                        generation=self._envelope.generation,
                        commitment=self._envelope.commitment,
                    )
                )
            return
        if observed == self._envelope.pending_commitment:
            assert self._envelope.pending_generation is not None
            self._write_envelope(
                _KekEnvelope(
                    kek=bytes(self._kek),
                    generation=self._envelope.pending_generation,
                    commitment=observed,
                )
            )
            return
        raise KeyStoreError(
            "KMIP operational store rollback or integrity validation failed."
        )

    def _commit_mutation(self, connection: sqlite3.Connection) -> None:
        """Handle commit mutation.

        Args:
            connection: Connection consumed by commit mutation.
        """
        pending = _KekEnvelope(
            kek=bytes(self._kek),
            generation=self._envelope.generation,
            commitment=self._envelope.commitment,
            pending_generation=self._envelope.generation + 1,
            pending_commitment=_store_commitment(connection),
        )
        self._write_envelope(pending)
        try:
            connection.commit()
        except Exception:
            connection.rollback()
            self._write_envelope(
                _KekEnvelope(
                    kek=bytes(self._kek),
                    generation=pending.generation,
                    commitment=pending.commitment,
                )
            )
            raise
        self._write_envelope(
            _KekEnvelope(
                kek=bytes(self._kek),
                generation=pending.pending_generation,
                commitment=pending.pending_commitment,
            )
        )

    def create_key(self, provider_id: str, *, name: str | None = None) -> StoredKey:
        """Create key.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            name: Stable name identifying the resource or operation.


        Returns:
            The created key.

        Raises:
            ValueError: If an input value is invalid.
        """
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
                self._verify_store_commitment(connection)
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
                self._commit_mutation(connection)
            return metadata
        finally:
            plaintext[:] = b"\0" * len(plaintext)

    def _row(
        self,
        connection: sqlite3.Connection,
        provider_id: str,
        key_id: str,
    ) -> sqlite3.Row:
        """Return row.

        Args:
            connection: Connection consumed by row.
            provider_id: Stable identifier of the associated provider resource.
            key_id: Stable identifier of the associated key resource.


        Raises:
            KeyNotFoundError: If the operation encounters an invalid state.
        """
        normalized_provider = _validated_uuid(provider_id, label="provider_id")
        normalized_key = _validated_uuid(key_id, label="key_id")
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
        """Return metadata.

        Args:
            row: Persistent database row affected by the operation.
        """
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

    def _decrypt_row(self, row: sqlite3.Row) -> tuple[StoredKey, bytes]:
        """Return decrypt row.

        Args:
            row: Persistent database row affected by the operation.


        Raises:
            KeyStoreError: If the operation encounters an invalid state.
        """
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

    def get_key(self, provider_id: str, key_id: str) -> tuple[StoredKey, bytes]:
        """Return key.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            key_id: Stable identifier of the associated key resource.
        """
        with self._lock, self._connect() as connection:
            self._verify_store_commitment(connection)
            row = self._row(connection, provider_id, key_id)
            return self._decrypt_row(row)

    def get_metadata(self, provider_id: str, key_id: str) -> StoredKey:
        """Return metadata.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            key_id: Stable identifier of the associated key resource.
        """
        with self._lock, self._connect() as connection:
            self._verify_store_commitment(connection)
            row = self._row(connection, provider_id, key_id)
            metadata, plaintext = self._decrypt_row(row)
            cleared = bytearray(plaintext)
            cleared[:] = b"\0" * len(cleared)
            return metadata

    def activate_key(self, provider_id: str, key_id: str) -> StoredKey:
        """Return activate key.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            key_id: Stable identifier of the associated key resource.


        Raises:
            KeyStateError: If the operation encounters an invalid state.
        """
        with self._lock, self._connect() as connection:
            self._verify_store_commitment(connection)
            row = self._row(connection, provider_id, key_id)
            metadata, decrypted = self._decrypt_row(row)
            plaintext = bytearray(decrypted)
            if metadata.state == "Active":
                plaintext[:] = b"\0" * len(plaintext)
                return metadata
            if metadata.state != "Pre-Active":
                plaintext[:] = b"\0" * len(plaintext)
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
            nonce = os.urandom(12)
            new_aad = _canonical_aad(updated)
            try:
                ciphertext = AESGCM(bytes(self._kek)).encrypt(nonce, bytes(plaintext), new_aad)
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
                self._commit_mutation(connection)
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
        """Return locate keys.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            state: Current lifecycle state consumed by the operation.
            name: Stable name identifying the resource or operation.
            limit: Limit consumed by locate keys.


        Raises:
            ValueError: If an input value is invalid.
        """
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
            self._verify_store_commitment(connection)
            return [row["key_id"] for row in connection.execute(sql, parameters).fetchall()]

    def lifecycle_counts(self) -> dict[str, dict[str, int]]:
        """Return authenticated key counts grouped by provider and lifecycle state.

        Returns:
            Redacted per-provider counts with no operational key identifiers.
        """
        counts: dict[str, dict[str, int]] = {}
        with self._lock, self._connect() as connection:
            self._verify_store_commitment(connection)
            rows = connection.execute(
                """
                SELECT provider_id, key_id, algorithm, key_length, name, state,
                       created_at, activated_at, nonce, ciphertext, aad_json
                FROM wrapped_keys
                ORDER BY provider_id, key_id
                """
            ).fetchall()
            for row in rows:
                metadata, plaintext = self._decrypt_row(row)
                try:
                    provider = counts.setdefault(
                        metadata.provider_id,
                        {"pre_active": 0, "active": 0, "total": 0},
                    )
                    field = "pre_active" if metadata.state == "Pre-Active" else "active"
                    provider[field] += 1
                    provider["total"] += 1
                finally:
                    mutable = bytearray(plaintext)
                    mutable[:] = b"\0" * len(mutable)
        return counts

    def close(self) -> None:
        """Handle close."""
        self._master_key[:] = b"\0" * len(self._master_key)
        self._master_key = bytearray()
        self._kek[:] = b"\0" * len(self._kek)
        self._kek = bytearray()
