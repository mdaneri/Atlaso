from __future__ import annotations

import os
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from atlaso.app.kmip.store import KeyNotFoundError, KeyStoreError, WrappedKeyStore


def store(tmp_path: Path, *, secret: str = "appliance-secrets-key") -> WrappedKeyStore:
    return WrappedKeyStore(
        tmp_path / "store.db",
        tmp_path / "kek.json",
        secrets_key=secret,
    )


def test_wrapped_store_survives_restart_without_persisting_plaintext(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    first = store(tmp_path)
    metadata = first.create_key(provider_id)
    _stored_metadata, plaintext = first.get_key(provider_id, metadata.key_id)

    assert len(plaintext) == 32
    assert metadata.state == "Pre-Active"
    assert plaintext not in (tmp_path / "store.db").read_bytes()
    assert plaintext not in (tmp_path / "kek.json").read_bytes()
    first.close()

    reopened = store(tmp_path)
    restored_metadata, restored_plaintext = reopened.get_key(provider_id, metadata.key_id)

    assert restored_metadata == metadata
    assert restored_plaintext == plaintext


def test_provider_namespace_isolation_fails_closed(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    other_provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)

    with pytest.raises(KeyNotFoundError, match="authenticated provider"):
        operational_store.get_key(other_provider_id, metadata.key_id)

    assert operational_store.locate_keys(other_provider_id) == []


def test_activation_rewraps_key_and_preserves_material(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)
    _stored_metadata, plaintext = operational_store.get_key(provider_id, metadata.key_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        before = connection.execute(
            "SELECT nonce, ciphertext, aad_json FROM wrapped_keys WHERE key_id = ?",
            (metadata.key_id,),
        ).fetchone()

    activated = operational_store.activate_key(provider_id, metadata.key_id)
    restored, restored_plaintext = operational_store.get_key(provider_id, metadata.key_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        after = connection.execute(
            "SELECT nonce, ciphertext, aad_json FROM wrapped_keys WHERE key_id = ?",
            (metadata.key_id,),
        ).fetchone()

    assert activated.state == "Active"
    assert restored.state == "Active"
    assert restored_plaintext == plaintext
    assert before != after
    assert operational_store.activate_key(provider_id, metadata.key_id) == activated


def test_concurrent_activation_is_idempotent(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)

    with ThreadPoolExecutor(max_workers=8) as executor:
        activated = list(
            executor.map(
                lambda _index: operational_store.activate_key(
                    provider_id,
                    metadata.key_id,
                ),
                range(32),
            )
        )

    assert {item.state for item in activated} == {"Active"}
    assert {item.key_id for item in activated} == {metadata.key_id}


def test_wrong_appliance_secrets_key_cannot_open_kek(tmp_path: Path) -> None:
    first = store(tmp_path)
    first.close()

    with pytest.raises(KeyStoreError, match="configured appliance secrets key"):
        store(tmp_path, secret="different-appliance-secrets-key")


def test_store_and_kek_must_exist_as_a_pair(tmp_path: Path) -> None:
    (tmp_path / "store.db").write_bytes(b"orphan")

    with pytest.raises(KeyStoreError, match="must exist together"):
        store(tmp_path)


def test_wrapped_key_tamper_is_detected_without_secret_output(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)
    _stored_metadata, plaintext = operational_store.get_key(provider_id, metadata.key_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        ciphertext = bytearray(
            connection.execute(
                "SELECT ciphertext FROM wrapped_keys WHERE key_id = ?",
                (metadata.key_id,),
            ).fetchone()[0]
        )
        ciphertext[0] ^= 1
        connection.execute(
            "UPDATE wrapped_keys SET ciphertext = ? WHERE key_id = ?",
            (bytes(ciphertext), metadata.key_id),
        )

    with pytest.raises(KeyStoreError, match="integrity validation failed") as raised:
        operational_store.get_key(provider_id, metadata.key_id)

    assert plaintext.hex() not in str(raised.value)


def test_metadata_only_read_authenticates_wrapped_key_and_metadata(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id, name="vcenter-key")
    with sqlite3.connect(tmp_path / "store.db") as connection:
        connection.execute(
            "UPDATE wrapped_keys SET name = ? WHERE key_id = ?",
            ("tampered-name", metadata.key_id),
        )

    operational_store.close()
    with pytest.raises(KeyStoreError, match="rollback or integrity"):
        store(tmp_path)


def test_earlier_authenticated_row_cannot_be_restored_after_activation(
    tmp_path: Path,
) -> None:
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        before = connection.execute(
            """
            SELECT state, activated_at, nonce, ciphertext, aad_json
            FROM wrapped_keys
            WHERE key_id = ?
            """,
            (metadata.key_id,),
        ).fetchone()

    operational_store.activate_key(provider_id, metadata.key_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        connection.execute(
            """
            UPDATE wrapped_keys
            SET state = ?, activated_at = ?, nonce = ?, ciphertext = ?, aad_json = ?
            WHERE key_id = ?
            """,
            (*before, metadata.key_id),
        )

    operational_store.close()
    with pytest.raises(KeyStoreError, match="rollback or integrity"):
        store(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are enforced on the Photon appliance")
def test_kek_and_store_require_service_only_permissions(tmp_path: Path) -> None:
    store(tmp_path)

    assert (tmp_path / "store.db").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "kek.json").stat().st_mode & 0o777 == 0o600
