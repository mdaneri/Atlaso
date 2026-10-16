"""Test kmip store behavior."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from atlaso.app.kmip.store import (
    VSPHERE_CUSTOM_ATTRIBUTES,
    KeyNotFoundError,
    KeyStoreError,
    WrappedKeyStore,
)


def store(tmp_path: Path, *, secret: str = "appliance-secrets-key") -> WrappedKeyStore:
    """Persist operation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        secret: Secret supplied to the test scenario.


    Returns:
        The store result.
    """
    return WrappedKeyStore(
        tmp_path / "store.db",
        tmp_path / "kek.json",
        secrets_key=secret,
    )


def test_wrapped_store_survives_restart_without_persisting_plaintext(tmp_path: Path) -> None:
    """Verify that wrapped store survives restart without persisting plaintext.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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


def test_vcenter_custom_attributes_round_trip_and_preserve_existing_rows(
    tmp_path: Path,
) -> None:
    """Authenticate bounded vSphere metadata through activation and restart.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    original = operational_store.create_key(provider_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        original_row_before = connection.execute(
            "SELECT * FROM wrapped_keys WHERE key_id = ?", (original.key_id,)
        ).fetchone()
    operational_store.close()

    reopened = store(tmp_path)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        original_row_after_open = connection.execute(
            "SELECT * FROM wrapped_keys WHERE key_id = ?", (original.key_id,)
        ).fetchone()
    assert original_row_after_open == original_row_before

    attributes = (
        ("x-Product_Version", "9.1.1"),
        ("x-Component", "vCenter"),
        ("x-Identifier", "vc-key-17"),
        ("x-Vendor", "VMware"),
        ("x-Product", "vSphere"),
    )
    created = reopened.create_key(provider_id, custom_attributes=attributes)
    assert created.custom_attributes == tuple(sorted(attributes))
    with sqlite3.connect(tmp_path / "store.db") as connection:
        assert connection.execute(
            "SELECT * FROM wrapped_keys WHERE key_id = ?", (original.key_id,)
        ).fetchone() == original_row_before

    _metadata, plaintext = reopened.get_key(provider_id, created.key_id)
    activated = reopened.activate_key(provider_id, created.key_id)
    assert activated.custom_attributes == created.custom_attributes
    reopened.close()

    restored = store(tmp_path)
    restored_metadata, restored_plaintext = restored.get_key(provider_id, created.key_id)
    assert restored_metadata.custom_attributes == created.custom_attributes
    assert restored_metadata.state == "Active"
    assert restored_plaintext == plaintext
    with sqlite3.connect(tmp_path / "store.db") as connection:
        assert connection.execute(
            "SELECT * FROM wrapped_keys WHERE key_id = ?", (original.key_id,)
        ).fetchone() == original_row_before


@pytest.mark.parametrize(
    "attributes",
    [
        (("x-Unknown", "value"),),
        (("x-Component", "one"), ("x-Component", "two")),
        (("x-Component", "é" * 257),),
        tuple((f"x-Component-{index}", "value") for index in range(6)),
        (("x-Component", 1),),
        (("x-Component", "value"), "malformed"),
    ],
)
def test_vcenter_custom_attributes_reject_unsupported_or_unbounded_values(
    tmp_path: Path, attributes: tuple[object, ...]
) -> None:
    """Reject unsupported vSphere metadata before creating a key.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        attributes: Invalid metadata candidate supplied by this test case.
    """
    operational_store = store(tmp_path)

    with pytest.raises(ValueError, match="custom_attributes"):
        operational_store.create_key(str(uuid.uuid4()), custom_attributes=attributes)  # type: ignore[arg-type]  # Invalid cases intentionally exercise runtime validation.

    with sqlite3.connect(tmp_path / "store.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM wrapped_keys").fetchone()[0] == 0


def test_vcenter_custom_attribute_tamper_and_provider_scope_fail_closed(
    tmp_path: Path,
) -> None:
    """Authenticate vSphere attributes and retain provider namespace isolation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    provider_id = str(uuid.uuid4())
    other_provider = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(
        provider_id, custom_attributes=(("x-Component", "vCenter"),)
    )
    with pytest.raises(KeyNotFoundError, match="authenticated provider"):
        operational_store.get_key(other_provider, metadata.key_id)
    with sqlite3.connect(tmp_path / "store.db") as connection:
        row = connection.execute(
            "SELECT * FROM wrapped_keys WHERE key_id = ?", (metadata.key_id,)
        ).fetchone()
        aad = json.loads(row[-1])
        assert set(aad["custom_attributes"]) <= VSPHERE_CUSTOM_ATTRIBUTES
        aad["custom_attributes"]["x-Component"] = "tampered"
        connection.execute(
            "UPDATE wrapped_keys SET aad_json = ? WHERE key_id = ?",
            (json.dumps(aad, separators=(",", ":"), sort_keys=True), metadata.key_id),
        )

    with pytest.raises(KeyStoreError, match="rollback or integrity"):
        operational_store.get_key(provider_id, metadata.key_id)
    with pytest.raises(KeyStoreError, match="rollback or integrity"):
        operational_store.get_key(other_provider, metadata.key_id)


def test_vcenter_custom_attributes_accept_empty_and_512_byte_values(
    tmp_path: Path,
) -> None:
    """Accept empty values and the inclusive UTF-8 byte limit.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    operational_store = store(tmp_path)
    attributes = (("x-Component", ""), ("x-Vendor", "é" * 256))

    metadata = operational_store.create_key(
        str(uuid.uuid4()), custom_attributes=attributes
    )

    assert metadata.custom_attributes == tuple(sorted(attributes))


def test_provider_namespace_isolation_fails_closed(tmp_path: Path) -> None:
    """Verify that provider namespace isolation fails closed.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    provider_id = str(uuid.uuid4())
    other_provider_id = str(uuid.uuid4())
    operational_store = store(tmp_path)
    metadata = operational_store.create_key(provider_id)

    with pytest.raises(KeyNotFoundError, match="authenticated provider"):
        operational_store.get_key(other_provider_id, metadata.key_id)

    assert operational_store.locate_keys(other_provider_id) == []


def test_lifecycle_counts_authenticate_rows_and_isolate_provider_namespaces(tmp_path: Path) -> None:
    """Verify redacted lifecycle counts authenticate every counted row.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    first_provider = str(uuid.uuid4())
    second_provider = str(uuid.uuid4())
    empty_provider = str(uuid.uuid4())
    operational_store = store(tmp_path)
    first_pre_active = operational_store.create_key(first_provider)
    first_active = operational_store.create_key(first_provider)
    operational_store.activate_key(first_provider, first_active.key_id)
    operational_store.create_key(second_provider)

    assert operational_store.lifecycle_counts([empty_provider]) == {
        first_provider: {"pre_active": 1, "active": 1, "total": 2},
        second_provider: {"pre_active": 1, "active": 0, "total": 1},
        empty_provider: {"pre_active": 0, "active": 0, "total": 0},
    }

    with sqlite3.connect(tmp_path / "store.db") as connection:
        connection.execute(
            "UPDATE wrapped_keys SET ciphertext = ? WHERE key_id = ?",
            (b"tampered", first_pre_active.key_id),
        )
        connection.commit()
    with pytest.raises(KeyStoreError, match="integrity"):
        operational_store.lifecycle_counts()


def test_activation_rewraps_key_and_preserves_material(tmp_path: Path) -> None:
    """Verify that activation rewraps key and preserves material.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that concurrent activation is idempotent.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that wrong appliance secrets key cannot open kek.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    first = store(tmp_path)
    first.close()

    with pytest.raises(KeyStoreError, match="configured appliance secrets key"):
        store(tmp_path, secret="different-appliance-secrets-key")


def test_store_and_kek_must_exist_as_a_pair(tmp_path: Path) -> None:
    """Verify that store and kek must exist as a pair.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    (tmp_path / "store.db").write_bytes(b"orphan")

    with pytest.raises(KeyStoreError, match="must exist together"):
        store(tmp_path)


def test_wrapped_key_tamper_is_detected_without_secret_output(tmp_path: Path) -> None:
    """Verify that wrapped key tamper is detected without secret output.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that metadata only read authenticates wrapped key and metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that earlier authenticated row cannot be restored after activation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that kek and store require service only permissions.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    store(tmp_path)

    assert (tmp_path / "store.db").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "kek.json").stat().st_mode & 0o777 == 0o600
