"""Verify Apply admission also covers ordinary nonparticipating desired saves."""

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import dialect

from atlaso.app.database import Base
from atlaso.app.models import DnsSettings
from atlaso.app.services.appliance_apply_admission import (
    lock_appliance_apply_snapshot_tables,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock


def test_postgresql_admission_locks_all_registered_tables_without_writer_cooperation():
    """Use DML-conflicting table locks including DNS rows and insert targets."""
    connection = Mock(dialect=dialect())
    session = Mock()
    session.connection.return_value = connection
    lock_appliance_apply_snapshot_tables(session)
    statement = connection.exec_driver_sql.call_args.args[0]
    preparer = connection.dialect.identifier_preparer
    expected = ", ".join(preparer.format_table(table) for table in
                         sorted(Base.metadata.tables.values(), key=lambda table: table.fullname))
    assert statement == f"LOCK TABLE {expected} IN SHARE ROW EXCLUSIVE MODE"
    assert preparer.format_table(DnsSettings.__table__) in statement
    session.commit.assert_not_called()
    session.rollback.assert_not_called()


@pytest.mark.parametrize("backend", ["mysql", "unknown"])
def test_admission_refuses_unsupported_backend(backend):
    """An unsupported backend cannot silently omit snapshot serialization.

    Args:
        backend: Database dialect without an implemented writer boundary.
    """
    connection = Mock(dialect=SimpleNamespace(name=backend))
    session = Mock()
    session.connection.return_value = connection
    with pytest.raises(RuntimeError, match="writer admission"):
        lock_appliance_apply_snapshot_tables(session)
    connection.exec_driver_sql.assert_not_called()


def test_sqlite_admission_blocks_dns_save_without_advisory_participation(client):
    """A plain desired-state UPDATE waits until Apply releases its transaction.

    Args:
        client: Initializes the isolated application schema for both sessions.
    """
    from atlaso.app.database import SessionLocal

    started = threading.Event()
    committed = threading.Event()
    failures = []

    def save_dns():
        """Commit an ordinary DNS save without explicitly acquiring admission."""
        try:
            with SessionLocal() as writer:
                started.set()
                writer.execute(update(DnsSettings).values(enabled=False))
                writer.commit()
                committed.set()
        except Exception as exc:  # noqa: BLE001 - Propagate thread failures into this assertion.
            failures.append(exc)

    with SessionLocal() as admission:
        acquire_network_objects_write_lock(admission)
        lock_appliance_apply_snapshot_tables(admission)
        worker = threading.Thread(target=save_dns)
        worker.start()
        try:
            assert started.wait(1)
            assert not committed.wait(0.1)
        finally:
            admission.rollback()
            worker.join(timeout=5)
        assert not worker.is_alive()
        assert not failures
        assert committed.is_set()
