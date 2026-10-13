"""Verify Apply admission also covers ordinary nonparticipating desired saves."""

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.exc import OperationalError

from atlaso.app.database import Base
from atlaso.app.models import DnsSettings
from atlaso.app.services.appliance_apply_admission import (
    ApplianceApplyAdmissionBusy,
    lock_appliance_apply_snapshot_tables,
)


def test_postgresql_admission_locks_all_registered_tables_without_writer_cooperation():
    """Use DML-conflicting table locks including DNS rows and insert targets."""
    connection = Mock(dialect=dialect())
    connection.execute.return_value.scalar_one.return_value = True
    session = Mock()
    session.connection.return_value = connection
    lock_appliance_apply_snapshot_tables(session)
    statement = connection.exec_driver_sql.call_args.args[0]
    preparer = connection.dialect.identifier_preparer
    expected = ", ".join(preparer.format_table(table) for table in
                         sorted(Base.metadata.tables.values(), key=lambda table: table.fullname))
    assert statement == f"LOCK TABLE {expected} IN EXCLUSIVE MODE NOWAIT"
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


@pytest.mark.parametrize("attribute", ["sqlstate", "pgcode"])
def test_postgresql_contention_releases_partial_admission(attribute):
    """Refuse NOWAIT contention and release earlier table and advisory locks.

    Args:
        attribute: SQLSTATE spelling supplied by supported PostgreSQL drivers.
    """
    original = RuntimeError("private database diagnostic")
    setattr(original, attribute, "55P03")
    connection = Mock(dialect=dialect())
    connection.execute.return_value.scalar_one.return_value = True
    connection.exec_driver_sql.side_effect = OperationalError("LOCK TABLE", None, original)
    session = Mock()
    session.connection.return_value = connection
    with pytest.raises(ApplianceApplyAdmissionBusy) as failure:
        lock_appliance_apply_snapshot_tables(session)
    assert "private" not in str(failure.value)
    session.rollback.assert_called_once_with()
    session.commit.assert_not_called()


def test_postgresql_advisory_contention_refuses_before_table_locks():
    """An occupied advisory gate never blocks or acquires partial table locks."""
    connection = Mock(dialect=dialect())
    connection.execute.return_value.scalar_one.return_value = False
    session = Mock()
    session.connection.return_value = connection
    with pytest.raises(ApplianceApplyAdmissionBusy):
        lock_appliance_apply_snapshot_tables(session)
    statement = str(connection.execute.call_args.args[0])
    assert statement == "SELECT pg_try_advisory_xact_lock(:lock_id)"
    connection.exec_driver_sql.assert_not_called()
    session.rollback.assert_called_once_with()
    session.commit.assert_not_called()


@pytest.mark.parametrize("code", [5, 6, 517, 262])
def test_sqlite_busy_codes_release_admission(code):
    """SQLite primary and extended busy/locked codes return typed contention.

    Args:
        code: SQLite driver result code for a busy or locked database.
    """
    original = RuntimeError("private database diagnostic")
    original.sqlite_errorcode = code
    connection = Mock(dialect=SimpleNamespace(name="sqlite"))
    connection.exec_driver_sql.side_effect = OperationalError("UPDATE settings", None, original)
    session = Mock()
    session.connection.return_value = connection
    with pytest.raises(ApplianceApplyAdmissionBusy) as failure:
        lock_appliance_apply_snapshot_tables(session)
    assert "private" not in str(failure.value)
    session.rollback.assert_called_once_with()


def test_sqlite_other_error_is_not_reported_as_contention():
    """Do not conceal missing-schema or other database failures as a busy gate."""
    original = RuntimeError("synthetic schema failure")
    original.sqlite_errorcode = 1
    connection = Mock(dialect=SimpleNamespace(name="sqlite"))
    failure = OperationalError("UPDATE settings", None, original)
    connection.exec_driver_sql.side_effect = failure
    session = Mock()
    session.connection.return_value = connection
    with pytest.raises(OperationalError) as result:
        lock_appliance_apply_snapshot_tables(session)
    assert result.value is failure


def test_sqlite_busy_admission_can_retry_after_writer_release(client):
    """Actual SQLite timeout refuses admission and permits a later fresh attempt.

    Args:
        client: Initializes the isolated schema used by both sessions.
    """
    from sqlalchemy.orm import Session

    from atlaso.app.database import SessionLocal, engine

    with SessionLocal() as writer, engine.connect() as connection, Session(bind=connection) as admission:
        lock_appliance_apply_snapshot_tables(writer)
        timeout = connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one()
        connection.exec_driver_sql("PRAGMA busy_timeout=0")
        try:
            with pytest.raises(ApplianceApplyAdmissionBusy):
                lock_appliance_apply_snapshot_tables(admission)
            writer.rollback()
            lock_appliance_apply_snapshot_tables(admission)
            admission.rollback()
        finally:
            # Only this isolated pooled connection's test setting is changed.
            connection.exec_driver_sql(f"PRAGMA busy_timeout={int(timeout)}")
            admission.rollback()
