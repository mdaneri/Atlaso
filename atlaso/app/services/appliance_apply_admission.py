"""Protect complete Apply snapshot capture from nonparticipating writers."""

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.services.network_objects import (
    NETWORK_OBJECTS_WRITE_LOCK_ID,
    acquire_network_objects_write_lock,
)


class ApplianceApplyAdmissionBusy(RuntimeError):
    """Indicate contention without exposing database or configuration diagnostics."""


def lock_appliance_apply_snapshot_tables(db: Session) -> None:
    """Extend ordinary writer admission across every registered snapshot input.

    PostgreSQL advisory locks only protect participating writers. Table locks
    refuse admission while earlier INSERT/UPDATE/DELETE transactions are active
    and block later ones through job capture without requiring writer cooperation.
    NOWAIT prevents partial acquisition from waiting in another writer's lock order;
    contention rolls back all admission locks before returning a safe refusal.
    All application tables are covered so related rows, inserts and new models
    cannot silently escape the snapshot boundary. Ordinary reads remain allowed.
    PostgreSQL also tries the shared advisory gate without waiting. SQLite uses
    the ordinary database-wide writer boundary.

    Args:
        db: Submission session before read-only snapshot capture.

    Raises:
        RuntimeError: If the backend or model registry cannot provide admission.
        ApplianceApplyAdmissionBusy: If a concurrent writer prevents immediate admission.
    """
    connection = db.connection()
    if connection.dialect.name == "sqlite":
        acquire_network_objects_write_lock(db)
        return
    if connection.dialect.name != "postgresql":
        raise RuntimeError("Appliance Apply requires SQLite or PostgreSQL writer admission.")
    acquired = connection.execute(
        text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
        {"lock_id": NETWORK_OBJECTS_WRITE_LOCK_ID},
    ).scalar_one()
    if acquired is not True:
        db.rollback()
        raise ApplianceApplyAdmissionBusy("Appliance Apply writer admission is busy.")
    tables = sorted(Base.metadata.tables.values(), key=lambda table: table.fullname)
    if not tables:
        raise RuntimeError("Appliance Apply snapshot tables are unavailable.")
    preparer = connection.dialect.identifier_preparer
    names = ", ".join(preparer.format_table(table) for table in tables)
    try:
        connection.exec_driver_sql(f"LOCK TABLE {names} IN EXCLUSIVE MODE NOWAIT")
    except OperationalError as exc:
        if (getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)) != "55P03":
            raise
        db.rollback()
        raise ApplianceApplyAdmissionBusy("Appliance Apply writer admission is busy.") from None
