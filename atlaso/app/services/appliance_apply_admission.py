"""Protect complete Apply snapshot capture from nonparticipating writers."""

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from atlaso.app.database import Base


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
    SQLite already has database-wide writer admission from the caller's lock.

    Args:
        db: Submission session already holding the network-object writer lock.

    Raises:
        RuntimeError: If the backend or model registry cannot provide admission.
        ApplianceApplyAdmissionBusy: If a concurrent writer prevents immediate admission.
    """
    connection = db.connection()
    if connection.dialect.name == "sqlite":
        return
    if connection.dialect.name != "postgresql":
        raise RuntimeError("Appliance Apply requires SQLite or PostgreSQL writer admission.")
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
