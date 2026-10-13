"""Protect complete Apply snapshot capture from nonparticipating writers."""

from sqlalchemy.orm import Session

from atlaso.app.database import Base


def lock_appliance_apply_snapshot_tables(db: Session) -> None:
    """Extend ordinary writer admission across every registered snapshot input.

    PostgreSQL advisory locks only protect participating writers. Table locks
    also wait for earlier INSERT/UPDATE/DELETE transactions and block later ones
    through job capture, even when their endpoints do not take the advisory lock.
    All application tables are covered so related rows, inserts and new models
    cannot silently escape the snapshot boundary. Ordinary reads remain allowed.
    SQLite already has database-wide writer admission from the caller's lock.

    Args:
        db: Submission session already holding the network-object writer lock.

    Raises:
        RuntimeError: If the backend or model registry cannot provide admission.
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
    connection.exec_driver_sql(f"LOCK TABLE {names} IN SHARE ROW EXCLUSIVE MODE")
