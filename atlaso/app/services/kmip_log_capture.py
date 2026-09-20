"""Optional in-process KMS capture preserving its regular stderr mirror."""

import logging
from pathlib import Path
from typing import TextIO


class CapturingStreamHandler(logging.StreamHandler[TextIO]):
    """Commit a sanitized KMS record before its established stderr mirror."""

    def __init__(self, path: Path, stream: TextIO | None = None) -> None:
        """Bind a pre-created trusted producer history store.

        Args:
            path: Prepared KMS-owned store inside its writable logging directory.
            stream: Existing stderr stream, or an isolated test mirror.
        """
        super().__init__(stream)
        self.history_path = path

    def emit(self, record: logging.LogRecord) -> None:
        """Persist the record synchronously before acknowledging the logger.

        Args:
            record: Newly emitted KMS logging record, including exception text.
        """
        from atlaso.app.services.producer_log_history import capture_record

        capture_record(self.history_path, "service", record,
                       self.formatter or logging.Formatter(), source="kms")
        super().emit(record)
