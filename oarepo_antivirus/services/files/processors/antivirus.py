# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""File service processors that integrate antivirus handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flask import current_app
from invenio_records_resources.services.files.processors import FileProcessor

from ..antivirus_wrapper import Antivirus, AntivirusResult

if TYPE_CHECKING:
    from invenio_records_resources.records import FileRecord


class AntivirusFileProcessor(FileProcessor):
    """File processor that accepts every file record for antivirus handling."""

    @override
    def can_process(self, file_record: FileRecord) -> bool:
        """Return whether this processor can handle ``file_record``.

        This implementation accepts all file records.
        """
        return True

    @override
    def process(self, file_record: FileRecord) -> None:
        """Run this processor for ``file_record``."""
        address = current_app.config["ANTIVIRUS_DAEMON_ADDRESS"]
        with file_record.get_stream("rb") as stream:
            antivirus_result: AntivirusResult = Antivirus.scan_stream(stream, address)

        metadata = file_record.metadata or {}

        if not antivirus_result.is_ok:
            metadata["error"] = antivirus_result.details

        file_record.metadata = metadata
