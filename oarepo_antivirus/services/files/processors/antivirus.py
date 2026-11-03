# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""File service processors that integrate antivirus handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flask import current_app
from invenio_records_resources.services.files.processors import FileProcessor

from ....notifications import notify_scan_failure
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
        """Run this processor for ``file_record``.

        This method modifies the record's ``metadata`` in case of malware detection.
        """
        metadata = file_record.metadata or {}

        try:
            address = current_app.config["ANTIVIRUS_DAEMON_ADDRESS"]

            with file_record.get_stream("rb") as stream:
                antivirus_result: AntivirusResult = Antivirus.scan_stream(stream, address)

            if not antivirus_result.is_ok:
                metadata["antivirus_detected"] = antivirus_result.details
                notify_scan_failure(file_record, str(antivirus_result.details))

        except Exception:
            current_app.logger.exception("An error occurred during file processing")

        object.__setattr__(file_record, "metadata", metadata)
