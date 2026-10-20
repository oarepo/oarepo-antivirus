# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""File service processors that integrate antivirus handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, override

from invenio_records_resources.services.files.config import FileServiceConfig
from invenio_records_resources.services.files.processors import FileProcessor

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

        The current implementation emits a placeholder message; it does not
        yet invoke the ClamAV scanner.
        """
        raise NotImplementedError


class AntivirusFileProcessorsMixin:
    """Append the antivirus processor to the file processors on FileServiceConfig."""

    file_processors: ClassVar[list] = [*FileServiceConfig.file_processors, AntivirusFileProcessor()]
