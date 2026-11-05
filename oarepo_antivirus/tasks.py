# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Celery tasks for scanning OARepo records and their files."""

from __future__ import annotations

from typing import TYPE_CHECKING

from celery import shared_task
from flask import current_app
from invenio_access.permissions import system_identity
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_rdm_records.records import RDMRecord
from invenio_records_resources.services.uow import RecordCommitOp, UnitOfWork
from oarepo_runtime.proxies import current_runtime
from oarepo_runtime.typing import record_from_result

from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor

if TYPE_CHECKING:
    from invenio_records_resources.records import FileRecord
    from invenio_records_resources.records.systemfields.files.manager import FilesManager
    from invenio_records_resources.services import FileService
    from invenio_records_resources.services.records.results import RecordItem

# --- helpers ----


def print_scan_file_result(file_record: FileRecord) -> None:
    """Log the antivirus status recorded on a file record."""
    # obtain the metadata
    metadata = file_record.metadata or {}

    # get the details
    details: str | None = None
    if metadata.get("antivirus_detected", False) or metadata.get("antivirus_error", False):
        details = metadata.get("antivirus_detected") or metadata.get("antivirus_error")

    # print the status
    status = f"FAIL, details: {details}" if details else "OK"
    current_app.logger.info("  - %s: %s", file_record.key, status)


def scan_files(record: RDMRecord) -> None:
    """Scan and commit every enabled file attached to ``record``.

    :raises RuntimeError: If the record has no file service or antivirus
        processor configured.
    """
    # obtain AntivirusFileProcessor instance
    file_service: FileService | None = current_runtime.get_file_service_for_record(record)
    if file_service is None:
        raise RuntimeError("No file service configured for this model")
    processor: AntivirusFileProcessor | None = next(
        (p for p in file_service.config.file_processors if isinstance(p, AntivirusFileProcessor)),
        None,
    )
    if processor is None:
        raise RuntimeError("No AntivirusFileProcessor configured for this model")

    # A single record index can contain models with files disabled.
    files: FilesManager = record.files
    if not files.enabled:
        current_app.logger.info(
            "Skipping record %s: files are not enabled",
            record.pid.pid_value,
        )
        return

    # scan the record's files
    for file_record in files.entries.values():
        # process the file
        processor.process(file_record)

        # commit possible modifications
        with UnitOfWork() as uow:
            uow.register(RecordCommitOp(file_record))
            uow.commit()

        # print result to the Celery console
        print_scan_file_result(file_record)


# ----------------


@shared_task()
def record_scan(record_id: str) -> None:
    """Read ``record_id`` and scan all files attached to that record."""
    try:
        record_item: RecordItem = current_rdm_records_service.read(system_identity, record_id)
        record: RDMRecord = record_from_result(record_item, RDMRecord)
        scan_files(record)
    except Exception:
        current_app.logger.exception("An error occurred during file scanning")


@shared_task()
def record_scan_all() -> None:
    """Enqueue scans for all records returned by the current RDM service."""
    try:
        for record in current_rdm_records_service.scan(system_identity):
            record_scan(record["id"])

    except Exception:
        current_app.logger.exception("An error occurred during file scanning")
