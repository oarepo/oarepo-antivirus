# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Celery tasks for scanning OARepo records and their files."""

from celery import shared_task
from flask import current_app
from invenio_access.permissions import system_identity
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_rdm_records.records import RDMRecord
from invenio_rdm_records.services import RDMRecordService
from invenio_records_resources.records import FileRecord
from invenio_records_resources.services import FileService
from invenio_records_resources.services.uow import RecordCommitOp, UnitOfWork
from oarepo_runtime.proxies import current_runtime

from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor

# --- helpers ----

def print_scan_file_result(file_record: FileRecord) -> None:
    """Print the antivirus status recorded on a file record."""
    # obtain the metadata
    metadata = file_record.metadata or {}

    # get the details
    details: str | None = None
    if metadata.get("antivirus_detected", False) or metadata.get("antivirus_error", False):
        details = metadata.get("antivirus_detected")

    # print the status
    status = f"FAIL, details: {details}" if details else "OK"
    print(f"  - {file_record.key}: {status}")

def scan_files(record: RDMRecord) -> None:
    """Scan and commit every enabled file attached to a record."""
    # obtain AntivirusFileProcessor instance
    file_service: FileService = current_runtime.get_file_service_for_record(record)
    processor: AntivirusFileProcessor | None = next(
        (
            p for p in file_service.config.file_processors
            if isinstance(p, AntivirusFileProcessor)
        ),
        None,
    )
    if processor is None:
        raise RuntimeError("No AntivirusFileProcessor configured for this model")

    # A single record index can contain models with files disabled. Accessing
    # their file mapping raises InvalidOperationError, so skip metadata-only
    # records before iterating it.
    files = record.files
    if not files.enabled:
        print(f"Skipping record {record.pid.pid_value}: files are not enabled")
        return

    # scan the record's files
    for file_key, file_record in files.items():
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
def record_scan(record_id: str):
    """Scan all files attached to a record."""
    try:
        record_item = current_rdm_records_service.read(system_identity, record_id)
        record: RDMRecord = record_item._record
        scan_files(record)
    except Exception as e:
        current_app.logger.error(e)

@shared_task()
def scan_all():
    """Scan all files attached to all published records."""
    try:
        for model_name, model in current_runtime.models.items():
            service = model.service

            if not isinstance(service, RDMRecordService):
                continue

            for hit in service.scan(system_identity):
                item = service.read(system_identity, hit["id"])
                scan_files(item._record)
    except Exception as e:
        current_app.logger.error(e)
