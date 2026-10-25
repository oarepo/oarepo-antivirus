from celery import shared_task
from invenio_records_resources.records import FileRecord
from invenio_records_resources.services import FileService
from oarepo_runtime.proxies import current_runtime
from flask import current_app
from invenio_access.permissions import system_identity
from invenio_rdm_records.records import RDMRecord
from invenio_rdm_records.proxies import current_rdm_records_service
from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor
from invenio_records_resources.services.uow import RecordCommitOp, UnitOfWork


# --- helpers ----

def print_scan_file_result(file_record: FileRecord) -> None:
    metadata = file_record.metadata or {}
    status = f"FAIL, details: {metadata['error']}" if metadata.get("error") else "OK"
    print(f"  - {file_record.key}: {status}")


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

def scan_files(record: RDMRecord) -> None:
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

    # scan the record's files
    for file_key, file_record in record.files.items():
        # process the file
        processor.process(file_record)

        # commit possible modifications
        with UnitOfWork() as uow:
            uow.register(RecordCommitOp(file_record))
            uow.commit()

        # print result
        print_scan_file_result(file_record)
