from celery import shared_task
from flask import current_app
from invenio_access.permissions import system_identity
from oarepo_antivirus.services.files.antivirus_wrapper import Antivirus, AntivirusResult
from invenio_rdm_records.proxies import current_rdm_records_service

@shared_task()
def record_scan(record_id: str):
    """Scan all files attached to a record."""
    record_item = current_rdm_records_service.read(system_identity, record_id)
    record = record_item._record

    if not record.files:
        print(f"The record {record_id} does not have any files.")
        return

    antivirus_daemon_address = current_app.config.get("ANTIVIRUS_DAEMON_ADDRESS")

    print(f"Scanning all files for record: {record_id}")
    for file_key, file_obj in record.files.items():
        try:
            stream = file_obj.get_stream("rb")
            result: AntivirusResult = Antivirus.scan_stream(stream, antivirus_daemon_address)
            status = "OK" if result.is_ok else f"FAILED, details: {result.details}"
            print(f"  - {file_key}: {status}")
        except Exception as e:
            print(f"  - {file_key}: ERROR during scan ({e})")