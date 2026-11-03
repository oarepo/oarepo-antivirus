# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Unit tests for antivirus scan tasks."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from invenio_rdm_records.services import RDMRecordService

from oarepo_antivirus import tasks
from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor


@pytest.fixture
def app() -> Flask:
    """Provide an application context for task logging and proxies."""
    return Flask(__name__)


def _file_record(metadata: dict | None = None) -> MagicMock:
    """Create a mock file record with the supplied metadata."""
    file_record = MagicMock()
    file_record.key = "example.txt"
    file_record.metadata = metadata
    return file_record


def test_print_scan_file_result_reports_clean(
    app: Flask,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Print a clean result when no antivirus metadata is present."""
    caplog.set_level("INFO")
    with app.app_context():
        tasks.print_scan_file_result(_file_record())

    assert "example.txt: OK" in caplog.text


def test_print_scan_file_result_reports_detection(
    app: Flask,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Print the detection details when a file is infected."""
    caplog.set_level("INFO")
    with app.app_context():
        tasks.print_scan_file_result(_file_record({"antivirus_detected": "Eicar-Test-Signature"}))

    assert "FAIL, details: Eicar-Test-Signature" in caplog.text


def test_scan_files_processes_and_commits_enabled_files(app: Flask) -> None:
    """Process each enabled file and commit each file record."""
    record = MagicMock()
    record.files.enabled = True
    file_record = _file_record()
    record.files.items.return_value = [("example.txt", file_record)]
    record.files.entries = {"example.txt": file_record}
    processor = AntivirusFileProcessor()
    processor.process = MagicMock()
    file_service = SimpleNamespace(config=SimpleNamespace(file_processors=[processor]))
    unit_of_work = MagicMock()
    unit_of_work.__enter__.return_value = unit_of_work

    with (
        patch.object(
            tasks,
            "current_runtime",
            new=MagicMock(),
        ) as runtime,
        patch.object(tasks, "UnitOfWork", return_value=unit_of_work),
        patch.object(tasks, "RecordCommitOp") as commit_op,
    ):
        runtime.get_file_service_for_record.return_value = file_service
        tasks.scan_files(record)

    processor.process.assert_called_once_with(file_record)
    commit_op.assert_called_once_with(file_record)
    unit_of_work.register.assert_called_once_with(commit_op.return_value)
    unit_of_work.commit.assert_called_once_with()


def test_scan_files_skips_disabled_files(app: Flask) -> None:
    """Do not access or process files when files are disabled."""
    record = MagicMock()
    record.files.enabled = False
    processor = AntivirusFileProcessor()
    processor.process = MagicMock()
    file_service = SimpleNamespace(config=SimpleNamespace(file_processors=[processor]))

    with (
        patch.object(tasks, "current_runtime", new=MagicMock()) as runtime,
    ):
        runtime.get_file_service_for_record.return_value = file_service
        tasks.scan_files(record)

    processor.process.assert_not_called()
    record.files.items.assert_not_called()


def test_scan_files_requires_antivirus_processor() -> None:
    """Raise an explicit error when the model has no antivirus processor."""
    record = MagicMock()
    file_service = SimpleNamespace(config=SimpleNamespace(file_processors=[]))

    with patch.object(tasks, "current_runtime", new=MagicMock()) as runtime:
        runtime.get_file_service_for_record.return_value = file_service
        with pytest.raises(RuntimeError, match="No AntivirusFileProcessor"):
            tasks.scan_files(record)


def test_record_scan_reads_record_and_scans(app: Flask) -> None:
    """Read the requested record and delegate to the file scanner."""
    record = MagicMock()
    record_item = SimpleNamespace(_record=record)

    with (
        app.app_context(),
        patch.object(
            tasks,
            "current_rdm_records_service",
            new=MagicMock(),
        ) as service,
        patch.object(
            service,
            "read",
            return_value=record_item,
        ) as read,
        patch.object(tasks, "scan_files") as scan_files,
    ):
        tasks.record_scan.run("record-id")

    read.assert_called_once_with(tasks.system_identity, "record-id")
    scan_files.assert_called_once_with(record)


def test_record_scan_logs_errors(app: Flask, caplog: pytest.LogCaptureFixture) -> None:
    """Log failures raised while reading or scanning a record."""
    with (
        app.app_context(),
        patch.object(
            tasks,
            "current_rdm_records_service",
            new=MagicMock(),
        ) as service,
    ):
        service.read.side_effect = RuntimeError("read failed")
        tasks.record_scan.run("record-id")

    assert "read failed" in caplog.text


def test_scan_all_scans_all_rdm_models(app: Flask) -> None:
    """Scan records from every registered RDM model service."""
    service = MagicMock(spec=RDMRecordService)
    service.scan.return_value = [{"id": "record-id"}]
    record = MagicMock()
    service.read.return_value = SimpleNamespace(_record=record)
    rdm_model = SimpleNamespace(service=service)
    other_model = SimpleNamespace(service=MagicMock())

    with (
        app.app_context(),
        patch.object(
            tasks,
            "current_runtime",
            new=MagicMock(),
        ) as runtime,
        patch.object(
            tasks,
            "scan_files",
        ) as scan_files,
    ):
        runtime.models = {"datasets": rdm_model, "other": other_model}
        tasks.record_scan_all.run()

    service.scan.assert_called_once_with(tasks.system_identity)
    service.read.assert_called_once_with(tasks.system_identity, "record-id")
    scan_files.assert_called_once_with(record)
    other_model.service.scan.assert_not_called()


def test_scan_all_logs_errors(app: Flask, caplog: pytest.LogCaptureFixture) -> None:
    """Log failures raised while scanning models."""
    service = MagicMock(spec=RDMRecordService)
    service.scan.side_effect = RuntimeError("scan failed")

    with (
        app.app_context(),
        patch.object(tasks, "current_runtime", new=MagicMock()) as runtime,
    ):
        runtime.models = {"datasets": SimpleNamespace(service=service)}
        tasks.record_scan_all.run()

    assert "scan failed" in caplog.text
