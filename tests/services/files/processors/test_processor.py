# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Unit tests for the antivirus file processor."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from flask import Flask

from oarepo_antivirus.services.files.antivirus_wrapper import AntivirusResult
from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor

if TYPE_CHECKING:
    import pytest


def test_can_process_accepts_any_file_record() -> None:
    """The processor can handle any file record."""
    processor = AntivirusFileProcessor()

    assert processor.can_process(MagicMock())


def test_process_logs_missing_address_and_records_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Log configuration errors and add a notification-worthy metadata field.

    Here it raises Exception when the configuration for antivirus is missing.
    """
    processor = AntivirusFileProcessor()
    app = Flask(__name__)
    file_record = MagicMock()
    file_record.metadata = None

    with app.app_context():
        processor.process(file_record)

    assert file_record.metadata == {"antivirus_error": "Antivirus scan could not be completed."}
    assert "ANTIVIRUS_DAEMON_ADDRESS" in caplog.text


def test_process_scans_stream_and_preserves_metadata(app: Flask) -> None:
    """A clean scan leaves existing metadata intact."""
    processor = AntivirusFileProcessor()
    stream = MagicMock()
    file_record = MagicMock()
    file_record.get_stream.return_value.__enter__.return_value = stream
    file_record.metadata = {"key": "value"}

    with (
        patch(
            "oarepo_antivirus.services.files.processors.antivirus.Antivirus.scan_stream",
            return_value=AntivirusResult("OK", None),
        ) as scan_stream,
        app.app_context(),
    ):
        processor.process(file_record)

    file_record.get_stream.assert_called_once_with("rb")
    scan_stream.assert_called_once_with(stream, {"ip": "127.0.0.1", "port": 3310})
    assert file_record.metadata == {"key": "value"}


def test_process_stores_detection_in_metadata(app: Flask) -> None:
    """A detection is stored in metadata without discarding existing values."""
    processor = AntivirusFileProcessor()
    file_record = MagicMock()
    file_record.get_stream.return_value.__enter__.return_value = MagicMock()
    file_record.metadata = {"key": "value"}

    with (
        patch(
            "oarepo_antivirus.services.files.processors.antivirus.Antivirus.scan_stream",
            return_value=AntivirusResult("FOUND", "Eicar-Test-Signature"),
        ),
        app.app_context(),
    ):
        processor.process(file_record)

    assert file_record.metadata == {
        "key": "value",
        "antivirus_detected": "Eicar-Test-Signature",
    }


def test_process_initializes_metadata_when_missing(app: Flask) -> None:
    """A detection creates metadata if the record has none."""
    processor = AntivirusFileProcessor()
    file_record = MagicMock()
    file_record.get_stream.return_value.__enter__.return_value = MagicMock()
    file_record.metadata = None

    with (
        patch(
            "oarepo_antivirus.services.files.processors.antivirus.Antivirus.scan_stream",
            return_value=AntivirusResult("ERROR", "Scanner unavailable"),
        ),
        app.app_context(),
    ):
        processor.process(file_record)

    assert file_record.metadata == {"antivirus_detected": "Scanner unavailable"}


def test_process_logs_scan_exception_and_records_error(
    app: Flask,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Log scanner exceptions and add a notification-worthy metadata field."""
    processor = AntivirusFileProcessor()
    file_record = MagicMock()
    file_record.get_stream.return_value.__enter__.return_value = MagicMock()
    file_record.metadata = {"key": "value"}

    with (
        patch(
            "oarepo_antivirus.services.files.processors.antivirus.Antivirus.scan_stream",
            side_effect=OSError("Scanner unavailable"),
        ),
        app.app_context(),
    ):
        processor.process(file_record)

    assert file_record.metadata == {
        "key": "value",
        "antivirus_error": "Antivirus scan could not be completed.",
    }
    assert "Scanner unavailable" in caplog.text
