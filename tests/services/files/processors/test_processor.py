# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Unit tests for the antivirus file processor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from oarepo_antivirus.services.files.antivirus_wrapper import AntivirusResult
from oarepo_antivirus.services.files.processors.antivirus import AntivirusFileProcessor


def test_can_process_accepts_any_file_record() -> None:
    """The processor can handle any file record."""
    processor = AntivirusFileProcessor()

    assert processor.can_process(MagicMock())


def test_process_fails_loudly_when_address_is_not_configured() -> None:
    """Do not start a scan with an implicit or missing daemon address."""
    processor = AntivirusFileProcessor()
    app = Flask(__name__)

    with app.app_context(), pytest.raises(KeyError, match="ANTIVIRUS_DAEMON_ADDRESS"):
        processor.process(MagicMock())


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


def test_process_stores_scan_error_in_metadata(app: Flask) -> None:
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
        "error": "Eicar-Test-Signature",
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

    assert file_record.metadata == {"error": "Scanner unavailable"}
