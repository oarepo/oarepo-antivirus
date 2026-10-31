# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Tests for antivirus CLI commands."""

from __future__ import annotations

from unittest.mock import patch

from flask import Flask

from oarepo_antivirus.cli import antivirus_cli


def _app() -> Flask:
    """Create a Flask application with the antivirus CLI registered."""
    app = Flask(__name__)
    app.cli.add_command(antivirus_cli)
    return app


def test_scan_record_enqueues_record_task() -> None:
    """The record command enqueues a scan for the requested ID."""
    app = _app()
    runner = app.test_cli_runner()

    with patch("oarepo_antivirus.cli.record_scan.delay") as delay:
        result = runner.invoke(app.cli, ["antivirus", "scan", "record", "record-id"])

    assert result.exit_code == 0
    delay.assert_called_once_with("record-id")
    assert "Record 'record-id' scan is being executed in Celery" in result.output


def test_scan_all_enqueues_all_records_task() -> None:
    """The all command enqueues a scan of all records."""
    app = _app()
    runner = app.test_cli_runner()

    with patch("oarepo_antivirus.cli.scan_all.delay") as delay:
        result = runner.invoke(app.cli, ["antivirus", "scan", "all"])

    assert result.exit_code == 0
    delay.assert_called_once_with()
    assert "Scanning all files of all records in the system" in result.output
