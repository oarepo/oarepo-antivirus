# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Tests for antivirus notification dispatch."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from flask import Flask

from oarepo_antivirus.notifications.helpers import notify_scan_failure

if TYPE_CHECKING:
    import pytest


def _file_record(owner: object | None) -> MagicMock:
    """Create a file record with an owner on its parent record."""
    file_record = MagicMock()
    file_record.key = "virus.txt"
    file_record.record = SimpleNamespace(
        pid=SimpleNamespace(pid_value="rec-1"),
        parent=SimpleNamespace(access=SimpleNamespace(owned_by=owner)),
    )
    return file_record


def test_notify_scan_failure_broadcasts_to_record_owner() -> None:
    """Queue serialized notification data addressed to the record owner."""
    app = Flask(__name__)
    user = SimpleNamespace(email="uploader@example.org")
    owner = SimpleNamespace(resolve=MagicMock(return_value=user))
    file_record = _file_record(owner)

    with (
        app.app_context(),
        patch(
            "oarepo_antivirus.notifications.helpers.broadcast_notification.delay",
        ) as broadcast,
    ):
        notify_scan_failure(file_record, "Eicar-Test-Signature")

    owner.resolve.assert_called_once_with()
    broadcast.assert_called_once()
    notification = broadcast.call_args.args[0]
    assert notification["type"] == "antivirus-scan.failure"
    assert notification["context"] == {
        "record_id": "rec-1",
        "findings": [{"file": "virus.txt", "details": "Eicar-Test-Signature"}],
        "owner_email": "uploader@example.org",
    }


def test_notify_scan_failure_does_not_queue_without_owner_email(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Skip dispatch and log a warning when the owner has no email address."""
    app = Flask(__name__)
    owner = SimpleNamespace(resolve=MagicMock(return_value=SimpleNamespace(email=None)))
    file_record = _file_record(owner)

    with (
        app.app_context(),
        patch(
            "oarepo_antivirus.notifications.helpers.broadcast_notification.delay",
        ) as broadcast,
    ):
        notify_scan_failure(file_record, "Eicar-Test-Signature")

    broadcast.assert_not_called()
    assert "owner has no email" in caplog.text


def test_notify_scan_failure_logs_and_suppresses_dispatch_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Do not propagate notification task submission failures to file processing."""
    app = Flask(__name__)
    user = SimpleNamespace(email="uploader@example.org")
    owner = SimpleNamespace(resolve=MagicMock(return_value=user))
    file_record = _file_record(owner)

    with (
        app.app_context(),
        patch(
            "oarepo_antivirus.notifications.helpers.broadcast_notification.delay",
            side_effect=RuntimeError("queue unavailable"),
        ),
    ):
        notify_scan_failure(file_record, "Eicar-Test-Signature")

    assert "could not be notified" in caplog.text
    assert "queue unavailable" in caplog.text
