# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Tests for antivirus notification dispatch."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask

from oarepo_antivirus.notifications import notify_scan_failure


def test_notify_scan_failure_broadcasts_to_record_owner() -> None:
    """Broadcast a finding to the uploader's email address."""
    app = Flask(__name__)
    file_record = MagicMock()
    file_record.key = "virus.txt"
    file_record.record = SimpleNamespace(
        data={"created_by": {"id": 42}},
        pid=SimpleNamespace(pid_value="rec-1"),
    )
    user = SimpleNamespace(email="uploader@example.org")

    with (
        app.app_context(),
        patch(
            "oarepo_antivirus.notifications.current_datastore",
            new=MagicMock(find_user=MagicMock(return_value=user)),
        ),
        patch(
            "oarepo_antivirus.notifications.broadcast_notification"
            ".delay",
        ) as broadcast,
    ):
        notify_scan_failure(file_record, "Eicar-Test-Signature")

    broadcast.assert_called_once()
    notification = broadcast.call_args.args[0]
    assert notification["context"]["owner_email"] == "uploader@example.org"
    assert notification["context"]["record_id"] == "rec-1"
