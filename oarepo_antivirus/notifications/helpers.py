# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Helpers for handling notifications."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from flask import current_app
from invenio_notifications.tasks import broadcast_notification

from .builder import AntivirusScanFailureNotificationBuilder

if TYPE_CHECKING:
    from invenio_rdm_records.records import RDMRecord
    from invenio_records_resources.records import FileRecord


def notify_scan_failure(file_record: FileRecord, details: str) -> None:
    """Queue a failure notification for the owner of ``file_record``.

    Notifications are skipped when the owner cannot be resolved or has no
    email address. Errors while resolving the owner or queueing the task are
    logged and do not interrupt file processing.
    """
    file_key: str = str(file_record.key)
    try:
        rdm_record: RDMRecord = cast("RDMRecord", file_record.record)
        rdm_record_pid: str = str(rdm_record.pid.pid_value)

        notification = AntivirusScanFailureNotificationBuilder.build(
            record_id=rdm_record_pid,
            findings=[{"file": file_key, "details": details}],
            receiver=rdm_record.parent.access.owned_by.owner_id,
        )

        broadcast_notification.delay(notification.dumps())

    except ValueError:
        current_app.logger.warning(
            "Antivirus finding for file %s could not be notified: email extraction failed",
            file_key,
            exc_info=True,
        )
    except Exception:
        current_app.logger.warning(
            "Antivirus finding for file %s could not be notified",
            file_key,
            exc_info=True,
        )
