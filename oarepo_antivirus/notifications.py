# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Notifications emitted by antivirus scans."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, override

from flask import current_app
from invenio_notifications.models import Notification, Recipient
from invenio_notifications.services.builders import NotificationBuilder
from invenio_notifications.services.generators import (
    EmailBackendGenerator,
    RecipientGenerator,
)
from invenio_notifications.tasks import broadcast_notification

if TYPE_CHECKING:
    from invenio_records_resources.records import FileRecord


class ContextEmailRecipient(RecipientGenerator):
    """Add a recipient whose email address is stored in the notification context."""

    def __init__(self, key: str):
        self._key = key

    @override
    def __call__(
        self,
        notification: Notification,
        recipients: dict[str, Recipient],
    ) -> dict[str, Recipient]:
        email = notification.context.get(self._key)
        if email:
            recipients[email] = Recipient(data={"email": email})
        return recipients


class AntivirusScanFailureNotificationBuilder(NotificationBuilder):
    """Notify the record owner about files rejected or not verified by antivirus."""

    type = "antivirus-scan.failure"

    @classmethod
    @override
    def build(
        cls,
        *,
        record_id: str,
        findings: list[dict[str, str]],
        owner_email: str,
    ) -> Notification:
        """Build a serializable notification (it is processed in a Celery task)."""
        return Notification(
            type=cls.type,
            context={
                "record_id": record_id,
                "findings": findings,
                "owner_email": owner_email,
            },
        )

    recipients: ClassVar = [ContextEmailRecipient(key="owner_email")]
    recipient_backends: ClassVar = [EmailBackendGenerator()]


def notify_scan_failure(file_record: FileRecord, details: str) -> None:
    """Notify the record owner when a file scan reports a failure."""
    file_key = str(getattr(file_record, "key", "<unknown>"))
    try:
        record = file_record.record
        record_id = str(record.pid.pid_value)

        owner = record.parent.access.owned_by
        user = owner.resolve() if owner is not None else None
        owner_email = getattr(user, "email", None)

        if not owner_email:
            current_app.logger.warning(
                "Antivirus finding for record %s was not notified: owner has no email",
                record_id,
            )
            return

        notification = AntivirusScanFailureNotificationBuilder.build(
            record_id=record_id,
            findings=[{"file": file_key, "details": details}],
            owner_email=owner_email,
        )

        # NotificationManager.broadcast() currently calls a validate() method
        # that is absent in the installed invenio-notifications version. Queue
        # the same task directly; it accepts the serialized notification.
        broadcast_notification.delay(notification.dumps())
    except Exception:
        current_app.logger.warning(
            "Antivirus finding for file %s could not be notified",
            file_key,
            exc_info=True,
        )