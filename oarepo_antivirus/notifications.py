# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Notifications emitted by antivirus scans."""

from __future__ import annotations

from typing import ClassVar, override

from flask import current_app
from invenio_accounts.proxies import current_datastore
from invenio_notifications.models import Notification, Recipient
from invenio_notifications.tasks import broadcast_notification
from invenio_notifications.services.builders import NotificationBuilder
from invenio_notifications.services.generators import UserEmailBackend
from invenio_records_resources.records import FileRecord
from invenio_accounts.models import User

class OwnerRecipient:
    """Generate the record owner's recipient from the notification context."""

    def __call__(
            self,
            notification: Notification,
            recipients: dict[str, Recipient],
    ) -> dict[str, Recipient]:
        """Add the record owner as a recipient."""
        email = notification.context["owner_email"]
        recipients[email] = Recipient(data={"email": email})
        return recipients


class AntivirusScanFailureNotificationBuilder(NotificationBuilder):
    """Build notifications for files rejected or not verified by antivirus."""

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
        """Build a serializable notification for a scanned record."""
        return Notification(
            type=cls.type,
            context={
                "record_id": record_id,
                "findings": findings,
                "owner_email": owner_email,
            },
        )

    recipients: ClassVar = [OwnerRecipient()]
    recipient_backends: ClassVar = [UserEmailBackend()]


def notify_scan_failure(file_record: FileRecord, details: str) -> None:
    """Notify the uploader when a file scan reports a failure."""
    try:
        record = file_record.record
        user_id: int = record.parent.access.owned_by.owner_id
        user: User = current_datastore.get_user(user_id)
        record_id: str = record.pid.pid_value


        if user is None or not user.email:
            current_app.logger.warning(
                "Antivirus finding for record %s was not notified: owner has no email",
                record_id,
            )
            return

        notification = AntivirusScanFailureNotificationBuilder.build(
            record_id=str(record_id),
            findings=[
                {
                    "file": str(getattr(file_record, "key", "<unknown>")),
                    "details": details,
                }
            ],
            owner_email=user.email,
        )
        # NotificationManager.broadcast() currently calls a validate() method
        # that is absent in the installed invenio-notifications version. Queue
        # the same task directly; it accepts the serialized notification.
        broadcast_notification.delay(notification.dumps())
    except Exception:
        current_app.logger.warning(
            "Antivirus finding for file %s could not be notified",
            getattr(file_record, "key", "<unknown>"),
            exc_info=True,
        )
