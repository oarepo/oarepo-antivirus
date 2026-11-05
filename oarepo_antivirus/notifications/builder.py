# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Notifications emitted by antivirus scans."""

from __future__ import annotations

from typing import Any, override

from invenio_notifications.models import Notification, Recipient
from invenio_notifications.services.builders import NotificationBuilder
from invenio_notifications.services.generators import (
    EmailBackendGenerator,
    RecipientGenerator,
)


class ContextEmailRecipient(RecipientGenerator):
    """Add a recipient whose email address is stored in notification context.

    :param key: Context key containing the recipient's email address.
    """

    def __init__(self, key: str):
        """Create a recipient generator for ``key``."""
        self._key = key

    @override
    def __call__(
        self,
        notification: Notification,
        recipients: dict[str, Recipient],
    ) -> dict[str, Recipient]:
        """Add the context email to ``recipients`` when it is present."""
        email = notification.context.get(self._key)
        if email:
            recipients[email] = Recipient(data={"email": email})
        return recipients


class AntivirusScanFailureNotificationBuilder(NotificationBuilder):
    """Build notifications for files reported as unsafe by antivirus."""

    type = "antivirus-scan.failure"

    @classmethod
    @override
    def build(cls, **kwargs: Any) -> Notification:
        """Build a serializable notification processed by a Celery task.

        :param kwargs: Record identifier, findings, and owner email.
        :return: A notification containing the record and finding context.
        """
        return Notification(
            type=cls.type,
            context={
                "record_id": kwargs["record_id"],
                "findings": kwargs["findings"],
                "owner_email": kwargs["owner_email"],
            },
        )

    recipients: list[RecipientGenerator] = [ContextEmailRecipient(key="owner_email")]  # noqa: RUF012
    recipient_backends: list[EmailBackendGenerator] = [EmailBackendGenerator()]  # noqa: RUF012
