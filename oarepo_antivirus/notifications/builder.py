# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Notifications emitted by antivirus scans."""

from __future__ import annotations

from typing import Any, override

from invenio_notifications.models import Notification
from invenio_notifications.services.builders import NotificationBuilder
from invenio_notifications.services.generators import (
    EmailBackendGenerator,
    EntityResolve,
    RecipientGenerator,
)
from invenio_users_resources.notifications.generators import UserRecipient


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
                "receiver": {"user": str(kwargs["receiver"])},
            },
        )

    context = [EntityResolve(key="receiver")]  # noqa: RUF012
    recipients: list[RecipientGenerator] = [UserRecipient(key="receiver")]  # noqa: RUF012
    recipient_backends: list[EmailBackendGenerator] = [EmailBackendGenerator()]  # noqa: RUF012
