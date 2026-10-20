# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o
# SPDX-License-Identifier: MIT

"""Flask extension registration for OARepo Antivirus."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


class OARepoAntivirus:
    """Register OARepo Antivirus with a Flask application.

    The extension stores itself in ``app.extensions`` under the
    ``oarepo-antivirus`` key so other application components can retrieve it.
    """

    def __init__(self, app: Flask | None = None) -> None:
        """Create the extension and optionally initialize it for ``app``."""
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Register this extension on ``app``."""
        self.app = app
        app.extensions["oarepo-antivirus"] = self
