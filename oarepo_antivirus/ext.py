# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o
# SPDX-License-Identifier: MIT

"""Antivirus extension."""

from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from invenio_base.utils import obj_or_import_string

if TYPE_CHECKING:
    from typing import Any

    from flask import Flask


class OARepoAntivirus:
    """OARepo DOI extension."""

    def __init__(self, app: Flask | None = None) -> None:
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Flask application initialization."""
        self.app = app
        app.extensions["antivirus-settings"] = self
        self.init_config(app)

    def init_config(self, app: Flask) -> None:
        """Initialize configuration."""
        pass


def api_finalize_app(app: Flask) -> None:
    """Finalize app."""
    finalize_app(app)


def finalize_app(app: Flask) -> None:
    """Finalize app."""
    init(app)


def init(app: Flask) -> None:
    """Init app."""
    pass
