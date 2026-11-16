# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Tests for Flask extension registration."""

from __future__ import annotations

from flask import Flask

from oarepo_antivirus.ext import OARepoAntivirus


def test_init_app_registers_extension() -> None:
    """Register the extension under the documented app.extensions key."""
    app = Flask(__name__)
    extension = OARepoAntivirus()

    extension.init_app(app)

    assert app.extensions["oarepo-antivirus"] is extension
    assert extension.app is app
    assert "antivirus-scan.failure" in app.config["NOTIFICATIONS_BUILDERS"]


def test_constructor_can_initialize_app() -> None:
    """Passing an app to the constructor initializes the extension."""
    app = Flask(__name__)

    extension = OARepoAntivirus(app)

    assert app.extensions["oarepo-antivirus"] is extension
    assert extension.app is app
