# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Flask blueprints exposed by OARepo Antivirus."""

from __future__ import annotations

from flask import Blueprint

blueprint = Blueprint(
    "oarepo_antivirus",
    __name__,
    template_folder="templates",
)
