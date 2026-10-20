# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Service integrations exposed by OARepo Antivirus."""

from __future__ import annotations

from .files import AntivirusFileProcessor

__all__ = ["AntivirusFileProcessor"]
