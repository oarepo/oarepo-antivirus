# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""File service integrations and antivirus scanning helpers."""

from __future__ import annotations

from .processors import AntivirusFileProcessor

__all__ = ["AntivirusFileProcessor"]
