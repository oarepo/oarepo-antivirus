# SPDX-FileCopyrightText: 2025 CESNET z.s.p.o
# SPDX-License-Identifier: MIT

"""OARepo Antivirus package public interface and version metadata."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .services import AntivirusFileProcessor

__all__ = ["AntivirusFileProcessor"]


try:
    __version__ = version("oarepo-antivirus")
except PackageNotFoundError:
    __version__ = "0.0.0dev0+unknown"
