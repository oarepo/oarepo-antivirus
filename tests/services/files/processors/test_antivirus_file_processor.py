# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Verify ClamAV stream scanning for clean and infected sample files."""

from __future__ import annotations

from typing import TYPE_CHECKING

from oarepo_antivirus.services.files.antivirus_wrapper import Antivirus, AntivirusResult

if TYPE_CHECKING:
    from .conftest import OpenedFile


def test_antivirus_scan_stream_virus_free(
    innocent_file_fp: OpenedFile,
) -> None:
    """Return a clean result when ClamAV scans a harmless sample."""
    result: AntivirusResult = Antivirus.scan_stream(innocent_file_fp)

    assert result.is_ok
    assert result.details is None


def test_antivirus_scan_stream_virus_infected(
    virus_file_fp: OpenedFile,
) -> None:
    """Report the EICAR signature when ClamAV scans the test sample."""
    result: AntivirusResult = Antivirus.scan_stream(virus_file_fp)

    assert not result.is_ok
    assert result.details is not None
    assert "eicar" in result.details.lower()  # signature names can slightly vary over time
