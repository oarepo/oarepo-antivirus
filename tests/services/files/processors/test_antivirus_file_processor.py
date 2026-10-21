# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Antivirus file processor tests."""

from oarepo_antivirus.services.files.antivirus_wrapper import Antivirus, AntivirusResult

from .conftest import OpenedFile


def test_antivirus_scan_stream_virus_free(
        innocent_file_fp: OpenedFile,
) -> None:

    result: AntivirusResult = Antivirus.scan_stream(innocent_file_fp)

    assert result.is_ok == True
    assert result.details == None


def test_antivirus_scan_stream_virus_infected(
        virus_file_fp: OpenedFile,
) -> None:

    result: AntivirusResult = Antivirus.scan_stream(virus_file_fp)

    assert result.is_ok == False
    assert "eicar" in result.details.lower() # signature names can slightly vary over time