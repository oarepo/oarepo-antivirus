# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Shared fixtures for antivirus file processor tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import BinaryIO

import pytest

# Fixture type: a generator yielding an opened binary file.
OpenedFile = Generator[BinaryIO]

# Directory containing the test sample files.
HERE = Path(__file__).resolve().parent


@pytest.fixture
def virus_file_fp() -> OpenedFile:
    """Yield the EICAR test file as an open binary stream."""
    with (HERE / "./eicar.txt").open("rb") as fp:
        yield fp


@pytest.fixture
def innocent_file_fp() -> OpenedFile:
    """Yield a harmless sample file as an open binary stream."""
    with (HERE / "./innocent.txt").open("rb") as fp:
        yield fp
