# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

from pathlib import Path
from typing import BinaryIO, Generator
import pytest

OpenedFile = Generator[BinaryIO, None, None]

HERE = Path(__file__).resolve().parent


@pytest.fixture
def virus_file_fp() -> OpenedFile:
    """Virus file processor fixture."""
    with (HERE / "./eicar.txt").open("rb") as fp:
        yield fp


@pytest.fixture
def innocent_file_fp() -> OpenedFile:
    """Virus file processor fixture."""
    with (HERE / "./innocent.txt").open("rb") as fp:
        yield fp
