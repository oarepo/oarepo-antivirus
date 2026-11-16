# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Shared fixtures for antivirus file processor tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import BinaryIO

import pytest
from flask import Flask

from oarepo_antivirus.config import ANTIVIRUS_DAEMON_ADDRESS

# Fixture type: a generator yielding an opened binary file.
OpenedFile = Generator[BinaryIO]

# Directory containing the test sample data.
FILES_PATH = Path(__file__).resolve().parent / "data"


@pytest.fixture
def virus_file_fp() -> OpenedFile:
    """Yield the EICAR test file as an open binary stream."""
    with (FILES_PATH / "eicar.txt").open("rb") as fp:
        yield fp


@pytest.fixture
def innocent_file_fp() -> OpenedFile:
    """Yield a harmless sample file as an open binary stream."""
    with (FILES_PATH / "innocent.txt").open("rb") as fp:
        yield fp


@pytest.fixture
def app() -> Flask:
    """Provide the configured Flask app context used by the processor."""
    app = Flask(__name__)
    app.config["ANTIVIRUS_DAEMON_ADDRESS"] = ANTIVIRUS_DAEMON_ADDRESS
    return app
