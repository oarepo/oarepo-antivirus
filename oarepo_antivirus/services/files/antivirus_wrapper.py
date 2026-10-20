# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Scan files for malware using a local ClamAV daemon."""

from __future__ import annotations

import warnings
from pathlib import Path

import clamd

warnings.filterwarnings("ignore", category=UserWarning, module="clamd")


class AntivirusResult:
    """Represent a ClamAV scan status and its optional details.

    A status of ``OK`` indicates a clean scan; other statuses can represent a
    detection or a scanner error.
    """

    def __init__(self, status: str, details: str | None):
        """Initialize a result with the scanner status and optional details."""
        self._status = status
        self._details = details

    @property
    def is_ok(self) -> bool:
        """Return whether the scan completed and found the file clean."""
        return self._status == "OK"

    @property
    def details(self) -> str | None:
        """Return scanner details, such as a detection name or error message."""
        return self._details


class Antivirus:
    """Provide a convenience interface to the local ClamAV daemon."""

    @staticmethod
    def scan(file_path: str) -> AntivirusResult:
        """Scan the file at ``file_path`` and return its status and details.

        Connection, file access, and scanner errors are returned as an
        ``ERROR`` result instead of being raised to the caller.
        """
        try:
            clam = clamd.ClamdNetworkSocket(host="localhost", port=3310)
            clam.reload()

            with Path(file_path).open("rb") as f:
                scan_result = clam.instream(f)

            # Parse the result dictionary, e.g., {'stream': ('OK', None)} or ('FOUND', 'Virus_Name')
            status, details = scan_result.get("stream", ("ERROR", "Unknown error"))
            return AntivirusResult(status, details)

        except clamd.BufferTooLongError as e:
            return AntivirusResult("ERROR", str(e))

        except clamd.ConnectionError as e:
            return AntivirusResult("ERROR", str(e))
