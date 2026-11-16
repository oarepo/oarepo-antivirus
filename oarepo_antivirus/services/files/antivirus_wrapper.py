# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Scan data for malware using a local ClamAV daemon."""

from __future__ import annotations

import warnings
from typing import Any

# hide unwanted warning
with warnings.catch_warnings(record=False):
    warnings.filterwarnings(
        "ignore",
        message=r"^pkg_resources is deprecated as an API\.",
        category=UserWarning,
        module=r"^clamd(\.|$)",
    )
    import clamd


class AntivirusResult:
    """Represent a ClamAV scan status and its optional details.

    A status of ``OK`` indicates a clean scan; other statuses indicate a
    detection or scanner response that should be treated as a failure.
    """

    def __init__(self, status: str, details: str | None):
        """Initialize a result with the scanner status and optional details."""
        self._status: str = status
        self._details: str | None = details

    @property
    def is_ok(self) -> bool:
        """Return whether the scan completed and found the file clean."""
        return self._status == "OK"

    @property
    def details(self) -> str | None:
        """Return scanner details, such as a detection name."""
        return self._details


class Antivirus:
    """Provide a convenience interface to a network-accessible ClamAV daemon."""

    @staticmethod
    def scan_stream(file_stream: Any, address: dict[str, str | int]) -> AntivirusResult:
        """Scan a binary file stream and return its status and details.

        :param file_stream: File-like object accepted by ClamAV's ``INSTREAM``.
        :param address: Mapping with the daemon ``ip`` and integer ``port``.
        :return: The status and optional details returned for the stream.
        :raises clamd.BufferTooLongError: if the buffer size exceeds clamd limits.
        :raises clamd.ConnectionError: If the daemon cannot be reached.
        :raises ValueError: If the address is malformed.
        :raises OSError: If the stream cannot be read by the scanner.

        The stream is passed to ClamAV's ``INSTREAM`` command.

        """
        clam = clamd.ClamdNetworkSocket(host=str(address["ip"]), port=int(address["port"]))
        clam.reload()  # update the signature database

        scan_result = clam.instream(file_stream)

        # Parse the result dictionary, e.g., {'stream': ('OK', None)} or ('FOUND', 'Virus_Name')
        status, details = scan_result.get("stream", ("ERROR", "Unknown error"))
        return AntivirusResult(status, details)
