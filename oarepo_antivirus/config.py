# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Configuration defaults for OARepo Antivirus."""

from __future__ import annotations

ANTIVIRUS_DAEMON_ADDRESS: dict[str, str | int] = {
    "ip": "127.0.0.1",
    "port": 3310,
}
