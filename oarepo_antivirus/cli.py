# SPDX-FileCopyrightText: 2026 CESNET z.s.p.o.
# SPDX-License-Identifier: MIT

"""Command-line interface for enqueueing antivirus scans."""

from __future__ import annotations

import click
from flask.cli import with_appcontext

from .tasks import record_scan, scan_all


@click.group("antivirus")
def antivirus_cli() -> None:
    """Antivirus management commands."""


@antivirus_cli.group("scan")
def antivirus_scan_cli() -> None:
    """Provide commands for scanning records and files."""


@antivirus_scan_cli.command("record")
@click.argument("record_id")
@with_appcontext
def scan_record(record_id: str) -> None:
    """Scan all files attached to a specific record ID."""
    record_scan.delay(record_id)
    click.secho(f"Record '{record_id}' scan is being executed in Celery", fg="green")


@antivirus_scan_cli.command("all")
@with_appcontext
def scan_all_records() -> None:
    """Scan of all files in all published records."""
    scan_all.delay()
    click.secho("Scanning all files of all records in the system", fg="green")
