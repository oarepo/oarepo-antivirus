import click
from flask.cli import with_appcontext
from .tasks import record_scan

@click.group("antivirus")
def antivirus_cli():
    """Antivirus management commands."""
    pass

@antivirus_cli.group("scan")
def antivirus_scan_cli():
    """Antivirus scanning commands."""
    pass

@antivirus_scan_cli.command("record")
@click.argument("record_id")
@with_appcontext
def scan_record(record_id: str) -> None:
    """Scan all files attached to a specific record ID."""
    record_scan.delay(record_id)
    click.secho(f"Record '{record_id}' scan is being executed in Celery", fg="green")