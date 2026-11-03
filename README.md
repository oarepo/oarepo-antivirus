# OARepo Antivirus

`oarepo-antivirus` adds ClamAV scanning to file processing in an OARepo application. Its registered file processor accepts every file record, scans its stream, and records detections in the file record metadata.

## Requirements

- Python 3.14
- OARepo 14
- A ClamAV daemon reachable by the application at the address configured by
  `ANTIVIRUS_DAEMON_ADDRESS` in `oarepo_antivirus/config.py`

The package uses the `clamd` Python client to communicate with ClamAV. The daemon must be configured to accept network socket connections and support the `INSTREAM` command.

## Installation

Install the package in the environment used by the OARepo application:

```bash
uv pip install oarepo-antivirus
```

The package registers `AntivirusFileProcessor` through the `oarepo.file_processors` entry point. In an application that discovers OARepo file processor entry points.

## Scan behavior

For each file record, `AntivirusFileProcessor` opens the file as a binary stream and passes it to ClamAV using the `INSTREAM` command. ClamAV signatures are reloaded before each scan. A result with status `OK` is treated as clean and leaves the FileRecord metadata unchanged. Any other result stores its details in metadata under `antivirus_detected`:

```json
{
  "antivirus_detected": "Eicar-Test-Signature"
}
```

Exceptions raised while configuring the scanner, opening the stream, or communicating with ClamAV are caught and logged by the processor. Existing metadata is preserved. The processor does not itself reject, quarantine, or delete a file; the host application must enforce any policy based on `antivirus_detected`.

The default scanner address is defined by `ANTIVIRUS_DAEMON_ADDRESS` in
`oarepo_antivirus/config.py` (`127.0.0.1:3310`). To change the package default,
edit that setting:

```python
ANTIVIRUS_DAEMON_ADDRESS = {"ip": "clamav", "port": 3310}
```

You can also override the setting in the OARepo application's Flask
configuration, for example:

```python
ANTIVIRUS_DAEMON_ADDRESS = {"ip": "clamav", "port": 3310}
```

The file processor reads this setting from the active Flask application when it scans a file. ClamAV is asked to reload its signatures before each stream scan.

## Testing

Before running the tests, start the ClamAV test service by executing the Docker
Compose setup script:

```bash
tests/docker/test-setup.sh start
```

The script uses `tests/docker/docker-compose.yaml` to start the service. Stop
the service after testing with:

```bash
tests/docker/test-setup.sh stop
```

## Scan a record from the command line

The package provides an Invenio CLI command to enqueue a scan of all files attached to an RDM record. It runs through Celery, so a worker must be running:

```bash
invenio antivirus scan record <record-id>
```

The command reports that the scan was enqueued; it does not wait for the scan to finish.

## Scan all records from the command line

To enqueue a scan of all published records from all registered OARepo RDM
metadata models:

```bash
invenio antivirus scan all
```

The task iterates `current_runtime.models`, selects each model whose service is
an `RDMRecordService`, and scans its records through that model's own service.
It therefore covers multiple metadata models.
Records with files disabled are skipped. Draft records and media-file services are not included.
The command requires a running Celery worker.

## Antivirus notifications

The package emits an `antivirus-scan.failure` notification to the user who
uploaded the record when a scan detects a threat or cannot contact the scanner.
The application must have the standard Invenio Notifications email backend,
Celery, and mail settings configured. No notification is sent if the record
owner cannot be resolved or has no email address.

## Direct use

The scanner wrapper can also be used without the file processor:

```python
from oarepo_antivirus.services.files.antivirus_wrapper import Antivirus

with open("upload.bin", "rb") as stream:
    result = Antivirus.scan_stream(stream, {"ip": "127.0.0.1", "port": 3310})

if result.is_ok:
    print("File is clean")
else:
    print(f"Scan reported: {result.details}")
```

`Antivirus.scan_stream` returns an `AntivirusResult`. Its `is_ok` property is true only for a clean `OK` status, and `details` contains the detection name or scanner response details when the status is not `OK`. Connection and stream exceptions are raised by the wrapper; the file processor catches and logs them.
