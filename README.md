# OARepo Antivirus

`oarepo-antivirus` adds ClamAV scanning to file processing in an OARepo application. Its registered file processor scans uploaded file streams and records scan failures or detections in the file record metadata.

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

The package registers `AntivirusFileProcessor` through the `oarepo.file_processors` entry point. In an application that discovers OARepo file processor entry points, no additional processor registration is needed. The Flask extension is also registered through the standard Invenio application entry points.

## Scan behavior

For each file record, `AntivirusFileProcessor` opens the file as a binary stream and passes it to ClamAV. A result with status `OK` is treated as clean and leaves the FileRecord metadata unchanged. Any other ClamAV result stores its details in metadata under `malicious_code_detected`:

```json
{
  "malicious_code_detected": "Eicar-Test-Signature"
}
```

Exceptions raised while configuring the scanner, opening the stream, or communicating with ClamAV are caught and stored under `antivirus_error`. Existing metadata is preserved. The processor does not itself reject, quarantine, or delete a file; the host application must enforce any policy based on these metadata fields.

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

## Scan a record from the command line

The package provides a Flask CLI command to enqueue a scan of all files attached to an RDM record. It runs through Celery, so a worker must be running:

```bash
flask antivirus scan record <record-id>
```

The command reports that the scan was enqueued; it does not wait for the scan to finish.

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

`Antivirus.scan_stream` returns an `AntivirusResult`. Its `is_ok` property is true only for a clean `OK` status, and `details` contains the detection name or scanner response details when the status is not `OK`. Connection and stream exceptions are raised by the wrapper; the file processor catches them and records them as `antivirus_error`.
