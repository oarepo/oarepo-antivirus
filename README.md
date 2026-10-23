# OARepo Antivirus

`oarepo-antivirus` adds ClamAV scanning to file processing in an OARepo application. Its registered file processor scans uploaded file streams and records scan failures or detections in the file record metadata.

## Requirements

- Python 3.14
- OARepo 14
- A ClamAV daemon reachable by the application at `localhost:3310`

The package uses the `clamd` Python client to communicate with ClamAV. The daemon must be configured to accept network socket connections and support the `INSTREAM` command.

## Installation

Install the package in the environment used by the OARepo application:

```bash
uv pip install oarepo-antivirus
```

The package registers `AntivirusFileProcessor` through the `oarepo.file_processors` entry point. In an application that discovers OARepo file processor entry points, no additional processor registration is needed. The Flask extension is also registered through the standard Invenio application entry points.

## Scan behavior

For each file record, `AntivirusFileProcessor` opens the file as a binary stream and passes it to ClamAV. A result with status `OK` is treated as clean and no modifications are performed on the FileRecord instance. For any other result, the processor stores the scanner details in the FileRecord's metadata under `error`:

```json
{
  "error": "Eicar-Test-Signature"
}
```

The processor does not raise an exception for ClamAV connection or stream-size errors; the wrapper returns these as `ERROR` results, which are likewise recorded in metadata. The processor does not itself reject, quarantine, or delete a file. The host application can use the `error` metadata to apply its own policy.

The scanner address defaults to `127.0.0.1:3310`. Override it in the OARepo application's Flask configuration with `ANTIVIRUS_DAEMON_ADDRESS`, for example:

```python
ANTIVIRUS_DAEMON_ADDRESS = {"ip": "clamav", "port": 3310}
```

The file processor reads this setting from the active Flask application when it scans a file. ClamAV is asked to reload its signatures before each stream scan.

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

`Antivirus.scan_stream` returns an `AntivirusResult`. Its `is_ok` property is true only for a clean `OK` status, and `details` contains the scanner's detection name of case of some virus found or error message in case of some error occurred.
