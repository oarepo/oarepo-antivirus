# OARepo Antivirus

`oarepo-antivirus` adds ClamAV scanning to file processing in an OARepo
application. It provides a file processor, notification delivery for detected
files, and CLI commands for scanning records.

## Requirements

- Python 3.14
- OARepo 14
- A ClamAV daemon reachable through a network socket
- An OARepo application with Celery configured for task execution

The ClamAV daemon must accept network socket connections and support the
`INSTREAM` command. The package uses the `clamd` Python client.

## Installation

Install the package in the environment used by the OARepo application:

```bash
uv pip install oarepo-antivirus
```

The package registers `AntivirusFileProcessor` through the
`oarepo.file_processors` entry point. Add the processor to the file service
configuration used by the records that should be scanned.

## Configuration

The default ClamAV address is defined by `ANTIVIRUS_DAEMON_ADDRESS` in
`oarepo_antivirus/config.py`:

```python
ANTIVIRUS_DAEMON_ADDRESS = {"ip": "127.0.0.1", "port": 3310}
```

For a Docker-based setup, configure the address with the ClamAV service name
from the application container, for example:

```python
ANTIVIRUS_DAEMON_ADDRESS = {"ip": "clamav", "port": 3310}
```

The setting can be overridden in the OARepo application's `conf.py` or Flask
configuration. The processor reads the active Flask configuration when it
processes a file. ClamAV signatures are reloaded before each scan.

The package registers the `antivirus-scan.failure` notification builder when
the Flask extension is initialized. Its email content is rendered by the
bundled template:

```text
oarepo_antivirus/templates/invenio_notifications/antivirus-scan.failure.jinja
```

Configure the application's standard Invenio Notifications email backend,
mail settings, and Celery worker for delivery.

## Behaviour on RecordFile

`AntivirusFileProcessor` accepts every `FileRecord`. For each record it:

1. Opens the file as a binary stream.
2. Sends the stream to ClamAV using `INSTREAM`.
3. Leaves metadata unchanged when ClamAV returns `OK`.
4. Stores a non-`OK` result in `antivirus_detected`:

   ```json
   {
     "antivirus_detected": "Eicar-Test-Signature"
   }
   ```

5. Queues an `antivirus-scan.failure` email notification for the record owner.
   The notification contains the record ID, file name, and scanner details and
   is rendered using the configured notification template.

The processor does not reject, quarantine, or delete files. The host
application can enforce those policies using the `antivirus_detected` metadata.

### Error handling

Exceptions raised while reading the Flask configuration, opening the file,
reloading signatures, or communicating with ClamAV are caught and logged by
the processor. Existing metadata is preserved and the exception is not
propagated to the file-processing caller.

Notification errors are also isolated from file processing. If the owner
cannot be resolved or has no email address, no notification is sent and a
warning is logged. Failures while building or queueing the notification are
logged and do not undo the `antivirus_detected` metadata update.

## CLI interface

The commands enqueue Celery tasks; they do not wait for scans to finish. A
Celery worker must be running.

Scan all files attached to one record:

```bash
invenio antivirus scan record <record-id>
```

Scan all records returned by the application's current RDM records service:

```bash
invenio antivirus scan all
```

Records whose file service is disabled are skipped. Errors while reading a
record or scanning its files are logged by the Celery task and do not escape
the task invocation. The CLI itself only reports that the task was queued.

## Testing

Start the ClamAV test service from the repository root:

```bash
./test-setup.sh start
```

Run the test suite:

```bash
pytest
```

The script uses `tests/docker/docker-compose.yaml` and accepts `start` and
`stop` commands. Stop the service after testing:

```bash
./test-setup.sh stop
```
