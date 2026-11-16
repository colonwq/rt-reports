# RT Queue Audit

`rt_queue_audit.py` audits tickets currently in a queue on Best Practical Request Tracker (RT) 5.0.10 using its REST2 API. It uses only the Python standard library; no packages need to be installed.

## Requirements

- Python 3.9 or later
- An RT account with permission to view the queue, tickets, ticket histories, and attachments
- REST2 access for RT 5.0.10, or REST 1.0 access for RT 4.4.3
- HTTPS is recommended to protect credentials in transit

## RT 4.4.3

RT 4.4.3 uses the legacy REST 1.0 API. Run `rt_queue_audit_rt44.py` for that server; it logs in to REST 1.0 and keeps the session cookie for subsequent requests.

```powershell
python rt_queue_audit_rt44.py "General" --server https://rt.example.com --username alice --output rt44-report.json
```

The queue may also be specified by numeric ID. If the password is omitted, the script prompts for it. As with the RT 5 script, supplying `--password` is supported but can expose it in shell history or process listings.

REST 1.0 reports attachment data through a legacy content endpoint. The script hashes the returned content bytes; depending on RT's encoding of a particular attachment, those bytes may not reproduce the original uploaded binary exactly.

## RT 5.0.10 Usage

The queue is the positional argument and may be its name or numeric ID. If `--server` is given as a bare hostname, the script assumes HTTPS and appends `/REST/2.0`. A server URL may include an RT installation path, for example `https://rt.example.com/rt`.

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --username alice
```

The script prompts for the password without echoing it. To save the JSON report to a file, use `--output`:

```powershell
python rt_queue_audit.py 3 --server https://rt.example.com/rt --username alice --output rt-report.json
```

A password can also be supplied explicitly on the command line:

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --username alice --password "your-password" --output rt-report.json
```

Avoid the `--password` form where possible: command-line arguments can be exposed in shell history or process listings. The interactive prompt is safer.

### Options

| Option | Description |
| --- | --- |
| `queue` | Required queue name or ID. |
| `--server` | Required RT hostname or base URL. A missing scheme defaults to HTTPS. |
| `--username` | Required RT username. |
| `--password` | Optional RT password. If omitted, the script securely prompts for it. |
| `--output` | Optional path for the JSON report. Without it, JSON is written to standard output. |
| `--timeout` | HTTP timeout in seconds; defaults to `30`. |

## Report Contents

The JSON report includes queue details and a ticket entry for each matching ticket. Each ticket contains its ID, subject, creation time, attachment count and attachment records, plus reply/comment transaction records.

Each attachment record includes its ID, filename, content type, size in bytes, and MD5 checksum. The total attachment count and the sum of available attachment sizes are included at the report level.

Each reply/comment record includes its transaction ID and type, creation time, UTF-8 content size, and MD5 checksum. The ticket-level `reply_comment_content_md5` is an aggregate MD5 of transaction `Content` values encoded as UTF-8 and concatenated in transaction ID order without separators. This aggregate is `null` if RT does not return content for any selected transaction.

A `null` individual checksum indicates the content could not be retrieved or MD5 was unavailable. Attachment size may still be reported when RT provides a length even if its content is unavailable. The report contains checksums and metadata, not attachment or reply bodies.

## Errors and Permissions

The RT account must have access to the data being audited. If RT does not expose a ticket, transaction, or attachment to that account, the report may omit it or report unavailable content. HTTP/API errors are printed to standard error and the script exits with status `2`.
