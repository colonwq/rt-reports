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

Add `--debug` to print request paths and HTTP/RT response statuses to standard error while the report is generated. Debug output does not include credentials, cookies, or response bodies.

If the RT server uses a certificate that cannot be validated, add `-k` (or `--insecure`) to accept it:

```powershell
python rt_queue_audit_rt44.py "General" --server https://rt.example.com --username alice -k
```

This disables TLS certificate validation and makes the connection vulnerable to interception. Prefer installing or trusting the correct CA certificate instead.

REST 1.0 reports attachment data through a legacy content endpoint. The script hashes the returned content bytes; depending on RT's encoding of a particular attachment, those bytes may not reproduce the original uploaded binary exactly.

### Automatic Retry Wrapper

On Linux, macOS, or another Bash environment, use the wrapper to restart the audit after a nonzero exit. It retries with `--resume` and prints the restart count and total elapsed time after success:

```bash
bash run_rt_queue_audit_rt44.sh "General" --server https://rt.example.com --username alice --output rt44-report.json
```

The RT 5.0.10 wrapper uses the same pattern:

```bash
bash run_rt_queue_audit.sh "General" --server https://rt.example.com --token "$RT_TOKEN" --output rt5-report.json
```

Both wrappers require `--output`; the audit state file is needed to resume. They retry indefinitely while a checkpoint exists, waiting a randomized 0–36 seconds between attempts by default. Set `RT_RETRY_DELAY_SECONDS` to use a fixed delay instead. Press Ctrl+C to stop retrying. If the audit exits before creating a checkpoint (such as invalid arguments or an unwritable output path), the wrapper stops and returns the failure status instead of repeating an unrecoverable run. Set `PYTHON` to select a Python executable other than `python3`.

## Compare Reports

After generating reports from both systems, compare them with `compare_rt_reports.py`:

```powershell
python compare_rt_reports.py rt44-report.json rt5-report.json --output comparison.json
```

The comparison JSON summarizes matched and missing tickets, attachments missing from either report, attachments with changed checksums, and reply/comment messages with differing content hashes or present on only one side. Tickets are matched by ID first, then by a unique subject and creation-time pair if IDs differ. Attachments are matched by MD5, then filename and size; messages are paired by type and creation time. `from_right` means present only in the first (left) input; `from_left` means present only in the second (right) input. RT 4.4 attachment encoding can produce checksum differences even when source files are the same, so review those differences with the RT 4.4 encoding caveat above.

## RT 5.0.10 Usage

The queue is the positional argument and may be its name or numeric ID. If `--server` is given as a bare hostname, the script assumes HTTPS and appends `/REST/2.0`. A server URL may include an RT installation path, for example `https://rt.example.com/rt`.

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --token "RT_TOKEN"
```

To save the JSON report to a file, use `--output`:

```powershell
python rt_queue_audit.py 3 --server https://rt.example.com/rt --token "RT_TOKEN" --output rt-report.json
```

The RT 5 script supports the same `-k`/`--insecure` option if certificate validation must be disabled. The TLS warning above applies.

The RT 5 script uses RT's token authentication header (`Authorization: token ...`); it no longer accepts a username/password. Treat the token as a secret: command-line arguments can be exposed in shell history or process listings. Use HTTPS for requests.

### Options

| Option | Description |
| --- | --- |
| `queue` | Required queue name or ID. |
| `--server` | Required RT hostname or base URL. A missing scheme defaults to HTTPS. |
| `--token` | Required RT authentication token. |
| `--output` | Optional path for the JSON report. Without it, JSON is written to standard output. |
| `--timeout` | HTTP timeout in seconds; defaults to `30`. |
| `-k`, `--insecure` | Accept HTTPS certificates without validation. Use only when necessary. |

Audit scripts return `0` on success and a nonzero status on failure. The Bash wrappers use this status to decide when to resume.

## Report Contents

The JSON report includes queue details and a ticket entry for each matching ticket. Each ticket contains its ID, subject, creation time, attachment count and attachment records, plus reply/comment transaction records.

Both audit scripts stream each completed ticket directly to the output rather than retaining the full report in memory. Summary counts and sizes are written when processing finishes. If an error occurs after output has started, the scripts close the JSON structure and mark it with `"complete": false` plus an `error` message; tickets completed before the failure remain available. A normally finished report has `"complete": true`.

When `--output` is used, each script creates a checkpoint file beside the report, named `<output>.state.json`. To continue an interrupted run, repeat the same command with `--resume`:

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --token "RT_TOKEN" --output rt-report.json --resume
```

For RT 4.4.3, use the same `--resume` option with `rt_queue_audit_rt44.py`. The state records the last fully written ticket ID, output byte offset, and summary counters. Resume truncates any incomplete JSON written after that checkpoint, preserves completed tickets, and continues with higher ticket IDs. Use the same queue, server, output path, and state file as the original run. A custom checkpoint path can be supplied with `--state-file` on both the original and resumed commands. Keep the state file until the report is complete; it can be deleted afterward.

Each attachment record includes its ID, filename, content type, size in bytes, and MD5 checksum. The total attachment count and the sum of available attachment sizes are included at the report level.

Each reply/comment record includes its transaction ID and type, creation time, UTF-8 content size, and MD5 checksum. The ticket-level `reply_comment_content_md5` is an aggregate MD5 of transaction `Content` values encoded as UTF-8 and concatenated in transaction ID order without separators. This aggregate is `null` if RT does not return content for any selected transaction.

A `null` individual checksum indicates the content could not be retrieved or MD5 was unavailable. Attachment size may still be reported when RT provides a length even if its content is unavailable. The report contains checksums and metadata, not attachment or reply bodies.

## Errors and Permissions

The RT account must have access to the data being audited. If RT does not expose a ticket, transaction, or attachment to that account, the report may omit it or report unavailable content. HTTP/API errors are printed to standard error and the script exits with status `2`.
