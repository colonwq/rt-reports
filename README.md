# RT Queue Audit

`rt_queue_audit.py` audits tickets currently in a queue on Best Practical Request Tracker (RT) 5.0.10 using its REST2 API. It uses only the Python standard library; no packages need to be installed.

## Requirements

- Python 3.9 or later
- An RT account with permission to view the queue, tickets, ticket histories, and attachments
- REST2 access for RT 5.0.10, or REST 1.0 access for RT 4.4.3
- HTTPS is recommended to protect credentials in transit

## Credentials File

The repository includes an `example-auth.json` template with placeholder values. Copy it to a local credentials file and replace the placeholders with your RT credentials. The RT4 `password` and RT5 `token` values in this file must be Base64-encoded UTF-8 strings; the `name` and `url` values remain plain text. Its structure is:

```json
{
	"rt4": {
		"url": "https://rt44.example.com",
		"name": "rt4-user-name",
		"password": "replace-with-rt4-password"
	},
	"rt5": {
		"url": "https://rt5.example.com",
		"token": "replace-with-rt5-token"
	}
}
```

Use `--auth-file example-auth.json` (or your local credentials file) with either queue audit script. The RT 4.4.3 `name` is the login username; each `url` is the server base URL, optionally including an installation path. Base64 is an encoding, not encryption; protect the credentials file and keep real credentials out of version control.

Generate the encoded values from the plain-text password or token. In PowerShell:

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('your-rt4-password'))
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('your-rt5-token'))
```

In Bash, with GNU `base64`:

```bash
printf %s 'your-rt4-password' | base64
printf %s 'your-rt5-token' | base64
```

Paste each result into the corresponding `password` or `token` field in your local JSON file. The scripts decode those fields before authenticating. Existing `--password` and `--token` command-line options continue to accept plain-text values.

## RT 4.4.3

RT 4.4.3 uses the legacy REST 1.0 API. Run `rt_queue_audit_rt44.py` for that server; it logs in to REST 1.0 and keeps the session cookie for subsequent requests.

```powershell
python rt_queue_audit_rt44.py "General" --server https://rt.example.com --username alice --output rt44-report.json
```

To read connection details and credentials from `example-auth.json` instead:

```powershell
python rt_queue_audit_rt44.py "General" --auth-file example-auth.json --output rt44-report.json
```

The queue may also be specified by numeric ID. If the password is omitted, the script prompts for it. As with the RT 5 script, supplying `--password` is supported but can expose it in shell history or process listings. The RT 4.4.3 request connect/read timeout defaults to 300 seconds for large tickets; override it with `--timeout` if needed.

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

## RT 5.0.10 Usage

The queue is the positional argument and may be its name or numeric ID. If `--server` is given as a bare hostname, the script assumes HTTPS and appends `/REST/2.0`. A server URL may include an RT installation path, for example `https://rt.example.com/rt`.

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --token "RT_TOKEN"
```

With credentials from `example-auth.json`:

```powershell
python rt_queue_audit.py "General" --auth-file example-auth.json
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
| `--timeout` | HTTP connect/read timeout in seconds; defaults to `300` for RT 4.4.3 and `60` for RT 5.0.10. |
| `--debug` | Log the selected auth source (secrets redacted), request paths/statuses, timestamps, and ticket/attachment progress to standard error. |
| `-k`, `--insecure` | Accept HTTPS certificates without validation. Use only when necessary. |

Audit scripts return `0` on success and `1` on a handled error. The Bash wrappers use this status to decide when to resume.

## Compare Reports

After generating reports from both systems, compare them with `compare_rt_reports.py`:

```powershell
python compare_rt_reports.py rt44-report.json rt5-report.json --output comparison.json
```

In Bash, run the same comparison with:

```bash
python3 compare_rt_reports.py rt44-report.json rt5-report.json --output comparison.json
```

### Verify One Ticket Directly

`audit_rt_ticket.py` fetches one ticket from each RT system, then applies the same ticket, attachment, and reply/comment comparison rules as the report comparer. If IDs differ between systems, pass both IDs; otherwise `--ticket-id` can be used for both:

```bash
python3 audit_rt_ticket.py --auth-file example-auth.json --ticket-id 12345 --output ticket-comparison.json
python3 audit_rt_ticket.py --auth-file example-auth.json --rt4-ticket-id 12345 --rt5-ticket-id 67890 --output ticket-comparison.json
```

The verifier prints the comparison JSON to standard output when `--output` is omitted. A ticket that returns HTTP 404 on one side appears as missing in the comparison.

Attachments present on only one side are also extracted beside the output file under `<RT4-ticket-id>/missing_left/` or `<RT4-ticket-id>/missing_right/`. The folder name indicates which side lacks the attachment. Existing attachment filenames are used when available; otherwise files are named `missing-001.txt`, `missing-002.txt`, and so on. The comparison JSON lists extracted paths and any contents that RT did not make available.

Alongside `comparison.json`, this writes four focused JSON reports: `comparison_missing_tickets.json`, `comparison_ticket_metadata_differences.json`, `comparison_attachment_differences.json`, and `comparison_attachment_content_differences.json`. They cover tickets present in only one input, ticket ID/title/creation-date/attachment-count changes, attachment ID/type/name changes or missing attachments, and attachment size/MD5 changes, respectively. The aggregate comparison JSON also includes these categories and the existing reply/comment message comparison.

Tickets are matched by ID first, then by a unique normalized subject and creation-time pair if IDs differ. Creation timestamps with an explicit timezone (such as RT 5's UTC timestamps) are compared as instants; timezone-naive RT 4.4 timestamps are interpreted as local time in `America/Chicago`. Attachments are paired by ID, then filename and type/name, so changed size or checksum can be reported separately from attachment metadata changes. `from_right` means present only in the first (left) input; `from_left` means present only in the second (right) input. RT 4.4 attachment encoding can produce checksum differences even when source files are the same, so review those differences with the RT 4.4 encoding caveat above. The audit JSON does not associate attachments or ticket metadata with a transaction, so those report entries have a null transaction ID and URL rather than an inferred link.

## Report Contents

The JSON report includes queue details and a ticket entry for each matching ticket. Each ticket contains its ID, subject, creation time, last-updated time, attachment count and attachment records, plus reply/comment transaction records. Attachment records include the attachment creation/add time when RT provides it.

When comparing systems, changes are considered only through the other system's ticket `last_updated` time. Reply/comment updates and attachments added after that time are excluded for missing-item checks, in both comparison directions. Attachment counts are computed from the attachments within that comparison window.

Both audit scripts stream each completed ticket directly to the output rather than retaining the full report in memory. Summary counts and sizes are written when processing finishes. If an error occurs after output has started, the scripts close the JSON structure and mark it with `"complete": false` plus an `error` message; tickets completed before the failure remain available. A normally finished report has `"complete": true`. The RT 4.4.3 request connect/read timeout defaults to 300 seconds; RT 5.0.10 defaults to 60 seconds.

When `--output` is used, each script creates a checkpoint file beside the report, named `<output>.state.json`. To continue an interrupted run, repeat the same command with `--resume`:

```powershell
python rt_queue_audit.py "General" --server https://rt.example.com --token "RT_TOKEN" --output rt-report.json --resume
```

For RT 4.4.3, use the same `--resume` option with `rt_queue_audit_rt44.py`. The state records the last fully written ticket ID, output byte offset, and summary counters. Resume truncates any incomplete JSON written after that checkpoint, preserves completed tickets, and continues with higher ticket IDs. Use the same queue, server, output path, and state file as the original run. A custom checkpoint path can be supplied with `--state-file` on both the original and resumed commands. Keep the state file until the report is complete; it can be deleted afterward.

Each attachment record includes its ID, filename, content type, size in bytes, and MD5 checksum. The total attachment count and the sum of available attachment sizes are included at the report level.

Each reply/comment record includes its transaction ID and type, creation time, UTF-8 content size, and MD5 checksum. The ticket-level `reply_comment_content_md5` is an aggregate MD5 of transaction `Content` values encoded as UTF-8 and concatenated in transaction ID order without separators. This aggregate is `null` if RT does not return content for any selected transaction.

A `null` individual checksum indicates the content could not be retrieved or MD5 was unavailable. Attachment size may still be reported when RT provides a length even if its content is unavailable. The report contains checksums and metadata, not attachment or reply bodies.

## Errors and Permissions

The RT account must have access to the data being audited. If RT does not expose a ticket, transaction, or attachment to that account, the report may omit it or report unavailable content. HTTP/API errors are printed to standard error and the script exits with status `1`.
