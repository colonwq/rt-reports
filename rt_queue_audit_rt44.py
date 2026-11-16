#!/usr/bin/env python3
"""Audit RT 4.4 tickets using the legacy REST 1.0 interface."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.cookiejar
import json
import re
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener


API_SUFFIX = "/REST/1.0"
FIELD_LINE = re.compile(r"^([^:\r\n]+):(?: ?(.*))?$")
UPDATE_TYPES = {"correspond", "comment"}


class RTError(Exception):
    """An RT API or response error suitable for displaying to the user."""


class RTClient:
    def __init__(self, server: str, username: str, password: str, timeout: int, insecure: bool) -> None:
        if "://" not in server:
            server = "https://" + server
        parsed = urlsplit(server.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RTError("--server must be a hostname or an http(s) URL")
        if parsed.query or parsed.fragment:
            raise RTError("--server must not include a query string or fragment")

        root = parsed.geturl().rstrip("/")
        self.api_base = root if root.lower().endswith(API_SUFFIX.lower()) else root + API_SUFFIX
        self.timeout = timeout
        handlers = [HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if insecure:
            handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = build_opener(*handlers)
        self.login(username, password)

    def login(self, username: str, password: str) -> None:
        # REST 1.0 uses an RT session cookie, not HTTP Basic authentication.
        self.request_bytes("", form={"user": username, "pass": password})

    def request_bytes(
        self,
        path: str,
        params: dict[str, str] | None = None,
        form: dict[str, str] | None = None,
    ) -> bytes:
        url = self.api_base + "/" + path.lstrip("/")
        if params:
            url += "?" + urlencode(params)
        data = urlencode(form).encode("utf-8") if form is not None else None
        request = Request(
            url,
            data=data,
            headers={"Accept": "text/plain"},
        )
        if data is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RTError(f"RT returned HTTP {exc.code}: {detail}") from None
        except URLError as exc:
            raise RTError(f"Could not connect to RT: {exc.reason}") from None

        first_line = payload.splitlines()[0].decode("ascii", errors="ignore") if payload else ""
        status = re.match(r"^RT/\S+\s+(\d{3})\b", first_line)
        if status and int(status.group(1)) >= 400:
            raise RTError(f"RT returned {first_line}: {payload.decode('utf-8', errors='replace')}")
        return payload

    def get_text(self, path: str, params: dict[str, str] | None = None) -> str:
        return self.request_bytes(path, params).decode("utf-8", errors="replace")


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current_key: str | None = None
    for line in text.splitlines():
        if line.startswith("RT/"):
            continue
        if current_key is None and line.lstrip().startswith("#"):
            continue
        match = FIELD_LINE.match(line) if not line.startswith((" ", "\t")) else None
        if match:
            key = match.group(1).strip()
            value = match.group(2) or ""
            if key in fields:
                fields[key] += "\n" + value
            else:
                fields[key] = value
            current_key = key
        elif current_key is not None:
            continuation = line[1:] if line.startswith(" ") else line
            fields[current_key] += "\n" + continuation
    return fields


def md5_hex(data: bytes) -> str | None:
    try:
        return hashlib.md5(data).hexdigest()
    except (ValueError, TypeError):
        return None


def ticket_ids(search_response: str) -> list[str]:
    found = re.findall(r"\bticket/(\d+)\b", search_response)
    return list(dict.fromkeys(found))


def attachment_ids(response: str) -> list[str]:
    found: list[str] = []
    patterns = (
        r"(?m)^\s*(?:id:\s*)?(?:attachment|attachments)/(\d+)\s*$",
        r"(?m)^\s*id:\s*ticket/\d+/attachments/(\d+)\s*$",
        r"(?m)^\s*(\d+)\s*:\s*[^\r\n]*$",
    )
    for pattern in patterns:
        found.extend(re.findall(pattern, response))
    return list(dict.fromkeys(found))


def history_records(response: str) -> list[dict[str, str]]:
    records = re.split(r"(?m)^--\s*$", response)
    return [parse_fields(record) for record in records if "Type:" in record]


def extract_attachment_bytes(response: bytes) -> bytes:
    """Remove the two REST 1.0 response preamble lines from /content."""
    if not response.startswith(b"RT/"):
        raise RTError("Attachment content response did not contain an RT status line")
    _, first_sep, remainder = response.partition(b"\n")
    if not first_sep:
        raise RTError("Attachment content response was incomplete")
    _, second_sep, content = remainder.partition(b"\n")
    if not second_sep:
        raise RTError("Attachment content response was incomplete")
    return content


def resolve_queue(client: RTClient, queue_arg: str) -> tuple[str, str | None]:
    if queue_arg.isdigit():
        fields = parse_fields(client.get_text("queue/" + quote(queue_arg, safe="")))
        name = fields.get("Name")
        if not name:
            raise RTError(f"Could not resolve queue ID {queue_arg!r}")
        return name.strip(), queue_arg
    return queue_arg, None


def list_ticket_ids(client: RTClient, queue_name: str) -> list[str]:
    escaped_name = queue_name.replace("\\", "\\\\").replace("'", "\\'")
    response = client.get_text(
        "search/ticket",
        {"query": f"Queue = '{escaped_name}'", "format": "i"},
    )
    return ticket_ids(response)


def ticket_attachments(client: RTClient, ticket_id: str) -> list[dict[str, Any]]:
    ticket_path = "ticket/" + quote(ticket_id, safe="")
    listing = client.get_text(ticket_path + "/attachments")
    results: list[dict[str, Any]] = []

    for attachment_id in attachment_ids(listing):
        detail: dict[str, str] = {}
        detail_error: str | None = None
        try:
            detail = parse_fields(
                client.get_text(ticket_path + "/attachments/" + quote(attachment_id, safe=""))
            )
        except RTError as exc:
            detail_error = str(exc)

        size_bytes: int | None = None
        checksum: str | None = None
        content_error: str | None = None
        try:
            response = client.request_bytes(
                ticket_path + "/attachments/" + quote(attachment_id, safe="") + "/content"
            )
            raw_content = extract_attachment_bytes(response)
            size_bytes = len(raw_content)
            checksum = md5_hex(raw_content)
        except RTError as exc:
            content_error = str(exc)

        length_match = re.search(r"(?im)^Content-Length:\s*(\d+)\s*$", "\n".join(detail.values()))
        if size_bytes is None and length_match:
            size_bytes = int(length_match.group(1))

        results.append({
            "id": attachment_id,
            "filename": detail.get("Filename"),
            "content_type": detail.get("ContentType"),
            "size_bytes": size_bytes,
            "md5": checksum,
            "error": content_error or detail_error,
        })
    return results


def ticket_updates(client: RTClient, ticket_id: str) -> tuple[list[dict[str, Any]], str | None]:
    response = client.get_text(
        "ticket/" + quote(ticket_id, safe="") + "/history",
        {"format": "l"},
    )
    updates: list[dict[str, Any]] = []
    content_by_id: dict[str, bytes] = {}
    complete = True

    for fields in history_records(response):
        update_type = fields.get("Type", "")
        if update_type.lower() not in UPDATE_TYPES:
            continue

        update_id_match = re.search(r"\d+", fields.get("id", ""))
        update_id = update_id_match.group(0) if update_id_match else None
        content = fields.get("Content")
        content_bytes = content.encode("utf-8") if content is not None else None
        updates.append({
            "id": update_id,
            "type": update_type,
            "created": fields.get("Created"),
            "content_md5": md5_hex(content_bytes) if content_bytes is not None else None,
            "content_size_bytes": len(content_bytes) if content_bytes is not None else None,
        })
        if update_id is None or content_bytes is None:
            complete = False
        else:
            content_by_id[update_id] = content_bytes

    updates.sort(key=lambda update: int(update["id"]) if update["id"] else -1)
    try:
        aggregate = hashlib.md5()
        for update in updates:
            content_bytes = content_by_id.get(update["id"])
            if content_bytes is not None:
                aggregate.update(content_bytes)
        aggregate_md5 = aggregate.hexdigest() if complete else None
    except ValueError:
        aggregate_md5 = None
    return updates, aggregate_md5


def build_report(client: RTClient, queue_arg: str) -> dict[str, Any]:
    queue_name, queue_id = resolve_queue(client, queue_arg)
    ids = list_ticket_ids(client, queue_name)
    tickets: list[dict[str, Any]] = []

    for ticket_id in ids:
        fields = parse_fields(client.get_text(f"ticket/{quote(ticket_id, safe='')}/show"))
        attachments = ticket_attachments(client, ticket_id)
        updates, updates_md5 = ticket_updates(client, ticket_id)
        tickets.append({
            "id": ticket_id,
            "subject": fields.get("Subject"),
            "created": fields.get("Created"),
            "attachment_count": len(attachments),
            "attachments": attachments,
            "reply_comment_count": len(updates),
            "reply_comment_updates": updates,
            "reply_comment_content_md5": updates_md5,
        })

    tickets.sort(key=lambda ticket: int(ticket["id"]))
    sizes = [
        attachment["size_bytes"]
        for ticket in tickets
        for attachment in ticket["attachments"]
        if attachment["size_bytes"] is not None
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "server": client.api_base,
        "queue": {"id": queue_id, "name": queue_name},
        "ticket_count": len(tickets),
        "attachment_count": sum(ticket["attachment_count"] for ticket in tickets),
        "attachment_size_bytes": sum(sizes),
        "tickets": tickets,
        "checksum_notes": {
            "attachment_md5": "MD5 of the bytes returned by the REST 1.0 attachment /content endpoint; original binary reconstruction can vary by RT encoding.",
            "update_md5": "MD5 of UTF-8 history Content; aggregate concatenates available contents in transaction ID order with no separators.",
            "unavailable_content": "A null checksum means content was unavailable or MD5 could not be calculated.",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report attachments and reply/comment checksums from an RT 4.4.3 queue."
    )
    parser.add_argument("queue", help="RT queue name or numeric ID")
    parser.add_argument("--server", required=True, help="RT hostname or base URL, optionally including an installation path")
    parser.add_argument("--username", required=True, help="RT username")
    parser.add_argument(
        "--password",
        help="RT password (visible in process listings); omit to enter it securely at the prompt",
    )
    parser.add_argument("--output", type=Path, help="write JSON to this file instead of stdout")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)")
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="accept HTTPS certificates without validation (insecure; use only when necessary)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = args.password if args.password is not None else getpass.getpass("RT password: ")
    try:
        client = RTClient(args.server, args.username, password, args.timeout, args.insecure)
        if urlsplit(client.api_base).scheme != "https":
            print("Warning: credentials are being sent without HTTPS.", file=sys.stderr)
        report = build_report(client, args.queue)
        rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (RTError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
