#!/usr/bin/env python3
"""Report ticket attachments and reply/comment checksums from RT REST2."""

from __future__ import annotations

import argparse
import base64
from contextlib import nullcontext
import hashlib
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, Request, build_opener
from rt_report_writer import JSONReportWriter
from rt_auth import load_auth


API_SUFFIX = "/REST/2.0"
PAGE_SIZE = 100
UPDATE_TYPES = {"correspond", "comment"}
RT_SYSTEM_CREATORS = {"the rt system itself", "rt_system", "rtsystem"}


class RTError(Exception):
    """An RT API or response error suitable for displaying to the user."""


class RTClient:
    def __init__(self, server: str, token: str, timeout: int, insecure: bool) -> None:
        if "://" not in server:
            server = "https://" + server
        parsed = urlsplit(server.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RTError("--server must be a hostname or an http(s) URL")
        if parsed.query or parsed.fragment:
            raise RTError("--server must not include a query string or fragment")

        root = parsed.geturl().rstrip("/")
        self.api_base = root if root.lower().endswith(API_SUFFIX.lower()) else root + API_SUFFIX
        self.token = token
        self.timeout = timeout
        handlers = [HTTPSHandler(context=ssl._create_unverified_context())] if insecure else []
        self.opener = build_opener(*handlers)

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = self.api_base + "/" + path.lstrip("/")
        if params:
            url += "?" + urlencode(params, doseq=True)
        return self._request_json(url)

    def _request_json(self, url: str) -> Any:
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": "token " + self.token,
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            endpoint = urlsplit(url).path
            hint = (
                " Check that the token is valid, active, unexpired, and that RT or its web server passes the Authorization header through."
                if exc.code == 401
                else ""
            )
            raise RTError(
                f"RT returned HTTP {exc.code} for {request.get_method()} {endpoint}: "
                f"{detail}.{hint}"
            ) from None
        except URLError as exc:
            raise RTError(f"Could not connect to RT: {exc.reason}") from None

        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RTError(f"RT returned an invalid JSON response: {exc}") from None

    def collection(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return list(self.iter_collection(path, params))

    def iter_collection(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        page = 1
        while True:
            page_params = dict(params or {})
            page_params.update({"page": page, "per_page": PAGE_SIZE})
            result = self.get_json(path, page_params)
            if not isinstance(result, dict) or not isinstance(result.get("items"), list):
                raise RTError(f"Unexpected collection response from {path}")
            page_items = result["items"]
            for item in page_items:
                if isinstance(item, dict):
                    yield item

            pages = result.get("pages")
            if pages is not None:
                if page >= int(pages):
                    break
            elif len(page_items) < PAGE_SIZE:
                break
            page += 1


def md5_hex(data: bytes) -> str | None:
    try:
        return hashlib.md5(data).hexdigest()
    except (ValueError, TypeError):
        return None


def value_id(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    return str(value) if value is not None else None


def is_rt_system_status(transaction_type: Any, creator: Any) -> bool:
    if str(transaction_type or "").strip().casefold() != "status":
        return False
    if isinstance(creator, dict):
        creator_values = (creator.get("id"), creator.get("name"), creator.get("Name"))
    else:
        creator_values = (creator,)
    return any(
        str(value or "").strip().casefold() in RT_SYSTEM_CREATORS
        for value in creator_values
    )


def load_queue(client: RTClient, queue: str) -> dict[str, Any]:
    encoded_queue = quote(queue, safe="")
    result = client.get_json("queue/" + encoded_queue)
    if not isinstance(result, dict) or not result.get("id"):
        raise RTError(f"Could not resolve queue {queue!r}")
    return result


def ticket_updates(client: RTClient, ticket_id: str) -> tuple[list[dict[str, Any]], str | None]:
    history = client.collection(f"ticket/{quote(ticket_id, safe='')}/history")
    updates: list[dict[str, Any]] = []
    content_by_id: dict[str, bytes] = {}
    all_content_available = True

    for entry in history:
        update_type = str(entry.get("Type", entry.get("type", "")))
        if is_rt_system_status(update_type, entry.get("Creator", entry.get("creator"))):
            continue
        if update_type.lower() not in UPDATE_TYPES:
            continue

        transaction_id = value_id(entry)
        if transaction_id is None:
            updates.append({
                "id": None,
                "type": update_type,
                "created": entry.get("Created"),
                "content_md5": None,
                "content_size_bytes": None,
            })
            all_content_available = False
            continue

        transaction = client.get_json("transaction/" + quote(transaction_id, safe=""))
        if isinstance(transaction, dict) and is_rt_system_status(
            update_type,
            transaction.get("Creator", transaction.get("creator")),
        ):
            continue
        content = transaction.get("Content") if isinstance(transaction, dict) else None
        content_bytes = content.encode("utf-8") if isinstance(content, str) else None
        updates.append({
            "id": transaction_id,
            "type": update_type,
            "created": transaction.get("Created", entry.get("Created")),
            "content_md5": md5_hex(content_bytes) if content_bytes is not None else None,
            "content_size_bytes": len(content_bytes) if content_bytes is not None else None,
        })
        if content_bytes is None:
            all_content_available = False
        else:
            content_by_id[transaction_id] = content_bytes

    updates.sort(key=lambda update: int(update["id"]) if str(update["id"]).isdigit() else -1)
    try:
        aggregate = hashlib.md5()
        for update in updates:
            content_bytes = content_by_id.get(update["id"])
            if content_bytes is not None:
                aggregate.update(content_bytes)
        aggregate_md5 = aggregate.hexdigest() if all_content_available else None
    except ValueError:
        aggregate_md5 = None
    return updates, aggregate_md5


def ticket_attachments(
    client: RTClient,
    ticket_id: str,
    contents: dict[str, bytes] | None = None,
) -> list[dict[str, Any]]:
    entries = client.collection(f"ticket/{quote(ticket_id, safe='')}/attachments")
    attachments: list[dict[str, Any]] = []
    for entry in entries:
        attachment_id = value_id(entry)
        detail = (
            client.get_json("attachment/" + quote(attachment_id, safe=""))
            if attachment_id is not None
            else entry
        )
        content = detail.get("Content") if isinstance(detail, dict) else None
        size_bytes: int | None = None
        checksum: str | None = None
        error: str | None = None

        if isinstance(content, str):
            try:
                raw_content = base64.b64decode("".join(content.split()), validate=True)
                size_bytes = len(raw_content)
                checksum = md5_hex(raw_content)
                if contents is not None and attachment_id is not None:
                    contents[str(attachment_id)] = raw_content
            except (ValueError, TypeError):
                error = "Attachment content was not valid base64"
        else:
            reported_size = detail.get("ContentLength") if isinstance(detail, dict) else None
            if reported_size is not None:
                try:
                    size_bytes = int(reported_size)
                except (TypeError, ValueError):
                    pass
            error = "Attachment content was not available"

        attachments.append({
            "id": attachment_id,
            "filename": detail.get("Filename", detail.get("FileName")) if isinstance(detail, dict) else None,
            "content_type": detail.get("ContentType", detail.get("FileType")) if isinstance(detail, dict) else None,
            "size_bytes": size_bytes,
            "md5": checksum,
            "error": error,
        })
    return attachments


def build_report(client: RTClient, queue_arg: str, writer: JSONReportWriter) -> None:
    print(f"Connecting to RT REST2 at {client.api_base}", file=sys.stderr)
    print(f"Resolving queue {queue_arg!r}...", file=sys.stderr)
    queue = load_queue(client, queue_arg)
    queue_id = str(queue["id"])
    writer.set_queue({"id": queue_id, "name": queue.get("Name")})
    print(f"Resolved queue {queue.get('Name', queue_arg)!r} (ID {queue_id})", file=sys.stderr)
    print("Searching for tickets in the queue...", file=sys.stderr)
    tickets = client.iter_collection(
        "tickets",
        {
            "query": f"Queue = '{queue_id}'",
            "fields": "Subject,Created,Queue",
            "orderby": "id",
            "order": "ASC",
        },
    )

    for index, item in enumerate(tickets, start=1):
        ticket_id = value_id(item)
        if ticket_id is None:
            continue
        if writer.should_skip_ticket(ticket_id):
            continue
        print(f"Processing ticket {index} (ID {ticket_id})...", file=sys.stderr)
        details = client.get_json("ticket/" + quote(ticket_id, safe=""))
        attachments = ticket_attachments(client, ticket_id)
        updates, updates_md5 = ticket_updates(client, ticket_id)
        writer.write_ticket({
            "id": ticket_id,
            "subject": details.get("Subject", item.get("Subject")),
            "created": details.get("Created", item.get("Created")),
            "attachment_count": len(attachments),
            "attachments": attachments,
            "reply_comment_count": len(updates),
            "reply_comment_updates": updates,
            "reply_comment_content_md5": updates_md5,
        })

    print(f"Finished processing {writer.ticket_count} ticket(s)", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report attachments and reply/comment checksums for every ticket in an RT queue."
    )
    parser.add_argument("queue", help="RT queue name or numeric ID")
    parser.add_argument("--server", help="RT hostname or base URL, optionally including an installation path")
    parser.add_argument(
        "--token",
        help="RT authentication token (visible in process listings and shell history)",
    )
    parser.add_argument("--auth-file", type=Path, help="JSON credentials file containing an rt5 object")
    parser.add_argument("--output", type=Path, help="write JSON to this file instead of stdout")
    parser.add_argument("--state-file", type=Path, help="checkpoint path (defaults to OUTPUT.state.json)")
    parser.add_argument("--resume", action="store_true", help="resume from the output and state files")
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout in seconds (default: 60)")
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="accept HTTPS certificates without validation (insecure; use only when necessary)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        auth = load_auth(args.auth_file, "rt5") if args.auth_file else {}
        server = args.server or auth.get("url")
        token = args.token or auth.get("token")
        if not server or not token:
            raise RTError("provide --auth-file with rt5 credentials, or both --server and --token")
        if args.resume and args.output is None:
            raise RTError("--resume requires --output")
        if args.state_file is not None and args.output is None:
            raise RTError("--state-file requires --output")
        state_path = args.state_file or (Path(str(args.output) + ".state.json") if args.output else None)
        output_context = (
            args.output.open("r+b" if args.resume else "w+b")
            if args.output
            else nullcontext(sys.stdout.buffer)
        )
        with output_context as output_stream:
            root = server if "://" in server else "https://" + server
            root = root.rstrip("/")
            api_base = root if root.lower().endswith(API_SUFFIX.lower()) else root + API_SUFFIX
            notes = {
                "attachment_md5": "MD5 of decoded raw attachment bytes.",
                "update_md5": "MD5 of UTF-8 transaction Content; aggregate concatenates available contents in transaction ID order with no separators.",
                "unavailable_content": "A null checksum means RT did not return content or MD5 was unavailable.",
            }
            writer = JSONReportWriter(
                output_stream,
                api_base,
                notes,
                state_path,
                args.output,
                args.resume,
            )
            try:
                client = RTClient(server, token, args.timeout, args.insecure)
                if urlsplit(client.api_base).scheme != "https":
                    print("Warning: the RT token is being sent without HTTPS.", file=sys.stderr)
                build_report(client, args.queue, writer)
            except BaseException as exc:
                writer.close(f"{type(exc).__name__}: {exc}")
                raise
            else:
                writer.close()
            if args.output:
                print(f"Report written to {args.output}", file=sys.stderr)
            else:
                print("Report written to standard output", file=sys.stderr)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())