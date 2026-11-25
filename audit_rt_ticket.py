#!/usr/bin/env python3
"""Compare one ticket fetched directly from RT 4.4.3 and RT 5.0.10."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import compare_rt_reports
import rt_queue_audit as rt5
import rt_queue_audit_rt44 as rt4
from rt_auth import load_auth


def fetch_rt4_ticket(
    client: rt4.RTClient,
    ticket_id: str,
    contents: dict[str, bytes],
) -> dict[str, Any] | None:
    try:
        fields = rt4.parse_fields(client.get_text(f"ticket/{quote(ticket_id, safe='')}/show"))
    except rt4.RTError as exc:
        if "HTTP 404" in str(exc) or "RT 404" in str(exc):
            return None
        raise
    attachments = rt4.ticket_attachments(client, ticket_id, contents)
    updates, updates_md5 = rt4.ticket_updates(client, ticket_id)
    updates = [update for update in updates if not rt4.is_status_transaction(update.get("type"))]
    return {
        "id": ticket_id,
        "subject": fields.get("Subject"),
        "created": fields.get("Created"),
        "last_updated": fields.get("LastUpdated"),
        "attachment_count": len(attachments),
        "attachments": attachments,
        "reply_comment_count": len(updates),
        "reply_comment_updates": updates,
        "reply_comment_content_md5": updates_md5,
    }


def fetch_rt5_ticket(
    client: rt5.RTClient,
    ticket_id: str,
    contents: dict[str, bytes],
) -> dict[str, Any] | None:
    try:
        details = client.get_json("ticket/" + quote(ticket_id, safe=""))
    except rt5.RTError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    if not isinstance(details, dict):
        raise rt5.RTError(f"Unexpected ticket response for RT 5 ticket {ticket_id}")
    attachments = rt5.ticket_attachments(client, ticket_id, contents)
    updates, updates_md5 = rt5.ticket_updates(client, ticket_id)
    updates = [update for update in updates if not rt5.is_status_transaction(update.get("type"))]
    return {
        "id": str(rt5.value_id(details) or ticket_id),
        "subject": details.get("Subject"),
        "created": details.get("Created"),
        "last_updated": details.get("LastUpdated"),
        "attachment_count": len(attachments),
        "attachments": attachments,
        "reply_comment_count": len(updates),
        "reply_comment_updates": updates,
        "reply_comment_content_md5": updates_md5,
    }


def safe_filename(value: Any) -> str | None:
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    if not name or name in {".", ".."}:
        return None
    if re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", name):
        name = "_" + name
    return name


def write_missing_attachment_files(
    ticket_id: str,
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
    left_contents: dict[str, bytes],
    right_contents: dict[str, bytes],
    base_dir: Path,
) -> tuple[list[Path], list[dict[str, Any]]]:
    left_ticket, right_ticket = compare_rt_reports.filter_ticket_changes(left_ticket, right_ticket)
    left_items = compare_rt_reports.ticket_attachment_items(left_ticket)
    right_items = compare_rt_reports.ticket_attachment_items(right_ticket)
    _, missing_from_right, missing_from_left = compare_rt_reports.pair_attachments(left_items, right_items)
    written: list[Path] = []
    unavailable: list[dict[str, Any]] = []

    for folder_name, attachments, contents in (
        ("missing_right", missing_from_right, left_contents),
        ("missing_left", missing_from_left, right_contents),
    ):
        folder = base_dir / str(ticket_id) / folder_name
        fallback_number = 0
        used_names: set[str] = set()
        for attachment in attachments:
            attachment_id = attachment.get("id")
            if attachment_id is None or str(attachment_id) not in contents:
                unavailable.append({
                    "directory": folder_name,
                    "attachment_id": attachment_id,
                    "filename": safe_filename(attachment.get("filename", attachment.get("FileName"))),
                    "reason": "content was not available from RT",
                })
                continue
            filename = safe_filename(attachment.get("filename", attachment.get("FileName")))
            if filename is None:
                fallback_number += 1
                filename = f"missing-{fallback_number:03d}.txt"
            candidate = filename
            duplicate_number = 2
            while candidate.casefold() in used_names:
                path = Path(filename)
                candidate = f"{path.stem}-{duplicate_number}{path.suffix}"
                duplicate_number += 1
            used_names.add(candidate.casefold())
            folder.mkdir(parents=True, exist_ok=True)
            destination = folder / candidate
            destination.write_bytes(contents[str(attachment_id)])
            written.append(destination)
    return written, unavailable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and compare one ticket from RT 4.4.3 and RT 5.0.10."
    )
    parser.add_argument("--auth-file", type=Path, default=Path("example-auth.json"), help="JSON credentials file (default: example-auth.json)")
    parser.add_argument("--ticket-id", help="same ticket ID in both systems")
    parser.add_argument("--rt4-ticket-id", help="RT 4.4.3 ticket ID (overrides --ticket-id)")
    parser.add_argument("--rt5-ticket-id", help="RT 5.0.10 ticket ID (overrides --ticket-id)")
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout in seconds (default: 60)")
    parser.add_argument("-k", "--insecure", action="store_true", help="accept invalid HTTPS certificates")
    parser.add_argument("--debug", action="store_true", help="log RT 4.4.3 REST request paths and statuses")
    parser.add_argument("--output", type=Path, help="write comparison JSON here instead of standard output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rt4_ticket_id = args.rt4_ticket_id or args.ticket_id
    rt5_ticket_id = args.rt5_ticket_id or args.ticket_id
    if not rt4_ticket_id or not rt5_ticket_id:
        print("Error: provide --ticket-id or both --rt4-ticket-id and --rt5-ticket-id", file=sys.stderr)
        return 2

    try:
        auth4 = load_auth(args.auth_file, "rt4")
        auth5 = load_auth(args.auth_file, "rt5")
        client4 = rt4.RTClient(
            auth4["url"], auth4["name"], auth4["password"], args.timeout, args.insecure, args.debug
        )
        client5 = rt5.RTClient(auth5["url"], auth5["token"], args.timeout, args.insecure)
        rt4_contents: dict[str, bytes] = {}
        rt5_contents: dict[str, bytes] = {}
        ticket4 = fetch_rt4_ticket(client4, rt4_ticket_id, rt4_contents)
        ticket5 = fetch_rt5_ticket(client5, rt5_ticket_id, rt5_contents)
        left_report = {"server": client4.api_base, "tickets": [ticket4] if ticket4 else []}
        right_report = {"server": client5.api_base, "tickets": [ticket5] if ticket5 else []}
        forced_pairs = [(ticket4, ticket5)] if ticket4 is not None and ticket5 is not None else None
        result = compare_rt_reports.compare_reports(left_report, right_report, forced_pairs)
        if ticket4 is not None and ticket5 is not None:
            result["comparison_window"] = {
                "rt4_last_updated": ticket4.get("last_updated"),
                "rt5_last_updated": ticket5.get("last_updated"),
                "rt4_changes_after": ticket5.get("last_updated"),
                "rt5_changes_after": ticket4.get("last_updated"),
            }
        if ticket4 is not None and ticket5 is not None:
            base_dir = args.output.parent if args.output else Path.cwd()
            written_files, unavailable_files = write_missing_attachment_files(
                rt4_ticket_id,
                ticket4,
                ticket5,
                rt4_contents,
                rt5_contents,
                base_dir,
            )
            result["missing_attachment_files"] = [str(path) for path in written_files]
            result["missing_attachment_contents_unavailable"] = unavailable_files
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Ticket comparison written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError, rt4.RTError, rt5.RTError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
