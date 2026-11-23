#!/usr/bin/env python3
"""Compare JSON reports produced by the RT 4.4 and RT 5 queue audit scripts."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read JSON report {path}: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("tickets"), list):
        raise ValueError(f"{path} is not an RT audit report (expected a tickets array)")
    for index, ticket in enumerate(data["tickets"]):
        if not isinstance(ticket, dict) or ticket.get("id") is None:
            raise ValueError(f"{path}: ticket entry {index + 1} has no id")
    return data


def normalized(value: Any) -> str:
    return str(value or "").strip().casefold()


def second_sunday(year: int, month: int) -> int:
    first_day = datetime(year, month, 1).weekday()
    first_sunday = 1 + (6 - first_day) % 7
    return first_sunday + 7


def first_sunday(year: int, month: int) -> int:
    first_day = datetime(year, month, 1).weekday()
    return 1 + (6 - first_day) % 7


def parse_creation_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo("America/Chicago"))
        except ZoneInfoNotFoundError:
            # Windows may not have an IANA timezone database installed.
            year = parsed.year
            dst_start = datetime(year, 3, second_sunday(year, 3), 2)
            dst_end = datetime(year, 11, first_sunday(year, 11), 2)
            offset_hours = -5 if dst_start <= parsed < dst_end else -6
            parsed = parsed.replace(tzinfo=timezone(timedelta(hours=offset_hours)))
    return parsed.astimezone(timezone.utc)


def creation_timestamp_key(value: Any) -> str:
    parsed = parse_creation_timestamp(value)
    return parsed.isoformat() if parsed else normalized(value)


def ticket_fallback_key(ticket: dict[str, Any]) -> tuple[str, str] | None:
    subject = normalized(ticket.get("subject"))
    created = creation_timestamp_key(ticket.get("created"))
    if not subject or not created:
        return None
    return subject, created


def pair_tickets(
    left_tickets: list[dict[str, Any]],
    right_tickets: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
    right_by_id = {str(ticket["id"]): ticket for ticket in right_tickets}
    unmatched_left = list(left_tickets)
    unmatched_right = list(right_tickets)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []

    right_ids = {str(ticket["id"]): ticket for ticket in unmatched_right}
    remaining_left: list[dict[str, Any]] = []
    used_right_ids: set[str] = set()
    for ticket in unmatched_left:
        match = right_by_id.get(str(ticket["id"]))
        if match is not None:
            pairs.append((ticket, match))
            used_right_ids.add(str(match["id"]))
        else:
            remaining_left.append(ticket)

    unmatched_right = [ticket for ticket in unmatched_right if str(ticket["id"]) not in used_right_ids]
    right_by_fallback: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    left_fallback_counts: dict[tuple[str, str], int] = defaultdict(int)
    for ticket in unmatched_right:
        key = ticket_fallback_key(ticket)
        if key:
            right_by_fallback[key].append(ticket)
    for ticket in remaining_left:
        key = ticket_fallback_key(ticket)
        if key:
            left_fallback_counts[key] += 1

    matched_left_ids: set[str] = set()
    matched_right_ids: set[str] = set()
    for ticket in remaining_left:
        key = ticket_fallback_key(ticket)
        candidates = right_by_fallback.get(key, []) if key else []
        if key and left_fallback_counts[key] == 1 and len(candidates) == 1:
            match = candidates[0]
            pairs.append((ticket, match))
            matched_left_ids.add(str(ticket["id"]))
            matched_right_ids.add(str(match["id"]))

    missing_left = [ticket for ticket in remaining_left if str(ticket["id"]) not in matched_left_ids]
    missing_right = [ticket for ticket in unmatched_right if str(ticket["id"]) not in matched_right_ids]
    pairs.sort(key=lambda pair: str(pair[0]["id"]))
    return pairs, missing_left, missing_right


def attachment_identity(attachment: dict[str, Any]) -> tuple[str, ...]:
    checksum = normalized(attachment.get("md5"))
    if checksum:
        return ("md5", checksum)
    filename = normalized(attachment.get("filename"))
    size = attachment.get("size_bytes")
    if filename or size is not None:
        return ("file", filename, str(size) if size is not None else "")
    attachment_id = attachment.get("id")
    return ("id", str(attachment_id)) if attachment_id is not None else ("unknown",)


def attachment_fallback_key(attachment: dict[str, Any]) -> tuple[str, str] | None:
    filename = normalized(attachment.get("filename"))
    size = attachment.get("size_bytes")
    if not filename and size is None:
        return None
    return filename, str(size) if size is not None else ""


def attachment_content_unavailable(attachment: dict[str, Any]) -> bool:
    return normalized(attachment.get("error")) == "attachment content was not available"


def attachment_report_fields(attachment: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": attachment.get("id"),
        "type": attachment.get("content_type", attachment.get("type")),
        "name": attachment.get("filename", attachment.get("FileName")),
        "size_bytes": attachment.get("size_bytes"),
        "md5": attachment.get("md5"),
    }


def pair_attachments(
    left_items: list[dict[str, Any]],
    right_items: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
    remaining_right = set(range(len(right_items)))
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    missing_right: list[dict[str, Any]] = []

    for left_item in left_items:
        left_id = left_item.get("id")
        left_name = normalized(left_item.get("filename", left_item.get("FileName")))
        left_type = normalized(left_item.get("content_type", left_item.get("type")))
        candidates = [
            index for index in sorted(remaining_right)
            if left_id is not None and str(right_items[index].get("id")) == str(left_id)
        ]
        if not candidates and left_name:
            candidates = [
                index for index in sorted(remaining_right)
                if normalized(right_items[index].get("filename", right_items[index].get("FileName"))) == left_name
                and normalized(right_items[index].get("content_type", right_items[index].get("type"))) == left_type
            ]
            if not candidates:
                candidates = [
                    index for index in sorted(remaining_right)
                    if normalized(right_items[index].get("filename", right_items[index].get("FileName"))) == left_name
                ]
        if candidates:
            index = candidates[0]
            remaining_right.remove(index)
            pairs.append((left_item, right_items[index]))
        else:
            missing_right.append(left_item)

    missing_left = [right_items[index] for index in sorted(remaining_right)]
    return pairs, missing_right, missing_left


def ticket_attachment_items(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in ticket.get("attachments", []) if isinstance(item, dict)]


def ticket_attachment_count(ticket: dict[str, Any]) -> int:
    count = ticket.get("attachment_count")
    return count if isinstance(count, int) else len(ticket_attachment_items(ticket))


def compare_ticket_metadata(
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
) -> dict[str, Any] | None:
    left_created = left_ticket.get("created")
    right_created = right_ticket.get("created")
    left_created_utc = parse_creation_timestamp(left_created)
    right_created_utc = parse_creation_timestamp(right_created)
    created_matches = (
        left_created_utc == right_created_utc
        if left_created_utc is not None and right_created_utc is not None
        else left_created == right_created
    )
    values = {
        "id": (str(left_ticket["id"]), str(right_ticket["id"])),
        "title": (left_ticket.get("subject"), right_ticket.get("subject")),
        "attachment_count": (ticket_attachment_count(left_ticket), ticket_attachment_count(right_ticket)),
    }
    differences = {
        field: {"left": left_value, "right": right_value}
        for field, (left_value, right_value) in values.items()
        if left_value != right_value
    }
    if not created_matches:
        differences["creation_date"] = {"left": left_created, "right": right_created}
    if not differences:
        return None
    return {
        "ticket_id": str(left_ticket["id"]),
        "ticket_id_left": str(left_ticket["id"]),
        "ticket_id_right": str(right_ticket["id"]),
        "transaction_id": None,
        "transaction_url": None,
        "differences": differences,
    }


def compare_attachment_reports(
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    pairs, missing_right, missing_left = pair_attachments(
        ticket_attachment_items(left_ticket),
        ticket_attachment_items(right_ticket),
    )
    ticket_context = {
        "ticket_id": str(left_ticket["id"]),
        "ticket_id_left": str(left_ticket["id"]),
        "ticket_id_right": str(right_ticket["id"]),
        "transaction_id": None,
        "transaction_url": None,
    }
    metadata_items: list[dict[str, Any]] = []
    content_items: list[dict[str, Any]] = []

    for left_item, right_item in pairs:
        left_fields = attachment_report_fields(left_item)
        right_fields = attachment_report_fields(right_item)
        differences = {
            field: {"left": left_fields[field], "right": right_fields[field]}
            for field in ("id", "type", "name")
            if left_fields[field] != right_fields[field]
        }
        if differences:
            metadata_items.append({
                **ticket_context,
                "status": "different",
                "differences": differences,
                "left": left_fields,
                "right": right_fields,
            })

        content_differences = {
            field: {"left": left_fields[field], "right": right_fields[field]}
            for field in ("size_bytes", "md5")
            if left_fields[field] is not None
            and right_fields[field] is not None
            and left_fields[field] != right_fields[field]
        }
        if content_differences:
            content_items.append({
                **ticket_context,
                "differences": content_differences,
                "left": left_fields,
                "right": right_fields,
            })

    for direction, items in (("missing_from_right", missing_right), ("missing_from_left", missing_left)):
        for item in items:
            metadata_items.append({
                **ticket_context,
                "status": direction,
                "differences": {},
                "left": attachment_report_fields(item) if direction == "missing_from_left" else None,
                "right": attachment_report_fields(item) if direction == "missing_from_right" else None,
            })

    metadata_report = {**ticket_context, "attachments": metadata_items} if metadata_items else None
    content_report = {**ticket_context, "attachments": content_items} if content_items else None
    return metadata_report, content_report


def compare_attachments(
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
) -> dict[str, Any] | None:
    left_items = [
        item for item in left_ticket.get("attachments", [])
        if isinstance(item, dict) and not attachment_content_unavailable(item)
    ]
    right_items = [
        item for item in right_ticket.get("attachments", [])
        if isinstance(item, dict) and not attachment_content_unavailable(item)
    ]
    remaining_right = set(range(len(right_items)))
    remaining_left: list[dict[str, Any]] = []
    changed_content: list[dict[str, Any]] = []
    missing_right: list[dict[str, Any]] = []
    for item in left_items:
        candidates = [
            index for index in remaining_right
            if attachment_identity(right_items[index]) == attachment_identity(item)
        ]
        if candidates:
            remaining_right.remove(candidates[0])
        else:
            remaining_left.append(item)

    for item in remaining_left:
        fallback_key = attachment_fallback_key(item)
        candidates = [
            index for index in remaining_right
            if fallback_key is not None and attachment_fallback_key(right_items[index]) == fallback_key
        ]
        if candidates:
            index = candidates[0]
            remaining_right.remove(index)
            right_item = right_items[index]
            if item.get("md5") and right_item.get("md5") and item["md5"] != right_item["md5"]:
                changed_content.append({
                    "filename": item.get("filename") or right_item.get("filename"),
                    "left": {"md5": item.get("md5"), "size_bytes": item.get("size_bytes")},
                    "right": {"md5": right_item.get("md5"), "size_bytes": right_item.get("size_bytes")},
                })
        else:
            missing_right.append(item)

    missing_left = [right_items[index] for index in sorted(remaining_right)]
    if not changed_content and not missing_left and not missing_right:
        return None
    return {
        "ticket_id_left": str(left_ticket["id"]),
        "ticket_id_right": str(right_ticket["id"]),
        "changed_content": changed_content,
        "missing_from_right": missing_right,
        "missing_from_left": missing_left,
    }


def message_base_key(message: dict[str, Any]) -> tuple[str, str]:
    return normalized(message.get("type")), normalized(message.get("created"))


def compare_messages(
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
) -> dict[str, Any] | None:
    left_messages = [item for item in left_ticket.get("reply_comment_updates", []) if isinstance(item, dict)]
    right_messages = [item for item in right_ticket.get("reply_comment_updates", []) if isinstance(item, dict)]
    unused_right = set(range(len(right_messages)))
    differing: list[dict[str, Any]] = []
    missing_right: list[dict[str, Any]] = []

    for left_message in left_messages:
        candidates = [
            index for index in unused_right
            if message_base_key(right_messages[index]) == message_base_key(left_message)
        ]
        left_id = left_message.get("id")
        same_id = [index for index in candidates if str(right_messages[index].get("id")) == str(left_id)]
        if same_id:
            match_index = same_id[0]
        elif candidates:
            match_index = candidates[0]
        else:
            missing_right.append(left_message)
            continue

        unused_right.remove(match_index)
        right_message = right_messages[match_index]
        left_hash = left_message.get("content_md5")
        right_hash = right_message.get("content_md5")
        if left_hash and right_hash and left_hash != right_hash:
            differing.append({
                "type": left_message.get("type"),
                "created": left_message.get("created"),
                "left": {"id": left_message.get("id"), "content_md5": left_hash},
                "right": {"id": right_message.get("id"), "content_md5": right_hash},
            })

    missing_left = [right_messages[index] for index in sorted(unused_right)]
    if not differing and not missing_left and not missing_right:
        return None
    return {
        "ticket_id_left": str(left_ticket["id"]),
        "ticket_id_right": str(right_ticket["id"]),
        "differing_content": differing,
        "missing_from_right": missing_right,
        "missing_from_left": missing_left,
    }


def compare_reports(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    pairs, missing_left, missing_right = pair_tickets(left["tickets"], right["tickets"])
    differing_attachments: list[dict[str, Any]] = []
    attachment_comparison_details: list[dict[str, Any]] = []
    differing_attachment_content: list[dict[str, Any]] = []
    differing_ticket_metadata: list[dict[str, Any]] = []
    differing_messages: list[dict[str, Any]] = []

    for left_ticket, right_ticket in pairs:
        metadata_diff = compare_ticket_metadata(left_ticket, right_ticket)
        if metadata_diff:
            differing_ticket_metadata.append(metadata_diff)
        attachment_report, content_report = compare_attachment_reports(left_ticket, right_ticket)
        if attachment_report:
            differing_attachments.append(attachment_report)
        if content_report:
            differing_attachment_content.append(content_report)
        attachment_diff = compare_attachments(left_ticket, right_ticket)
        if attachment_diff:
            attachment_comparison_details.append(attachment_diff)
        message_diff = compare_messages(left_ticket, right_ticket)
        if message_diff:
            differing_messages.append(message_diff)

    left_queue = left.get("queue", {})
    right_queue = right.get("queue", {})
    return {
        "left_report": {"server": left.get("server"), "queue": left_queue},
        "right_report": {"server": right.get("server"), "queue": right_queue},
        "summary": {
            "tickets_matched": len(pairs),
            "tickets_missing_from_right": len(missing_left),
            "tickets_missing_from_left": len(missing_right),
            "tickets_with_metadata_differences": len(differing_ticket_metadata),
            "tickets_with_attachment_differences": len(attachment_comparison_details),
            "tickets_with_attachment_metadata_differences": len(differing_attachments),
            "tickets_with_attachment_content_differences": len(differing_attachment_content),
            "tickets_with_message_differences": len(differing_messages),
        },
        "missing_tickets": {
            "from_right": missing_left,
            "from_left": missing_right,
        },
        "ticket_metadata_differences": differing_ticket_metadata,
        "attachment_differences": attachment_comparison_details,
        "attachment_metadata_differences": differing_attachments,
        "attachment_content_differences": differing_attachment_content,
        "message_differences": differing_messages,
        "comparison_notes": {
            "ticket_matching": "Ticket IDs are matched first. If IDs differ, a unique normalized subject plus creation timestamp is used as fallback.",
            "creation_time_matching": "Creation timestamps with an explicit timezone are compared as instants; timezone-naive timestamps are interpreted as America/Chicago local time before comparison.",
            "attachment_matching": "Attachments are matched by MD5 first, then normalized filename and size to identify changed content, then by ID when hashes and metadata are unavailable.",
            "message_matching": "Reply/comment messages are paired by type and creation timestamp; matching content MD5s are compared. RT 4.4 attachment byte encoding may cause checksum differences.",
            "direction": "from_right means present only in the left input report; from_left means present only in the right input report.",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two RT audit JSON reports for missing tickets, attachments, and differing messages."
    )
    parser.add_argument("left", type=Path, help="first audit JSON report (for example RT 4.4)")
    parser.add_argument("right", type=Path, help="second audit JSON report (for example RT 5)")
    parser.add_argument("--output", type=Path, help="write comparison JSON here instead of standard output")
    return parser.parse_args()


def companion_report_paths(output: Path) -> dict[str, Path]:
    reports = (
        "missing_tickets",
        "ticket_metadata_differences",
        "attachment_differences",
        "attachment_content_differences",
    )
    return {name: output.with_name(f"{output.stem}_{name}.json") for name in reports}


def missing_ticket_report(result: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for direction, tickets in result["missing_tickets"].items():
        present_in = "left" if direction == "from_right" else "right"
        for ticket in tickets:
            ticket_id = str(ticket["id"])
            entries.append({
                "ticket_id": ticket_id,
                "ticket_id_left": ticket_id if present_in == "left" else None,
                "ticket_id_right": ticket_id if present_in == "right" else None,
                "present_in": present_in,
                "transaction_id": None,
                "transaction_url": None,
                "ticket": ticket,
            })
    return entries


def write_companion_reports(output: Path, result: dict[str, Any]) -> None:
    report_items = {
        "missing_tickets": missing_ticket_report(result),
        "ticket_metadata_differences": result["ticket_metadata_differences"],
        "attachment_differences": result["attachment_metadata_differences"],
        "attachment_content_differences": result["attachment_content_differences"],
    }
    for name, path in companion_report_paths(output).items():
        document = {"report": name, "count": len(report_items[name]), "items": report_items[name]}
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    try:
        left = load_report(args.left)
        right = load_report(args.right)
        result = compare_reports(left, right)
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            write_companion_reports(args.output, result)
            print(f"Comparison written to {args.output}", file=sys.stderr)
            for path in companion_report_paths(args.output).values():
                print(f"Report written to {path}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
