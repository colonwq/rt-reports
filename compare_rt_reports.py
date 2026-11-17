#!/usr/bin/env python3
"""Compare JSON reports produced by the RT 4.4 and RT 5 queue audit scripts."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


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


def ticket_fallback_key(ticket: dict[str, Any]) -> tuple[str, str] | None:
    subject = normalized(ticket.get("subject"))
    created = normalized(ticket.get("created"))
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


def compare_attachments(
    left_ticket: dict[str, Any],
    right_ticket: dict[str, Any],
) -> dict[str, Any] | None:
    left_items = [item for item in left_ticket.get("attachments", []) if isinstance(item, dict)]
    right_items = [item for item in right_ticket.get("attachments", []) if isinstance(item, dict)]
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
    differing_messages: list[dict[str, Any]] = []

    for left_ticket, right_ticket in pairs:
        attachment_diff = compare_attachments(left_ticket, right_ticket)
        if attachment_diff:
            differing_attachments.append(attachment_diff)
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
            "tickets_with_attachment_differences": len(differing_attachments),
            "tickets_with_message_differences": len(differing_messages),
        },
        "missing_tickets": {
            "from_right": missing_left,
            "from_left": missing_right,
        },
        "attachment_differences": differing_attachments,
        "message_differences": differing_messages,
        "comparison_notes": {
            "ticket_matching": "Ticket IDs are matched first. If IDs differ, a unique normalized subject plus creation timestamp is used as fallback.",
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


def main() -> int:
    args = parse_args()
    try:
        left = load_report(args.left)
        right = load_report(args.right)
        result = compare_reports(left, right)
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Comparison written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
