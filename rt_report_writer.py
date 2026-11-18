"""Incremental JSON report writer with resumable per-ticket checkpoints."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO


class ReportWriterError(Exception):
    """Invalid report or resume state."""


class JSONReportWriter:
    def __init__(
        self,
        stream: BinaryIO,
        server: str,
        checksum_notes: dict[str, str],
        state_path: Path | None = None,
        output_path: Path | None = None,
        resume: bool = False,
    ) -> None:
        self.stream = stream
        self.server = server
        self.notes = checksum_notes
        self.state_path = state_path
        self.output_path = output_path.resolve() if output_path is not None else None
        self.queue: dict[str, Any] | None = None
        self.ticket_count = 0
        self.attachment_count = 0
        self.attachment_size_bytes = 0
        self.last_ticket_id: str | None = None
        self.closed = False
        self.resuming = resume

        if resume:
            self._restore_checkpoint()
        else:
            self._write("{\n")
            self._write(f'  "generated_at": {json.dumps(datetime.now(timezone.utc).isoformat())},\n')
            self._write(f'  "server": {json.dumps(server)},\n')
            self._write('  "tickets": [')
            self.stream.flush()
            self._save_checkpoint()

    def _restore_checkpoint(self) -> None:
        if self.state_path is None or self.output_path is None:
            raise ReportWriterError("Resume requires an output file and a state file")
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReportWriterError(f"Could not read resume state {self.state_path}: {exc}") from None
        if state.get("version") != 1:
            raise ReportWriterError("Unsupported resume state version")
        if state.get("server") != self.server:
            raise ReportWriterError("Resume state belongs to a different RT server")
        if state.get("output_path") != str(self.output_path):
            raise ReportWriterError("Resume state belongs to a different output file")

        offset = state.get("output_offset")
        if not isinstance(offset, int) or offset < 0:
            raise ReportWriterError("Resume state has an invalid output offset")
        self.stream.seek(0, os.SEEK_END)
        if offset > self.stream.tell():
            raise ReportWriterError("Resume output is shorter than its checkpoint")
        self.stream.seek(offset)
        self.stream.truncate()
        self.queue = state.get("queue")
        self.ticket_count = int(state.get("ticket_count", 0))
        self.attachment_count = int(state.get("attachment_count", 0))
        self.attachment_size_bytes = int(state.get("attachment_size_bytes", 0))
        last_ticket_id = state.get("last_ticket_id")
        self.last_ticket_id = str(last_ticket_id) if last_ticket_id is not None else None
        self.stream.flush()

    def _write(self, text: str) -> None:
        self.stream.write(text.encode("utf-8"))

    def _save_checkpoint(self) -> None:
        if self.state_path is None:
            return
        self.stream.flush()
        state = {
            "version": 1,
            "server": self.server,
            "output_path": str(self.output_path),
            "output_offset": self.stream.tell(),
            "queue": self.queue,
            "last_ticket_id": self.last_ticket_id,
            "ticket_count": self.ticket_count,
            "attachment_count": self.attachment_count,
            "attachment_size_bytes": self.attachment_size_bytes,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.state_path.parent,
                prefix=self.state_path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as temp_file:
                temp_name = temp_file.name
                json.dump(state, temp_file, ensure_ascii=False)
                temp_file.write("\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_name, self.state_path)
        finally:
            if temp_name is not None and os.path.exists(temp_name):
                os.unlink(temp_name)

    def set_queue(self, queue: dict[str, Any]) -> None:
        if self.resuming and self.queue is not None and self.queue != queue:
            raise ReportWriterError("Resume state is for a different queue")
        self.queue = queue
        self._save_checkpoint()

    def should_skip_ticket(self, ticket_id: str) -> bool:
        if self.last_ticket_id is None:
            return False
        try:
            return int(ticket_id) <= int(self.last_ticket_id)
        except ValueError:
            return ticket_id == self.last_ticket_id

    def write_ticket(self, ticket: dict[str, Any]) -> None:
        if self.closed:
            raise ReportWriterError("Cannot write to a closed report")
        ticket_id = ticket.get("id")
        if ticket_id is None:
            raise ReportWriterError("Cannot checkpoint a ticket without an ID")
        rendered = json.dumps(ticket, indent=2, ensure_ascii=False)
        if self.ticket_count:
            self._write(",")
        self._write("\n" + "\n".join("  " + line for line in rendered.splitlines()))
        self.stream.flush()

        self.ticket_count += 1
        self.attachment_count += int(ticket.get("attachment_count", 0))
        self.attachment_size_bytes += sum(
            attachment["size_bytes"]
            for attachment in ticket.get("attachments", [])
            if attachment.get("size_bytes") is not None
        )
        self.last_ticket_id = str(ticket_id)
        self._save_checkpoint()

    def close(self, error: str | None = None) -> None:
        if self.closed:
            return
        self._write("\n  ],\n")
        self._write(f'  "queue": {json.dumps(self.queue, ensure_ascii=False)},\n')
        self._write(f'  "ticket_count": {self.ticket_count},\n')
        self._write(f'  "attachment_count": {self.attachment_count},\n')
        self._write(f'  "attachment_size_bytes": {self.attachment_size_bytes},\n')
        self._write('  "checksum_notes": {\n')
        for index, (key, value) in enumerate(self.notes.items()):
            comma = "," if index < len(self.notes) - 1 else ""
            self._write(f"    {json.dumps(key)}: {json.dumps(value)}{comma}\n")
        self._write("  },\n")
        self._write(f'  "complete": {json.dumps(error is None)}')
        if error is not None:
            self._write(f',\n  "error": {json.dumps(error, ensure_ascii=False)}')
        self._write("\n}\n")
        self.stream.flush()
        self.closed = True

