"""Async, rotation/truncation-safe file tailer (SPEC.md section 6.1).

Polls a file for growth rather than using OS file-change notifications, so it
behaves the same on every platform. Each poll:

- detects rotation (the path now resolves to a different inode/file id) and
  **drains the old file first**, through the descriptor that is kept open
  (POSIX), before starting the new file from its beginning, so lines written
  just before a rename are not lost;
- detects truncation (the file shrank below our last-known offset) and an
  in-place replacement that regrew past the old offset (the first bytes no
  longer match what was read before), and restarts at offset 0;
- reads at most ``max_chunk_bytes`` of new data, splits on newlines, and
  buffers a trailing partial line until the rest of it arrives;
- refuses lines longer than ``max_line_bytes``: the bytes are discarded as they
  arrive (memory stays bounded by the cap plus one chunk), counted, and the
  remainder of the line is skipped up to the next newline;
- pushes complete, non-empty lines onto a bounded ``asyncio.Queue`` so a slow
  downstream parser applies backpressure instead of unbounded memory growth.

``run()`` is the supervisor: a transient read error (permissions, I/O error,
network share hiccup) is counted, reported through :meth:`status`, and retried
with capped exponential back-off instead of ending the task.

Reads are bounded and byte-oriented: offsets are true byte positions that can
be persisted and resumed from. The tailer only ever opens files read-only.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional

from app.ingest import reasons
from app.privacy.safe_log import safe_exc

logger = logging.getLogger(__name__)

DEFAULT_MAX_CHUNK_BYTES = 1 << 20
DEFAULT_MAX_LINE_BYTES = 1 << 20  # 1 MiB; a single log record this large is not a log record
HEAD_SIGNATURE_BYTES = 64
# The start of a file is a log line and may hold an identifier, so it is never kept: only a
# salted digest (random per process, never persisted) is compared to notice in-place replacement.
_HEAD_SALT = os.urandom(16)


def _head_digest(data: bytes) -> bytes:
    return hashlib.blake2b(data, key=_HEAD_SALT, digest_size=16).digest()
MAX_BACKOFF_SECONDS = 30.0

# (reason_code, byte_offset_of_line_start, length_in_bytes)
RejectHook = Callable[[str, int, int], None]


class SourceLine(NamedTuple):
    """A line tagged with the source it came from and its byte offset. Tailers
    created with ``source=...`` queue these; without it they queue bare ``str``
    (the original behaviour)."""

    source: str
    line: str
    offset: int


class Tailer:
    def __init__(
        self,
        path: Path,
        queue: "asyncio.Queue[str]",
        *,
        from_start: bool = False,
        poll_interval: float = 0.1,
        resume_offset: Optional[int] = None,
        resume_file_id: Optional[int] = None,
        max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        stalled_after: Optional[float] = None,
        max_backoff: float = MAX_BACKOFF_SECONDS,
        on_reject: Optional[RejectHook] = None,
        source: Optional[str] = None,
    ) -> None:
        self.path = Path(path)
        self.queue = queue
        self.from_start = from_start
        self.poll_interval = poll_interval
        self.max_chunk_bytes = max_chunk_bytes
        self.max_line_bytes = max(1, int(max_line_bytes))
        self.stalled_after = stalled_after
        self.max_backoff = max_backoff
        self.on_reject = on_reject
        self.source = source
        self._resume_offset = resume_offset
        self._resume_file_id = resume_file_id

        self._buffer = b""
        self._offset = 0
        self._inode: Optional[int] = None
        self._fh: Optional[Any] = None  # kept open on POSIX so a rotated file can be drained
        self._head_sig: Optional[bytes] = None
        self._discarding = False
        self._stopped = False
        self.caught_up = False
        self.file_size = 0

        # -- source-state reporting (status()) --
        self._state = "starting"
        self.lines_queued = 0
        self.oversize_lines = 0
        self.decode_errors = 0
        self.rotations = 0
        self.truncations = 0
        self.errors = 0
        self.last_error: Optional[str] = None  # exception class name only, never a message or path
        self.last_data_at: Optional[datetime] = None
        self.last_poll_at: Optional[datetime] = None
        self._last_data_mono = time.monotonic()

    # -- lifecycle ------------------------------------------------------------

    def stop(self) -> None:
        self._stopped = True

    def close(self) -> None:
        fh, self._fh = self._fh, None
        if fh is not None:
            try:
                fh.close()
            except OSError:  # pragma: no cover - nothing useful to do
                pass

    def __del__(self) -> None:  # pragma: no cover - best-effort descriptor hygiene
        try:
            self.close()
        except Exception:
            pass

    @property
    def file_id(self) -> Optional[int]:
        return self._inode

    @property
    def committed_offset(self) -> int:
        """Byte offset of the end of the last complete line handed to the queue
        (or discarded as oversize)."""
        return self._offset - len(self._buffer)

    @property
    def state(self) -> str:
        """starting | ok | stalled | missing | error"""
        if (
            self._state == "ok"
            and self.stalled_after is not None
            and time.monotonic() - self._last_data_mono > self.stalled_after
        ):
            return "stalled"
        return self._state

    def status(self) -> dict[str, Any]:
        return {
            "path": self.path.name,
            "state": self.state,
            "file_size": self.file_size,
            "offset": self.committed_offset,
            "caught_up": self.caught_up,
            "lines_queued": self.lines_queued,
            "oversize_lines": self.oversize_lines,
            "decode_errors": self.decode_errors,
            "rotations": self.rotations,
            "truncations": self.truncations,
            "errors": self.errors,
            "last_error": self.last_error,
            "last_data_at": self.last_data_at.isoformat() if self.last_data_at else None,
            "last_poll_at": self.last_poll_at.isoformat() if self.last_poll_at else None,
        }

    # -- supervisor loop ------------------------------------------------------

    async def run(self) -> None:
        """Poll until :meth:`stop` is called. Sleeps only once caught up, so a
        large backlog is drained as fast as the downstream queue allows. Never
        exits on an I/O error: it backs off and tries again."""
        backoff = self.poll_interval
        try:
            while not self._stopped:
                try:
                    await self.poll_once()
                    backoff = self.poll_interval
                except FileNotFoundError:
                    self._state = "missing"
                    self.caught_up = True
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # transient: permission flap, EIO, share hiccup...
                    self.errors += 1
                    self.last_error = type(exc).__name__
                    self._state = "error"
                    self.caught_up = True
                    self._drop_handle()  # reopen from the saved offset on the next success
                    logger.warning("tailer %s: %s; retrying in %.1fs", self.path.name, self.last_error, backoff)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                    continue
                if self.caught_up:
                    await asyncio.sleep(self.poll_interval)
                else:
                    await asyncio.sleep(0)
        finally:
            self.close()

    # -- internals ------------------------------------------------------------

    def _initial_offset(self, file_id: int, size: int) -> int:
        if self._resume_offset is not None:
            same_file = self._resume_file_id is None or self._resume_file_id == file_id
            if same_file and self._resume_offset <= size:
                return self._resume_offset
            return 0  # rotated or truncated since the position was saved: read the new file whole
        return 0 if self.from_start else size

    def _drop_handle(self) -> None:
        self.close()

    def _ensure_handle(self) -> Any:
        if self._fh is None:
            self._fh = self.path.open("rb")
        return self._fh

    def _reset_position(self) -> None:
        self._offset = 0
        self._buffer = b""
        self._discarding = False
        self._head_sig = None
        self._drop_handle()

    def _reject(self, reason: str, offset: int, length: int) -> None:
        if reason == reasons.LINE_TOO_LONG:
            self.oversize_lines += 1
        if self.on_reject is not None:
            try:
                self.on_reject(reason, offset, length)
            except Exception as exc:  # a broken hook must never stop ingestion
                logger.error("tailer: reject hook failed: %s", safe_exc(exc))

    async def _feed(self, chunk: bytes, chunk_start: int) -> int:
        """Split ``chunk`` (which begins at file offset ``chunk_start``) into
        lines. Returns the number of lines queued."""
        data = chunk
        if self._discarding:
            nl = data.find(b"\n")
            if nl < 0:
                return 0  # still inside an oversize line: keep dropping
            data = data[nl + 1:]
            chunk_start += nl + 1
            self._discarding = False
            if not data:
                return 0
        pos = chunk_start - len(self._buffer)
        *parts, self._buffer = (self._buffer + data).split(b"\n")
        queued = 0
        for raw in parts:
            start, pos = pos, pos + len(raw) + 1
            if len(raw) > self.max_line_bytes:
                self._reject(reasons.LINE_TOO_LONG, start, len(raw))
                continue
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                self.decode_errors += 1
                line = raw.decode("utf-8", errors="replace")
            line = line.rstrip("\r")
            if line:
                await self.queue.put(SourceLine(self.source, line, start) if self.source else line)
                queued += 1
        if len(self._buffer) > self.max_line_bytes:
            self._reject(reasons.LINE_TOO_LONG, pos, len(self._buffer))
            self._buffer = b""
            self._discarding = True
        self.lines_queued += queued
        if queued:
            self.last_data_at = datetime.now(timezone.utc)
            self._last_data_mono = time.monotonic()
        return queued

    async def _drain_handle(self) -> int:
        """Read whatever is left in the currently open descriptor (which still
        refers to the old file after a rename/unlink), then flush a final
        unterminated line, which a writer that rotated is not going to finish."""
        fh = self._fh
        if fh is None:
            return 0
        queued = 0
        try:
            fh.seek(self._offset)
            while True:
                chunk = fh.read(self.max_chunk_bytes)
                if not chunk:
                    break
                start = self._offset
                self._offset += len(chunk)
                queued += await self._feed(chunk, start)
            if self._buffer and not self._discarding:
                tail, self._buffer = self._buffer, b""
                queued += await self._feed(tail + b"\n", self._offset - len(tail))
        except OSError:
            pass  # the old file is gone for good; nothing more to recover
        return queued

    async def poll_once(self) -> int:
        """Read up to one chunk of whatever is new since the last poll.
        Returns the number of complete lines queued."""
        self.last_poll_at = datetime.now(timezone.utc)
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            # The file was renamed away: recover its tail through the open descriptor.
            if os.name != "nt":
                await self._drain_handle()
            raise
        self.file_size = stat.st_size
        self._state = "ok"
        queued = 0

        if self._inode is None:
            self._inode = stat.st_ino
            self._offset = self._initial_offset(stat.st_ino, stat.st_size)
        elif stat.st_ino != self._inode:
            if os.name != "nt":
                queued += await self._drain_handle()
            self.rotations += 1
            self._inode = stat.st_ino
            self._reset_position()
        elif stat.st_size < self._offset:
            self.truncations += 1
            self._reset_position()
        elif self._head_sig is not None and self._head_changed():
            # Same inode and size >= offset, but the start of the file differs from
            # what we read: it was replaced in place and has regrown past our offset.
            self.rotations += 1
            self._reset_position()

        if stat.st_size <= self._offset:
            self.caught_up = True
            return queued

        fh = self._ensure_handle() if os.name != "nt" else self.path.open("rb")
        try:
            fh.seek(self._offset)
            start = self._offset
            chunk = fh.read(self.max_chunk_bytes)
            self._offset = fh.tell()
            if self._head_sig is None and start == 0 and len(chunk) >= HEAD_SIGNATURE_BYTES:
                self._head_sig = _head_digest(chunk[:HEAD_SIGNATURE_BYTES])
        finally:
            if os.name == "nt":
                fh.close()

        self.caught_up = self._offset >= stat.st_size
        if chunk:
            queued += await self._feed(chunk, start)
        return queued

    def _head_changed(self) -> bool:
        try:
            with self.path.open("rb") as f:
                head = f.read(HEAD_SIGNATURE_BYTES)
        except OSError:
            return False
        return _head_digest(head) != self._head_sig
