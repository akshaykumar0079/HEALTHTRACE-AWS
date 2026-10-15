"""Stage A regression tests: failures confirmed by the readiness audit
(docs/REAL_HOSPITAL_READINESS_AUDIT.md section 1.2 / 1.8). Synthetic data only."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from app.config import load_config
from app.ingest import reasons
from app.ingest.tailer import Tailer
from app.pipeline import Pipeline
from app.simulation.runner import _isolated_settings


async def _drain(q: "asyncio.Queue[str]") -> list[str]:
    out: list[str] = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(text)


# -- oversize lines / bounded memory --------------------------------------------

async def test_no_newline_file_keeps_memory_bounded(tmp_path: Path):
    """Audit: a 5 MB file with no newline left 5,000,000 bytes buffered."""
    path = tmp_path / "x.log"
    path.write_bytes(b"x" * 5_000_000)
    q: asyncio.Queue[str] = asyncio.Queue()
    rejects: list[tuple[str, int, int]] = []
    t = Tailer(path, q, from_start=True, max_line_bytes=4096, max_chunk_bytes=65536,
               on_reject=lambda *a: rejects.append(a))
    peak = 0
    while not t.caught_up:
        await t.poll_once()
        peak = max(peak, len(t._buffer))
    assert peak <= 4096 + 65536
    assert len(t._buffer) <= 4096
    assert q.empty()
    assert t.oversize_lines == 1
    assert rejects and rejects[0][0] == reasons.LINE_TOO_LONG and rejects[0][1] == 0
    # The next line after the oversize one is read normally.
    _append(path, "\n" + "ok-line\n")
    await t.poll_once()
    assert await _drain(q) == ["ok-line"]


async def test_complete_oversize_line_is_rejected_neighbours_kept(tmp_path: Path):
    path = tmp_path / "x.log"
    path.write_bytes(b"first\n" + b"y" * 300 + b"\nlast\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    rejects: list[tuple[str, int, int]] = []
    t = Tailer(path, q, from_start=True, max_line_bytes=100, on_reject=lambda *a: rejects.append(a))
    await t.poll_once()
    assert await _drain(q) == ["first", "last"]
    assert rejects == [(reasons.LINE_TOO_LONG, 6, 300)]
    assert t.committed_offset == path.stat().st_size


async def test_oversize_line_spanning_chunks_is_skipped_to_newline(tmp_path: Path):
    path = tmp_path / "x.log"
    path.write_bytes(b"a\n" + b"z" * 1000 + b"\nb\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(path, q, from_start=True, max_line_bytes=50, max_chunk_bytes=64)
    while not t.caught_up:
        await t.poll_once()
    assert await _drain(q) == ["a", "b"]
    assert t.oversize_lines == 1


async def test_invalid_utf8_is_counted_not_fatal(tmp_path: Path):
    path = tmp_path / "x.log"
    path.write_bytes(b'ok\n\xff\xfe bad\nok2\n')
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(path, q, from_start=True)
    await t.poll_once()
    lines = await _drain(q)
    assert len(lines) == 3 and lines[0] == "ok" and lines[2] == "ok2"
    assert t.decode_errors == 1


# -- rotation / truncation ----------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="drain-before-rotate needs a descriptor kept open (POSIX)")
async def test_rotation_by_rename_loses_no_line(tmp_path: Path):
    """Audit: l1,l2 read, l3 appended, file renamed, new file started with n1 -> l3 was lost."""
    f = tmp_path / "a.log"
    f.write_text("l1\nl2\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    _append(f, "l3-written-before-rotate\n")
    os.rename(f, tmp_path / "a.log.1")
    f.write_text("n1\n")
    await t.poll_once()
    assert await _drain(q) == ["l1", "l2", "l3-written-before-rotate", "n1"]
    assert t.rotations == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor semantics")
async def test_rotation_with_gap_where_file_is_missing(tmp_path: Path):
    f = tmp_path / "a.log"
    f.write_text("l1\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    _append(f, "l2\n")
    os.rename(f, tmp_path / "a.log.1")
    with pytest.raises(FileNotFoundError):
        await t.poll_once()  # between rename and re-create
    assert await _drain(q) == ["l1", "l2"]
    f.write_text("n1\n")
    await t.poll_once()
    assert await _drain(q) == ["n1"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor semantics")
async def test_rotation_flushes_unterminated_final_line(tmp_path: Path):
    f = tmp_path / "a.log"
    f.write_text("l1\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    _append(f, '{"last": true}')  # no trailing newline
    os.rename(f, tmp_path / "a.log.1")
    f.write_text("n1\n")
    await t.poll_once()
    assert await _drain(q) == ["l1", '{"last": true}', "n1"]


async def test_copy_truncate_that_regrows_past_old_offset_is_detected(tmp_path: Path):
    """Audit: a replaced-in-place file that regrew past the old offset was missed."""
    f = tmp_path / "a.log"
    old = "".join(f"old-line-{i:04d}-padding-padding\n" for i in range(5))
    f.write_text(old)
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    assert len(await _drain(q)) == 5
    # Same inode: truncate in place and write MORE than before.
    new = "".join(f"new-line-{i:04d}-padding-padding-more\n" for i in range(20))
    with f.open("r+b") as h:
        h.truncate(0)
        h.write(new.encode())
    assert f.stat().st_size > len(old)
    await t.poll_once()
    got = await _drain(q)
    assert got[0] == "new-line-0000-padding-padding-more" and len(got) == 20
    assert t.rotations == 1


async def test_truncation_is_counted(tmp_path: Path):
    f = tmp_path / "a.log"
    f.write_text("one\ntwo\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    f.write_text("x\n")
    await t.poll_once()
    assert await _drain(q) == ["one", "two", "x"]
    assert t.truncations == 1


async def test_appended_data_does_not_trigger_false_rotation(tmp_path: Path):
    f = tmp_path / "a.log"
    f.write_text("".join(f"line-{i:05d}-padding-padding-padding\n" for i in range(10)))
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True)
    await t.poll_once()
    for i in range(10, 20):
        _append(f, f"line-{i:05d}-padding-padding-padding\n")
        await t.poll_once()
    assert len(await _drain(q)) == 20
    assert t.rotations == 0 and t.truncations == 0


# -- transient errors and supervision -----------------------------------------------

async def test_transient_permission_error_pauses_then_resumes(tmp_path: Path, monkeypatch):
    f = tmp_path / "a.log"
    f.write_text("a\nb\n")
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True, poll_interval=0.01, max_backoff=0.05)
    failures = {"left": 3}
    real = Tailer._ensure_handle

    def flaky(self):
        if failures["left"] > 0:
            failures["left"] -= 1
            raise PermissionError("denied")
        return real(self)

    monkeypatch.setattr(Tailer, "_ensure_handle", flaky)
    task = asyncio.create_task(t.run())
    try:
        for _ in range(200):
            await asyncio.sleep(0.01)
            if q.qsize() >= 2:
                break
        assert await _drain(q) == ["a", "b"]
        assert t.errors == 3
        assert t.last_error == "PermissionError"  # class name only: no message or path
        assert not task.done()
        _append(f, "c\n")
        for _ in range(100):
            await asyncio.sleep(0.01)
            if not q.empty():
                break
        assert await _drain(q) == ["c"]
        assert t.state == "ok"
    finally:
        t.stop()
        await asyncio.wait_for(task, 2)


async def test_state_reports_missing_error_and_stalled(tmp_path: Path):
    f = tmp_path / "a.log"
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(f, q, from_start=True, poll_interval=0.01, stalled_after=0.05)
    assert t.state == "starting"
    task = asyncio.create_task(t.run())
    try:
        await asyncio.sleep(0.05)
        assert t.state == "missing"
        f.write_text("x\n")
        await asyncio.sleep(0.05)
        assert t.state in ("ok", "stalled")
        await asyncio.sleep(0.15)
        assert t.state == "stalled"
        _append(f, "y\n")
        await asyncio.sleep(0.05)
        assert t.state == "ok"
        st = t.status()
        assert st["lines_queued"] == 2 and st["path"] == "a.log" and "/" not in st["path"]
    finally:
        t.stop()
        await asyncio.wait_for(task, 2)


async def test_pipeline_restarts_a_tailer_task_that_died(tmp_path: Path):
    work = tmp_path
    (work / "logs").mkdir()
    p = Pipeline(_isolated_settings(work), load_config())
    q: asyncio.Queue[str] = asyncio.Queue()
    t = Tailer(work / "logs" / "app.log", q, poll_interval=0.01)
    p._tailers = [t]

    async def boom() -> None:
        raise RuntimeError("bug")

    dead = asyncio.create_task(boom())
    p._tailer_tasks = {t: dead}
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert dead.done()
    p._supervise_tailers()
    assert p.tailer_restarts == 1
    assert p._tailer_tasks[t] is not dead and not p._tailer_tasks[t].done()
    t.stop()
    await asyncio.wait_for(p._tailer_tasks[t], 2)
    p._supervise_tailers()  # a stopped tailer is not restarted
    assert p.tailer_restarts == 1
