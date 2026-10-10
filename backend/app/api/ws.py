"""WebSocket endpoint and broadcaster (SPEC.md section 6.11).

On connect: a snapshot, then a stream of metric/alert/incident_update/logs/
heartbeat messages.

Each client gets its own bounded outbound queue drained by its own sender
task, so ``broadcast()`` never awaits a network write: one slow or stalled
browser can't slow detection down. The snapshot is queued *before* the client
joins the broadcast set, so it is always the first message a client sees and
can't interleave with a live message. A client that falls more than
``CLIENT_QUEUE_SIZE`` messages behind is disconnected rather than silently
skipped; its reconnect fetches a fresh snapshot, so it never shows a state
with holes in it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()

CLIENT_QUEUE_SIZE = 2000
SLOW_CLIENT_CLOSE_CODE = 4008


class _Client:
    def __init__(self, ws: WebSocket) -> None:
        self.ws = ws
        self.queue: "asyncio.Queue[Optional[str]]" = asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE)
        self.too_slow = False

    async def pump(self) -> None:
        while True:
            payload = await self.queue.get()
            if payload is None:
                await self.ws.close(code=SLOW_CLIENT_CLOSE_CODE)
                return
            await self.ws.send_text(payload)


class Broadcaster:
    def __init__(self) -> None:
        self._clients: set[_Client] = set()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def add(self, client: _Client) -> None:
        self._clients.add(client)

    def remove(self, client: _Client) -> None:
        self._clients.discard(client)

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._clients:
            return
        payload = json.dumps(message, default=str)
        for client in list(self._clients):
            try:
                client.queue.put_nowait(payload)
            except asyncio.QueueFull:
                self._drop_slow(client)

    def _drop_slow(self, client: _Client) -> None:
        self.remove(client)
        client.too_slow = True
        try:
            while True:
                client.queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        client.queue.put_nowait(None)
        logger.warning("ws: disconnecting a client that fell %d messages behind", CLIENT_QUEUE_SIZE)


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    pipeline = ws.app.state.pipeline
    from app.api.auth import read_requires_auth, resolve_caller

    if read_requires_auth(pipeline.settings):
        token = ws.query_params.get("token")
        if resolve_caller(pipeline.settings, token) is None:
            await ws.close(code=1008)
            return
    await ws.accept()
    client = _Client(ws)
    client.queue.put_nowait(json.dumps(pipeline.snapshot(), default=str))
    pipeline.broadcaster.add(client)
    sender = asyncio.create_task(client.pump())
    receiver = asyncio.create_task(_drain_incoming(ws))
    try:
        await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        pipeline.broadcaster.remove(client)
        for task in (sender, receiver):
            task.cancel()
        for task in (sender, receiver):
            try:
                await task
            except (asyncio.CancelledError, WebSocketDisconnect, RuntimeError):
                pass
            except Exception:
                logger.debug("ws: connection task ended with an error", exc_info=True)


async def _drain_incoming(ws: WebSocket) -> None:
    """The stream is push-only; incoming frames are ignored, but reading them
    is how a client disconnect is noticed."""
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        return
