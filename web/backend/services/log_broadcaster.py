"""WebSocket client management and log broadcasting."""
import asyncio
import json
from collections import deque
from datetime import datetime, timezone
from fastapi import WebSocket
from ..config import settings


class LogBroadcaster:
    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._buffer: deque[dict] = deque(maxlen=settings.log_buffer_size)
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
            # Replay buffer
            for msg in self._buffer:
                try:
                    await ws.send_json(msg)
                except Exception:
                    break

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, level: str, message: str, source: str = "system"):
        msg = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            "source": source,
        }
        self._buffer.append(msg)
        dead: list[WebSocket] = []
        for ws in self._clients.copy():
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    def clear_buffer(self):
        self._buffer.clear()


broadcaster = LogBroadcaster()
