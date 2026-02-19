"""WebSocket route for real-time log streaming."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..services.log_broadcaster import broadcaster

router = APIRouter()


@router.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket):
    await broadcaster.connect(ws)
    try:
        while True:
            # Keep connection alive, wait for client messages (ping/pong)
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.disconnect(ws)
