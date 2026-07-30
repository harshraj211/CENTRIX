"""
WebSocket route: /ws/scan/{scan_id}

The client connects and receives a stream of newline-delimited log messages
pushed in real-time by the scanner engine via the asyncio.Queue stored in
db.store. When the scan finishes, a special "__DONE__" sentinel is sent and
the connection closes cleanly.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import db.store as store

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scan/{scan_id}")
async def scan_log_stream(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    # Wait up to 5 s for the scan to be registered
    for _ in range(50):
        q = store.get_log_queue(scan_id)
        if q is not None:
            break
        await asyncio.sleep(0.1)
    else:
        await websocket.send_text("[ERROR] Scan not found or not started.")
        await websocket.close()
        return

    try:
        while True:
            try:
                # Wait for a log message (timeout 30 s — acts as heartbeat guard)
                msg: str = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a keep-alive ping
                await websocket.send_text("[PING]")
                continue

            await websocket.send_text(msg)

            if msg == "__DONE__":
                break

    except WebSocketDisconnect:
        pass  # Client disconnected — fine
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
