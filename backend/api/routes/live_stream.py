"""Server-Sent Events (SSE) live stream of alerts and risk pulses.

Provides a real-time push channel to the frontend dashboard so operators
see new drift alerts and risk score pulses without polling.

Endpoint:
    GET /api/v1/stream/events?token=<jwt>

Notes:
- EventSource cannot send Authorization headers, so the JWT is passed as a
  query param `token` and validated explicitly here.
- Stream emits keep-alive comments every 15s to keep proxies happy.
- Diff-based: only alerts seen for the first time since the connection
  opened are pushed.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncGenerator, Set

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt

from config.settings import settings

router = APIRouter(prefix="/stream", tags=["Live Stream"])


def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="invalid token")
        return sub
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid token")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _event_source() -> AsyncGenerator[bytes, None]:
    from main import app_state

    seen_ids: Set[str] = set()

    # Initial hello frame
    yield f"event: hello\ndata: {json.dumps({'ts': _now_iso(), 'msg': 'connected'})}\n\n".encode()

    last_keepalive = asyncio.get_event_loop().time()
    while True:
        try:
            # Snapshot active alerts
            active = []
            for scope_alerts in app_state.early_warning._active_alerts.values():
                active.extend(scope_alerts)

            # Emit only new alerts
            new_alerts = [a for a in active if a.alert_id not in seen_ids]
            for a in new_alerts:
                seen_ids.add(a.alert_id)
                payload = {
                    "alert_id": a.alert_id,
                    "domain": a.domain,
                    "pattern": getattr(a.pattern_type, "value", str(a.pattern_type)),
                    "level": getattr(a.alert_level, "value", str(a.alert_level)),
                    "severity": int(getattr(a, "severity_score", 0) or 0),
                    "confidence": float(getattr(a, "confidence_score", 0.0) or 0.0),
                    "status": getattr(a.status, "value", str(a.status)),
                    "ts": _now_iso(),
                }
                yield f"event: alert\ndata: {json.dumps(payload)}\n\n".encode()

            # Pulse with active counts every tick
            pulse = {
                "ts": _now_iso(),
                "active_alerts": len(active),
                "domains": sorted({a.domain for a in active}),
            }
            yield f"event: pulse\ndata: {json.dumps(pulse)}\n\n".encode()

            # Keep-alive comment every ~15s
            now_t = asyncio.get_event_loop().time()
            if now_t - last_keepalive > 15:
                yield b": keep-alive\n\n"
                last_keepalive = now_t

            await asyncio.sleep(3)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            err = json.dumps({"ts": _now_iso(), "error": str(exc)[:200]})
            yield f"event: error\ndata: {err}\n\n".encode()
            await asyncio.sleep(5)


@router.get("/events")
async def stream_events(token: str = Query(..., description="JWT access token")):
    """Open an SSE stream of live alerts and pulses.

    Frontend usage:
        const es = new EventSource(`/api/v1/stream/events?token=${jwt}`)
        es.addEventListener('alert', (e) => ...)
        es.addEventListener('pulse', (e) => ...)
    """
    _decode_token(token)
    return StreamingResponse(
        _event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
