"""Scan scheduling — on-demand and scheduled drift scans with history."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from api.middleware.auth import get_current_user
from models import User

router = APIRouter(prefix="/scans", tags=["Scans"])

# In-memory scan history and schedule state
_scan_history: list[dict] = []
_scheduled_scans: list[dict] = []
_active_scan: Optional[dict] = None


class ScanRequest(BaseModel):
    domain: str = "enterprise"
    scope: str = "full"  # full | quick | targeted
    target_patterns: list[str] = []


class ScheduleRequest(BaseModel):
    domain: str = "enterprise"
    scope: str = "full"
    cron_expression: str = "0 2 * * *"  # default: 2 AM daily
    enabled: bool = True


@router.post("/trigger")
async def trigger_scan(
    req: ScanRequest,
    user: User = Depends(get_current_user),
):
    """Trigger an on-demand drift scan."""
    global _active_scan
    from main import app_state

    if _active_scan and _active_scan["status"] == "running":
        return {"error": "A scan is already in progress", "scan_id": _active_scan["scan_id"]}

    scan_id = str(uuid.uuid4())[:8]
    scan = {
        "scan_id": scan_id,
        "domain": req.domain,
        "scope": req.scope,
        "target_patterns": req.target_patterns,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "signals_processed": 0,
        "alerts_generated": 0,
        "triggered_by": user.username,
    }
    _active_scan = scan

    # Run scan asynchronously
    asyncio.create_task(_execute_scan(scan, app_state))
    return {"scan_id": scan_id, "status": "started", "message": f"Scan {scan_id} initiated for {req.domain} ({req.scope})"}


async def _execute_scan(scan: dict, app_state) -> None:
    """Execute the scan in background — processes pending signals."""
    global _active_scan
    try:
        pipeline = app_state.pipeline
        early_warning = app_state.early_warning

        # Process any buffered signals through the pipeline
        processed = 0
        alerts = 0

        # Run a classification cycle
        from pipeline.signal_ingestion import SignalBuffer
        buffer = getattr(pipeline, '_signal_buffer', SignalBuffer())
        pending = buffer.flush()
        processed = len(pending)

        for signal in pending:
            result = pipeline.classify(signal)
            if result and result.get("severity", 0) >= 3:
                alerts += 1

        # Get current alert counts to determine generated alerts
        for scope_alerts in early_warning._active_alerts.values():
            for a in scope_alerts:
                if a.domain == scan["domain"]:
                    alerts += 1

        scan["status"] = "completed"
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["signals_processed"] = processed
        scan["alerts_generated"] = alerts

    except Exception as e:
        scan["status"] = "failed"
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["error"] = str(e)

    _scan_history.insert(0, scan.copy())
    _active_scan = None


@router.get("/status")
async def scan_status(user: User = Depends(get_current_user)):
    """Get current scan status."""
    if _active_scan:
        return {"active": True, **_active_scan}
    return {"active": False, "message": "No scan currently running"}


@router.get("/history")
async def scan_history(
    limit: int = Query(20, le=100),
    user: User = Depends(get_current_user),
):
    """Get scan history."""
    return {"scans": _scan_history[:limit], "total": len(_scan_history)}


@router.post("/schedule")
async def create_schedule(
    req: ScheduleRequest,
    user: User = Depends(get_current_user),
):
    """Create or update a scan schedule."""
    schedule_id = str(uuid.uuid4())[:8]
    schedule = {
        "schedule_id": schedule_id,
        "domain": req.domain,
        "scope": req.scope,
        "cron_expression": req.cron_expression,
        "enabled": req.enabled,
        "created_at": datetime.utcnow().isoformat(),
        "created_by": user.username,
        "last_run": None,
        "next_run": None,
    }
    _scheduled_scans.append(schedule)
    return {"schedule_id": schedule_id, "status": "created", "schedule": schedule}


@router.get("/schedules")
async def list_schedules(user: User = Depends(get_current_user)):
    """List all scan schedules."""
    return {"schedules": _scheduled_scans, "total": len(_scheduled_scans)}


@router.delete("/schedule/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    user: User = Depends(get_current_user),
):
    """Delete a scan schedule."""
    global _scheduled_scans
    before = len(_scheduled_scans)
    _scheduled_scans = [s for s in _scheduled_scans if s["schedule_id"] != schedule_id]
    if len(_scheduled_scans) < before:
        return {"status": "deleted", "schedule_id": schedule_id}
    return {"error": "Schedule not found"}
