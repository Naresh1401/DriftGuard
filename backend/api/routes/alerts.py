"""Alert management API endpoints."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.middleware.auth import get_current_user, require_role
from core.ethical_guardrails import require_human_approval_for_critical
from models import AlertLevel, AlertStatus, AuditAction, User, UserRole

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertActionRequest(BaseModel):
    action: str  # acknowledge, escalate, resolve, acted_upon, approve
    reason: Optional[str] = None


@router.get("")
async def list_alerts(
    level: Optional[str] = None,
    status: Optional[str] = None,
    domain: Optional[str] = None,
    team_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    user: User = Depends(get_current_user),
):
    """List alerts with optional filters."""
    from main import app_state

    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(scope_alerts)

    # Apply filters
    if level:
        all_alerts = [a for a in all_alerts if a.alert_level.value == level]
    if status:
        all_alerts = [a for a in all_alerts if a.status.value == status]
    if domain:
        all_alerts = [a for a in all_alerts if a.domain == domain]
    if team_id:
        all_alerts = [a for a in all_alerts if a.team_id == team_id]

    # Sort by created_at desc
    all_alerts.sort(key=lambda a: a.created_at, reverse=True)

    return {
        "alerts": [a.model_dump(mode="json") for a in all_alerts[:limit]],
        "total": len(all_alerts),
    }


@router.get("/active/count")
async def active_alert_counts(user: User = Depends(get_current_user)):
    """Get counts of active alerts by level."""
    from main import app_state

    counts = {"Watch": 0, "Warning": 0, "Critical": 0}
    for scope_alerts in app_state.early_warning._active_alerts.values():
        for a in scope_alerts:
            if a.status == AlertStatus.ACTIVE:
                counts[a.alert_level.value] = counts.get(a.alert_level.value, 0) + 1

    return counts


@router.get("/{alert_id}")
async def get_alert(alert_id: str, user: User = Depends(get_current_user)):
    """Get a specific alert with full details."""
    from main import app_state

    for scope_alerts in app_state.early_warning._active_alerts.values():
        for a in scope_alerts:
            if str(a.id) == alert_id:
                return a.model_dump(mode="json")

    raise HTTPException(status_code=404, detail="Alert not found")


@router.post("/{alert_id}/action")
async def alert_action(
    alert_id: str,
    request: AlertActionRequest,
    user: User = Depends(get_current_user),
):
    """Perform an action on an alert.

    Actions: acknowledge, escalate, resolve, acted_upon, approve
    The 'acted_upon' action is CRITICAL — it closes the feedback
    loop to the NI calibration layer.
    """
    from main import app_state

    action = request.action

    if action == "approve":
        # Critical Alert Human Review Gate
        alert = app_state.early_warning.approve_critical_alert(
            alert_id=alert_id,
            approved_by=user.email,
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Log to governance
        app_state.critical_review_gate.approve(alert_id, user.email)
        app_state.audit_logger.log(
            AuditAction.HUMAN_REVIEW_APPROVED,
            actor=user.email,
            resource_type="alert",
            details={"alert_id": alert_id},
        )
        return {"status": "approved", "alert_id": alert_id}

    elif action == "resolve":
        alert = app_state.early_warning.resolve_alert(
            alert_id=alert_id,
            resolved_by=user.email,
            acted_upon=False,
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        app_state.audit_logger.log(
            AuditAction.ALERT_RESOLVED,
            actor=user.email,
            resource_type="alert",
            details={"alert_id": alert_id},
        )
        return {"status": "resolved", "alert_id": alert_id}

    elif action == "acted_upon":
        alert = app_state.early_warning.resolve_alert(
            alert_id=alert_id,
            resolved_by=user.email,
            acted_upon=True,
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        app_state.audit_logger.log(
            AuditAction.ALERT_ACTED_UPON,
            actor=user.email,
            resource_type="alert",
            details={"alert_id": alert_id},
        )
        return {"status": "acted_upon", "alert_id": alert_id}

    elif action == "acknowledge":
        # Find and mark acknowledged
        for scope_alerts in app_state.early_warning._active_alerts.values():
            for a in scope_alerts:
                if str(a.id) == alert_id:
                    a.status = AlertStatus.ACKNOWLEDGED
                    app_state.audit_logger.log(
                        AuditAction.ALERT_ACKNOWLEDGED,
                        actor=user.email,
                        resource_type="alert",
                        details={"alert_id": alert_id},
                    )
                    return {"status": "acknowledged", "alert_id": alert_id}
        raise HTTPException(status_code=404, detail="Alert not found")

    elif action == "escalate":
        for scope_alerts in app_state.early_warning._active_alerts.values():
            for a in scope_alerts:
                if str(a.id) == alert_id:
                    a.status = AlertStatus.ESCALATED
                    app_state.audit_logger.log(
                        AuditAction.ALERT_ESCALATED,
                        actor=user.email,
                        resource_type="alert",
                        details={"alert_id": alert_id, "reason": request.reason},
                    )
                    return {"status": "escalated", "alert_id": alert_id}
        raise HTTPException(status_code=404, detail="Alert not found")

    raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


@router.get("/health-score/{domain}")
async def get_health_score(
    domain: str,
    user: User = Depends(get_current_user),
):
    """Get organization drift health score (0-100)."""
    from main import app_state

    score = app_state.early_warning.get_org_health_score(domain)

    # Gather active alerts for breakdown
    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(
            a for a in scope_alerts
            if a.status == AlertStatus.ACTIVE and a.domain == domain
        )

    critical = sum(1 for a in all_alerts if a.alert_level == AlertLevel.CRITICAL)
    warning = sum(1 for a in all_alerts if a.alert_level == AlertLevel.WARNING)
    watch = sum(1 for a in all_alerts if a.alert_level == AlertLevel.WATCH)
    patterns = len({a.drift_pattern for a in all_alerts})

    # Determine trend based on recent alert count
    if critical > 0:
        trend = "declining"
    elif warning > 1:
        trend = "declining"
    elif len(all_alerts) == 0:
        trend = "stable"
    else:
        trend = "stable"

    return {
        "score": round(score, 1),
        "trend": trend,
        "active_patterns": patterns,
        "critical_alerts": critical,
        "warning_alerts": warning,
        "watch_alerts": watch,
    }
