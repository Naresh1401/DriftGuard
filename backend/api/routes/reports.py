"""Reports API — trend analysis, PDF export, board-ready summaries."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from api.middleware.auth import get_current_user
from models import DriftPatternType, User

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/weekly-summary")
async def weekly_drift_summary(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """Weekly drift summary report."""
    from main import app_state

    # Gather alert data
    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(a for a in scope_alerts if a.domain == domain)

    health_score = app_state.early_warning.get_org_health_score(domain)

    pattern_counts = {}
    for a in all_alerts:
        for p in a.drift_patterns:
            pattern_counts[p.pattern.value] = pattern_counts.get(p.pattern.value, 0) + 1

    return {
        "period": "weekly",
        "domain": domain,
        "health_score": round(health_score, 1),
        "total_alerts": len(all_alerts),
        "critical_count": sum(1 for a in all_alerts if a.alert_level.value == "Critical"),
        "warning_count": sum(1 for a in all_alerts if a.alert_level.value == "Warning"),
        "watch_count": sum(1 for a in all_alerts if a.alert_level.value == "Watch"),
        "pattern_distribution": pattern_counts,
        "nist_controls_at_risk": list(set(
            c.value for a in all_alerts for c in a.nist_controls_at_risk
        )),
    }


@router.get("/trend/{pattern}")
async def pattern_trend(
    pattern: str,
    days: int = Query(default=30, le=90),
    team_id: Optional[str] = None,
    system_id: Optional[str] = None,
    user: User = Depends(get_current_user),
):
    """Get trend data for a specific drift pattern (30/60/90 day)."""
    from main import app_state

    try:
        pattern_type = DriftPatternType(pattern)
    except ValueError:
        return {"error": f"Unknown pattern: {pattern}"}

    trend = app_state.pipeline.get_temporal_engine().get_trend(
        pattern_type=pattern_type,
        team_id=team_id,
        system_id=system_id,
        window_days=days,
    )
    return {"pattern": pattern, "days": days, "trend": trend}


@router.get("/nist-risk")
async def nist_compliance_risk(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """NIST compliance risk report showing controls at risk."""
    from main import app_state

    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(a for a in scope_alerts if a.domain == domain)

    control_risk = {}
    for a in all_alerts:
        for c in a.nist_controls_at_risk:
            key = c.value
            if key not in control_risk:
                control_risk[key] = {"control": key, "alert_count": 0, "max_severity": 0, "patterns": []}
            control_risk[key]["alert_count"] += 1
            control_risk[key]["max_severity"] = max(
                control_risk[key]["max_severity"], a.severity_score.value
            )
            for p in a.drift_patterns:
                if p.pattern.value not in control_risk[key]["patterns"]:
                    control_risk[key]["patterns"].append(p.pattern.value)

    return {
        "domain": domain,
        "controls_at_risk": list(control_risk.values()),
    }


@router.get("/board-summary")
async def board_ready_summary(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """Board-ready one-page governance summary."""
    from main import app_state

    health_score = app_state.early_warning.get_org_health_score(domain)
    effectiveness = app_state.content_api.get_effectiveness_report()

    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(a for a in scope_alerts if a.domain == domain)

    trend_direction = "stable"
    if len(all_alerts) > 5:
        recent = sum(1 for a in all_alerts[-10:] if a.alert_level.value in ("Warning", "Critical"))
        older = sum(1 for a in all_alerts[:10] if a.alert_level.value in ("Warning", "Critical"))
        if recent > older:
            trend_direction = "degrading"
        elif recent < older:
            trend_direction = "improving"

    return {
        "domain": domain,
        "executive_summary": {
            "health_score": round(health_score, 1),
            "trend": trend_direction,
            "active_critical": sum(1 for a in all_alerts if a.alert_level.value == "Critical"),
            "active_warnings": sum(1 for a in all_alerts if a.alert_level.value == "Warning"),
            "calibration_responses_delivered": sum(e.get("delivered", 0) for e in effectiveness),
            "calibration_acted_upon": sum(e.get("acted_upon", 0) for e in effectiveness),
        },
        "recommendation": (
            "Organization drift health is within acceptable parameters."
            if health_score >= 70
            else "Elevated drift detected. Governance review recommended."
            if health_score >= 40
            else "CRITICAL: Significant drift across multiple teams. Immediate governance intervention required."
        ),
    }
