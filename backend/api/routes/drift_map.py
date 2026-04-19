"""Drift Map API — heatmap, trend, and snapshot data."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from api.middleware.auth import get_current_user
from models import DriftPatternType, User

router = APIRouter(prefix="/drift-map", tags=["Drift Map"])


@router.get("/heatmap")
async def get_heatmap(
    domain: str = "enterprise",
    days: int = Query(default=30, le=90),
    user: User = Depends(get_current_user),
):
    """Get department × pattern severity heatmap.

    Returns DB-persisted drift history aggregated by team & pattern.
    Falls back to in-memory alert data if DB is empty.
    """
    from main import app_state

    # Try DB first
    heatmap = await app_state.persistence.get_drift_heatmap(domain, days)

    if not heatmap:
        # Fallback: derive from in-memory alerts
        heatmap = _heatmap_from_memory(app_state, domain)

    # Ensure all 6 patterns present for every department
    all_patterns = [p.value for p in DriftPatternType]
    for dept in heatmap:
        for p in all_patterns:
            heatmap[dept].setdefault(p, 0)

    return {
        "domain": domain,
        "days": days,
        "departments": sorted(heatmap.keys()),
        "patterns": all_patterns,
        "data": heatmap,
    }


@router.get("/trend/{pattern}")
async def get_pattern_trend(
    pattern: str,
    days: int = Query(default=30, le=90),
    team_id: Optional[str] = None,
    user: User = Depends(get_current_user),
):
    """Get time-series trend for a specific drift pattern."""
    from main import app_state

    trend = await app_state.persistence.get_drift_trend(pattern, days, team_id)
    return {"pattern": pattern, "days": days, "team_id": team_id, "data": trend}


@router.get("/summary")
async def get_drift_summary(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """Get current drift summary — active patterns and overall health."""
    from main import app_state

    health_score = app_state.early_warning.get_org_health_score(domain)

    # Gather active pattern counts
    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(a for a in scope_alerts if a.domain == domain)

    pattern_counts = {}
    for a in all_alerts:
        for p in a.drift_patterns:
            name = p.pattern.value
            if name not in pattern_counts:
                pattern_counts[name] = {"count": 0, "max_severity": 0, "avg_confidence": 0}
            pattern_counts[name]["count"] += 1
            pattern_counts[name]["max_severity"] = max(
                pattern_counts[name]["max_severity"], p.severity.value
            )

    active_critical = sum(1 for a in all_alerts if a.alert_level.value == "Critical")
    active_warning = sum(1 for a in all_alerts if a.alert_level.value == "Warning")

    return {
        "domain": domain,
        "health_score": round(health_score, 1),
        "total_active_alerts": len(all_alerts),
        "critical": active_critical,
        "warnings": active_warning,
        "patterns": pattern_counts,
    }


def _heatmap_from_memory(app_state, domain: str) -> dict:
    """Derive heatmap from in-memory alert state."""
    heatmap: dict = {}
    for scope_alerts in app_state.early_warning._active_alerts.values():
        for alert in scope_alerts:
            if alert.domain != domain:
                continue
            dept = alert.team_id or "Organization"
            if dept not in heatmap:
                heatmap[dept] = {}
            for c in alert.drift_patterns:
                name = c.pattern.value
                current = heatmap[dept].get(name, 0)
                heatmap[dept][name] = max(current, c.severity.value)
    return heatmap
