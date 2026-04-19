"""Convenience / shortcut endpoints for the DriftGuard API.

These proxy to existing route handlers to provide the endpoint paths
expected by clients and the test suite.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.auth import get_current_user
from models import AlertStatus, User

router = APIRouter(tags=["Convenience"])

# ── In-memory API key store ──────────────────────────

_api_keys: dict[str, dict] = {}


class APIKeyCreateRequest(BaseModel):
    name: str = "default"
    scopes: List[str] = ["read", "write"]


@router.post("/api-key")
async def create_api_key(
    body: APIKeyCreateRequest,
    user: User = Depends(get_current_user),
):
    """Generate an API key for SDK / webhook integrations."""
    key = f"dg_{secrets.token_urlsafe(32)}"
    _api_keys[key] = {
        "name": body.name,
        "scopes": body.scopes,
        "created_by": user.email,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
    }
    return {"api_key": key, "name": body.name, "scopes": body.scopes}


@router.get("/api-key/status")
async def api_key_status(user: User = Depends(get_current_user)):
    """List all API keys for the current user."""
    user_keys = [
        {"name": v["name"], "active": v["active"], "created_at": v["created_at"], "scopes": v["scopes"]}
        for v in _api_keys.values()
        if v["created_by"] == user.email
    ]
    return {"keys": user_keys, "total": len(user_keys)}


# ── Analyze (proxy → signals/ingest/batch) ──────────


class AnalyzeRequest(BaseModel):
    signals: List[Dict[str, Any]]
    domain: str = "enterprise"


@router.post("/analyze")
async def analyze(
    body: AnalyzeRequest,
    user: User = Depends(get_current_user),
):
    """Run drift analysis on a batch of signals (convenience wrapper)."""
    from main import app_state
    from models import RawSignal, SignalType

    raw_signals = []
    for s in body.signals:
        try:
            signal_type = SignalType(s.get("signal_type", "custom"))
        except ValueError:
            signal_type = SignalType.CUSTOM
        raw = RawSignal(
            signal_type=signal_type,
            source=s.get("source", "api"),
            timestamp=datetime.utcnow(),
            data=s.get("data", s),
            domain=body.domain,
        )
        raw_signals.append(raw)

    processed = [app_state.pipeline._ingestion.ingest(r) for r in raw_signals]
    report = await app_state.pipeline.process(raw_signals, domain=body.domain)

    return {
        "status": "complete",
        "signals_processed": len(raw_signals),
        "report": report.model_dump(mode="json") if hasattr(report, "model_dump") else report,
    }


# ── Simulate (proxy → scans/trigger) ────────────────


class SimulateRequest(BaseModel):
    domain: str = "enterprise"
    scope: str = "full"
    target_patterns: List[str] = []


@router.post("/simulate")
async def simulate(
    body: SimulateRequest,
    user: User = Depends(get_current_user),
):
    """Simulate a drift scan (convenience wrapper)."""
    from api.routes.scans import trigger_scan, ScanRequest

    scan_req = ScanRequest(domain=body.domain, scope=body.scope, target_patterns=body.target_patterns)
    return await trigger_scan(scan_req, user)


# ── Dashboard overview ───────────────────────────────


@router.get("/dashboard/overview")
async def dashboard_overview(user: User = Depends(get_current_user)):
    """Aggregated dashboard data."""
    from main import app_state

    # Aggregate from active alerts
    active_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        active_alerts.extend(a for a in scope_alerts if a.status == AlertStatus.ACTIVE)

    # Build drift pattern summary from alert history
    heatmap_data = {}
    for scope_alerts in app_state.early_warning._alert_history.values():
        for alert in scope_alerts:
            for cls in getattr(alert, "drift_patterns", []):
                pattern = cls.pattern.value if hasattr(cls.pattern, "value") else str(cls.pattern)
                if pattern not in heatmap_data:
                    heatmap_data[pattern] = {"count": 0, "max_severity": 0}
                heatmap_data[pattern]["count"] += 1

    alert_summary = {"total": len(active_alerts), "critical": 0, "warning": 0, "watch": 0}
    for a in active_alerts:
        level = a.alert_level.value.lower()
        if level in alert_summary:
            alert_summary[level] += 1

    return {
        "drift_patterns": heatmap_data,
        "alerts": alert_summary,
        "health_score": app_state.early_warning.get_org_health_score("enterprise"),
    }


# ── Drift detections (inline logic, not proxy) ──────


@router.get("/drift/detections")
async def drift_detections(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """Return current drift detections."""
    from main import app_state
    from models import DriftPatternType

    heatmap = await app_state.persistence.get_drift_heatmap(domain, 30)
    if not heatmap:
        heatmap = {}
        for scope_alerts in app_state.early_warning._active_alerts.values():
            for alert in scope_alerts:
                if alert.domain == domain:
                    for cls in alert.drift_patterns:
                        p = cls.pattern.value
                        heatmap.setdefault("default", {}).setdefault(p, 0)
                        heatmap["default"][p] += 1

    return {"domain": domain, "departments": heatmap}


# ── NIST risk shortcut (inline logic) ────────────────


@router.get("/nist-risk")
async def nist_risk(
    domain: str = "enterprise",
    user: User = Depends(get_current_user),
):
    """NIST risk report shortcut."""
    from main import app_state

    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(a for a in scope_alerts if a.domain == domain)

    control_risk = {}
    for a in all_alerts:
        for c in a.nist_controls_at_risk:
            key = c.value
            if key not in control_risk:
                control_risk[key] = {"control": key, "alert_count": 0, "max_severity": 0}
            control_risk[key]["alert_count"] += 1
            control_risk[key]["max_severity"] = max(
                control_risk[key]["max_severity"], a.severity_score.value
            )

    health_score = app_state.early_warning.get_org_health_score(domain)
    return {"domain": domain, "health_score": health_score, "controls_at_risk": list(control_risk.values())}


# ── Trends shortcut (inline logic) ───────────────────


@router.get("/trends")
async def trends(
    pattern: str = "all",
    user: User = Depends(get_current_user),
):
    """Drift trend report shortcut."""
    from main import app_state
    from models import DriftPatternType

    if pattern == "all":
        results = {}
        for p in DriftPatternType:
            trend = app_state.pipeline.get_temporal_engine().get_trend(
                pattern_type=p, window_days=30,
            )
            results[p.value] = trend
        return {"pattern": "all", "days": 30, "trends": results}

    try:
        pattern_type = DriftPatternType(pattern)
    except ValueError:
        return {"error": f"Unknown pattern: {pattern}"}

    trend = app_state.pipeline.get_temporal_engine().get_trend(
        pattern_type=pattern_type, window_days=30,
    )
    return {"pattern": pattern, "days": 30, "trend": trend}


# ── PATCH alerts/{id} alias ──────────────────────────


class AlertPatchRequest(BaseModel):
    action: str
    reason: Optional[str] = None


@router.patch("/alerts/{alert_id}")
async def patch_alert(
    alert_id: str,
    body: AlertPatchRequest,
    user: User = Depends(get_current_user),
):
    """Update an alert (alias for POST /alerts/{id}/action)."""
    from api.routes.alerts import alert_action, AlertActionRequest

    req = AlertActionRequest(action=body.action, reason=body.reason)
    return await alert_action(alert_id, req, user)
