"""Threat Intelligence Feed — curated advisories mapped to drift patterns."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from api.middleware.auth import get_current_user
from models import User

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

# Curated threat intelligence items — in production these would come from
# CISA KEV, MITRE ATT&CK, or vendor feeds via scheduled ingestion.
_THREAT_FEED: list[dict] = [
    {
        "source": "CISA",
        "title": "Alert Fatigue Exploitation in SOC Teams",
        "description": "Threat actors deliberately trigger high volumes of low-severity alerts to induce fatigue in SOC analysts, enabling real attacks to pass unnoticed.",
        "severity": "high",
        "drift_patterns": ["Fatigue_Numbness"],
        "nist_controls": ["AU-6", "CA-7"],
        "published": (datetime.utcnow() - timedelta(days=2)).isoformat(),
        "recommendations": [
            "Review alert triage procedures for rubber-stamp patterns",
            "Implement analyst rotation during high-volume periods",
            "Audit dismiss rates above 40%",
        ],
    },
    {
        "source": "MITRE ATT&CK",
        "title": "Privilege Escalation via Access Hoarding (T1078.004)",
        "description": "Compromised accounts with accumulated privileges across systems provide lateral movement paths. Organizations with poor access review hygiene are most vulnerable.",
        "severity": "critical",
        "drift_patterns": ["Hoarding"],
        "nist_controls": ["AC-2", "AC-6"],
        "published": (datetime.utcnow() - timedelta(days=5)).isoformat(),
        "recommendations": [
            "Enforce quarterly access recertification",
            "Flag accounts with privileges in more than 3 systems",
            "Implement just-in-time access for privileged operations",
        ],
    },
    {
        "source": "NIST",
        "title": "Compliance Theater Undermines Control Effectiveness",
        "description": "Organizations that achieve 100% compliance training completion but show no improvement in security outcomes exhibit compliance theater drift, leaving actual control gaps unaddressed.",
        "severity": "medium",
        "drift_patterns": ["Compliance_Theater"],
        "nist_controls": ["CA-7", "AT-2"],
        "published": (datetime.utcnow() - timedelta(days=8)).isoformat(),
        "recommendations": [
            "Measure training outcomes, not just completion rates",
            "Compare self-assessment scores with external audit findings",
            "Track incident rate changes after compliance activities",
        ],
    },
    {
        "source": "CISA",
        "title": "Rushed Deployments Create Supply Chain Vulnerabilities",
        "description": "Organizations under delivery pressure compress change approval windows, bypassing security reviews. Threat actors target these gaps to inject malicious code into CI/CD pipelines.",
        "severity": "high",
        "drift_patterns": ["Hurry"],
        "nist_controls": ["IR-6", "SA-11"],
        "published": (datetime.utcnow() - timedelta(days=12)).isoformat(),
        "recommendations": [
            "Enforce minimum review periods for production changes",
            "Alert on approval windows under 10 minutes",
            "Require dual approval for off-hours deployments",
        ],
    },
    {
        "source": "Insider Threat Research",
        "title": "Fear-Driven Under-Reporting Masks Security Incidents",
        "description": "Punitive incident response cultures cause employees to suppress or retract security reports, creating blind spots that threat actors exploit.",
        "severity": "medium",
        "drift_patterns": ["Quiet_Fear"],
        "nist_controls": ["IR-6", "PM-12"],
        "published": (datetime.utcnow() - timedelta(days=15)).isoformat(),
        "recommendations": [
            "Implement anonymous reporting channels",
            "Track report-then-retract patterns as a drift signal",
            "Monitor communication blackout periods exceeding 48 hours",
        ],
    },
    {
        "source": "MITRE ATT&CK",
        "title": "Overconfidence in Single-Approver Models (T1562.001)",
        "description": "Security teams that rely on single senior approvers for critical decisions create exploitable bottlenecks. Compromising one trusted insider grants unchecked approval authority.",
        "severity": "high",
        "drift_patterns": ["Overconfidence"],
        "nist_controls": ["AC-2", "AT-2"],
        "published": (datetime.utcnow() - timedelta(days=20)).isoformat(),
        "recommendations": [
            "Require dual approval for high-risk security decisions",
            "Monitor exception grant frequency per approver",
            "Rotate approval authority regularly",
        ],
    },
]


def _make_id(item: dict) -> str:
    return hashlib.sha256(f"{item['source']}:{item['title']}".encode()).hexdigest()[:12]


@router.get("/feed")
async def threat_feed(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    pattern: Optional[str] = Query(None, description="Filter by drift pattern"),
    limit: int = Query(20, le=50),
    user: User = Depends(get_current_user),
):
    """Get curated threat intelligence feed with drift pattern correlation."""
    items = _THREAT_FEED.copy()

    if severity:
        items = [i for i in items if i["severity"] == severity]
    if pattern:
        items = [i for i in items if pattern in i["drift_patterns"]]

    results = []
    for item in items[:limit]:
        results.append({**item, "id": _make_id(item)})

    return {"items": results, "total": len(results)}


@router.get("/correlate")
async def correlate_threats(
    user: User = Depends(get_current_user),
):
    """Correlate current drift alerts with known threat patterns."""
    from main import app_state

    all_alerts = []
    for scope_alerts in app_state.early_warning._active_alerts.values():
        all_alerts.extend(scope_alerts)

    correlations = []
    for item in _THREAT_FEED:
        matching_alerts = []
        for alert in all_alerts:
            alert_patterns = [p.pattern.value for p in alert.drift_patterns]
            if any(tp in alert_patterns for tp in item["drift_patterns"]):
                matching_alerts.append(str(alert.id))

        if matching_alerts:
            correlations.append({
                "threat": {**item, "id": _make_id(item)},
                "matching_alert_count": len(matching_alerts),
                "alert_ids": matching_alerts[:10],
                "risk_level": "critical" if len(matching_alerts) >= 3 else "elevated",
            })

    correlations.sort(key=lambda c: c["matching_alert_count"], reverse=True)
    return {"correlations": correlations, "total_threats": len(_THREAT_FEED), "active_correlations": len(correlations)}
