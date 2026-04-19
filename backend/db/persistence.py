"""Database persistence service — wires core engines to SQLAlchemy.

Provides async methods to persist alerts, audit entries, drift history,
and governance actions to the database alongside the in-memory state.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import (
    AlertRecord,
    AuditRecord,
    CalibrationDeliveryRecord,
    CalibrationRecord,
    DriftHistoryRecord,
    NISTMappingRecord,
    async_session,
)
from models import Alert, AuditAction, AuditEntry, DriftClassification, DriftReport

logger = logging.getLogger(__name__)


class PersistenceService:
    """Centralized persistence for all DriftGuard state."""

    # ── Alerts ────────────────────────────────────────

    async def save_alert(self, alert: Alert) -> None:
        async with async_session() as session:
            record = AlertRecord(
                id=str(alert.id),
                created_at=alert.created_at,
                alert_level=alert.alert_level.value,
                domain=alert.domain,
                team_id=alert.team_id,
                system_id=alert.system_id,
                severity_score=alert.severity_score.value,
                confidence_score=alert.confidence_score,
                drift_patterns_json=json.dumps([
                    {"pattern": c.pattern.value, "confidence": c.confidence,
                     "severity": c.severity.value, "reasoning": c.reasoning}
                    for c in alert.drift_patterns
                ]),
                nist_controls_json=json.dumps([c.value for c in alert.nist_controls_at_risk]),
                signals_summary=alert.signals_summary,
                plain_language_explanation=alert.plain_language_explanation,
                calibration_recommendation=alert.calibration_recommendation,
                acceleration_flag=alert.acceleration_flag,
                acceleration_details=alert.acceleration_details,
                status=alert.status.value,
                human_approved=alert.human_approved,
            )
            session.add(record)
            await session.commit()
            logger.debug(f"Alert {alert.id} persisted to DB")

    async def update_alert_status(self, alert_id: str, status: str,
                                   resolved_by: Optional[str] = None) -> None:
        async with async_session() as session:
            stmt = (
                update(AlertRecord)
                .where(AlertRecord.id == alert_id)
                .values(
                    status=status,
                    resolved_at=datetime.utcnow() if status in ("resolved", "acted_upon") else None,
                    resolved_by=resolved_by,
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def get_alerts(self, limit: int = 50, offset: int = 0,
                         status: Optional[str] = None,
                         domain: Optional[str] = None) -> List[Dict]:
        async with async_session() as session:
            q = select(AlertRecord).order_by(desc(AlertRecord.created_at))
            if status:
                q = q.where(AlertRecord.status == status)
            if domain:
                q = q.where(AlertRecord.domain == domain)
            q = q.offset(offset).limit(limit)
            result = await session.execute(q)
            rows = result.scalars().all()
            return [self._alert_to_dict(r) for r in rows]

    async def count_alerts(self, status: Optional[str] = None) -> int:
        async with async_session() as session:
            q = select(func.count(AlertRecord.id))
            if status:
                q = q.where(AlertRecord.status == status)
            result = await session.execute(q)
            return result.scalar() or 0

    # ── Drift History ─────────────────────────────────

    async def save_drift_snapshot(self, report: DriftReport) -> None:
        async with async_session() as session:
            for cls in report.active_patterns:
                record = DriftHistoryRecord(
                    timestamp=report.timestamp,
                    domain=report.domain,
                    team_id=report.team_id,
                    system_id=report.system_id,
                    pattern=cls.pattern.value,
                    severity=cls.severity.value,
                    confidence=cls.confidence,
                    alert_level=report.alert_level.value,
                )
                session.add(record)
            await session.commit()

    async def get_drift_heatmap(self, domain: str = "enterprise",
                                 days: int = 30) -> Dict[str, Dict[str, float]]:
        """Get dept × pattern drift heatmap from history."""
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            q = select(DriftHistoryRecord).where(
                DriftHistoryRecord.domain == domain,
                DriftHistoryRecord.timestamp >= cutoff,
            )
            result = await session.execute(q)
            rows = result.scalars().all()

        heatmap: Dict[str, Dict[str, list]] = {}
        for r in rows:
            dept = r.team_id or "Organization"
            if dept not in heatmap:
                heatmap[dept] = {}
            if r.pattern not in heatmap[dept]:
                heatmap[dept][r.pattern] = []
            heatmap[dept][r.pattern].append(r.severity)

        # Average severities
        return {
            dept: {
                pattern: round(sum(vals) / len(vals), 1)
                for pattern, vals in patterns.items()
            }
            for dept, patterns in heatmap.items()
        }

    async def get_drift_trend(self, pattern: str, days: int = 30,
                               team_id: Optional[str] = None) -> List[Dict]:
        """Get time-series trend for a specific pattern."""
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            q = select(DriftHistoryRecord).where(
                DriftHistoryRecord.pattern == pattern,
                DriftHistoryRecord.timestamp >= cutoff,
            ).order_by(DriftHistoryRecord.timestamp)
            if team_id:
                q = q.where(DriftHistoryRecord.team_id == team_id)
            result = await session.execute(q)
            rows = result.scalars().all()

        return [
            {"date": r.timestamp.isoformat(), "severity": r.severity,
             "confidence": r.confidence, "alert_level": r.alert_level}
            for r in rows
        ]

    # ── Audit Log ─────────────────────────────────────

    async def save_audit_entry(self, entry: AuditEntry) -> None:
        async with async_session() as session:
            record = AuditRecord(
                id=str(entry.id),
                timestamp=entry.timestamp,
                action=entry.action.value,
                actor=entry.actor,
                resource_type=entry.resource_type,
                resource_id=str(entry.resource_id) if entry.resource_id else None,
                details_json=json.dumps(entry.details),
                ip_address=entry.ip_address,
            )
            session.add(record)
            await session.commit()

    async def get_audit_entries(self, limit: int = 100, offset: int = 0,
                                 action: Optional[str] = None) -> List[Dict]:
        async with async_session() as session:
            q = select(AuditRecord).order_by(desc(AuditRecord.timestamp))
            if action:
                q = q.where(AuditRecord.action == action)
            q = q.offset(offset).limit(limit)
            result = await session.execute(q)
            rows = result.scalars().all()
            return [
                {"id": r.id, "timestamp": r.timestamp.isoformat(),
                 "action": r.action, "actor": r.actor,
                 "resource_type": r.resource_type,
                 "resource_id": r.resource_id,
                 "details": json.loads(r.details_json or "{}"),
                 "ip_address": r.ip_address}
                for r in rows
            ]

    async def count_audit_entries(self) -> int:
        async with async_session() as session:
            result = await session.execute(select(func.count(AuditRecord.id)))
            return result.scalar() or 0

    # ── Report aggregation queries ────────────────────

    async def get_pattern_distribution(self, domain: str = "enterprise",
                                        days: int = 7) -> Dict[str, int]:
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            q = select(AlertRecord).where(
                AlertRecord.domain == domain,
                AlertRecord.created_at >= cutoff,
            )
            result = await session.execute(q)
            rows = result.scalars().all()

        dist: Dict[str, int] = {}
        for r in rows:
            patterns = json.loads(r.drift_patterns_json or "[]")
            for p in patterns:
                name = p.get("pattern", "Unknown")
                dist[name] = dist.get(name, 0) + 1
        return dist

    async def get_nist_risk_summary(self, domain: str = "enterprise",
                                     days: int = 30) -> List[Dict]:
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            q = select(AlertRecord).where(
                AlertRecord.domain == domain,
                AlertRecord.created_at >= cutoff,
            )
            result = await session.execute(q)
            rows = result.scalars().all()

        control_risk: Dict[str, Dict] = {}
        for r in rows:
            controls = json.loads(r.nist_controls_json or "[]")
            patterns = json.loads(r.drift_patterns_json or "[]")
            for ctrl in controls:
                if ctrl not in control_risk:
                    control_risk[ctrl] = {"control": ctrl, "alert_count": 0,
                                          "max_severity": 0, "patterns": set()}
                control_risk[ctrl]["alert_count"] += 1
                control_risk[ctrl]["max_severity"] = max(
                    control_risk[ctrl]["max_severity"], r.severity_score
                )
                for p in patterns:
                    control_risk[ctrl]["patterns"].add(p.get("pattern", ""))

        return [
            {**v, "patterns": list(v["patterns"]),
             "risk_score": round(min(v["max_severity"] + v["alert_count"] * 0.3, 5.0), 1)}
            for v in control_risk.values()
        ]

    async def get_weekly_stats(self, domain: str = "enterprise") -> Dict:
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=7)
            q = select(AlertRecord).where(
                AlertRecord.domain == domain,
                AlertRecord.created_at >= cutoff,
            )
            result = await session.execute(q)
            rows = result.scalars().all()

        critical = sum(1 for r in rows if r.alert_level == "Critical")
        warning = sum(1 for r in rows if r.alert_level == "Warning")
        watch = sum(1 for r in rows if r.alert_level == "Watch")

        return {
            "total_alerts": len(rows),
            "critical": critical,
            "warning": warning,
            "watch": watch,
        }

    # ── Scan History ──────────────────────────────────

    async def get_alert_stats_24h(self, domain: str = "enterprise") -> Dict:
        async with async_session() as session:
            cutoff = datetime.utcnow() - timedelta(hours=24)
            q = select(AlertRecord).where(
                AlertRecord.domain == domain,
                AlertRecord.created_at >= cutoff,
            )
            result = await session.execute(q)
            rows = result.scalars().all()

        return {
            "total_24h": len(rows),
            "critical_24h": sum(1 for r in rows if r.alert_level == "Critical"),
            "resolved_24h": sum(1 for r in rows if r.status in ("resolved", "acted_upon")),
        }

    # ── Helpers ───────────────────────────────────────

    @staticmethod
    def _alert_to_dict(r: AlertRecord) -> Dict:
        return {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "alert_level": r.alert_level,
            "domain": r.domain,
            "team_id": r.team_id,
            "system_id": r.system_id,
            "severity_score": r.severity_score,
            "confidence_score": r.confidence_score,
            "drift_patterns": json.loads(r.drift_patterns_json or "[]"),
            "nist_controls": json.loads(r.nist_controls_json or "[]"),
            "signals_summary": r.signals_summary,
            "plain_language_explanation": r.plain_language_explanation,
            "calibration_recommendation": r.calibration_recommendation,
            "acceleration_flag": r.acceleration_flag,
            "acceleration_details": r.acceleration_details,
            "status": r.status,
            "human_approved": r.human_approved,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            "resolved_by": r.resolved_by,
        }
