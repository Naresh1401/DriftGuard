"""
COMPONENT 3 — EARLY WARNING ENGINE
====================================
This is what makes DriftGuard categorically different from every
other cybersecurity tool on the market. Every other tool detects
AFTER the breach. This engine detects BEFORE it.

Alert Levels (strictly defined, never overridden by automated systems):
- Watch:    Early drift signal. Severity 1-2. Log. Monitor.
- Warning:  Confirmed drift with persistence or co-occurrence.
            Severity 3 or two patterns simultaneously.
- Critical: Severity 4-5 or three+ patterns simultaneously.
            Requires human review before external notification.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from core.drift_patterns import DRIFT_PATTERNS
from core.ethical_guardrails import (
    require_human_approval_for_critical,
    validate_alert_transparency,
)
from models import (
    Alert,
    AlertLevel,
    AlertStatus,
    DriftClassification,
    DriftPatternType,
    DriftReport,
    NISTControl,
    Severity,
)

logger = logging.getLogger(__name__)


class EarlyWarningEngine:
    """Detect drift at Stage 1 and Stage 2 — before drift becomes visible behavior.

    Requires temporal sequence modeling across all six pattern types
    simultaneously.
    """

    def __init__(self):
        # Alert history for acceleration detection
        self._alert_history: Dict[str, List[Alert]] = defaultdict(list)
        # Active alerts by scope
        self._active_alerts: Dict[str, List[Alert]] = defaultdict(list)

    def evaluate(
        self,
        report: DriftReport,
        acceleration_data: Optional[Dict] = None,
    ) -> Optional[Alert]:
        """Evaluate a drift report and generate an alert if warranted.

        Single pattern → Watch
        Two co-occurring → Warning (regardless of individual severity)
        Three+ or severity ≥ 4 → Critical
        """
        if not report.active_patterns:
            return None

        classifications = report.active_patterns
        alert_level = self._determine_alert_level(classifications)
        max_severity = max(c.severity for c in classifications)
        avg_confidence = sum(c.confidence for c in classifications) / len(classifications)

        # Collect all NIST controls at risk
        nist_at_risk: set = set()
        for c in classifications:
            nist_at_risk.update(c.nist_controls_at_risk)

        # Build plain language explanation
        plain_explanation = self._build_plain_explanation(
            classifications, alert_level, report
        )

        # Build signals summary
        signals_summary = self._build_signals_summary(classifications)

        # Validate ethical guardrails: transparency required
        validate_alert_transparency(
            confidence=avg_confidence,
            explanation=plain_explanation,
            signals_summary=signals_summary,
        )

        # Check acceleration
        acceleration_flag = False
        acceleration_details = None
        if report.acceleration_detected:
            acceleration_flag = True
            acceleration_details = report.acceleration_details

        # Cross-reference with prior alerts for acceleration detection
        scope_key = f"{report.team_id or 'org'}::{report.system_id or 'all'}"
        prior_acceleration = self._detect_alert_acceleration(
            scope_key, alert_level
        )
        if prior_acceleration:
            acceleration_flag = True
            if acceleration_details:
                acceleration_details += f" | {prior_acceleration}"
            else:
                acceleration_details = prior_acceleration

        alert = Alert(
            id=uuid4(),
            created_at=datetime.utcnow(),
            alert_level=alert_level,
            drift_patterns=classifications,
            team_id=report.team_id,
            system_id=report.system_id,
            domain=report.domain,
            nist_controls_at_risk=list(nist_at_risk),
            severity_score=max_severity,
            confidence_score=round(avg_confidence, 4),
            signals_summary=signals_summary,
            plain_language_explanation=plain_explanation,
            acceleration_flag=acceleration_flag,
            acceleration_details=acceleration_details,
            status=AlertStatus.ACTIVE,
            human_approved=False,
        )

        # Record for history
        self._alert_history[scope_key].append(alert)
        self._active_alerts[scope_key].append(alert)

        # Determine routing
        self._apply_routing(alert)

        logger.info(
            f"Alert generated: {alert.alert_level.value} | "
            f"Patterns: {[c.pattern.value for c in classifications]} | "
            f"Severity: {max_severity.value} | "
            f"Confidence: {avg_confidence:.2f}"
        )

        return alert

    def _determine_alert_level(
        self, classifications: List[DriftClassification]
    ) -> AlertLevel:
        """Strictly defined alert levels — never overridden by automated systems.

        Watch:    Severity 1-2, single pattern
        Warning:  Severity 3, or two patterns co-occurring
        Critical: Severity 4-5, or three+ patterns active
        """
        active_count = len(classifications)
        max_severity = max(c.severity.value for c in classifications)

        # Critical: 3+ patterns or any at severity 4+
        if active_count >= 3 or max_severity >= 4:
            return AlertLevel.CRITICAL

        # Warning: 2 patterns co-occurring (regardless of individual severity)
        # OR any pattern at severity 3
        if active_count >= 2 or max_severity >= 3:
            return AlertLevel.WARNING

        # Watch: early signal, severity 1-2
        return AlertLevel.WATCH

    def _detect_alert_acceleration(
        self, scope_key: str, current_level: AlertLevel
    ) -> Optional[str]:
        """Detect if alert level has escalated from a recent prior alert.

        A drift signal that was Watch two days ago and is now at
        Warning is MORE DANGEROUS than a signal that has been stable
        at Warning for two weeks.
        """
        history = self._alert_history.get(scope_key, [])
        if len(history) < 2:
            return None

        level_rank = {AlertLevel.WATCH: 1, AlertLevel.WARNING: 2, AlertLevel.CRITICAL: 3}
        current_rank = level_rank[current_level]

        # Check last 7 days
        cutoff = datetime.utcnow() - timedelta(days=7)
        recent = [a for a in history[:-1] if a.created_at >= cutoff]

        if not recent:
            return None

        # Find the most recent prior alert
        prior = recent[-1]
        prior_rank = level_rank[prior.alert_level]

        if current_rank > prior_rank:
            days_ago = (datetime.utcnow() - prior.created_at).days
            return (
                f"ALERT ACCELERATION: Escalated from {prior.alert_level.value} "
                f"to {current_level.value} in {days_ago} day(s). "
                f"Rapid escalation indicates accelerating drift — "
                f"this is more dangerous than a stable signal at the same level."
            )

        return None

    def _build_plain_explanation(
        self,
        classifications: List[DriftClassification],
        alert_level: AlertLevel,
        report: DriftReport,
    ) -> str:
        """Build a clear, non-technical explanation for each alert."""
        parts = []

        if alert_level == AlertLevel.CRITICAL:
            parts.append(
                "CRITICAL: Immediate attention required. "
                "Human review must approve before any external notification."
            )
        elif alert_level == AlertLevel.WARNING:
            parts.append(
                "WARNING: Confirmed drift patterns detected that require action."
            )
        else:
            parts.append(
                "WATCH: Early drift signals detected. Monitoring in progress."
            )

        for cls in classifications:
            defn = DRIFT_PATTERNS[cls.pattern]
            parts.append(
                f"\n• {defn.display_name} (Severity {cls.severity.value}/5, "
                f"Confidence {cls.confidence:.0%}): {defn.plain_language_summary}"
            )

        if report.acceleration_detected:
            parts.append(
                "\n⚡ ACCELERATION DETECTED: Signal frequency is increasing. "
                "This makes the current pattern more dangerous than a stable "
                "signal at the same severity level."
            )

        # NIST controls at risk
        nist_controls = set()
        for cls in classifications:
            nist_controls.update(c.value for c in cls.nist_controls_at_risk)
        if nist_controls:
            parts.append(
                f"\nNIST Controls at Risk: {', '.join(sorted(nist_controls))}"
            )

        return "\n".join(parts)

    def _build_signals_summary(
        self, classifications: List[DriftClassification]
    ) -> str:
        """Build human-readable signals summary."""
        parts = []
        for cls in classifications:
            parts.append(
                f"{cls.pattern.value}: {cls.reasoning} "
                f"({len(cls.signals_used)} signals, weight={cls.temporal_weight:.2f})"
            )
        return " | ".join(parts)

    def _apply_routing(self, alert: Alert) -> None:
        """Set routing decision based on alert level."""
        if alert.alert_level == AlertLevel.WATCH:
            # Log and monitor. Do not notify yet.
            alert.calibration_recommendation = (
                "Monitoring in progress. System needs more signal before escalating."
            )
        elif alert.alert_level == AlertLevel.WARNING:
            # Notify compliance officer with specifics
            patterns = [c.pattern.value for c in alert.drift_patterns]
            controls = [c.value for c in alert.nist_controls_at_risk]
            alert.calibration_recommendation = (
                f"Notify compliance officer. "
                f"Drift patterns: {', '.join(patterns)}. "
                f"NIST controls at risk: {', '.join(controls)}. "
                f"Calibration response recommended."
            )
        elif alert.alert_level == AlertLevel.CRITICAL:
            # Route to governance. Require human review.
            alert.calibration_recommendation = (
                "CRITICAL: Route to governance layer. "
                "Human review and explicit approval required before "
                "any external notification is triggered."
            )

    def get_active_alerts(
        self,
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
    ) -> List[Alert]:
        """Get active (unresolved) alerts for a scope."""
        scope_key = f"{team_id or 'org'}::{system_id or 'all'}"
        return [
            a for a in self._active_alerts.get(scope_key, [])
            if a.status == AlertStatus.ACTIVE
        ]

    def resolve_alert(
        self,
        alert_id: UUID,
        resolved_by: str,
        acted_upon: bool = False,
    ) -> Optional[Alert]:
        """Resolve an alert. Track whether it was acted upon (feedback loop)."""
        for scope_alerts in self._active_alerts.values():
            for alert in scope_alerts:
                if alert.id == alert_id:
                    alert.status = (
                        AlertStatus.ACTED_UPON if acted_upon
                        else AlertStatus.RESOLVED
                    )
                    alert.resolved_at = datetime.utcnow()
                    alert.resolved_by = resolved_by
                    if acted_upon:
                        alert.acted_upon_at = datetime.utcnow()
                    return alert
        return None

    def approve_critical_alert(
        self,
        alert_id: UUID,
        approved_by: str,
    ) -> Optional[Alert]:
        """Human approval gate for Critical alerts.

        No Critical alert triggers external notification without
        explicit human approval.
        """
        for scope_alerts in self._active_alerts.values():
            for alert in scope_alerts:
                if alert.id == alert_id:
                    if alert.alert_level != AlertLevel.CRITICAL:
                        return alert
                    alert.human_approved = True
                    logger.info(
                        f"Critical alert {alert_id} approved by {approved_by}"
                    )
                    return alert
        return None

    def get_org_health_score(self, domain: str = "enterprise") -> float:
        """Compute organization drift health score (0-100).

        100 = no drift detected, perfectly safe.
        0 = maximum drift across all patterns.
        """
        all_alerts = []
        for scope_alerts in self._active_alerts.values():
            all_alerts.extend(
                a for a in scope_alerts
                if a.status == AlertStatus.ACTIVE and a.domain == domain
            )

        if not all_alerts:
            return 100.0

        # Weighted penalty: Critical=30, Warning=15, Watch=5
        penalty_map = {
            AlertLevel.CRITICAL: 30,
            AlertLevel.WARNING: 15,
            AlertLevel.WATCH: 5,
        }
        total_penalty = sum(
            penalty_map.get(a.alert_level, 5) for a in all_alerts
        )

        return max(0.0, 100.0 - total_penalty)
