"""Fatigue / Numbness — Drift Pattern Agent.

Detects when teams are overwhelmed by alerts, reviews, and approvals
to the point where they stop truly seeing what they're looking at.
"""
from __future__ import annotations
from typing import List
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class FatigueAgent(DriftPatternAgent):
    """Specialized detection for alert fatigue and review numbness."""

    INDICATORS = {
        "rubber_stamp_ratio",      # approvals with <5s review time
        "review_variance",         # how much review outcomes vary
        "alert_dismiss_rate",      # % of alerts dismissed without action
        "session_duration_trend",  # declining review session lengths
        "batch_approval_count",    # bulk approvals in single sessions
    }

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: High-volume low-engagement patterns
        audit_signals = [s for s in signals if s.signal_type.value == "audit_review"]
        if audit_signals:
            avg_features = self._avg_feature(audit_signals, "review_duration_seconds")
            if avg_features is not None and avg_features < 30:
                score += 0.25
                evidence.append(f"Avg review duration only {avg_features:.0f}s (rubber-stamping likely)")
                severity_val = max(severity_val, 3)

        # Indicator 2: Alert dismiss rate
        access_signals = [s for s in signals if s.signal_type.value == "access_log"]
        dismissed = sum(1 for s in access_signals if s.features.get("dismissed", False))
        if access_signals and len(access_signals) > 3:
            dismiss_rate = dismissed / len(access_signals)
            if dismiss_rate > 0.5:
                score += 0.3
                evidence.append(f"Alert dismiss rate {dismiss_rate:.0%} — signals being ignored")
                severity_val = max(severity_val, 4)
            elif dismiss_rate > 0.2:
                score += 0.15
                evidence.append(f"Elevated dismiss rate {dismiss_rate:.0%}")
                severity_val = max(severity_val, 2)

        # Indicator 3: Batch approvals
        batch_signals = [s for s in signals if s.features.get("batch_size", 1) > 5]
        if batch_signals:
            score += 0.2
            evidence.append(f"{len(batch_signals)} batch approval events (>5 items per batch)")
            severity_val = max(severity_val, 3)

        # Indicator 4: Declining engagement over time (temporal)
        tw = state.temporal_weights.get(DriftPatternType.FATIGUE.value, 1.0)
        if tw > 1.2:
            score += 0.15
            evidence.append(f"Temporal weight {tw:.2f} — pattern accelerating")
            severity_val = max(severity_val, severity_val + 1)

        # Indicator 5: Volume overload
        if len(signals) > 20:
            score += 0.1
            evidence.append(f"High signal volume ({len(signals)} signals)")

        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.FATIGUE,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.AU_6, NISTControl.CA_7],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state

    @staticmethod
    def _avg_feature(signals: List[ProcessedSignal], key: str) -> float | None:
        vals = [s.features.get(key) for s in signals if s.features.get(key) is not None]
        return sum(vals) / len(vals) if vals else None
