"""Hurry / Urgency-Override — Drift Pattern Agent.

Detects when deadline pressure compresses the time available for proper validation.
"""
from __future__ import annotations
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class HurryAgent(DriftPatternAgent):

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: Compressed approval windows
        fast_approvals = [s for s in signals if s.features.get("approval_window_minutes", 999) < 10]
        if fast_approvals:
            ratio = len(fast_approvals) / max(len(signals), 1)
            score += min(ratio * 0.5, 0.3)
            evidence.append(f"{len(fast_approvals)} approvals in <10 min — compressed validation")
            severity_val = max(severity_val, 3)

        # Indicator 2: High-velocity access changes
        access_bursts = [s for s in signals if s.features.get("changes_per_hour", 0) > 10]
        if access_bursts:
            score += 0.25
            evidence.append(f"{len(access_bursts)} high-velocity change bursts (>10/hr)")
            severity_val = max(severity_val, 3)

        # Indicator 3: Deployments with incomplete validation
        incomplete_deploys = [s for s in signals if s.features.get("validation_complete", True) is False]
        if incomplete_deploys:
            score += 0.3
            evidence.append(f"{len(incomplete_deploys)} deployments with incomplete validation signatures")
            severity_val = max(severity_val, 4)

        # Indicator 4: Shortened review cycles
        short_reviews = [s for s in signals if s.signal_type.value == "audit_review" and s.features.get("review_cycle_days", 7) < 2]
        if short_reviews:
            score += 0.15
            evidence.append(f"{len(short_reviews)} reviews completed in <2 days (normally 7)")
            severity_val = max(severity_val, 2)

        # Indicator 5: After-hours / weekend activity spikes
        off_hours = [s for s in signals if s.features.get("off_hours", False)]
        if len(off_hours) > 3:
            score += 0.1
            evidence.append(f"{len(off_hours)} off-hours events — deadline pressure")

        tw = state.temporal_weights.get(DriftPatternType.HURRY.value, 1.0)
        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.HURRY,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.IR_6, NISTControl.AU_6],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state
