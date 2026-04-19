"""Compliance Theater — Drift Pattern Agent.

Detects when audit scores are high but security outcomes aren't changing.
The most dangerous pattern because it generates false confidence.
"""
from __future__ import annotations
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class ComplianceTheaterAgent(DriftPatternAgent):

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: High completion rates, low outcome changes
        audit_signals = [s for s in signals if s.signal_type.value == "audit_review"]
        high_completion = [s for s in audit_signals if s.features.get("completion_rate", 0) > 0.9]
        low_outcome = [s for s in audit_signals if s.features.get("outcome_changed", True) is False]
        if high_completion and low_outcome:
            score += 0.35
            evidence.append(
                f"{len(high_completion)} audits at >90% completion but {len(low_outcome)} produced no security outcome change"
            )
            severity_val = max(severity_val, 4)

        # Indicator 2: Training completion without knowledge retention
        training_signals = [s for s in signals if s.signal_type.value == "training_completion"]
        poor_retention = [s for s in training_signals if s.features.get("post_test_score", 100) < 60]
        if training_signals and poor_retention:
            ratio = len(poor_retention) / len(training_signals)
            if ratio > 0.3:
                score += 0.25
                evidence.append(f"{ratio:.0%} of training completions with poor knowledge retention (<60%)")
                severity_val = max(severity_val, 3)

        # Indicator 3: Repetitive identical findings across audit cycles
        repeat_findings = [s for s in signals if s.features.get("repeat_finding", False)]
        if repeat_findings:
            score += 0.2
            evidence.append(f"{len(repeat_findings)} repeat findings across audit cycles — issues documented but never fixed")
            severity_val = max(severity_val, 4)

        # Indicator 4: Checkbox compliance — minimum effort
        checkbox = [s for s in signals if s.features.get("minimum_effort", False)]
        if checkbox:
            score += 0.15
            evidence.append(f"{len(checkbox)} minimum-effort compliance events (checkbox pattern)")
            severity_val = max(severity_val, 2)

        # Indicator 5: Divergence between self-assessment and external audit
        divergence = [s for s in signals if s.features.get("self_vs_external_gap", 0) > 20]
        if divergence:
            gap = max(s.features.get("self_vs_external_gap", 0) for s in divergence)
            score += 0.2
            evidence.append(f"Self-assessment vs external audit gap of {gap}% — false confidence")
            severity_val = max(severity_val, 4)

        # Indicator 6: Incident rate unchanged despite "improvements"
        incident_signals = [s for s in signals if s.signal_type.value == "incident_response"]
        if incident_signals and audit_signals and len(incident_signals) > 3:
            score += 0.1
            evidence.append("Incident rate unchanged despite active compliance program")
            severity_val = max(severity_val, 3)

        tw = state.temporal_weights.get(DriftPatternType.COMPLIANCE_THEATER.value, 1.0)
        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.COMPLIANCE_THEATER,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.CA_7, NISTControl.AT_2],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state
