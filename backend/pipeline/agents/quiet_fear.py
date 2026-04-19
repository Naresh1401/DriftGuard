"""Quiet Fear — Drift Pattern Agent.

Detects when known issues go unreported because the cost of speaking up
feels higher than the cost of silence.
"""
from __future__ import annotations
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class QuietFearAgent(DriftPatternAgent):

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: Incident reports declining despite stable/growing activity
        incident_signals = [s for s in signals if s.signal_type.value == "incident_response"]
        comm_signals = [s for s in signals if s.signal_type.value == "communication"]
        if len(signals) > 5 and len(incident_signals) == 0:
            score += 0.25
            evidence.append("Zero incident reports despite active signal stream — possible suppression")
            severity_val = max(severity_val, 3)

        # Indicator 2: Report-then-retract pattern
        retracted = [s for s in signals if s.features.get("retracted", False)]
        if retracted:
            score += 0.3
            evidence.append(f"{len(retracted)} reports filed then retracted — fear of reprisal")
            severity_val = max(severity_val, 4)

        # Indicator 3: Anonymous-only reporting
        anon_reports = [s for s in signals if s.features.get("anonymous", False)]
        named_reports = [s for s in incident_signals if not s.features.get("anonymous", False)]
        if anon_reports and len(anon_reports) > len(named_reports):
            score += 0.2
            evidence.append(f"{len(anon_reports)} anonymous vs {len(named_reports)} named reports — trust deficit")
            severity_val = max(severity_val, 3)

        # Indicator 4: Communication gaps — silence after incidents
        silence_gaps = [s for s in comm_signals if s.features.get("post_incident_silence_hours", 0) > 48]
        if silence_gaps:
            score += 0.2
            evidence.append(f"{len(silence_gaps)} communication blackouts >48h post-incident")
            severity_val = max(severity_val, 3)

        # Indicator 5: Escalation avoidance
        avoided = [s for s in signals if s.features.get("escalation_skipped", False)]
        if avoided:
            score += 0.15
            evidence.append(f"{len(avoided)} escalations explicitly skipped")
            severity_val = max(severity_val, 2)

        tw = state.temporal_weights.get(DriftPatternType.QUIET_FEAR.value, 1.0)
        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.QUIET_FEAR,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.IR_6, NISTControl.CA_7],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state
