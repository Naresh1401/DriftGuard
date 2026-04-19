"""Overconfidence — Drift Pattern Agent.

Detects when people believe their judgment is reliable enough to bypass protocols.
"""
from __future__ import annotations
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class OverconfidenceAgent(DriftPatternAgent):

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: Protocol bypass events
        bypass_signals = [s for s in signals if s.features.get("bypass", False) or s.features.get("exception", False)]
        if bypass_signals:
            bypass_rate = len(bypass_signals) / max(len(signals), 1)
            score += min(bypass_rate * 0.6, 0.35)
            evidence.append(f"{len(bypass_signals)} protocol bypass events ({bypass_rate:.0%} of signals)")
            severity_val = max(severity_val, 3 if bypass_rate > 0.15 else 2)

        # Indicator 2: Single-approver decisions on high-risk actions
        single_approver = [s for s in signals if s.features.get("approver_count", 2) == 1 and s.features.get("risk_level", "low") in ("high", "critical")]
        if single_approver:
            score += 0.25
            evidence.append(f"{len(single_approver)} high-risk single-approver decisions")
            severity_val = max(severity_val, 4)

        # Indicator 3: Exception request frequency
        exception_signals = [s for s in signals if s.features.get("is_exception", False)]
        if len(exception_signals) > 2:
            score += 0.2
            evidence.append(f"{len(exception_signals)} exception requests — 'just this once' pattern")
            severity_val = max(severity_val, 3)

        # Indicator 4: Informal approvals preceding formal ones
        informal = [s for s in signals if s.signal_type.value == "communication" and s.features.get("precedes_approval", False)]
        if informal:
            score += 0.15
            evidence.append(f"{len(informal)} informal pre-approvals detected (Slack/email before formal system)")

        tw = state.temporal_weights.get(DriftPatternType.OVERCONFIDENCE.value, 1.0)
        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.OVERCONFIDENCE,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.AC_2, NISTControl.AT_2],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state
