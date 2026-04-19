"""Hoarding — Drift Pattern Agent.

Detects access and authority accumulating beyond role requirements.
Not malicious — but concentrated access is concentrated risk.
"""
from __future__ import annotations
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity
from pipeline.agents import AgentState, DriftPatternAgent


class HoardingAgent(DriftPatternAgent):

    def analyze(self, state: AgentState) -> AgentState:
        signals = self._filter_relevant_signals(state.signals)
        if not signals:
            return state

        score = 0.0
        evidence: list[str] = []
        severity_val = 1

        # Indicator 1: Privilege accumulation
        priv_signals = [s for s in signals if s.features.get("privilege_count", 0) > 5]
        if priv_signals:
            max_privs = max(s.features.get("privilege_count", 0) for s in priv_signals)
            score += 0.3
            evidence.append(f"{len(priv_signals)} users with >5 privileges (max: {max_privs})")
            severity_val = max(severity_val, 3 if max_privs < 10 else 4)

        # Indicator 2: Access never revoked after role change
        stale_access = [s for s in signals if s.features.get("stale_access", False)]
        if stale_access:
            score += 0.25
            evidence.append(f"{len(stale_access)} stale access grants — privileges outlived role")
            severity_val = max(severity_val, 3)

        # Indicator 3: Shared credentials / API keys
        shared_creds = [s for s in signals if s.features.get("shared_credential", False)]
        if shared_creds:
            score += 0.2
            evidence.append(f"{len(shared_creds)} shared credential detections")
            severity_val = max(severity_val, 4)

        # Indicator 4: Data export volume anomalies
        export_signals = [s for s in signals if s.features.get("export_volume_mb", 0) > 100]
        if export_signals:
            total_mb = sum(s.features.get("export_volume_mb", 0) for s in export_signals)
            score += 0.2
            evidence.append(f"{len(export_signals)} large exports ({total_mb:.0f} MB total)")
            severity_val = max(severity_val, 3)

        # Indicator 5: Cross-department access patterns
        cross_dept = [s for s in signals if s.features.get("cross_department", False)]
        if len(cross_dept) > 2:
            score += 0.15
            evidence.append(f"{len(cross_dept)} cross-department access events")
            severity_val = max(severity_val, 2)

        tw = state.temporal_weights.get(DriftPatternType.HOARDING.value, 1.0)
        score = min(score * tw, 1.0)

        if score >= 0.15:
            cls = DriftClassification(
                pattern=DriftPatternType.HOARDING,
                confidence=round(score, 4),
                severity=Severity(min(severity_val, 5)),
                signals_used=[s.id for s in signals[:20]],
                nist_controls_at_risk=[NISTControl.AC_2, NISTControl.AU_6],
                temporal_weight=tw,
                reasoning=" | ".join(evidence),
            )
            state.classifications.append(cls)

        return state
