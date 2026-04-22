"""
AI BREACH RISK FORECASTER + HUMAN-DRIFT CORRELATION.
====================================================

Two advanced engines:

  1. RiskForecaster — exponentially weighted moving average over a rolling
     history of risk scores. Returns a 24-hour outlook with a 95% band.
     Pure NumPy-free implementation; no external ML dependency.

  2. CrossDriftCorrelator — given a set of AI breach detections AND a set
     of human-drift classifications (from the existing pipeline), surface
     pairs that fired in the same time window. The presence of an AI
     pattern overlapping with, eg, BEHAVIORAL_VARIANCE in the same actor
     window is a much stronger Critical signal than either alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Any, Dict, List, Optional

from core.ai_drift_patterns import AIBreachPatternType
from engine.ai_breach_detector import AIBreachDetection


# ── 1. Risk forecaster ────────────────────────────

@dataclass
class RiskForecastPoint:
    timestamp: datetime
    forecast: float
    lower_bound: float
    upper_bound: float


class RiskForecaster:
    """EWMA forecaster over a rolling buffer of (timestamp, risk) samples."""

    def __init__(self, alpha: float = 0.3, max_history: int = 288):  # 24h at 5-min cadence
        self.alpha = alpha
        self.max_history = max_history
        self.history: List[tuple] = []  # list of (datetime, float)

    def add(self, ts: datetime, risk: float) -> None:
        self.history.append((ts, max(0.0, min(100.0, risk))))
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

    def _ewma(self) -> float:
        if not self.history:
            return 0.0
        s = self.history[0][1]
        for _, v in self.history[1:]:
            s = self.alpha * v + (1 - self.alpha) * s
        return s

    def forecast(self, horizon_minutes: int = 1440, step_minutes: int = 60) -> List[RiskForecastPoint]:
        """Project the EWMA forward, widening the confidence band over horizon."""
        if not self.history:
            return []
        base = self._ewma()
        # noise band from observed stdev, fall back to 5
        vals = [v for _, v in self.history]
        sd = pstdev(vals) if len(vals) > 1 else 5.0
        sd = max(sd, 3.0)
        last_ts = self.history[-1][0]
        out: List[RiskForecastPoint] = []
        for i in range(1, (horizon_minutes // step_minutes) + 1):
            t = last_ts + timedelta(minutes=step_minutes * i)
            # band widens with sqrt(time)
            spread = 1.96 * sd * (i ** 0.5) / 4
            out.append(RiskForecastPoint(
                timestamp=t,
                forecast=round(base, 1),
                lower_bound=round(max(0.0, base - spread), 1),
                upper_bound=round(min(100.0, base + spread), 1),
            ))
        return out

    def to_dict(self) -> Dict[str, Any]:
        pts = self.forecast()
        return {
            "samples": len(self.history),
            "current_ewma": round(self._ewma(), 1),
            "forecast": [
                {
                    "timestamp": p.timestamp.isoformat(),
                    "forecast": p.forecast,
                    "lower_bound": p.lower_bound,
                    "upper_bound": p.upper_bound,
                }
                for p in pts
            ],
        }


# ── 2. Human-drift correlator ─────────────────────

@dataclass
class CrossDriftFinding:
    actor_id: str
    ai_pattern: AIBreachPatternType
    human_pattern: str  # eg 'BEHAVIORAL_VARIANCE'
    overlap_minutes: int
    combined_severity: int  # 1..5 capped
    reasoning: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "ai_pattern": self.ai_pattern.value,
            "human_pattern": self.human_pattern,
            "overlap_minutes": self.overlap_minutes,
            "combined_severity": self.combined_severity,
            "reasoning": self.reasoning,
        }


@dataclass
class HumanDriftEvent:
    """Lightweight projection of a human-drift classification for correlation."""
    actor_id: str
    pattern: str
    timestamp: datetime
    severity: int = 3


class CrossDriftCorrelator:
    """Surface AI breach detections that fired alongside human-drift events
    for the same actor within a configurable window."""

    def __init__(self, window_minutes: int = 60):
        self.window = timedelta(minutes=window_minutes)

    def correlate(
        self,
        ai_detections: List[AIBreachDetection],
        human_events: List[HumanDriftEvent],
        ai_signal_actor_map: Optional[Dict[str, str]] = None,
    ) -> List[CrossDriftFinding]:
        """ai_signal_actor_map: optional mapping of detection.id -> primary actor id.
        If None, we fall back to per-pattern global match."""
        out: List[CrossDriftFinding] = []
        if not ai_detections or not human_events:
            return out
        for det in ai_detections:
            actor = (ai_signal_actor_map or {}).get(str(det.id))
            for ev in human_events:
                if actor and ev.actor_id != actor:
                    continue
                # without explicit map, use time-window only
                delta = abs((det.detected_at - ev.timestamp).total_seconds()) / 60.0
                if delta * 60 > self.window.total_seconds():
                    continue
                combined = min(5, max(det.severity, ev.severity) + 1)
                out.append(CrossDriftFinding(
                    actor_id=ev.actor_id,
                    ai_pattern=det.pattern,
                    human_pattern=ev.pattern,
                    overlap_minutes=int(delta),
                    combined_severity=combined,
                    reasoning=(
                        f"AI pattern {det.pattern.value} (conf {det.confidence}) and "
                        f"human pattern {ev.pattern} (sev {ev.severity}) for actor "
                        f"{ev.actor_id} fired within {int(delta)} minutes — combined "
                        f"signals warrant priority review."
                    ),
                ))
        return out
