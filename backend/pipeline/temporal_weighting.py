"""Temporal weighting engine.

The transformer attention mechanism from Vaswani et al. 2017 is
architecturally suited to this problem because drift is NOT a single
event — it is a temporal sequence.

The attention mechanism weights signals differently across time:
recent acceleration patterns carry more weight than older signals of
the same type.

A single skipped review is noise.
Ten skipped reviews with accelerating frequency over two weeks is a
Fatigue signal at severity 4.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np

from models import DriftPatternType, ProcessedSignal


class TemporalWeightingEngine:
    """Compute temporal weights for drift pattern classification.

    Uses exponential decay so recent signals dominate, and explicitly
    detects acceleration across time windows.
    """

    def __init__(
        self,
        lookback_days: int = 14,
        half_life_days: float = 3.0,
        acceleration_window_days: int = 7,
        acceleration_threshold: float = 1.5,
    ):
        self._lookback_days = lookback_days
        self._half_life_days = half_life_days
        self._acceleration_window_days = acceleration_window_days
        self._acceleration_threshold = acceleration_threshold
        # Historical timestamps per pattern per team/system
        self._history: Dict[str, Dict[DriftPatternType, List[datetime]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def record_signals(
        self,
        signals: List[ProcessedSignal],
        pattern_type: DriftPatternType,
    ) -> None:
        """Record signal timestamps for trend analysis."""
        for signal in signals:
            key = self._scope_key(signal.team_id, signal.system_id)
            self._history[key][pattern_type].append(signal.timestamp)

    def compute_weights(
        self,
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
    ) -> Dict[str, float]:
        """Compute temporal weights for all drift patterns in scope."""
        key = self._scope_key(team_id, system_id)
        history = self._history.get(key, {})

        weights: Dict[str, float] = {}
        for pattern_type in DriftPatternType:
            timestamps = history.get(pattern_type, [])
            weights[pattern_type.value] = self._exponential_decay_weight(timestamps)

        return weights

    def detect_acceleration(
        self,
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
    ) -> Dict[str, Tuple[bool, float, str]]:
        """Detect signal acceleration per drift pattern.

        A drift signal that was Watch two days ago and is now at
        Warning is MORE DANGEROUS than a signal that has been stable
        at Warning for two weeks. Acceleration must be flagged
        explicitly in every alert.

        Returns: {pattern: (is_accelerating, ratio, description)}
        """
        key = self._scope_key(team_id, system_id)
        history = self._history.get(key, {})

        results: Dict[str, Tuple[bool, float, str]] = {}
        for pattern_type in DriftPatternType:
            timestamps = history.get(pattern_type, [])
            is_accel, ratio = self._compute_acceleration(timestamps)

            if is_accel:
                desc = (
                    f"{pattern_type.value} signal frequency increased by "
                    f"{ratio:.1f}x over the past {self._acceleration_window_days} days "
                    f"compared to the prior {self._acceleration_window_days}-day window. "
                    f"Acceleration makes this signal more dangerous than a stable pattern "
                    f"at the same severity level."
                )
            else:
                desc = f"{pattern_type.value} signal frequency is stable or decreasing."

            results[pattern_type.value] = (is_accel, ratio, desc)

        return results

    def get_trend(
        self,
        pattern_type: DriftPatternType,
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
        window_days: int = 30,
    ) -> List[Dict]:
        """Get daily signal counts for trend visualization."""
        key = self._scope_key(team_id, system_id)
        timestamps = self._history.get(key, {}).get(pattern_type, [])

        now = datetime.utcnow()
        trend = []
        for days_ago in range(window_days, -1, -1):
            day_start = (now - timedelta(days=days_ago)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            day_end = day_start + timedelta(days=1)
            count = sum(1 for t in timestamps if day_start <= t < day_end)
            trend.append({"date": day_start.isoformat(), "count": count})

        return trend

    # ── Internal methods ─────────────────────────────

    def _exponential_decay_weight(self, timestamps: List[datetime]) -> float:
        """Compute exponential decay weight — recent signals dominate."""
        if not timestamps:
            return 0.0

        now = datetime.utcnow()
        cutoff = now - timedelta(days=self._lookback_days)
        recent = [t for t in timestamps if t >= cutoff]

        if not recent:
            return 0.0

        decay_rate = np.log(2) / self._half_life_days
        ages = np.array([(now - t).total_seconds() / 86400.0 for t in recent])
        weights = np.exp(-decay_rate * ages)

        return float(np.sum(weights))

    def _compute_acceleration(
        self, timestamps: List[datetime]
    ) -> Tuple[bool, float]:
        """Compare recent window to prior window."""
        if len(timestamps) < 3:
            return False, 0.0

        now = datetime.utcnow()
        recent_cutoff = now - timedelta(days=self._acceleration_window_days)
        prior_cutoff = recent_cutoff - timedelta(days=self._acceleration_window_days)

        recent = sum(1 for t in timestamps if t >= recent_cutoff)
        prior = sum(1 for t in timestamps if prior_cutoff <= t < recent_cutoff)

        if prior == 0:
            return recent > 2, float(recent)

        ratio = recent / prior
        return ratio > self._acceleration_threshold, ratio

    @staticmethod
    def _scope_key(team_id: Optional[str], system_id: Optional[str]) -> str:
        """Create a scope key for team/system level tracking."""
        return f"{team_id or 'org'}::{system_id or 'all'}"
