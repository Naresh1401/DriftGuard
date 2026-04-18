"""Severity scoring with temporal weighting.

Severity 1-5 mirrors NIST severity levels.
Temporal weighting: recent acceleration carries more weight.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import List

import numpy as np

from models import DriftClassification, ProcessedSignal, Severity


def compute_temporal_weight(
    timestamps: List[datetime],
    lookback_days: int = 14,
    half_life_days: float = 3.0,
) -> float:
    """Exponential decay weighting — recent signals dominate.

    A single skipped review is noise. Ten skipped reviews with
    accelerating frequency over two weeks is a Fatigue signal at
    severity 4. This function implements that distinction.
    """
    if not timestamps:
        return 0.0

    now = datetime.utcnow()
    cutoff = now - timedelta(days=lookback_days)
    recent = [t for t in timestamps if t >= cutoff]

    if not recent:
        return 0.0

    decay_rate = np.log(2) / half_life_days
    ages_days = np.array([(now - t).total_seconds() / 86400 for t in recent])
    weights = np.exp(-decay_rate * ages_days)

    return float(np.sum(weights))


def detect_acceleration(
    timestamps: List[datetime],
    window_days: int = 7,
) -> tuple[bool, float]:
    """Detect if signal frequency is accelerating.

    Returns (is_accelerating, acceleration_ratio).
    Compares recent window to prior window of same length.
    """
    if len(timestamps) < 3:
        return False, 0.0

    now = datetime.utcnow()
    recent_cutoff = now - timedelta(days=window_days)
    prior_cutoff = recent_cutoff - timedelta(days=window_days)

    recent_count = sum(1 for t in timestamps if t >= recent_cutoff)
    prior_count = sum(1 for t in timestamps if prior_cutoff <= t < recent_cutoff)

    if prior_count == 0:
        return recent_count > 2, float(recent_count)

    ratio = recent_count / prior_count
    return ratio > 1.5, ratio


def compute_severity(
    signal_count: int,
    temporal_weight: float,
    acceleration_ratio: float,
    confidence: float,
) -> Severity:
    """Map weighted signal features to NIST-aligned severity 1-5."""
    raw_score = (
        0.3 * min(signal_count / 10.0, 1.0)
        + 0.35 * min(temporal_weight / 5.0, 1.0)
        + 0.2 * min(acceleration_ratio / 3.0, 1.0)
        + 0.15 * confidence
    )

    if raw_score >= 0.80:
        return Severity.CRITICAL
    elif raw_score >= 0.60:
        return Severity.HIGH
    elif raw_score >= 0.40:
        return Severity.MODERATE
    elif raw_score >= 0.20:
        return Severity.LOW
    else:
        return Severity.MINIMAL
