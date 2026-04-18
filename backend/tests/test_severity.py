"""
Tests for severity scoring and temporal weighting engine.
"""

import pytest
from datetime import datetime, timedelta, timezone
from core.severity import compute_temporal_weight, compute_severity_score, detect_acceleration
from pipeline.temporal_weighting import TemporalWeightingEngine


class TestTemporalWeight:
    def test_recent_signal_high_weight(self):
        now = datetime.now(timezone.utc)
        weight = compute_temporal_weight(now, half_life_days=30)
        assert weight > 0.9

    def test_old_signal_low_weight(self):
        old = datetime.now(timezone.utc) - timedelta(days=90)
        weight = compute_temporal_weight(old, half_life_days=30)
        assert weight < 0.2

    def test_half_life_at_half_life(self):
        half_life = 30
        at_half = datetime.now(timezone.utc) - timedelta(days=half_life)
        weight = compute_temporal_weight(at_half, half_life_days=half_life)
        assert abs(weight - 0.5) < 0.05

    def test_future_signal_capped(self):
        future = datetime.now(timezone.utc) + timedelta(days=1)
        weight = compute_temporal_weight(future, half_life_days=30)
        assert weight <= 1.0


class TestSeverityScore:
    def test_low_confidence_low_severity(self):
        score = compute_severity_score(confidence=0.5, signal_count=3, weight=0.8)
        assert 1 <= score <= 3

    def test_high_confidence_high_count(self):
        score = compute_severity_score(confidence=0.95, signal_count=20, weight=1.0)
        assert 4 <= score <= 5

    def test_score_bounded(self):
        for conf in [0.1, 0.5, 0.9, 1.0]:
            for count in [1, 5, 10, 50]:
                for w in [0.1, 0.5, 1.0]:
                    score = compute_severity_score(conf, count, w)
                    assert 1 <= score <= 5


class TestAccelerationDetection:
    def test_rising_trend(self):
        recent = [3.0, 3.5, 4.0, 4.2]
        older = [1.5, 2.0, 2.0, 2.5]
        result = detect_acceleration(recent, older)
        assert result > 0

    def test_declining_trend(self):
        recent = [1.0, 1.0, 0.8]
        older = [3.0, 3.5, 4.0]
        result = detect_acceleration(recent, older)
        assert result < 0

    def test_stable_trend(self):
        recent = [2.0, 2.0, 2.0]
        older = [2.0, 2.0, 2.0]
        result = detect_acceleration(recent, older)
        assert abs(result) < 0.1


class TestTemporalWeightingEngine:
    def test_engine_instantiation(self):
        engine = TemporalWeightingEngine()
        assert engine is not None

    def test_compute_weights(self):
        engine = TemporalWeightingEngine()
        timestamps = [
            datetime.now(timezone.utc) - timedelta(days=i)
            for i in range(10)
        ]
        weights = engine.compute_weights(timestamps)
        assert len(weights) == 10
        # Most recent should have highest weight
        assert weights[0] >= weights[-1]
